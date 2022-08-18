package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/annotations"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/cidr"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/google"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
)

const (
	FinalizerFirewall                 = "capg-firewall-rule-operator.finalizers.giantswarm.io"
	AnnotationBastionAllowListSubnets = "bastion.gcp.giantswarm.io/allowlist"
)

type GCPClusterClient interface {
	Get(context.Context, types.NamespacedName) (*capg.GCPCluster, error)
	GetOwner(context.Context, *capg.GCPCluster) (*capi.Cluster, error)
	AddFinalizer(context.Context, *capg.GCPCluster, string) error
	RemoveFinalizer(context.Context, *capg.GCPCluster, string) error
}

//counterfeiter:generate . FirewallsClient
type FirewallsClient interface {
	ApplyRule(context.Context, *capg.GCPCluster, firewall.Rule) error
	DeleteRule(context.Context, *capg.GCPCluster, string) error
}

type GCPClusterReconciler struct {
	logger logr.Logger

	client                   GCPClusterClient
	firewallClient           FirewallsClient
	securityPolicyReconciler *security.PolicyReconciler
}

func NewGCPClusterReconciler(
	logger logr.Logger,
	client GCPClusterClient,
	firewallClient FirewallsClient,
	securityPolicyReconciler *security.PolicyReconciler,
) *GCPClusterReconciler {
	return &GCPClusterReconciler{
		logger:                   logger,
		client:                   client,
		firewallClient:           firewallClient,
		securityPolicyReconciler: securityPolicyReconciler,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *GCPClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capg.GCPCluster{}).
		Complete(r)
}

func (r *GCPClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.logger.WithValues("gcpcluster", req.NamespacedName)
	logger.Info("Reconciling")
	defer logger.Info("Done reconciling")

	gcpCluster, err := r.client.Get(ctx, req.NamespacedName)
	if err != nil {
		if apimachineryerrors.IsNotFound(err) {
			logger.Info("GCP Cluster no longer exists")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.WithStack(err)
	}

	cluster, err := r.client.GetOwner(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	if cluster == nil {
		logger.Info("GCP Cluster does not have an owner cluster yet")
		return ctrl.Result{}, nil
	}

	if annotations.IsPaused(cluster, gcpCluster) {
		logger.Info("Infrastructure or core cluster is marked as paused. Won't reconcile")
		return ctrl.Result{}, nil
	}

	if !gcpCluster.DeletionTimestamp.IsZero() {
		result, err := r.reconcileDelete(ctx, gcpCluster)
		if err != nil {
			return ctrl.Result{}, errors.WithStack(err)
		}

		return result, nil
	}

	result, err := r.reconcileNormal(ctx, logger, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	return result, nil
}

func (r *GCPClusterReconciler) reconcileNormal(ctx context.Context, logger logr.Logger, gcpCluster *capg.GCPCluster) (ctrl.Result, error) {
	if google.IsNilOrEmpty(gcpCluster.Status.Network.SelfLink) {
		logger.Info("GCP Cluster does not have network set yet")
		return ctrl.Result{}, nil
	}

	if google.IsNilOrEmpty(gcpCluster.Status.Network.APIServerBackendService) {
		logger.Info("GCP Cluster does not have backend service set yet")
		return ctrl.Result{}, nil
	}

	err := r.client.AddFinalizer(ctx, gcpCluster, FinalizerFirewall)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	err = r.applyBastionFirewallRule(ctx, logger, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	err = r.securityPolicyReconciler.Reconcile(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	return ctrl.Result{}, nil
}

func (r *GCPClusterReconciler) reconcileDelete(ctx context.Context, gcpCluster *capg.GCPCluster) (ctrl.Result, error) {
	err := r.deleteBastionFirewallRule(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	err = r.securityPolicyReconciler.ReconcileDelete(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	err = r.client.RemoveFinalizer(ctx, gcpCluster, FinalizerFirewall)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	return ctrl.Result{}, nil
}

func (r *GCPClusterReconciler) applyBastionFirewallRule(ctx context.Context, logger logr.Logger, gcpCluster *capg.GCPCluster) error {
	ruleName := getBastionFirewallRuleName(gcpCluster.Name)
	tagName := fmt.Sprintf("%s-bastion", gcpCluster.Name)
	sourceIPRanges, err := getIPRangesFromAnnotation(logger, gcpCluster, AnnotationBastionAllowListSubnets)
	if err != nil {
		return errors.WithStack(err)
	}

	rule := firewall.Rule{
		Allowed: []firewall.Allowed{
			{
				IPProtocol: firewall.ProtocolTCP,
				Ports:      []uint32{firewall.PortSSH},
			},
		},
		Description:  "allow port 22 for SSH",
		Direction:    firewall.DirectionIngress,
		Name:         ruleName,
		TargetTags:   []string{tagName},
		SourceRanges: sourceIPRanges,
	}

	return r.firewallClient.ApplyRule(ctx, gcpCluster, rule)
}

func (r *GCPClusterReconciler) deleteBastionFirewallRule(ctx context.Context, gcpCluster *capg.GCPCluster) error {
	ruleName := getBastionFirewallRuleName(gcpCluster.Name)
	return r.firewallClient.DeleteRule(ctx, gcpCluster, ruleName)
}

func getBastionFirewallRuleName(clusterName string) string {
	return fmt.Sprintf("allow-%s-bastion-ssh", clusterName)
}

func getIPRangesFromAnnotation(logger logr.Logger, gcpCluster *capg.GCPCluster, annotation string) ([]string, error) {
	annotation, ok := gcpCluster.Annotations[annotation]
	if !ok {
		logger.Info("Cluster does not have bastion allow list annotation. Using cloud default.")
		return nil, nil
	}

	return cidr.ParseFromCommaSeparated(annotation)
}
