package controllers

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/annotations"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/google"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
)

const FinalizerFirewall = "capg-firewall-rule-operator.finalizers.giantswarm.io"

type GCPClusterClient interface {
	Get(context.Context, types.NamespacedName) (*capg.GCPCluster, error)
	GetOwner(context.Context, *capg.GCPCluster) (*capi.Cluster, error)
	AddFinalizer(context.Context, *capg.GCPCluster, string) error
	RemoveFinalizer(context.Context, *capg.GCPCluster, string) error
}

type GCPClusterReconciler struct {
	client                   GCPClusterClient
	firewallRuleReconciler   *firewall.RuleReconciler
	securityPolicyReconciler *security.PolicyReconciler
}

func NewGCPClusterReconciler(
	client GCPClusterClient,
	firewallRuleReconciler *firewall.RuleReconciler,
	securityPolicyReconciler *security.PolicyReconciler,
) *GCPClusterReconciler {
	return &GCPClusterReconciler{
		client:                   client,
		firewallRuleReconciler:   firewallRuleReconciler,
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
	logger := r.getLogger(ctx)

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

	if google.IsNilOrEmpty(gcpCluster.Status.Network.Router) {
		logger.Info("GCP Cluster does not have a router set yet")
		return ctrl.Result{}, nil
	}

	err := r.client.AddFinalizer(ctx, gcpCluster, FinalizerFirewall)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	err = r.firewallRuleReconciler.Reconcile(ctx, gcpCluster)
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
	err := r.firewallRuleReconciler.ReconcileDelete(ctx, gcpCluster)
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

func (r *GCPClusterReconciler) getLogger(ctx context.Context) logr.Logger {
	logger := log.FromContext(ctx)
	return logger.WithName("gcpcluster-reconciler")
}
