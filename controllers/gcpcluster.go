package controllers

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/annotations"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
)

const (
	FinalizerFirewall                 = "capg-firewall-rule-operator.finalizers.giantswarm.io"
	AnnotationBastionAllowListSubnets = "bastion.gcp.giantswarm.io/allowlist"
	AnnotationAPIAllowListSubnets     = "api.gcp.giantswarm.io/allowlist"
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

//counterfeiter:generate . SecurityPolicyClient
type SecurityPolicyClient interface {
	ApplyPolicy(context.Context, *capg.GCPCluster, security.Policy) error
	DeletePolicy(context.Context, *capg.GCPCluster, string) error
}

//counterfeiter:generate . ClusterNATIPResolver
type ClusterNATIPResolver interface {
	GetIPs(context.Context, types.NamespacedName) ([]string, error)
}

type GCPClusterReconciler struct {
	logger            logr.Logger
	managementCluster types.NamespacedName

	client               GCPClusterClient
	firewallClient       FirewallsClient
	securityPolicyClient SecurityPolicyClient
	ipResolver           ClusterNATIPResolver
}

func NewGCPClusterReconciler(
	logger logr.Logger,
	managementCluster types.NamespacedName,
	client GCPClusterClient,
	firewallClient FirewallsClient,
	securityPolicyClient SecurityPolicyClient,
	ipResolver ClusterNATIPResolver,
) *GCPClusterReconciler {
	return &GCPClusterReconciler{
		logger:               logger,
		managementCluster:    managementCluster,
		client:               client,
		firewallClient:       firewallClient,
		securityPolicyClient: securityPolicyClient,
		ipResolver:           ipResolver,
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
	if gcpCluster.Status.Network.SelfLink == nil || *gcpCluster.Status.Network.SelfLink == "" {
		logger.Info("GCP Cluster does not have network set yet")
		return ctrl.Result{}, nil
	}

	if gcpCluster.Status.Network.APIServerBackendService == nil || *gcpCluster.Status.Network.APIServerBackendService == "" {
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

	err = r.applyAPISecurityPolicy(ctx, logger, gcpCluster)
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

	err = r.deleteAPISecurityPolicy(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	err = r.client.RemoveFinalizer(ctx, gcpCluster, FinalizerFirewall)
	if err != nil {
		return ctrl.Result{}, errors.WithStack(err)
	}

	return ctrl.Result{}, nil
}

func (r *GCPClusterReconciler) applyAPISecurityPolicy(ctx context.Context, logger logr.Logger, gcpCluster *capg.GCPCluster) error {
	policyName := getAPISecurityPolicyName(gcpCluster.Name)
	sourceIPRanges, err := getIPRangesFromAnnotation(logger, gcpCluster, AnnotationAPIAllowListSubnets)
	if err != nil {
		return errors.WithStack(err)
	}

	rules := []security.PolicyRule{}
	if len(sourceIPRanges) != 0 {
		rules = append(rules, security.PolicyRule{
			Action:         security.ActionAllow,
			Description:    "allow user specified ips to connect to kubernetes api",
			SourceIPRanges: sourceIPRanges,
			Priority:       0,
		})
	}

	allowMCNATRule, err := r.getAllowMCNATRule(ctx)
	if err != nil {
		return errors.WithStack(err)
	}
	rules = append(rules, allowMCNATRule)

	policy := security.Policy{
		Name:          policyName,
		Description:   "allow IPs to connect to kubernetes api",
		DefaultAction: security.ActionDeny403,
		Rules:         rules,
	}

	return r.securityPolicyClient.ApplyPolicy(ctx, gcpCluster, policy)
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

func (r *GCPClusterReconciler) getAllowMCNATRule(ctx context.Context) (security.PolicyRule, error) {
	mcNATIPs, err := r.ipResolver.GetIPs(ctx, r.managementCluster)
	if err != nil {
		return security.PolicyRule{}, errors.WithStack(err)
	}

	return security.PolicyRule{
		Action:         security.ActionAllow,
		Description:    "allow MC NAT IPs",
		SourceIPRanges: mcNATIPs,
		Priority:       1,
	}, nil
}

func (r *GCPClusterReconciler) deleteBastionFirewallRule(ctx context.Context, gcpCluster *capg.GCPCluster) error {
	ruleName := getBastionFirewallRuleName(gcpCluster.Name)
	return r.firewallClient.DeleteRule(ctx, gcpCluster, ruleName)
}

func (r *GCPClusterReconciler) deleteAPISecurityPolicy(ctx context.Context, gcpCluster *capg.GCPCluster) error {
	policyName := getAPISecurityPolicyName(gcpCluster.Name)
	return r.securityPolicyClient.DeletePolicy(ctx, gcpCluster, policyName)
}

func getBastionFirewallRuleName(clusterName string) string {
	return fmt.Sprintf("allow-%s-bastion-ssh", clusterName)
}

func getAPISecurityPolicyName(clusterName string) string {
	return fmt.Sprintf("allow-%s-apiserver", clusterName)
}

func getIPRangesFromAnnotation(logger logr.Logger, gcpCluster *capg.GCPCluster, annotation string) ([]string, error) {
	annotation, ok := gcpCluster.Annotations[annotation]
	if !ok {
		logger.Info("Cluster does not have bastion allow list annotation. Using cloud default.")
		return nil, nil
	}

	ipRanges := strings.Split(annotation, ",")
	// validate the annotation contains valid CIRDs
	for _, cidr := range ipRanges {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			message := fmt.Sprintf("annotation %s contains invalid CIDRs", AnnotationBastionAllowListSubnets)
			logger.Error(err, message, "subnet", cidr)
			return nil, errors.New(message)
		}
	}
	return ipRanges, nil
}
