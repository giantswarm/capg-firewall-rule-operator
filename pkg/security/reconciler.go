package security

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/cidr"
)

const AnnotationAPIAllowListSubnets = "api.gcp.giantswarm.io/allowlist"

//counterfeiter:generate . SecurityPolicyClient
type SecurityPolicyClient interface {
	ApplyPolicy(context.Context, *capg.GCPCluster, Policy) error
	DeletePolicy(context.Context, *capg.GCPCluster, string) error
}

//counterfeiter:generate . ClusterNATIPResolver
type ClusterNATIPResolver interface {
	GetIPs(context.Context, types.NamespacedName) ([]string, error)
}

func NewPolicyReconciler(
	defaultAPIAllowList []string,
	managementCluster types.NamespacedName,
	securityPolicyClient SecurityPolicyClient,
	ipResolver ClusterNATIPResolver,
) *PolicyReconciler {
	return &PolicyReconciler{
		defaultAPIAllowList:  defaultAPIAllowList,
		managementCluster:    managementCluster,
		securityPolicyClient: securityPolicyClient,
		ipResolver:           ipResolver,
	}
}

type PolicyReconciler struct {
	defaultAPIAllowList []string
	managementCluster   types.NamespacedName

	securityPolicyClient SecurityPolicyClient
	ipResolver           ClusterNATIPResolver
}

func (r *PolicyReconciler) Reconcile(ctx context.Context, cluster *capg.GCPCluster) error {
	logger := r.getLogger(ctx)

	userRules, err := r.getUserRules(logger, cluster)
	if err != nil {
		return errors.WithStack(err)
	}

	defaultRules, err := r.getDefaultRules(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	rules := []PolicyRule{}
	rules = append(rules, userRules...)
	rules = append(rules, defaultRules...)

	policyName := getAPISecurityPolicyName(cluster.Name)
	policy := Policy{
		Name:          policyName,
		Description:   "allow IPs to connect to kubernetes api",
		DefaultAction: ActionDeny403,
		Rules:         rules,
	}

	return r.securityPolicyClient.ApplyPolicy(ctx, cluster, policy)
}

func (r *PolicyReconciler) ReconcileDelete(ctx context.Context, cluster *capg.GCPCluster) error {
	policyName := getAPISecurityPolicyName(cluster.Name)
	return r.securityPolicyClient.DeletePolicy(ctx, cluster, policyName)
}

func (r *PolicyReconciler) getUserRules(logger logr.Logger, cluster *capg.GCPCluster) ([]PolicyRule, error) {
	sourceIPRanges, err := getIPRanges(logger, cluster)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	rules := []PolicyRule{}
	if len(sourceIPRanges) != 0 {
		rules = append(rules, PolicyRule{
			Action:         ActionAllow,
			Description:    "allow user specified ips to connect to kubernetes api",
			SourceIPRanges: sourceIPRanges,
			Priority:       0,
		})
	}
	return rules, nil
}

func (r *PolicyReconciler) getDefaultRules(ctx context.Context) ([]PolicyRule, error) {
	mcNATIPs, err := r.ipResolver.GetIPs(ctx, r.managementCluster)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	allowMCNATRule := PolicyRule{
		Action:         ActionAllow,
		Description:    "allow MC NAT IPs",
		SourceIPRanges: mcNATIPs,
		Priority:       1,
	}

	allowDefaultAllowlist := PolicyRule{
		Action:         ActionAllow,
		Description:    "allow default IP ranges",
		SourceIPRanges: r.defaultAPIAllowList,
		Priority:       2,
	}

	return []PolicyRule{
		allowMCNATRule,
		allowDefaultAllowlist,
	}, nil
}

func (r *PolicyReconciler) getLogger(ctx context.Context) logr.Logger {
	logger := log.FromContext(ctx)
	return logger.WithName("security-policy-reconciler")
}

func getAPISecurityPolicyName(clusterName string) string {
	return fmt.Sprintf("allow-%s-apiserver", clusterName)
}

func getIPRanges(logger logr.Logger, gcpCluster *capg.GCPCluster) ([]string, error) {
	annotation, ok := gcpCluster.Annotations[AnnotationAPIAllowListSubnets]
	if !ok {
		logger.Info("Cluster does not have api allow list annotation. Skipping user rule")
		return nil, nil
	}

	return cidr.ParseFromCommaSeparated(annotation)
}
