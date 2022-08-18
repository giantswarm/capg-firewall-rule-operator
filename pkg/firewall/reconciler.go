package firewall

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/cidr"
)

const AnnotationBastionAllowListSubnets = "bastion.gcp.giantswarm.io/allowlist"

//counterfeiter:generate . FirewallsClient
type FirewallsClient interface {
	ApplyRule(context.Context, *capg.GCPCluster, Rule) error
	DeleteRule(context.Context, *capg.GCPCluster, string) error
}

func NewRuleReconciler(
	defaultBastionHostAllowList []string,
	firewallClient FirewallsClient,
) *RuleReconciler {
	return &RuleReconciler{
		defaultBastionHostAllowList: defaultBastionHostAllowList,
		firewallClient:              firewallClient,
	}
}

type RuleReconciler struct {
	defaultBastionHostAllowList []string

	firewallClient FirewallsClient
}

func (r *RuleReconciler) Reconcile(ctx context.Context, cluster *capg.GCPCluster) error {
	logger := r.getLogger(ctx)

	ruleName := getBastionFirewallRuleName(cluster.Name)
	tagName := fmt.Sprintf("%s-bastion", cluster.Name)
	sourceIPRanges, err := getIPRangesFromAnnotation(logger, cluster)
	if err != nil {
		return errors.WithStack(err)
	}
	sourceIPRanges = append(sourceIPRanges, r.defaultBastionHostAllowList...)

	rule := Rule{
		Allowed: []Allowed{
			{
				IPProtocol: ProtocolTCP,
				Ports:      []uint32{PortSSH},
			},
		},
		Description:  "allow port 22 for SSH",
		Direction:    DirectionIngress,
		Name:         ruleName,
		TargetTags:   []string{tagName},
		SourceRanges: sourceIPRanges,
	}

	return r.firewallClient.ApplyRule(ctx, cluster, rule)
}

func (r *RuleReconciler) ReconcileDelete(ctx context.Context, cluster *capg.GCPCluster) error {
	ruleName := getBastionFirewallRuleName(cluster.Name)
	return r.firewallClient.DeleteRule(ctx, cluster, ruleName)
}

func (r *RuleReconciler) getLogger(ctx context.Context) logr.Logger {
	logger := log.FromContext(ctx)
	return logger.WithName("firewall-rule-reconciler")
}

func getBastionFirewallRuleName(clusterName string) string {
	return fmt.Sprintf("allow-%s-bastion-ssh", clusterName)
}

func getIPRangesFromAnnotation(logger logr.Logger, gcpCluster *capg.GCPCluster) ([]string, error) {
	annotation, ok := gcpCluster.Annotations[AnnotationBastionAllowListSubnets]
	if !ok {
		logger.Info("Cluster does not have bastion allow list annotation. Using cloud default.")
		return nil, nil
	}

	return cidr.ParseFromCommaSeparated(annotation)
}
