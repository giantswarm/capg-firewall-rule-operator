package security

import (
	"context"
	"math"
	"net/http"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/to"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/google"
)

const (
	ActionAllow   = "allow"
	ActionDeny403 = "deny(403)"

	SecurityPolicyVersionedExpr = "SRC_IPS_V1"

	DefaultRuleDescription = "Default rule, higher priority overrides it"
	DefaultRuleIPRanges    = "*"
	DefaultRulePriority    = math.MaxInt32
)

type Policy struct {
	Name          string
	Description   string
	DefaultAction string
	Rules         []PolicyRule
}

type PolicyRule struct {
	Action         string
	Description    string
	SourceIPRanges []string
	Priority       int32
}

type Client struct {
	securityPolicies *compute.SecurityPoliciesClient
	backendServices  *compute.BackendServicesClient
}

func NewClient(securityPolicies *compute.SecurityPoliciesClient, backendServices *compute.BackendServicesClient) *Client {
	return &Client{
		securityPolicies: securityPolicies,
		backendServices:  backendServices,
	}
}

func (c *Client) ApplyPolicy(ctx context.Context, cluster *capg.GCPCluster, policy Policy) error {
	logger := c.getLogger(ctx, policy.Name)

	logger.Info("Applying security policy")
	defer logger.Info("Done applying security policy")

	if google.IsNilOrEmpty(cluster.Status.Network.APIServerBackendService) {
		return errors.New("cluster does not have backend service")
	}

	securityPolicy, err := c.applySecurityPolicy(ctx, logger, cluster, policy)
	if err != nil {
		return errors.WithStack(err)
	}

	return c.setSecurityPolicy(ctx, cluster, securityPolicy)
}

func (c *Client) setSecurityPolicy(ctx context.Context, cluster *capg.GCPCluster, policy *computepb.SecurityPolicy) error {
	req := &computepb.SetSecurityPolicyBackendServiceRequest{
		BackendService: google.GetResourceName(*cluster.Status.Network.APIServerBackendService),
		Project:        cluster.Spec.Project,
		SecurityPolicyReferenceResource: &computepb.SecurityPolicyReference{
			SecurityPolicy: policy.SelfLink,
		},
	}

	op, err := c.backendServices.SetSecurityPolicy(ctx, req)
	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	return errors.WithStack(err)
}

func (c *Client) applySecurityPolicy(ctx context.Context, logger logr.Logger, cluster *capg.GCPCluster, policy Policy) (*computepb.SecurityPolicy, error) {
	securityPolicy := toGCPSecurityPolicy(cluster, policy)

	gcpPolicy, err := c.createSecurityPolicy(ctx, cluster, securityPolicy)
	if google.HasHttpCode(err, http.StatusConflict) {
		logger.Info("securityPolicy already exists. Updating")
		return c.updateSecurityPolicy(ctx, cluster, securityPolicy)
	}

	if err != nil {
		return nil, errors.WithStack(err)
	}

	return gcpPolicy, nil
}

func (c *Client) DeletePolicy(ctx context.Context, cluster *capg.GCPCluster, name string) error {
	logger := c.getLogger(ctx, name)

	logger.Info("Deleting security policy")
	defer logger.Info("Done deleting security policy")

	if cluster.Status.Network.APIServerBackendService != nil {
		return errors.New("cluster backend service not deleted yet")
	}

	req := &computepb.DeleteSecurityPolicyRequest{
		Project:        cluster.Spec.Project,
		SecurityPolicy: name,
	}
	op, err := c.securityPolicies.Delete(ctx, req)
	if google.HasHttpCode(err, http.StatusNotFound) {
		logger.Info("Firewall already deleted")
		return nil
	}

	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	return errors.WithStack(err)
}

func (c *Client) createSecurityPolicy(ctx context.Context, cluster *capg.GCPCluster, policy *computepb.SecurityPolicy) (*computepb.SecurityPolicy, error) {
	req := &computepb.InsertSecurityPolicyRequest{
		Project:                cluster.Spec.Project,
		SecurityPolicyResource: policy,
	}

	op, err := c.securityPolicies.Insert(ctx, req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Getting the policy is necessary to populate the SelfLink.
	return c.getSecurityPolicy(ctx, cluster, *policy.Name)
}

func (c *Client) getSecurityPolicy(ctx context.Context, cluster *capg.GCPCluster, name string) (*computepb.SecurityPolicy, error) {
	req := &computepb.GetSecurityPolicyRequest{
		Project:        cluster.Spec.Project,
		SecurityPolicy: name,
	}
	return c.securityPolicies.Get(ctx, req)
}

func (c *Client) updateSecurityPolicy(ctx context.Context, cluster *capg.GCPCluster, policy *computepb.SecurityPolicy) (*computepb.SecurityPolicy, error) {
	currentPolicy, err := c.getSecurityPolicy(ctx, cluster, *policy.Name)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// There are three groups of rules - new rules, rules we want to update and
	// rules that we want to delete. Rules that are in the current policy, but
	// not in the new one should be deleted.
	// We start of by marking all the rules in the current policy for deletion.
	rulesToDelete := constructRulePriorityMap(currentPolicy.Rules)
	for _, rule := range policy.Rules {
		priority := *rule.Priority

		// If both the new and old policy contain a rule with the same
		// priority, then patch that rule and remove it from the rules that
		// need to be deleted.
		// If a rule is only in the new policy then it needs to be created.
		// NOTE: We can't check for 404 when patching the rule. GCP will always
		// return 400 if a rule doesn't exist. This also applies to `GetRule`
		_, ok := rulesToDelete[priority]
		if ok {
			delete(rulesToDelete, priority)
			err = c.patchRule(ctx, cluster, policy, rule)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			continue
		}

		err = c.createRule(ctx, cluster, policy, rule)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	for rulePriority := range rulesToDelete {
		// The default rule cannot be deleted
		if rulePriority == DefaultRulePriority {
			continue
		}

		err = c.deleteRule(ctx, cluster, policy, rulePriority)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	selfLink := *currentPolicy.SelfLink
	policy.SelfLink = &selfLink
	return policy, nil
}

func (c *Client) createRule(ctx context.Context, cluster *capg.GCPCluster, policy *computepb.SecurityPolicy, rule *computepb.SecurityPolicyRule) error {
	req := &computepb.AddRuleSecurityPolicyRequest{
		Project:                    cluster.Spec.Project,
		SecurityPolicy:             *policy.Name,
		SecurityPolicyRuleResource: rule,
	}
	op, err := c.securityPolicies.AddRule(ctx, req)
	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (c *Client) patchRule(ctx context.Context, cluster *capg.GCPCluster, policy *computepb.SecurityPolicy, rule *computepb.SecurityPolicyRule) error {
	req := &computepb.PatchRuleSecurityPolicyRequest{
		Priority:                   rule.Priority,
		Project:                    cluster.Spec.Project,
		SecurityPolicy:             *policy.Name,
		SecurityPolicyRuleResource: rule,
	}
	op, err := c.securityPolicies.PatchRule(ctx, req)
	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	return errors.WithStack(err)
}

func (c *Client) deleteRule(ctx context.Context, cluster *capg.GCPCluster, policy *computepb.SecurityPolicy, rulePriority int32) error {
	req := &computepb.RemoveRuleSecurityPolicyRequest{
		Priority:       &rulePriority,
		Project:        cluster.Spec.Project,
		SecurityPolicy: *policy.Name,
	}

	op, err := c.securityPolicies.RemoveRule(ctx, req)
	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	return errors.WithStack(err)
}

func (c *Client) getLogger(ctx context.Context, ruleName string) logr.Logger {
	logger := log.FromContext(ctx)
	logger = logger.WithName("security-client")
	return logger.WithValues("name", ruleName)
}

func constructRulePriorityMap(rules []*computepb.SecurityPolicyRule) map[int32]struct{} {
	priorityMap := map[int32]struct{}{}
	for _, rule := range rules {
		priorityMap[*rule.Priority] = struct{}{}
	}

	return priorityMap
}

func toGCPSecurityPolicy(cluster *capg.GCPCluster, policy Policy) *computepb.SecurityPolicy {
	defaultRule := getDefaultRule(policy.DefaultAction)
	rules := []*computepb.SecurityPolicyRule{defaultRule}

	for _, rule := range policy.Rules {
		rules = append(rules, &computepb.SecurityPolicyRule{
			Action:      to.StringP(rule.Action),
			Description: to.StringP(rule.Description),
			Match: &computepb.SecurityPolicyRuleMatcher{
				Config:        &computepb.SecurityPolicyRuleMatcherConfig{SrcIpRanges: rule.SourceIPRanges},
				VersionedExpr: to.StringP(SecurityPolicyVersionedExpr),
			},
			Priority: to.Int32P(rule.Priority),
		})
	}

	return &computepb.SecurityPolicy{
		Description: to.StringP(policy.Description),
		Name:        to.StringP(policy.Name),
		Rules:       rules,
	}
}

func getDefaultRule(defaultAction string) *computepb.SecurityPolicyRule {
	return &computepb.SecurityPolicyRule{
		Action:      to.StringP(defaultAction),
		Description: to.StringP(DefaultRuleDescription),
		Match: &computepb.SecurityPolicyRuleMatcher{
			Config: &computepb.SecurityPolicyRuleMatcherConfig{
				SrcIpRanges: []string{DefaultRuleIPRanges},
			},
			VersionedExpr: to.StringP(SecurityPolicyVersionedExpr),
		},
		Priority: to.Int32P(DefaultRulePriority),
	}
}
