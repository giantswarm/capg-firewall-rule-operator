package firewall

import (
	"context"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/microerror"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	fwService *compute.FirewallPoliciesClient
	k8sClient client.Client
}

func NewClient(fwService *compute.FirewallPoliciesClient, k8sClient client.Client) *Client {
	return &Client{
		fwService: fwService,
		k8sClient: k8sClient,
	}
}

const (
	ActionAllow      = "allow"
	DirectionIngress = "INGRESS"
	ProtocolTCP      = "tcp"
	EffectiveTag     = "EFFECTIVE"
	SourceIPAll      = "0.0.0.0/0"
	PortSSH          = "22"
)

func (c *Client) CreateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	// TODO
	action := ActionAllow
	direction := DirectionIngress
	effectiveTag := EffectiveTag
	ipProtocol := ProtocolTCP

	description := "allow port 22 for SSH to"
	priority := int32(1000)
	tagName := fmt.Sprintf("%s-bastion", cluster.GetName())

	req := &computepb.AddRuleFirewallPolicyRequest{
		FirewallPolicy: bastionFirewallPolicyRuleName(cluster.Name),
		FirewallPolicyRuleResource: &computepb.FirewallPolicyRule{
			Action:      &action,
			Description: &description,
			Direction:   &direction,
			Match: &computepb.FirewallPolicyRuleMatcher{
				SrcIpRanges: []string{SourceIPAll},
				Layer4Configs: []*computepb.FirewallPolicyRuleMatcherLayer4Config{
					{
						IpProtocol: &ipProtocol,
						Ports:      []string{PortSSH},
					},
				},
			},
			Priority: &priority,
			TargetSecureTags: []*computepb.FirewallPolicyRuleSecureTag{
				{
					Name:  &tagName,
					State: &effectiveTag,
				},
			},
		},
	}

	_, err := c.fwService.AddRule(ctx, req)
	if err != nil {
		return microerror.Mask(err)
	}

	return nil
}

func (c *Client) AssignBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {

	return nil
}

func (c *Client) DisassociateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	// TODO

	return nil
}

func (c *Client) DeleteBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	req := &computepb.DeleteFirewallPolicyRequest{
		FirewallPolicy: bastionFirewallPolicyRuleName(cluster.Name),
	}

	_, err := c.fwService.Delete(ctx, req)
	if err != nil {
		return microerror.Mask(err)
	}

	return nil
}

func bastionFirewallPolicyRuleName(clusterName string) string {
	return fmt.Sprintf("%s-allow-bastion-ssh", clusterName)
}
