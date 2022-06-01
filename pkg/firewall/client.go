package firewall

import (
	"context"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/microerror"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"google.golang.org/protobuf/proto"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	fwService *compute.FirewallsClient
	k8sClient client.Client
}

func NewClient(fwService *compute.FirewallsClient, k8sClient client.Client) *Client {
	return &Client{
		fwService: fwService,
		k8sClient: k8sClient,
	}
}

const (
	ProtocolTCP = "tcp"
	PortSSH     = "22"
)

func (c *Client) CreateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	fwName := bastionFirewallPolicyRuleName(cluster.Name)
	ipProtocol := ProtocolTCP

	tagName := fmt.Sprintf("%s-bastion", cluster.GetName())

	rule := &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: &ipProtocol,
				Ports:      []string{PortSSH},
			},
		},
		Description: proto.String("allow port 22 for SSH to"),
		Direction:   proto.String(computepb.Firewall_INGRESS.String()),
		Name:        &fwName,
		Network:     cluster.Status.Network.SelfLink,
		TargetTags:  []string{tagName},
	}

	req := &computepb.InsertFirewallRequest{
		Project:          cluster.Spec.Project,
		FirewallResource: rule,
	}

	op, err := c.fwService.Insert(ctx, req)
	if err != nil {
		return microerror.Mask(err)
	}

	if err = op.Wait(ctx); err != nil {
		return microerror.Mask(err)
	}

	return nil
}

func (c *Client) AssignBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {

	return nil
}

func (c *Client) DisassociateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {

	return nil
}

func (c *Client) DeleteBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	req := &computepb.DeleteFirewallRequest{
		Project:  cluster.Spec.Project,
		Firewall: bastionFirewallPolicyRuleName(cluster.Name),
	}

	op, err := c.fwService.Delete(ctx, req)
	if err != nil {
		return microerror.Mask(err)
	}

	if err = op.Wait(ctx); err != nil {
		return microerror.Mask(err)
	}

	return nil
}

func bastionFirewallPolicyRuleName(clusterName string) string {
	return fmt.Sprintf("%s-allow-bastion-ssh", clusterName)
}
