package firewall

import (
	"context"

	compute "cloud.google.com/go/compute/apiv1"
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

func (c *Client) CreateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	// TODO

	return nil
}

func (c *Client) AssignBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	// TODO
	/*
		_, err := c.dnsService.ResourceRecordSets.Create(cluster.Spec.Project, cluster.Name, record).
			Context(ctx).
			Do()

		if hasHttpCode(err, http.StatusConflict) {
			return nil
		}
		return microerror.Mask(err)

	*/
	return nil
}

func (c *Client) DisassociateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	// TODO

	return nil
}

func (c *Client) DeleteBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	// TODO
	return nil
}

/*
func hasHttpCode(err error, statusCode int) bool {
	var googleErr *googleapi.Error
	if errors.As(err, &googleErr) {
		if googleErr.Code == statusCode {
			return true
		}
	}

	return false
}
*/