package firewall

import (
	"context"
	"fmt"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/microerror"
	"github.com/go-logr/logr"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"google.golang.org/protobuf/proto"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	fwService *compute.FirewallsClient
	k8sClient client.Client
	logger    logr.Logger
}

func NewClient(fwService *compute.FirewallsClient, k8sClient client.Client, logger logr.Logger) *Client {
	return &Client{
		fwService: fwService,
		k8sClient: k8sClient,
		logger:    logger,
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
	c.logger.Info(fmt.Sprintf("Creating firewall rule for bastion %s", tagName))

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
		if isAlreadyExistError(err) {
			// pass thru, resource already exists
			return nil
		} else {
			return microerror.Mask(err)
		}
	}

	err = op.Wait(ctx)

	if err != nil {
		if isAlreadyExistError(err) {
			// pass thru, resource already exists
		} else {
			return microerror.Mask(err)
		}
	}

	c.logger.Info(fmt.Sprintf("Created firewall rule for bastion %s", tagName))
	return nil
}

func (c *Client) DeleteBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	name := fmt.Sprintf("%s-bastion", cluster.GetName())
	logger := c.logger.WithValues("name", name)
	logger.Info(fmt.Sprintf("Deleting firewall rule for bastion %s", name))

	req := &computepb.DeleteFirewallRequest{
		Project:  cluster.Spec.Project,
		Firewall: bastionFirewallPolicyRuleName(cluster.Name),
	}
	logger.Info("DEBUG: prepared request")

	op, err := c.fwService.Delete(ctx, req)
	logger.Info("DEBUG: executed delete op")

	if isNotFoundError(err) {
		// pass thru, resource is already deleted
		logger.Info("DEBUG: error is not found after deleted")

		return nil
	} else if err != nil {
		logger.Info("DEBUG: error is different after deleted", "error", err.Error())

		return microerror.Mask(err)
	}
	logger.Info("DEBUG: preparing op.wait")
	err = op.Wait(ctx)

	if isNotFoundError(err) {
		// pass thru, resource is already deleted
		logger.Info("DEBUG: error is not found, after wait")

	} else if err != nil {
		logger.Info("DEBUG: error is different after op wait", "error", err.Error())

		return microerror.Mask(err)
	}

	logger.Info("Deleted firewall rule for bastion")
	return nil
}

func bastionFirewallPolicyRuleName(clusterName string) string {
	return fmt.Sprintf("allow-%s-bastion-ssh", clusterName)
}

func isAlreadyExistError(err error) bool {
	return strings.Contains(err.Error(), "already exists")
}

func isNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "was not found")
}
