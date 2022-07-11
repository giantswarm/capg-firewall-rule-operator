package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"google.golang.org/protobuf/proto"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
)

type Client struct {
	fwService *compute.FirewallsClient
	logger    logr.Logger
}

func NewClient(fwService *compute.FirewallsClient, logger logr.Logger) *Client {
	return &Client{
		fwService: fwService,
		logger:    logger,
	}
}

const (
	ProtocolTCP = "tcp"
	PortSSH     = "22"

	AnnotationBastionWhitelistSubnets = "bastion.gcp.giantswarm.io/whitelist"
)

func (c *Client) CreateBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	fwName := bastionFirewallPolicyRuleName(cluster.Name)
	ipProtocol := ProtocolTCP

	tagName := fmt.Sprintf("%s-bastion", cluster.GetName())
	logger := c.logger.WithValues("name", tagName)
	logger.Info("Creating firewall rule for bastion")

	rule := &computepb.Firewall{
		Allowed: []*computepb.Allowed{
			{
				IPProtocol: &ipProtocol,
				Ports:      []string{PortSSH},
			},
		},
		Description:  proto.String("allow port 22 for SSH to"),
		Direction:    proto.String(computepb.Firewall_INGRESS.String()),
		Name:         &fwName,
		Network:      cluster.Status.Network.SelfLink,
		TargetTags:   []string{tagName},
		SourceRanges: GetIPRangesFromAnnotation(logger, cluster),
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
			return errors.WithStack(err)
		}
	}

	err = op.Wait(ctx)

	if err != nil {
		if isAlreadyExistError(err) {
			// pass thru, resource already exists
		} else {
			return errors.WithStack(err)
		}
	}

	logger.Info("Created firewall rule for bastion")
	return nil
}

func (c *Client) DeleteBastionFirewallRule(ctx context.Context, cluster *capg.GCPCluster) error {
	name := fmt.Sprintf("%s-bastion", cluster.GetName())
	logger := c.logger.WithValues("name", name)
	logger.Info("Deleting firewall rule for bastion")

	req := &computepb.DeleteFirewallRequest{
		Project:  cluster.Spec.Project,
		Firewall: bastionFirewallPolicyRuleName(cluster.Name),
	}

	op, err := c.fwService.Delete(ctx, req)

	if isNotFoundError(err) {
		// pass thru, resource is already deleted
		logger.Info("Firewall rule for bastion is already deleted")

		return nil
	} else if err != nil {
		return errors.WithStack(err)
	}
	err = op.Wait(ctx)

	if isNotFoundError(err) {
		// pass thru, resource is already deleted
	} else if err != nil {
		return errors.WithStack(err)
	}

	logger.Info("Deleted firewall rule for bastion")
	return nil
}

func GetIPRangesFromAnnotation(logger logr.Logger, gcpCluster *capg.GCPCluster) []string {
	var ipRanges []string

	if a, ok := gcpCluster.Annotations[AnnotationBastionWhitelistSubnets]; ok {
		parts := strings.Split(a, ",")

		for _, p := range parts {
			// try parse the cidr
			_, _, err := net.ParseCIDR(p)
			if err == nil {
				ipRanges = append(ipRanges, p)
				logger.Error(failedParseSubnetError, "failed parsing subnets from annotations on CPCLuster", "subnet", p)
			}
		}
	}

	return ipRanges
}

func bastionFirewallPolicyRuleName(clusterName string) string {
	return fmt.Sprintf("allow-%s-bastion-ssh", clusterName)
}
