package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/microerror"
	"github.com/go-logr/logr"
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

	sourceIPRanges := GetIPRangesFromAnnotation(logger, cluster)

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
		SourceRanges: sourceIPRanges,
	}

	req := &computepb.InsertFirewallRequest{
		Project:          cluster.Spec.Project,
		FirewallResource: rule,
	}

	op, err := c.fwService.Insert(ctx, req)
	if err != nil {
		if isAlreadyExistError(err) {
			err = c.UpdateRuleIfNotUpToDate(ctx, cluster, rule)
			if err != nil {
				return microerror.Mask(err)
			}

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
		return microerror.Mask(err)
	}
	err = op.Wait(ctx)

	if isNotFoundError(err) {
		// pass thru, resource is already deleted
	} else if err != nil {
		return microerror.Mask(err)
	}

	logger.Info("Deleted firewall rule for bastion")
	return nil
}

func (c *Client) UpdateRuleIfNotUpToDate(ctx context.Context, cluster *capg.GCPCluster, rule *computepb.Firewall) error {
	fwName := bastionFirewallPolicyRuleName(cluster.Name)
	tagName := fmt.Sprintf("%s-bastion", cluster.GetName())
	logger := c.logger.WithValues("name", tagName)

	req := &computepb.GetFirewallRequest{
		Firewall: fwName,
		Project:  cluster.Spec.Project,
	}
	resp, err := c.fwService.Get(ctx, req)
	if err != nil {
		return microerror.Mask(err)
	}

	updateRules := false

	if len(resp.SourceRanges) != len(rule.SourceRanges) {
		updateRules = true
	} else {
		for i, subnet := range resp.SourceRanges {
			if rule.SourceRanges[i] != subnet {
				updateRules = true
			}
		}
	}

	if updateRules {
		logger.Info("Changes detected, updating bastion firewall rule")

		req := &computepb.UpdateFirewallRequest{
			Firewall:         fwName,
			Project:          cluster.Spec.Project,
			FirewallResource: rule,
		}

		op, err := c.fwService.Update(ctx, req)
		if err != nil {
			return microerror.Mask(err)
		}

		err = op.Wait(ctx)
		if err != nil {
			return microerror.Mask(err)
		}

		logger.Info("Bastion firewall rules were updated")

	} else {
		logger.Info("No changes detected, not updating bastion firewall rule")
	}

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
			} else {
				logger.Error(err, "failed parsing subnets from annotations on GPCLuster", "subnet", p)
			}
		}
	}

	return ipRanges
}

func bastionFirewallPolicyRuleName(clusterName string) string {
	return fmt.Sprintf("allow-%s-bastion-ssh", clusterName)
}
