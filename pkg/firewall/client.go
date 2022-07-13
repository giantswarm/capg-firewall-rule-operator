package firewall

import (
	"context"
	"net/http"
	"strconv"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/to"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	ProtocolTCP      = "tcp"
	ProtocolUDP      = "udp"
	PortSSH          = uint32(22)
	DirectionIngress = "INGRESS"
	DirectionEgress  = "EGRESS"
)

type Rule struct {
	Allowed      []Allowed
	Description  string
	Direction    string
	Name         string
	TargetTags   []string
	SourceRanges []string
}

type Allowed struct {
	IPProtocol string
	Ports      []uint32
}

type Client struct {
	firewallClient *compute.FirewallsClient
}

func NewClient(firewallService *compute.FirewallsClient) *Client {
	return &Client{
		firewallClient: firewallService,
	}
}

func (c *Client) ApplyRule(ctx context.Context, cluster *capg.GCPCluster, rule Rule) error {
	logger := c.getLogger(ctx, rule.Name)

	logger.Info("Creating firewall rule")
	defer logger.Info("Done creating firewall rule")

	firewall := toGCPFirewall(cluster, rule)

	req := &computepb.InsertFirewallRequest{
		Project:          cluster.Spec.Project,
		FirewallResource: firewall,
	}
	op, err := c.firewallClient.Insert(ctx, req)

	if hasHttpCode(err, http.StatusConflict) {
		logger.Info("Firewall already exists. Updating")
		err = c.updateFirewall(ctx, cluster, firewall)
		return errors.WithStack(err)
	}

	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	return errors.WithStack(err)
}

func (c *Client) DeleteRule(ctx context.Context, cluster *capg.GCPCluster, ruleName string) error {
	logger := c.getLogger(ctx, ruleName)

	logger.Info("Deleting firewall rule")
	defer logger.Info("Done deleting firewall rule")

	req := &computepb.DeleteFirewallRequest{
		Project:  cluster.Spec.Project,
		Firewall: ruleName,
	}
	op, err := c.firewallClient.Delete(ctx, req)
	if hasHttpCode(err, http.StatusNotFound) {
		logger.Info("Firewall already deleted")
		return nil
	}

	err = op.Wait(ctx)

	return errors.WithStack(err)
}

func (c *Client) updateFirewall(ctx context.Context, cluster *capg.GCPCluster, firewall *computepb.Firewall) error {
	req := &computepb.PatchFirewallRequest{
		Firewall:         *firewall.Name,
		FirewallResource: firewall,
		Project:          cluster.Spec.Project,
	}
	op, err := c.firewallClient.Patch(ctx, req)
	if err != nil {
		return errors.WithStack(err)
	}

	err = op.Wait(ctx)
	return errors.WithStack(err)
}

func (c *Client) getLogger(ctx context.Context, ruleName string) logr.Logger {
	logger := log.FromContext(ctx)
	logger = logger.WithName("firewall-client")
	return logger.WithValues("name", ruleName)
}

func toGCPFirewall(cluster *capg.GCPCluster, rule Rule) *computepb.Firewall {
	allowed := []*computepb.Allowed{}
	for _, allowedPorts := range rule.Allowed {
		ports := convertPorts(allowedPorts.Ports)

		allowed = append(allowed, &computepb.Allowed{
			IPProtocol: to.StringP(allowedPorts.IPProtocol),
			Ports:      ports,
		})
	}

	return &computepb.Firewall{
		Allowed:      allowed,
		Description:  to.StringP(rule.Description),
		Direction:    to.StringP(rule.Direction),
		Name:         to.StringP(rule.Name),
		Network:      cluster.Status.Network.SelfLink,
		TargetTags:   rule.TargetTags,
		SourceRanges: rule.SourceRanges,
	}
}

func convertPorts(portsNums []uint32) []string {
	ports := []string{}
	for _, port := range portsNums {
		ports = append(ports, strconv.FormatUint(uint64(port), 10))
	}

	return ports
}
