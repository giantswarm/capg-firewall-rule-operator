package firewall_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/to"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/tests"
)

var _ = Describe("Client", func() {
	var (
		ctx context.Context

		networks  *compute.NetworksClient
		firewalls *compute.FirewallsClient
		client    *firewall.Client

		cluster *capg.GCPCluster
		network *computepb.Network
		rule    firewall.Rule
		name    string
	)

	BeforeEach(func() {
		SetDefaultEventuallyPollingInterval(time.Second)
		SetDefaultEventuallyTimeout(time.Second * 60)

		ctx = context.Background()
		name = tests.GenerateGUID("test")

		var err error
		networks, err = compute.NewNetworksRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		firewalls, err = compute.NewFirewallsRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		network = createNetwork(networks, name)
		networkSelfLink := network.SelfLink

		cluster = &capg.GCPCluster{
			Spec: capg.GCPClusterSpec{
				Project: gcpProject,
			},
			Status: capg.GCPClusterStatus{
				Network: capg.Network{
					SelfLink: networkSelfLink,
				},
			},
		}

		rule = firewall.Rule{
			Allowed: []firewall.Allowed{
				{
					IPProtocol: firewall.ProtocolUDP,
					Ports:      []uint32{6060, 7070},
				},
				{
					IPProtocol: firewall.ProtocolTCP,
					Ports:      []uint32{8080, 9090},
				},
			},
			Description:  "capg-firewall-rule-operator test firewall",
			Direction:    firewall.DirectionIngress,
			Name:         name,
			TargetTags:   []string{"first-tag", "second-tag"},
			SourceRanges: []string{"10.0.0.0/32", "127.0.0.0/24"},
		}

		client = firewall.NewClient(firewalls)
	})

	AfterEach(func() {
		deleteFirewall(firewalls, name)
		deleteNetwork(networks, name)
	})

	Describe("ApplyRule", func() {
		It("creates a firewall rule in GCP", func() {
			err := client.ApplyRule(ctx, cluster, rule)
			Expect(err).NotTo(HaveOccurred())

			req := &computepb.GetFirewallRequest{
				Firewall: name,
				Project:  gcpProject,
			}
			actualFirewall, err := firewalls.Get(ctx, req)
			Expect(err).NotTo(HaveOccurred())

			Expect(*actualFirewall.Name).To(Equal(name))
			Expect(*actualFirewall.Direction).To(Equal(firewall.DirectionIngress))
			Expect(*actualFirewall.Description).To(Equal("capg-firewall-rule-operator test firewall"))
			Expect(actualFirewall.Network).To(Equal(network.SelfLink))
			Expect(actualFirewall.TargetTags).To(ConsistOf("first-tag", "second-tag"))
			Expect(actualFirewall.Allowed).To(HaveLen(2))
			Expect(actualFirewall.Allowed[0].IPProtocol).To(Equal(to.StringP("udp")))
			Expect(actualFirewall.Allowed[0].Ports).To(ConsistOf("6060", "7070"))

			Expect(actualFirewall.Allowed[1].IPProtocol).To(Equal(to.StringP("tcp")))
			Expect(actualFirewall.Allowed[1].Ports).To(ConsistOf("8080", "9090"))
			Expect(actualFirewall.SourceRanges).To(ConsistOf("10.0.0.0/32", "127.0.0.0/24"))
		})

		When("the firewall rule already exists", func() {
			BeforeEach(func() {
				err := client.ApplyRule(ctx, cluster, rule)
				Expect(err).NotTo(HaveOccurred())

				rule.Description = "capg-firewall-rule-operator test firewall with another description"
				rule.Direction = firewall.DirectionEgress
				rule.TargetTags = []string{"third-tag", "fourth-tag"}
				rule.Allowed = []firewall.Allowed{
					{
						IPProtocol: firewall.ProtocolTCP,
						Ports:      []uint32{1010, 2020},
					},
				}
				rule.SourceRanges = []string{"192.168.0.0/32", "172.158.0.0/24"}
			})

			It("updates the rule", func() {
				err := client.ApplyRule(ctx, cluster, rule)
				Expect(err).NotTo(HaveOccurred())

				req := &computepb.GetFirewallRequest{
					Firewall: name,
					Project:  gcpProject,
				}
				actualFirewall, err := firewalls.Get(ctx, req)
				Expect(err).NotTo(HaveOccurred())
				Expect(*actualFirewall.Direction).To(Equal(firewall.DirectionEgress))
				Expect(*actualFirewall.Description).To(Equal("capg-firewall-rule-operator test firewall with another description"))
				Expect(actualFirewall.Network).To(Equal(network.SelfLink))
				Expect(actualFirewall.TargetTags).To(ConsistOf("third-tag", "fourth-tag"))
				Expect(actualFirewall.SourceRanges).To(ConsistOf("192.168.0.0/32", "172.158.0.0/24"))

				Expect(actualFirewall.Allowed).To(HaveLen(1))
				Expect(actualFirewall.Allowed[0].IPProtocol).To(Equal(to.StringP("tcp")))
				Expect(actualFirewall.Allowed[0].Ports).To(ConsistOf("1010", "2020"))
			})
		})

		When("applying an empty rule", func() {
			It("returns an error", func() {
				err := client.ApplyRule(ctx, cluster, firewall.Rule{})
				Expect(err).To(HaveOccurred())
			})
		})

		When("applying a rule with only the required values", func() {
			It("does not return an error", func() {
				minimalRule := firewall.Rule{
					Name: name,
					Allowed: []firewall.Allowed{
						{
							IPProtocol: firewall.ProtocolTCP,
							Ports:      []uint32{8080},
						},
					},
				}
				err := client.ApplyRule(ctx, cluster, minimalRule)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		When("the network does not exist", func() {
			BeforeEach(func() {
				nonExistingNetwork := fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/global/networks/does-not-exist", gcpProject)
				cluster.Status.Network.SelfLink = to.StringP(nonExistingNetwork)
			})

			It("returns an error", func() {
				err := client.ApplyRule(ctx, cluster, rule)
				Expect(err).To(HaveOccurred())
			})
		})

		When("the context has been canceled", func() {
			It("returns an error", func() {
				canceledCtx, cancel := context.WithCancel(ctx)
				cancel()

				err := client.ApplyRule(canceledCtx, cluster, rule)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	Describe("DeleteRule", func() {
		BeforeEach(func() {
			Expect(client.ApplyRule(ctx, cluster, rule)).To(Succeed())
		})

		It("deletes the firewall", func() {
			err := client.DeleteRule(ctx, cluster, name)
			Expect(err).NotTo(HaveOccurred())

			req := &computepb.GetFirewallRequest{
				Firewall: name,
				Project:  gcpProject,
			}
			_, err = firewalls.Get(ctx, req)
			Expect(err).To(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
		})

		When("the firewall does not exist", func() {
			It("does not return an error", func() {
				err := client.DeleteRule(ctx, cluster, "does-not-exist")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		When("the context has been canceled", func() {
			It("returns an error", func() {
				canceledCtx, cancel := context.WithCancel(ctx)
				cancel()

				err := client.ApplyRule(canceledCtx, cluster, rule)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
