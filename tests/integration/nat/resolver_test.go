package nat_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"

	"github.com/giantswarm/to"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/k8sclient"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/nat"
	"github.com/giantswarm/capg-firewall-rule-operator/tests"
	. "github.com/giantswarm/capg-firewall-rule-operator/tests/matchers"
)

var _ = Describe("Client", func() {
	var (
		ctx context.Context

		addresses *compute.AddressesClient
		routers   *compute.RoutersClient
		networks  *compute.NetworksClient
		resolver  *nat.IPResolver

		address     *computepb.Address
		cluster     *capg.GCPCluster
		clusterName types.NamespacedName
		name        string
	)

	BeforeEach(func() {
		SetDefaultEventuallyPollingInterval(time.Second)
		SetDefaultEventuallyTimeout(time.Second * 60)

		ctx = context.Background()
		name = tests.GenerateGUID("test")

		var err error

		networks, err = compute.NewNetworksRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())
		addresses, err = compute.NewAddressesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())
		routers, err = compute.NewRoutersRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		clusterName = types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		}
		cluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: capg.GCPClusterSpec{
				Project: gcpProject,
				Region:  tests.TestRegion,
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		gcpClusters := k8sclient.NewGCPCluster(k8sClient)
		resolver = nat.NewIPResolver(gcpClusters, addresses, routers)
	})

	Describe("GetIPs", func() {
		When("the router and nat ip are available", func() {
			BeforeEach(func() {
				network := tests.GetDefaultNetwork(networks, gcpProject)
				address = tests.CreateIPAddress(addresses, gcpProject, name)
				router := tests.CreateNATRouter(routers, address, network, gcpProject, name)

				status := capg.GCPClusterStatus{
					Ready: true,
					Network: capg.Network{
						Router: router.SelfLink,
					},
				}
				tests.PatchClusterStatus(k8sClient, cluster, status)
			})

			AfterEach(func() {
				tests.DeleteRouter(routers, gcpProject, name)
				tests.DeleteIPAddress(addresses, gcpProject, name)
			})

			It("gets the NAT ips for the cluster", func() {
				ips, err := resolver.GetIPs(ctx, clusterName)
				Expect(err).NotTo(HaveOccurred())
				Expect(ips).To(ConsistOf(*address.Address))
			})
		})

		When("the router has no IPs yet", func() {
			BeforeEach(func() {
				network := tests.GetDefaultNetwork(networks, gcpProject)
				router := tests.CreateEmptyRouter(routers, network, gcpProject, name)

				status := capg.GCPClusterStatus{
					Ready: true,
					Network: capg.Network{
						Router: router.SelfLink,
					},
				}
				tests.PatchClusterStatus(k8sClient, cluster, status)
			})

			AfterEach(func() {
				tests.DeleteRouter(routers, gcpProject, name)
			})

			It("gets the NAT ips for the cluster", func() {
				_, err := resolver.GetIPs(ctx, clusterName)
				Expect(err).To(MatchError(ContainSubstring(
					fmt.Sprintf("cluster %s/%s has no NAT IPs yet", namespace, name),
				)))
			})
		})

		When("the cluster does not exist", func() {
			It("returns an error", func() {
				nonExistentCluster := types.NamespacedName{
					Name:      "does-not-exist",
					Namespace: namespace,
				}
				_, err := resolver.GetIPs(ctx, nonExistentCluster)
				Expect(k8serrors.IsNotFound(err)).To(BeTrue())
			})
		})

		When("the cluster doesn't have a router yet", func() {
			BeforeEach(func() {
				status := capg.GCPClusterStatus{
					Ready:   true,
					Network: capg.Network{},
				}
				tests.PatchClusterStatus(k8sClient, cluster, status)
			})

			It("returns an error", func() {
				_, err := resolver.GetIPs(ctx, clusterName)
				Expect(err).To(MatchError(fmt.Sprintf(
					"cluster %s/%s does not have router yet",
					namespace, name,
				)))
			})
		})

		When("the router does not exist", func() {
			BeforeEach(func() {
				status := capg.GCPClusterStatus{
					Ready: true,
					Network: capg.Network{
						Router: to.StringP("https://example.com/does/not/exist-123"),
					},
				}
				tests.PatchClusterStatus(k8sClient, cluster, status)
			})

			It("returns an error", func() {
				_, err := resolver.GetIPs(ctx, clusterName)
				Expect(err).To(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
			})
		})
	})
})
