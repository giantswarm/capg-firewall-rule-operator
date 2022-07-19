package acceptance_test

import (
	"context"
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"

	"github.com/giantswarm/to"

	"github.com/giantswarm/capg-firewall-rule-operator/controllers"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/tests"
	. "github.com/giantswarm/capg-firewall-rule-operator/tests/matchers"
)

var _ = Describe("Firewalls", func() {
	var (
		ctx context.Context

		networks  *compute.NetworksClient
		firewalls *compute.FirewallsClient

		name         string
		firewallName string
		cluster      *capi.Cluster
		network      *computepb.Network
		gcpCluster   *capg.GCPCluster
	)

	BeforeEach(func() {
		SetDefaultEventuallyPollingInterval(time.Second)
		SetDefaultEventuallyTimeout(time.Second * 60)
		ctx = context.Background()

		name = tests.GenerateGUID("test")
		firewallName = fmt.Sprintf("allow-%s-bastion-ssh", name)

		cluster = &capi.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: capi.ClusterSpec{
				InfrastructureRef: &corev1.ObjectReference{
					APIVersion: capg.GroupVersion.String(),
					Kind:       "GCPCluster",
					Name:       name,
					Namespace:  namespace,
				},
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		var err error
		networks, err = compute.NewNetworksRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		firewalls, err = compute.NewFirewallsRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		network = tests.CreateNetwork(networks, gcpProject, name)

		gcpCluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Annotations: map[string]string{
					controllers.AnnotationBastionAllowListSubnets: "128.0.0.0/24,192.168.0.0/24",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: capi.GroupVersion.String(),
						Kind:       "Cluster",
						Name:       cluster.Name,
						UID:        cluster.UID,
					},
				},
			},
			Spec: capg.GCPClusterSpec{
				Project: gcpProject,
			},
		}
		Expect(k8sClient.Create(ctx, gcpCluster)).To(Succeed())

		status := capg.GCPClusterStatus{
			Ready: true,
			Network: capg.Network{
				SelfLink: network.SelfLink,
			},
		}

		tests.PatchClusterStatus(k8sClient, gcpCluster, status)
	})

	AfterEach(func() {
		Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())

		tests.DeleteFirewall(firewalls, gcpProject, firewallName)
		tests.DeleteNetwork(networks, gcpProject, name)
	})

	It("creates the firewall rule", func() {
		req := &computepb.GetFirewallRequest{
			Firewall: firewallName,
			Project:  gcpProject,
		}
		var actualFirewall *computepb.Firewall
		Eventually(func() error {
			var err error
			actualFirewall, err = firewalls.Get(ctx, req)
			return err
		}).Should(Succeed())

		Expect(*actualFirewall.Name).To(Equal(firewallName))
		Expect(*actualFirewall.Direction).To(Equal(firewall.DirectionIngress))
		Expect(*actualFirewall.Description).To(Equal("allow port 22 for SSH to"))
		Expect(actualFirewall.Network).To(Equal(network.SelfLink))
		Expect(actualFirewall.TargetTags).To(ConsistOf(fmt.Sprintf("%s-bastion", name)))
		Expect(actualFirewall.Allowed).To(HaveLen(1))
		Expect(actualFirewall.Allowed[0].IPProtocol).To(Equal(to.StringP("tcp")))
		Expect(actualFirewall.Allowed[0].Ports).To(ConsistOf("22"))
		Expect(actualFirewall.SourceRanges).To(ConsistOf("128.0.0.0/24", "192.168.0.0/24"))
	})

	When("the cluster is deleted", func() {
		BeforeEach(func() {
			req := &computepb.GetFirewallRequest{
				Firewall: firewallName,
				Project:  gcpProject,
			}
			Eventually(func() error {
				_, err := firewalls.Get(ctx, req)
				return err
			}).Should(Succeed())

			Expect(k8sClient.Delete(ctx, gcpCluster)).To(Succeed())
		})

		It("does not prevent cluster deletion", func() {
			nsName := types.NamespacedName{
				Name:      gcpCluster.Name,
				Namespace: namespace,
			}

			Eventually(func() error {
				return k8sClient.Get(ctx, nsName, &capg.GCPCluster{})
			}).ShouldNot(Succeed())
		})

		It("removes the firewall rule", func() {
			req := &computepb.GetFirewallRequest{
				Firewall: name,
				Project:  gcpProject,
			}
			Eventually(func() error {
				_, err := firewalls.Get(ctx, req)
				return err
			}).Should(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
		})
	})
})
