package acceptance_test

import (
	"context"
	"fmt"
	"math"
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
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
	"github.com/giantswarm/capg-firewall-rule-operator/tests"
	. "github.com/giantswarm/capg-firewall-rule-operator/tests/matchers"
)

var _ = Describe("Firewalls", func() {
	var (
		ctx context.Context

		networks         *compute.NetworksClient
		firewalls        *compute.FirewallsClient
		securityPolicies *compute.SecurityPoliciesClient
		backendServices  *compute.BackendServicesClient
		instanceGroups   *compute.InstanceGroupsClient
		healthChecks     *compute.HealthChecksClient

		name               string
		firewallName       string
		securityPolicyName string
		cluster            *capi.Cluster
		network            *computepb.Network
		gcpCluster         *capg.GCPCluster
	)

	BeforeEach(func() {
		SetDefaultEventuallyPollingInterval(time.Second)
		SetDefaultEventuallyTimeout(time.Second * 90)
		ctx = context.Background()

		name = tests.GenerateGUID("test")
		securityPolicyName = fmt.Sprintf("allow-%s-apiserver", name)
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

		securityPolicies, err = compute.NewSecurityPoliciesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		instanceGroups, err = compute.NewInstanceGroupsRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		healthChecks, err = compute.NewHealthChecksRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		backendServices, err = compute.NewBackendServicesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		network = tests.CreateNetwork(networks, gcpProject, name)
		instanceGroup := tests.CreateInstanceGroup(instanceGroups, gcpProject, name)
		healthCheck := tests.CreateHealthCheck(healthChecks, gcpProject, name)
		backendService := tests.CreateBackendService(backendServices, instanceGroup, healthCheck, gcpProject, name)

		gcpCluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Annotations: map[string]string{
					controllers.AnnotationBastionAllowListSubnets: "128.0.0.0/24,192.168.0.0/24",
					controllers.AnnotationAPIAllowListSubnets:     "10.0.0.0/24,172.158.0.0/24",
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
				SelfLink:                network.SelfLink,
				APIServerBackendService: backendService.SelfLink,
			},
		}

		tests.PatchClusterStatus(k8sClient, gcpCluster, status)
	})

	AfterEach(func() {
		tests.DeleteFirewall(firewalls, gcpProject, firewallName)
		tests.DeleteNetwork(networks, gcpProject, name)

		tests.DeleteBackendService(backendServices, gcpProject, name)
		tests.DeleteSecurityPolicy(securityPolicies, gcpProject, securityPolicyName)
		tests.DeleteHealthCheck(healthChecks, gcpProject, name)
		tests.DeleteInstanceGroup(instanceGroups, gcpProject, name)
	})

	When("the cluster is created", func() {
		AfterEach(func() {
			status := capg.GCPClusterStatus{Ready: true}
			tests.PatchClusterStatus(k8sClient, gcpCluster, status)

			Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())
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
			Expect(*actualFirewall.Description).To(Equal("allow port 22 for SSH"))
			Expect(actualFirewall.Network).To(Equal(network.SelfLink))
			Expect(actualFirewall.TargetTags).To(ConsistOf(fmt.Sprintf("%s-bastion", name)))
			Expect(actualFirewall.Allowed).To(HaveLen(1))
			Expect(actualFirewall.Allowed[0].IPProtocol).To(Equal(to.StringP("tcp")))
			Expect(actualFirewall.Allowed[0].Ports).To(ConsistOf("22"))
			Expect(actualFirewall.SourceRanges).To(ConsistOf("128.0.0.0/24", "192.168.0.0/24"))
		})

		It("creates the security policy", func() {
			getSecurityPolicy := &computepb.GetSecurityPolicyRequest{
				Project:        gcpProject,
				SecurityPolicy: securityPolicyName,
			}

			var securityPolicy *computepb.SecurityPolicy
			Eventually(func() error {
				var err error
				securityPolicy, err = securityPolicies.Get(ctx, getSecurityPolicy)
				return err
			}).Should(Succeed())

			Expect(*securityPolicy.Name).To(Equal(securityPolicyName))
			Expect(*securityPolicy.Description).To(Equal("allow IPs to connect to kubernetes api"))
			By("creating the rules in the policy")
			rule := securityPolicy.Rules[0]
			Expect(*rule.Action).To(Equal(security.ActionAllow))
			Expect(*rule.Description).To(Equal("allow user specified ips to connect to kubernetes api"))
			Expect(*rule.Priority).To(Equal(int32(0)))
			Expect(rule.Match).NotTo(BeNil())
			Expect(rule.Match.Config).NotTo(BeNil())
			Expect(rule.Match.Config.SrcIpRanges).To(ConsistOf(
				"10.0.0.0/24",
				"172.158.0.0/24",
			))

			By("creating the rules in the policy")
			defaultRule := securityPolicy.Rules[1]
			Expect(*defaultRule.Action).To(Equal(security.ActionDeny403))
			Expect(*defaultRule.Description).To(Equal(security.DefaultRuleDescription))
			Expect(*defaultRule.Priority).To(Equal(int32(math.MaxInt32)))
			Expect(defaultRule.Match).NotTo(BeNil())
			Expect(defaultRule.Match.Config).NotTo(BeNil())
			Expect(defaultRule.Match.Config.SrcIpRanges).To(ConsistOf(security.DefaultRuleIPRanges))
		})
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

			status := capg.GCPClusterStatus{Ready: true}
			tests.PatchClusterStatus(k8sClient, gcpCluster, status)

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
				Firewall: firewallName,
				Project:  gcpProject,
			}
			Eventually(func() error {
				_, err := firewalls.Get(ctx, req)
				return err
			}).Should(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
		})

		It("removes the security policy", func() {
			req := &computepb.GetSecurityPolicyRequest{
				SecurityPolicy: securityPolicyName,
				Project:        gcpProject,
			}
			Eventually(func() error {
				_, err := securityPolicies.Get(ctx, req)
				return err
			}).Should(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
		})
	})
})
