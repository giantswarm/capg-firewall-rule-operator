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
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"

	"github.com/giantswarm/to"

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
		addresses        *compute.AddressesClient
		routers          *compute.RoutersClient

		name               string
		firewallName       string
		securityPolicyName string
		cluster            *capi.Cluster
		network            *computepb.Network
		address            *computepb.Address
		workloadCluster    *capg.GCPCluster
		managementCluster  *capg.GCPCluster
	)

	BeforeEach(func() {
		SetDefaultEventuallyPollingInterval(time.Second)
		SetDefaultEventuallyTimeout(time.Second * 90)
		ctx = context.Background()

		var err error
		networks, err = compute.NewNetworksRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		firewalls, err = compute.NewFirewallsRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		addresses, err = compute.NewAddressesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		routers, err = compute.NewRoutersRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		securityPolicies, err = compute.NewSecurityPoliciesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		backendServices, err = compute.NewBackendServicesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		name = tests.GenerateGUID("test")
		securityPolicyName = fmt.Sprintf("allow-%s-apiserver", name)
		firewallName = fmt.Sprintf("allow-%s-bastion-ssh", name)
		network = tests.GetDefaultNetwork(networks, gcpProject)
		backendService := tests.CreateBackendService(backendServices, gcpProject, name)
		address = tests.CreateIPAddress(addresses, gcpProject, name)
		router := tests.CreateNATRouter(routers, address, network, gcpProject, name)

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

		managementCluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      managementClusterName.Name,
				Namespace: managementClusterName.Namespace,
			},
			Spec: capg.GCPClusterSpec{
				Project: gcpProject,
				Region:  tests.TestRegion,
			},
		}
		Expect(k8sClient.Create(ctx, managementCluster)).To(Succeed())
		mcStatus := capg.GCPClusterStatus{
			Ready: true,
			Network: capg.Network{
				Router: router.SelfLink,
			},
		}
		tests.PatchClusterStatus(k8sClient, managementCluster, mcStatus)

		workloadCluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Annotations: map[string]string{
					firewall.AnnotationBastionAllowListSubnets: "128.0.0.0/24,192.168.0.0/24",
					security.AnnotationAPIAllowListSubnets:     "10.0.0.0/24,172.158.0.0/24",
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
		Expect(k8sClient.Create(ctx, workloadCluster)).To(Succeed())

		wcStatus := capg.GCPClusterStatus{
			Ready: true,
			Network: capg.Network{
				SelfLink:                network.SelfLink,
				APIServerBackendService: backendService.SelfLink,
			},
		}
		tests.PatchClusterStatus(k8sClient, workloadCluster, wcStatus)
	})

	AfterEach(func() {
		tests.DeleteBackendService(backendServices, gcpProject, name)
		status := capg.GCPClusterStatus{Ready: true}
		tests.PatchClusterStatus(k8sClient, workloadCluster, status)

		err := k8sClient.Delete(ctx, workloadCluster)
		if !k8serrors.IsNotFound(err) {
			Expect(err).NotTo(HaveOccurred())
		}

		Expect(k8sClient.Delete(ctx, managementCluster)).To(Succeed())

		tests.DeleteFirewall(firewalls, gcpProject, firewallName)
		tests.DeleteSecurityPolicy(securityPolicies, gcpProject, securityPolicyName)
		tests.DeleteRouter(routers, gcpProject, name)
		tests.DeleteIPAddress(addresses, gcpProject, name)
	})

	It("applies firewall rules on the cluster", func() {
		By("creating the bastion firewall rule")
		getFirewall := &computepb.GetFirewallRequest{
			Firewall: firewallName,
			Project:  gcpProject,
		}
		var actualFirewall *computepb.Firewall
		Eventually(func() error {
			var err error
			actualFirewall, err = firewalls.Get(ctx, getFirewall)
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
		expectedSourceRanges := []string{"128.0.0.0/24", "192.168.0.0/24"}
		expectedSourceRanges = append(expectedSourceRanges, defaultBastionHostAllowList...)
		Expect(actualFirewall.SourceRanges).To(ConsistOf(expectedSourceRanges))

		By("creating the kube api security policy")
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

		By("creating the user specified rule in the policy")
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

		By("creating the defualt MC NAT IPs rule in the policy")
		defaultNATRule := securityPolicy.Rules[1]
		Expect(*defaultNATRule.Action).To(Equal(security.ActionAllow))
		Expect(*defaultNATRule.Description).To(Equal("allow MC NAT IPs"))
		Expect(*defaultNATRule.Priority).To(Equal(int32(1)))
		Expect(defaultNATRule.Match).NotTo(BeNil())
		Expect(defaultNATRule.Match.Config).NotTo(BeNil())
		Expect(defaultNATRule.Match.Config.SrcIpRanges).To(ConsistOf(*address.Address))

		By("creating the defualt allow list rule in the policy")
		defaultAllowListRule := securityPolicy.Rules[2]
		Expect(*defaultAllowListRule.Action).To(Equal(security.ActionAllow))
		Expect(*defaultAllowListRule.Description).To(Equal("allow default IP ranges"))
		Expect(*defaultAllowListRule.Priority).To(Equal(int32(2)))
		Expect(defaultAllowListRule.Match).NotTo(BeNil())
		Expect(defaultAllowListRule.Match.Config).NotTo(BeNil())
		Expect(defaultAllowListRule.Match.Config.SrcIpRanges).To(ConsistOf(defaultAPIAllowList))

		By("creating the default policy behaviour rule")
		defaultRule := securityPolicy.Rules[3]
		Expect(*defaultRule.Action).To(Equal(security.ActionDeny403))
		Expect(*defaultRule.Description).To(Equal(security.DefaultRuleDescription))
		Expect(*defaultRule.Priority).To(Equal(int32(math.MaxInt32)))
		Expect(defaultRule.Match).NotTo(BeNil())
		Expect(defaultRule.Match.Config).NotTo(BeNil())
		Expect(defaultRule.Match.Config.SrcIpRanges).To(ConsistOf(security.DefaultRuleIPRanges))

		tests.DeleteBackendService(backendServices, gcpProject, name)
		status := capg.GCPClusterStatus{Ready: true}
		tests.PatchClusterStatus(k8sClient, workloadCluster, status)

		Expect(k8sClient.Delete(ctx, workloadCluster)).To(Succeed())

		By("not preventing cluster deletion")
		nsName := types.NamespacedName{
			Name:      workloadCluster.Name,
			Namespace: workloadCluster.Namespace,
		}
		Eventually(func() error {
			return k8sClient.Get(ctx, nsName, &capg.GCPCluster{})
		}).ShouldNot(Succeed())

		By("removing the firewall rule")
		Eventually(func() error {
			_, err := firewalls.Get(ctx, getFirewall)
			return err
		}).Should(BeGoogleAPIErrorWithStatus(http.StatusNotFound))

		By("removing the security policy")
		Eventually(func() error {
			_, err := securityPolicies.Get(ctx, getSecurityPolicy)
			return err
		}).Should(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
	})
})
