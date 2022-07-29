package security_test

import (
	"context"
	"math"
	"net/http"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"

	"github.com/giantswarm/to"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
	"github.com/giantswarm/capg-firewall-rule-operator/tests"
	. "github.com/giantswarm/capg-firewall-rule-operator/tests/matchers"
)

var _ = Describe("Client", func() {
	var (
		ctx context.Context

		securityPolicies *compute.SecurityPoliciesClient
		backendServices  *compute.BackendServicesClient
		instanceGroups   *compute.InstanceGroupsClient
		healthChecks     *compute.HealthChecksClient
		client           *security.Client

		cluster *capg.GCPCluster
		policy  security.Policy
		name    string
	)

	BeforeEach(func() {
		SetDefaultEventuallyPollingInterval(time.Second)
		SetDefaultEventuallyTimeout(time.Second * 60)

		ctx = context.Background()
		name = tests.GenerateGUID("test")

		var err error
		securityPolicies, err = compute.NewSecurityPoliciesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		instanceGroups, err = compute.NewInstanceGroupsRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		healthChecks, err = compute.NewHealthChecksRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		backendServices, err = compute.NewBackendServicesRESTClient(ctx)
		Expect(err).NotTo(HaveOccurred())

		instanceGroup := tests.CreateInstanceGroup(instanceGroups, gcpProject, name)
		healthCheck := tests.CreateHealthCheck(healthChecks, gcpProject, name)
		backendService := tests.CreateBackendService(backendServices, instanceGroup, healthCheck, gcpProject, name)

		cluster = &capg.GCPCluster{
			Spec: capg.GCPClusterSpec{
				Project: gcpProject,
			},
			Status: capg.GCPClusterStatus{
				Network: capg.Network{
					APIServerBackendService: backendService.SelfLink,
				},
			},
		}

		policy = security.Policy{
			Name:          name,
			Description:   tests.TestDescription,
			DefaultAction: security.ActionDeny403,
			Rules: []security.PolicyRule{
				{
					Action:      security.ActionAllow,
					Description: tests.TestDescription,
					SourceIPRanges: []string{
						"10.0.0.0/24",
						"172.158.0.0/24",
					},
					Priority: 0,
				},
			},
		}

		client = security.NewClient(securityPolicies, backendServices)
	})

	AfterEach(func() {
		// The order of deletion here is important. If resources are deleted
		// out of order they will fail and in the case of the Security Policy
		// it will not return an error, but still not delete the resource
		tests.DeleteBackendService(backendServices, gcpProject, name)
		tests.DeleteSecurityPolicy(securityPolicies, gcpProject, name)
		tests.DeleteHealthCheck(healthChecks, gcpProject, name)
		tests.DeleteInstanceGroup(instanceGroups, gcpProject, name)
	})

	Describe("ApplyRule", func() {
		It("creates a security policy in GCP", func() {
			err := client.ApplyPolicy(ctx, cluster, policy)
			Expect(err).NotTo(HaveOccurred())

			getSecurityPolicy := &computepb.GetSecurityPolicyRequest{
				Project:        gcpProject,
				SecurityPolicy: name,
			}
			securityPolicy, err := securityPolicies.Get(ctx, getSecurityPolicy)
			Expect(err).NotTo(HaveOccurred())

			Expect(*securityPolicy.Name).To(Equal(name))
			Expect(*securityPolicy.Description).To(Equal(tests.TestDescription))
			Expect(securityPolicy.Rules).To(HaveLen(2))

			By("creating the rules in the policy")
			rule := securityPolicy.Rules[0]
			Expect(*rule.Action).To(Equal(security.ActionAllow))
			Expect(*rule.Description).To(Equal(tests.TestDescription))
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

			By("applying the security to the backend service")
			getBackendService := &computepb.GetBackendServiceRequest{
				Project:        gcpProject,
				BackendService: name,
			}
			backendService, err := backendServices.Get(ctx, getBackendService)
			Expect(err).NotTo(HaveOccurred())
			Expect(backendService.SecurityPolicy).To(Equal(securityPolicy.SelfLink))
		})

		When("the security policy already exists", func() {
			BeforeEach(func() {
				err := client.ApplyPolicy(ctx, cluster, policy)
				Expect(err).NotTo(HaveOccurred())

				policy.DefaultAction = security.ActionAllow
				policy.Rules[0].Action = security.ActionDeny403
				policy.Rules[0].SourceIPRanges = []string{
					"10.1.0.0/24",
					"172.158.1.0/24",
				}
			})

			It("updates the rule", func() {
				err := client.ApplyPolicy(ctx, cluster, policy)
				Expect(err).NotTo(HaveOccurred())

				getSecurityPolicy := &computepb.GetSecurityPolicyRequest{
					Project:        gcpProject,
					SecurityPolicy: name,
				}
				securityPolicy, err := securityPolicies.Get(ctx, getSecurityPolicy)
				Expect(err).NotTo(HaveOccurred())

				Expect(*securityPolicy.Name).To(Equal(name))
				Expect(*securityPolicy.Description).To(Equal(tests.TestDescription))
				Expect(securityPolicy.Rules).To(HaveLen(2))

				By("creating the rules in the policy")
				rule := securityPolicy.Rules[0]
				Expect(*rule.Action).To(Equal(security.ActionDeny403))
				Expect(*rule.Description).To(Equal(tests.TestDescription))
				Expect(*rule.Priority).To(Equal(int32(0)))
				Expect(rule.Match).NotTo(BeNil())
				Expect(rule.Match.Config).NotTo(BeNil())
				Expect(rule.Match.Config.SrcIpRanges).To(ConsistOf(
					"10.1.0.0/24",
					"172.158.1.0/24",
				))

				By("creating the rules in the policy")
				defaultRule := securityPolicy.Rules[1]
				Expect(*defaultRule.Action).To(Equal(security.ActionAllow))
			})
		})

		When("applying an empty policy", func() {
			BeforeEach(func() {
				policy = security.Policy{}
			})

			It("returns an error", func() {
				err := client.ApplyPolicy(ctx, cluster, policy)
				Expect(err).To(HaveOccurred())
			})
		})

		When("the cluster doesn't have a backend service yet", func() {
			BeforeEach(func() {
				cluster.Status.Network.APIServerBackendService = nil
			})

			It("returns an error", func() {
				err := client.ApplyPolicy(ctx, cluster, policy)
				Expect(err).To(MatchError(ContainSubstring("cluster does not have backend service")))
			})
		})

		When("the backend service does not exist", func() {
			BeforeEach(func() {
				cluster.Status.Network.APIServerBackendService = to.StringP("example.com/does-not-exist")
			})

			It("returns an error", func() {
				err := client.ApplyPolicy(ctx, cluster, policy)
				Expect(err).To(HaveOccurred())
			})
		})

		When("the context has been canceled", func() {
			It("returns an error", func() {
				canceledContext, cancel := context.WithCancel(ctx)
				cancel()
				err := client.ApplyPolicy(canceledContext, cluster, policy)
				Expect(err).To(MatchError(ContainSubstring("context canceled")))
			})
		})
	})

	Describe("DeleteRule", func() {
		BeforeEach(func() {
			err := client.ApplyPolicy(ctx, cluster, policy)
			Expect(err).NotTo(HaveOccurred())

			tests.DeleteBackendService(backendServices, gcpProject, name)
			cluster.Status.Network.APIServerBackendService = nil
		})

		JustBeforeEach(func() {
			err := client.DeletePolicy(ctx, cluster, name)
			Expect(err).NotTo(HaveOccurred())
		})

		It("deletes the securityPolicy", func() {
			getSecurityPolicy := &computepb.GetSecurityPolicyRequest{
				Project:        gcpProject,
				SecurityPolicy: name,
			}
			_, err := securityPolicies.Get(ctx, getSecurityPolicy)
			Expect(err).To(BeGoogleAPIErrorWithStatus(http.StatusNotFound))
		})

		When("the backend service hasn't been deleted", func() {
			It("returns an error", func() {
				cluster.Status.Network.APIServerBackendService = to.StringP("example.com/interesting")
				err := client.DeletePolicy(ctx, cluster, name)
				Expect(err).To(HaveOccurred())
			})
		})

		When("the security policy does not exist", func() {
			It("does not return an error", func() {
				err := client.DeletePolicy(ctx, cluster, name)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		When("the context has been canceled", func() {
			It("returns an error", func() {
				canceledContext, cancel := context.WithCancel(ctx)
				cancel()
				err := client.DeletePolicy(canceledContext, cluster, name)
				Expect(err).To(MatchError(ContainSubstring("context canceled")))
			})
		})
	})
})
