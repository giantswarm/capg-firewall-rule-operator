package controllers_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/giantswarm/to"

	"github.com/giantswarm/capg-firewall-rule-operator/controllers"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall/firewallfakes"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/k8sclient"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/security/securityfakes"
	"github.com/giantswarm/capg-firewall-rule-operator/tests"
)

var _ = Describe("GCPClusterReconciler", func() {
	var (
		ctx               context.Context
		managementCluster types.NamespacedName

		reconciler           *controllers.GCPClusterReconciler
		clusterClient        controllers.GCPClusterClient
		firewallClient       *firewallfakes.FakeFirewallsClient
		securityPolicyClient *securityfakes.FakeSecurityPolicyClient
		ipResolver           *securityfakes.FakeClusterNATIPResolver

		cluster    *capi.Cluster
		gcpCluster *capg.GCPCluster
		result     ctrl.Result

		request      ctrl.Request
		reconcileErr error
	)

	BeforeEach(func() {
		logger := zap.New(zap.WriteTo(GinkgoWriter))
		ctx = log.IntoContext(context.Background(), logger)

		clusterClient = k8sclient.NewGCPCluster(k8sClient)
		firewallClient = new(firewallfakes.FakeFirewallsClient)
		securityPolicyClient = new(securityfakes.FakeSecurityPolicyClient)
		ipResolver = new(securityfakes.FakeClusterNATIPResolver)

		ipResolver.GetIPsReturns([]string{"10.1.1.24", "192.168.1.218"}, nil)

		managementCluster = types.NamespacedName{
			Name:      "the-mc-name",
			Namespace: "the-namespace",
		}

		defaultAPIAllowList := []string{"10.128.0.0/24", "10.230.0.0/24"}
		securityPolicyReconciler := security.NewPolicyReconciler(
			defaultAPIAllowList,
			managementCluster,
			securityPolicyClient,
			ipResolver,
		)

		defaultBastionHostAllowList := []string{"192.168.0.0/24", "172.158.0.0/24"}
		firewallReconciler := firewall.NewRuleReconciler(defaultBastionHostAllowList, firewallClient)

		reconciler = controllers.NewGCPClusterReconciler(
			clusterClient,
			firewallReconciler,
			securityPolicyReconciler,
		)

		cluster = &capi.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "the-cluster",
				Namespace: namespace,
			},
		}
		Expect(k8sClient.Create(ctx, cluster)).To(Succeed())

		gcpCluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "the-gcp-cluster",
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
				Project: "the-gcp-project",
			},
		}
		Expect(k8sClient.Create(ctx, gcpCluster)).To(Succeed())

		status := capg.GCPClusterStatus{
			Ready: true,
			Network: capg.Network{
				SelfLink:                to.StringP("something"),
				APIServerBackendService: to.StringP("something"),
			},
		}
		tests.PatchClusterStatus(k8sClient, gcpCluster, status)

		request = ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "the-gcp-cluster",
				Namespace: namespace,
			},
		}
	})

	JustBeforeEach(func() {
		result, reconcileErr = reconciler.Reconcile(ctx, request)
	})

	It("adds a finalizer to the gcp cluster", func() {
		actualCluster := &capg.GCPCluster{}
		err := k8sClient.Get(ctx, request.NamespacedName, actualCluster)
		Expect(err).NotTo(HaveOccurred())

		Expect(actualCluster.Finalizers).To(ContainElement(controllers.FinalizerFirewall))
	})

	It("applies the firewall rules for the bastions", func() {
		Expect(firewallClient.ApplyRuleCallCount()).To(Equal(1))

		_, actualCluster, actualRule := firewallClient.ApplyRuleArgsForCall(0)
		Expect(actualCluster.Name).To(Equal("the-gcp-cluster"))
		Expect(*actualCluster.Status.Network.SelfLink).To(Equal("something"))
		Expect(actualRule.Name).To(Equal("allow-the-gcp-cluster-bastion-ssh"))
		Expect(actualRule.Allowed).To(ConsistOf(firewall.Allowed{
			IPProtocol: firewall.ProtocolTCP,
			Ports:      []uint32{firewall.PortSSH},
		}))
		Expect(actualRule.Description).To(Equal("allow port 22 for SSH"))
		Expect(actualRule.Direction).To(Equal(firewall.DirectionIngress))
		Expect(actualRule.Name).To(Equal("allow-the-gcp-cluster-bastion-ssh"))
		Expect(actualRule.TargetTags).To(Equal([]string{"the-gcp-cluster-bastion"}))
		Expect(actualRule.SourceRanges).To(Equal([]string{"128.0.0.0/24", "192.168.0.0/24", "192.168.0.0/24", "172.158.0.0/24"}))
	})

	It("applies the security policies for the kubernetes api", func() {
		By("using the ip resolver to get the MC's NAT IPs")
		Expect(ipResolver.GetIPsCallCount()).To(Equal(1))
		_, clusterName := ipResolver.GetIPsArgsForCall(0)
		Expect(clusterName).To(Equal(managementCluster))

		Expect(securityPolicyClient.ApplyPolicyCallCount()).To(Equal(1))
		_, actualCluster, actualPolicy := securityPolicyClient.ApplyPolicyArgsForCall(0)
		Expect(actualCluster.Name).To(Equal("the-gcp-cluster"))
		Expect(*actualCluster.Status.Network.SelfLink).To(Equal("something"))
		Expect(actualPolicy.Name).To(Equal("allow-the-gcp-cluster-apiserver"))
		Expect(actualPolicy.Description).To(Equal("allow IPs to connect to kubernetes api"))
		Expect(actualPolicy.DefaultAction).To(Equal(security.ActionDeny403))
		Expect(actualPolicy.Rules).To(ConsistOf(
			security.PolicyRule{
				Action:      security.ActionAllow,
				Description: "allow user specified ips to connect to kubernetes api",
				SourceIPRanges: []string{
					"10.0.0.0/24",
					"172.158.0.0/24",
				},
				Priority: 0,
			},
			security.PolicyRule{
				Action:      security.ActionAllow,
				Description: "allow MC NAT IPs",
				SourceIPRanges: []string{
					"10.1.1.24",
					"192.168.1.218",
				},
				Priority: 1,
			},
			security.PolicyRule{
				Action:      security.ActionAllow,
				Description: "allow default IP ranges",
				SourceIPRanges: []string{
					"10.128.0.0/24",
					"10.230.0.0/24",
				},
				Priority: 2,
			},
		))
	})

	When("the gcp cluster is marked for deletion", func() {
		BeforeEach(func() {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Finalizers = []string{controllers.FinalizerFirewall}
			Expect(k8sClient.Patch(ctx, patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())

			Expect(k8sClient.Delete(ctx, gcpCluster)).To(Succeed())

			actualCluster := &capg.GCPCluster{}
			err := k8sClient.Get(ctx, request.NamespacedName, actualCluster)
			Expect(err).NotTo(HaveOccurred())
		})

		It("removes the finalizer", func() {
			actualCluster := &capg.GCPCluster{}
			err := k8sClient.Get(ctx, request.NamespacedName, actualCluster)
			Expect(k8serrors.IsNotFound(err)).To(BeTrue())
		})

		It("uses the firewall client to remove firewall rules", func() {
			Expect(firewallClient.DeleteRuleCallCount()).To(Equal(1))

			_, actualCluster, actualRule := firewallClient.DeleteRuleArgsForCall(0)
			Expect(actualCluster.Name).To(Equal("the-gcp-cluster"))
			Expect(*actualCluster.Status.Network.SelfLink).To(Equal("something"))
			Expect(actualRule).To(Equal("allow-the-gcp-cluster-bastion-ssh"))
		})

		It("uses the firewall client to remove firewall rules", func() {
			Expect(securityPolicyClient.DeletePolicyCallCount()).To(Equal(1))

			_, actualCluster, actualPolicy := securityPolicyClient.DeletePolicyArgsForCall(0)
			Expect(actualCluster.Name).To(Equal("the-gcp-cluster"))
			Expect(*actualCluster.Status.Network.SelfLink).To(Equal("something"))
			Expect(actualPolicy).To(Equal("allow-the-gcp-cluster-apiserver"))
		})

		When("the cluster does not have Status.Network set", func() {
			BeforeEach(func() {
				status := capg.GCPClusterStatus{Ready: true}
				tests.PatchClusterStatus(k8sClient, gcpCluster, status)
			})

			It("removes the firewall rule", func() {
				Expect(firewallClient.DeleteRuleCallCount()).To(Equal(1))
			})

			When("the Status.Network.SelfLink is empty", func() {
				BeforeEach(func() {
					status := capg.GCPClusterStatus{
						Ready: true,
						Network: capg.Network{
							SelfLink:                to.StringP(""),
							APIServerBackendService: to.StringP("something"),
						},
					}
					tests.PatchClusterStatus(k8sClient, gcpCluster, status)
				})

				It("removes the firewall rule", func() {
					Expect(firewallClient.DeleteRuleCallCount()).To(Equal(1))
				})
			})

			When("the Status.Network.APIServerBackendService is empty", func() {
				BeforeEach(func() {
					status := capg.GCPClusterStatus{
						Ready: true,
						Network: capg.Network{
							SelfLink:                to.StringP("something"),
							APIServerBackendService: to.StringP(""),
						},
					}
					tests.PatchClusterStatus(k8sClient, gcpCluster, status)
				})

				It("removes the firewall rule", func() {
					Expect(firewallClient.DeleteRuleCallCount()).To(Equal(1))
				})
			})
		})

		When("the firewall client fails", func() {
			BeforeEach(func() {
				firewallClient.DeleteRuleReturns(errors.New("boom"))
			})

			It("returns an error", func() {
				Expect(reconcileErr).To(HaveOccurred())
			})

			It("does not remove the finalizer", func() {
				actualCluster := &capg.GCPCluster{}
				err := k8sClient.Get(ctx, request.NamespacedName, actualCluster)
				Expect(err).NotTo(HaveOccurred())

				Expect(actualCluster.Finalizers).To(ContainElement(controllers.FinalizerFirewall))
			})
		})

		When("the security policy client fails", func() {
			BeforeEach(func() {
				securityPolicyClient.DeletePolicyReturns(errors.New("boom"))
			})

			It("returns an error", func() {
				Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
			})

			It("does not remove the finalizer", func() {
				actualCluster := &capg.GCPCluster{}
				err := k8sClient.Get(ctx, request.NamespacedName, actualCluster)
				Expect(err).NotTo(HaveOccurred())

				Expect(actualCluster.Finalizers).To(ContainElement(controllers.FinalizerFirewall))
			})
		})
	})

	DescribeTable("when the bastion allowlist annotation is invalid",
		func(annotation string) {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Annotations = map[string]string{
				firewall.AnnotationBastionAllowListSubnets: annotation,
			}
			Expect(k8sClient.Patch(ctx, patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, request)
			Expect(err).To(HaveOccurred())
		},
		Entry("the annotation contains an invalid cidr", "128.0.0.0/24,random-string,192.168.0.0/24"),
		Entry("the annotation is not a CSV list", "128.0.0.0/24 192.168.0.0/24"),
		Entry("the annotation is an empty string", ""),
	)

	DescribeTable("when the apiserver allowlist annotation is invalid",
		func(annotation string) {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Annotations = map[string]string{
				security.AnnotationAPIAllowListSubnets: annotation,
			}
			Expect(k8sClient.Patch(ctx, patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, request)
			Expect(err).To(HaveOccurred())
		},
		Entry("the annotation contains an invalid cidr", "128.0.0.0/24,random-string,192.168.0.0/24"),
		Entry("the annotation is not a CSV list", "128.0.0.0/24 192.168.0.0/24"),
		Entry("the annotation is an empty string", ""),
	)

	When("the bastion allow list annotation is missing", func() {
		BeforeEach(func() {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Annotations = map[string]string{
				security.AnnotationAPIAllowListSubnets: "10.0.0.0/24",
			}
			Expect(k8sClient.Patch(ctx, patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())
		})

		It("does not return an error", func() {
			Expect(reconcileErr).NotTo(HaveOccurred())

			Expect(firewallClient.ApplyRuleCallCount()).To(Equal(1))
			_, _, actualRule := firewallClient.ApplyRuleArgsForCall(0)
			Expect(actualRule.SourceRanges).To(ConsistOf("192.168.0.0/24", "172.158.0.0/24"))
		})
	})

	When("the api allow list annotation is missing", func() {
		BeforeEach(func() {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Annotations = map[string]string{
				firewall.AnnotationBastionAllowListSubnets: "10.0.0.0/24",
			}
			Expect(k8sClient.Patch(ctx, patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())
		})

		It("still applies the default rules", func() {
			Expect(reconcileErr).NotTo(HaveOccurred())

			Expect(securityPolicyClient.ApplyPolicyCallCount()).To(Equal(1))
			_, _, actualPolicy := securityPolicyClient.ApplyPolicyArgsForCall(0)
			Expect(actualPolicy.Rules).To(HaveLen(2))
			Expect(actualPolicy.Rules[0].Description).To(Equal("allow MC NAT IPs"))
			Expect(actualPolicy.Rules[1].Description).To(Equal("allow default IP ranges"))
		})
	})

	When("the cluster does not exist", func() {
		BeforeEach(func() {
			request.Name = "does-not-exist"
		})

		It("does not requeue the event", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("getting the owner cluster fails", func() {
		BeforeEach(func() {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.OwnerReferences[0].Name = "does-not-exist"
			Expect(k8sClient.Patch(context.Background(), patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())
		})

		It("returns an error", func() {
			Expect(k8serrors.IsNotFound(reconcileErr)).To(BeTrue())
		})
	})

	When("the cluster does not have an owner yet", func() {
		BeforeEach(func() {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.OwnerReferences = []metav1.OwnerReference{}
			Expect(k8sClient.Patch(context.Background(), patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())
		})

		It("does not requeue the event", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("the cluster does not have Status.Network set yet", func() {
		BeforeEach(func() {
			status := capg.GCPClusterStatus{Ready: true}
			tests.PatchClusterStatus(k8sClient, gcpCluster, status)
		})

		It("does not requeue the event", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())

			Expect(firewallClient.DeleteRuleCallCount()).To(Equal(0))
			Expect(firewallClient.ApplyRuleCallCount()).To(Equal(0))
		})

		When("the Status.Network.SelfLink is empty", func() {
			BeforeEach(func() {
				status := capg.GCPClusterStatus{
					Ready: true,
					Network: capg.Network{
						SelfLink:                to.StringP(""),
						APIServerBackendService: to.StringP("something"),
					},
				}
				tests.PatchClusterStatus(k8sClient, gcpCluster, status)
			})

			It("does not requeue the event", func() {
				Expect(result.Requeue).To(BeFalse())
				Expect(result.RequeueAfter).To(BeZero())
				Expect(reconcileErr).NotTo(HaveOccurred())

				Expect(firewallClient.DeleteRuleCallCount()).To(Equal(0))
				Expect(firewallClient.ApplyRuleCallCount()).To(Equal(0))
			})
		})

		When("the Status.Network.APIServerBackendService is empty", func() {
			BeforeEach(func() {
				status := capg.GCPClusterStatus{
					Ready: true,
					Network: capg.Network{
						SelfLink:                to.StringP("something"),
						APIServerBackendService: to.StringP(""),
					},
				}
				tests.PatchClusterStatus(k8sClient, gcpCluster, status)
			})

			It("does not requeue the event", func() {
				Expect(result.Requeue).To(BeFalse())
				Expect(result.RequeueAfter).To(BeZero())
				Expect(reconcileErr).NotTo(HaveOccurred())

				Expect(firewallClient.DeleteRuleCallCount()).To(Equal(0))
				Expect(firewallClient.ApplyRuleCallCount()).To(Equal(0))
			})
		})
	})

	When("the cluster is paused", func() {
		BeforeEach(func() {
			patchedCluster := cluster.DeepCopy()
			patchedCluster.Spec.Paused = true
			Expect(k8sClient.Patch(context.Background(), patchedCluster, client.MergeFrom(cluster))).To(Succeed())
		})

		It("does not reconcile", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("the infrastructure cluster is paused", func() {
		BeforeEach(func() {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Annotations = map[string]string{
				capi.PausedAnnotation: "true",
			}
			Expect(k8sClient.Patch(context.Background(), patchedCluster, client.MergeFrom(cluster))).To(Succeed())
		})

		It("does not reconcile", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("the firewall client fails", func() {
		BeforeEach(func() {
			firewallClient.ApplyRuleReturns(errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})

	When("the IP resolver fails", func() {
		BeforeEach(func() {
			ipResolver.GetIPsReturns([]string{}, errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})

	When("the security policy client fails", func() {
		BeforeEach(func() {
			securityPolicyClient.ApplyPolicyReturns(errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})

	When("the context has been canceled", func() {
		BeforeEach(func() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("context canceled")))
		})
	})
})
