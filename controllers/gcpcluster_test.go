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
	"github.com/giantswarm/capg-firewall-rule-operator/controllers/controllersfakes"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/k8sclient"
)

var _ = Describe("GCPClusterReconciler", func() {
	var (
		ctx context.Context

		reconciler      *controllers.GCPClusterReconciler
		clusterClient   controllers.GCPClusterClient
		firewallsClient *controllersfakes.FakeFirewallsClient

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
		firewallsClient = new(controllersfakes.FakeFirewallsClient)

		reconciler = controllers.NewGCPClusterReconciler(
			logger,
			clusterClient,
			firewallsClient,
		)

		selfLink := "something"
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
				Project: "the-gcp-project",
			},
		}
		Expect(k8sClient.Create(ctx, gcpCluster)).To(Succeed())

		status := capg.GCPClusterStatus{
			Ready: true,
			Network: capg.Network{
				SelfLink: &selfLink,
			},
		}
		patchClusterStatus(gcpCluster, status)

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

	It("uses the firewall client to create firewall rules for the cluster", func() {
		Expect(firewallsClient.ApplyRuleCallCount()).To(Equal(1))

		_, actualCluster, actualRule := firewallsClient.ApplyRuleArgsForCall(0)
		Expect(actualCluster.Name).To(Equal("the-gcp-cluster"))
		Expect(*actualCluster.Status.Network.SelfLink).To(Equal("something"))
		Expect(actualRule.Name).To(Equal("allow-the-gcp-cluster-bastion-ssh"))
		Expect(actualRule.Allowed).To(ConsistOf(firewall.Allowed{
			IPProtocol: firewall.ProtocolTCP,
			Ports:      []uint32{firewall.PortSSH},
		}))
		Expect(actualRule.Description).To(Equal("allow port 22 for SSH to"))
		Expect(actualRule.Direction).To(Equal(firewall.DirectionIngress))
		Expect(actualRule.Name).To(Equal("allow-the-gcp-cluster-bastion-ssh"))
		Expect(actualRule.TargetTags).To(Equal([]string{"the-gcp-cluster-bastion"}))
		Expect(actualRule.SourceRanges).To(Equal([]string{"128.0.0.0/24", "192.168.0.0/24"}))
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
			Expect(firewallsClient.DeleteRuleCallCount()).To(Equal(1))

			_, actualCluster, actualRule := firewallsClient.DeleteRuleArgsForCall(0)
			Expect(actualCluster.Name).To(Equal("the-gcp-cluster"))
			Expect(*actualCluster.Status.Network.SelfLink).To(Equal("something"))
			Expect(actualRule).To(Equal("allow-the-gcp-cluster-bastion-ssh"))
		})

		When("the firewall client fails", func() {
			BeforeEach(func() {
				firewallsClient.DeleteRuleReturns(errors.New("boom"))
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
	})

	DescribeTable("when the bastion allowlist annotation is invalid",
		func(annotation string) {
			patchedCluster := gcpCluster.DeepCopy()
			patchedCluster.Annotations = map[string]string{
				controllers.AnnotationBastionAllowListSubnets: annotation,
			}
			Expect(k8sClient.Patch(ctx, patchedCluster, client.MergeFrom(gcpCluster))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, request)
			Expect(err).To(HaveOccurred())
		},
		Entry("the annotation contains an invalid cidr", "128.0.0.0/24,random-string,192.168.0.0/24"),
		Entry("the annotation is not a CSV list", "128.0.0.0/24 192.168.0.0/24"),
		Entry("the annotation is an empty string", "128.0.0.0/24 192.168.0.0/24"),
	)

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

	When("the cluster does not have Status.Network.SelfLink set yet", func() {
		BeforeEach(func() {
			status := capg.GCPClusterStatus{Ready: true}
			patchClusterStatus(gcpCluster, status)
		})

		It("does not requeue the event", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())

			Expect(firewallsClient.DeleteRuleCallCount()).To(Equal(0))
			Expect(firewallsClient.ApplyRuleCallCount()).To(Equal(0))
		})

		When("the Status.Network.SelfLink is empty", func() {
			BeforeEach(func() {
				status := capg.GCPClusterStatus{
					Ready: true,
					Network: capg.Network{
						SelfLink: to.StringP(""),
					},
				}
				patchClusterStatus(gcpCluster, status)
			})

			It("does not requeue the event", func() {
				Expect(result.Requeue).To(BeFalse())
				Expect(result.RequeueAfter).To(BeZero())
				Expect(reconcileErr).NotTo(HaveOccurred())

				Expect(firewallsClient.DeleteRuleCallCount()).To(Equal(0))
				Expect(firewallsClient.ApplyRuleCallCount()).To(Equal(0))
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
			firewallsClient.ApplyRuleReturns(errors.New("boom"))
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
