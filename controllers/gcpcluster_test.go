package controllers_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/giantswarm/capg-firewall-rule-operator/controllers"
	"github.com/giantswarm/capg-firewall-rule-operator/controllers/controllersfakes"
)

var _ = Describe("GCPClusterReconciler", func() {
	var (
		ctx context.Context

		reconciler      *controllers.GCPClusterReconciler
		client          *controllersfakes.FakeGCPClusterClient
		firewallsClient *controllersfakes.FakeFirewallsClient

		cluster      *capi.Cluster
		gcpCluster   *capg.GCPCluster
		result       ctrl.Result
		reconcileErr error
	)

	BeforeEach(func() {
		logger := zap.New(zap.WriteTo(GinkgoWriter))
		ctx = log.IntoContext(context.Background(), logger)

		client = new(controllersfakes.FakeGCPClusterClient)
		firewallsClient = new(controllersfakes.FakeFirewallsClient)

		reconciler = controllers.NewGCPClusterReconciler(
			logger,
			client,
			firewallsClient,
		)

		gcpCluster = &capg.GCPCluster{}
		client.GetReturns(gcpCluster, nil)

		cluster = &capi.Cluster{}
		client.GetOwnerReturns(cluster, nil)
	})

	JustBeforeEach(func() {
		request := ctrl.Request{
			NamespacedName: types.NamespacedName{
				Name:      "foo",
				Namespace: "bar",
			},
		}
		result, reconcileErr = reconciler.Reconcile(ctx, request)
	})

	It("gets the cluster and owner cluster", func() {
		Expect(client.GetCallCount()).To(Equal(1))
		Expect(client.GetOwnerCallCount()).To(Equal(1))

		_, actualCluster := client.GetOwnerArgsForCall(0)
		Expect(actualCluster).To(Equal(gcpCluster))
	})

	It("adds a finalizer to the gcp cluster", func() {
		Expect(client.AddFinalizerCallCount()).To(Equal(1))

		_, actualCluster, finalizer := client.AddFinalizerArgsForCall(0)
		Expect(actualCluster).To(Equal(gcpCluster))
		Expect(finalizer).To(Equal(controllers.FinalizerFW))
	})

	It("uses the firewall client to create firewall rules for the cluster", func() {
		Expect(firewallsClient.CreateBastionFirewallRuleCallCount()).To(Equal(1))

		_, actualCluster := firewallsClient.CreateBastionFirewallRuleArgsForCall(0)
		Expect(actualCluster).To(Equal(gcpCluster))
	})

	When("the gcp cluster is marked for deletion", func() {
		BeforeEach(func() {
			now := v1.Now()
			gcpCluster.DeletionTimestamp = &now
		})

		It("removes the finalizer", func() {
			Expect(client.RemoveFinalizerCallCount()).To(Equal(1))
			_, actualCluster, finalizer := client.RemoveFinalizerArgsForCall(0)
			Expect(actualCluster).To(Equal(gcpCluster))
			Expect(finalizer).To(Equal(controllers.FinalizerFW))
		})

		It("uses the firewall client to remove firewall rules", func() {
			Expect(firewallsClient.DeleteBastionFirewallRuleCallCount()).To(Equal(1))
			_, actualCluster := firewallsClient.DeleteBastionFirewallRuleArgsForCall(0)
			Expect(actualCluster).To(Equal(gcpCluster))
		})

		When("the firewall client fails", func() {
			BeforeEach(func() {
				firewallsClient.DeleteBastionFirewallRuleReturns(errors.New("boom"))
			})

			It("returns an error", func() {
				Expect(reconcileErr).To(HaveOccurred())
			})

			It("does not remove the finalizer", func() {
				Expect(client.RemoveFinalizerCallCount()).To(Equal(0))
			})
		})

		When("removing the finalizer fails", func() {
			BeforeEach(func() {
				client.RemoveFinalizerReturns(errors.New("boom"))
			})

			It("returns an error", func() {
				Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
			})
		})
	})

	When("getting the gcp cluster fails", func() {
		BeforeEach(func() {
			client.GetReturns(nil, errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})

	When("the cluster does not exist", func() {
		BeforeEach(func() {
			client.GetReturns(nil, k8serrors.NewNotFound(schema.GroupResource{}, "foo"))
		})

		It("does not requeue the event", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("getting the owner cluster fails", func() {
		BeforeEach(func() {
			client.GetOwnerReturns(nil, errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})

	When("the cluster does not have an owner yet", func() {
		BeforeEach(func() {
			client.GetOwnerReturns(nil, nil)
		})

		It("does not requeue the event", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("the cluster is paused", func() {
		BeforeEach(func() {
			cluster.Spec.Paused = true
			client.GetOwnerReturns(cluster, nil)
		})

		It("does not reconcile", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("the infrastructure cluster is paused", func() {
		BeforeEach(func() {
			gcpCluster.Annotations = map[string]string{
				capi.PausedAnnotation: "true",
			}
			client.GetReturns(gcpCluster, nil)
		})

		It("does not reconcile", func() {
			Expect(result.Requeue).To(BeFalse())
			Expect(result.RequeueAfter).To(BeZero())
			Expect(reconcileErr).NotTo(HaveOccurred())
		})
	})

	When("adding the finalizer fails", func() {
		BeforeEach(func() {
			client.AddFinalizerReturns(errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})

	When("the firewall client fails", func() {
		BeforeEach(func() {
			firewallsClient.CreateBastionFirewallRuleReturns(errors.New("boom"))
		})

		It("returns an error", func() {
			Expect(reconcileErr).To(MatchError(ContainSubstring("boom")))
		})
	})
})
