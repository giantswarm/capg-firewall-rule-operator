package controllers

import (
	"context"

	"github.com/giantswarm/microerror"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/annotations"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
)

const FinalizerFW = "capg-firewall-rule-operator.finalizers.giantswarm.io"

//counterfeiter:generate . GCPClusterClient
type GCPClusterClient interface {
	Get(context.Context, types.NamespacedName) (*capg.GCPCluster, error)
	GetOwner(context.Context, *capg.GCPCluster) (*capi.Cluster, error)
	AddFinalizer(context.Context, *capg.GCPCluster, string) error
	RemoveFinalizer(context.Context, *capg.GCPCluster, string) error
}

type GCPClusterReconciler struct {
	logger         logr.Logger
	client         GCPClusterClient
	firewallClient *firewall.Client
}

func NewGCPClusterReconciler(logger logr.Logger, client GCPClusterClient, firewallClient *firewall.Client) *GCPClusterReconciler {
	return &GCPClusterReconciler{
		logger:         logger,
		client:         client,
		firewallClient: firewallClient,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *GCPClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capg.GCPCluster{}).
		Complete(r)
}

func (r *GCPClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.logger.WithValues("gcpcluster", req.NamespacedName)
	log.Info("Reconciling")
	defer log.Info("Done reconciling")

	gcpCluster, err := r.client.Get(ctx, req.NamespacedName)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("GCP Cluster no longer exists")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, microerror.Mask(err)
	}

	cluster, err := r.client.GetOwner(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	if cluster == nil {
		log.Info("GCP Cluster does not have an owner cluster yet")
		return ctrl.Result{}, nil
	}

	if annotations.IsPaused(cluster, gcpCluster) {
		log.Info("Infrastructure or core cluster is marked as paused. Won't reconcile")
		return ctrl.Result{}, nil
	}

	if !gcpCluster.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, gcpCluster)
	}

	return r.reconcileNormal(ctx, gcpCluster)
}

func (r *GCPClusterReconciler) reconcileNormal(ctx context.Context, gcpCluster *capg.GCPCluster) (ctrl.Result, error) {
	err := r.client.AddFinalizer(ctx, gcpCluster, FinalizerFW)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	err = r.firewallClient.CreateBastionFirewallRule(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	err = r.firewallClient.AssignBastionFirewallRule(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	return ctrl.Result{}, nil
}

func (r *GCPClusterReconciler) reconcileDelete(ctx context.Context, gcpCluster *capg.GCPCluster) (ctrl.Result, error) {
	err := r.firewallClient.DisassociateBastionFirewallRule(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	err = r.firewallClient.DeleteBastionFirewallRule(ctx, gcpCluster)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	err = r.client.RemoveFinalizer(ctx, gcpCluster, FinalizerFW)
	if err != nil {
		return ctrl.Result{}, microerror.Mask(err)
	}

	return ctrl.Result{}, nil
}