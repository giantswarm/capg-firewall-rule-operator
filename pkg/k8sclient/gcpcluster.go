package k8sclient

import (
	"context"

	"github.com/giantswarm/microerror"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type GCPCluster struct {
	client client.Client
}

func NewGCPCluster(client client.Client) *GCPCluster {
	return &GCPCluster{
		client: client,
	}
}

func (g *GCPCluster) Get(ctx context.Context, namespacedName types.NamespacedName) (*capg.GCPCluster, error) {
	gcpCluster := &capg.GCPCluster{}
	err := g.client.Get(ctx, namespacedName, gcpCluster)
	if err != nil {
		return nil, microerror.Mask(err)
	}

	return gcpCluster, microerror.Mask(err)
}

func (g *GCPCluster) GetOwner(ctx context.Context, capgCluster *capg.GCPCluster) (*capi.Cluster, error) {
	cluster, err := util.GetOwnerCluster(ctx, g.client, capgCluster.ObjectMeta)
	if err != nil {
		return nil, microerror.Mask(err)
	}

	return cluster, nil
}

func (g *GCPCluster) AddFinalizer(ctx context.Context, capgCluster *capg.GCPCluster, finalizer string) error {
	originalCluster := capgCluster.DeepCopy()
	controllerutil.AddFinalizer(capgCluster, finalizer)
	return g.client.Patch(ctx, capgCluster, client.MergeFrom(originalCluster))
}

func (g *GCPCluster) RemoveFinalizer(ctx context.Context, capgCluster *capg.GCPCluster, finalizer string) error {
	originalCluster := capgCluster.DeepCopy()
	controllerutil.RemoveFinalizer(capgCluster, finalizer)
	return g.client.Patch(ctx, capgCluster, client.MergeFrom(originalCluster))
}
