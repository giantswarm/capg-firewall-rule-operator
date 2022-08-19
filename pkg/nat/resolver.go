package nat

import (
	"context"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/pkg/errors"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/google"
	"github.com/giantswarm/capg-firewall-rule-operator/pkg/k8sclient"
)

func NewIPResolver(gcpClusters *k8sclient.GCPCluster, addresses *compute.AddressesClient, routers *compute.RoutersClient) *IPResolver {
	return &IPResolver{
		gcpClusters: gcpClusters,
		addresses:   addresses,
		routers:     routers,
	}
}

type IPResolver struct {
	gcpClusters *k8sclient.GCPCluster
	addresses   *compute.AddressesClient
	routers     *compute.RoutersClient
}

func (r *IPResolver) GetIPs(ctx context.Context, managementCluster types.NamespacedName) ([]string, error) {
	cluster, err := r.gcpClusters.Get(ctx, managementCluster)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if google.IsNilOrEmpty(cluster.Status.Network.Router) {
		return nil, fmt.Errorf("cluster %s/%s does not have router yet", managementCluster.Namespace, managementCluster.Name)
	}

	getRouterReq := &computepb.GetRouterRequest{
		Project: cluster.Spec.Project,
		Region:  cluster.Spec.Region,
		Router:  google.GetResourceName(*cluster.Status.Network.Router),
	}
	router, err := r.routers.Get(ctx, getRouterReq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ips := []string{}
	for _, natGateway := range router.Nats {
		for _, natIP := range natGateway.NatIps {
			getAddressReq := &computepb.GetAddressRequest{
				Address: google.GetResourceName(natIP),
				Project: cluster.Spec.Project,
				Region:  cluster.Spec.Region,
			}
			address, err := r.addresses.Get(ctx, getAddressReq)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			ips = append(ips, *address.Address)
		}
	}

	return ips, nil
}
