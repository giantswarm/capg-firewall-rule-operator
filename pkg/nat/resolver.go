package nat

import (
	"context"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	"google.golang.org/api/iterator"
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

	listAddressesReq := &computepb.ListAddressesRequest{
		Project: cluster.Spec.Project,
		Region:  cluster.Spec.Region,
	}
	addressIterator := r.addresses.List(ctx, listAddressesReq)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	ips := []string{}
	for {
		address, err := addressIterator.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			return nil, errors.WithStack(err)
		}

		if contains(address.Users, *router.SelfLink) {
			ips = append(ips, *address.Address)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("cluster %s/%s has no NAT IPs yet", cluster.Namespace, cluster.Name)
	}

	return ips, nil
}

func contains(slice []string, element string) bool {
	for _, a := range slice {
		if a == element {
			return true
		}
	}
	return false
}
