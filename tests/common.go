package tests

import (
	"context"
	"fmt"
	"net/http"
	"os"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/giantswarm/to"
	"github.com/google/uuid"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"
	"k8s.io/apimachinery/pkg/types"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	. "github.com/giantswarm/capg-firewall-rule-operator/tests/matchers"
)

func GenerateGUID(prefix string) string {
	guid := uuid.NewString()

	return fmt.Sprintf("%s-%s", prefix, guid[:13])
}

func GetEnvOrSkip(env string) string {
	value := os.Getenv(env)
	if value == "" {
		ginkgo.Skip(fmt.Sprintf("%s not exported", env))
	}

	return value
}

func PatchClusterStatus(k8sClient client.Client, cluster *capg.GCPCluster, status capg.GCPClusterStatus) {
	patchedCluster := cluster.DeepCopy()
	patchedCluster.Status = status
	Expect(k8sClient.Status().Patch(context.Background(), patchedCluster, client.MergeFrom(cluster))).To(Succeed())

	nsName := types.NamespacedName{
		Name:      cluster.Name,
		Namespace: cluster.Namespace,
	}
	Expect(k8sClient.Get(context.Background(), nsName, cluster)).To(Succeed())
}

func DeleteFirewall(firewalls *compute.FirewallsClient, gcpProject, firewallName string) {
	req := &computepb.DeleteFirewallRequest{
		Firewall: firewallName,
		Project:  gcpProject,
	}

	// Explicitly do not wait for the deletion to complete. This makes the
	// tests significantly slower
	_, err := firewalls.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))
}

func DeleteNetwork(networks *compute.NetworksClient, gcpProject, networkName string) {
	req := &computepb.DeleteNetworkRequest{
		Network: networkName,
		Project: gcpProject,
	}

	// Explicitly do not wait for the deletion to complete. This makes the
	// tests significantly slower
	_, err := networks.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))
}

func CreateNetwork(networks *compute.NetworksClient, gcpProject, networkName string) *computepb.Network {
	ctx := context.Background()
	network := &computepb.Network{
		AutoCreateSubnetworks: to.BoolP(false),
		Description:           to.StringP("firewall operator test network"),
		Name:                  to.StringP(networkName),
	}

	insertReq := &computepb.InsertNetworkRequest{
		NetworkResource: network,
		Project:         gcpProject,
	}

	op, err := networks.Insert(ctx, insertReq)
	Expect(err).NotTo(HaveOccurred())
	Expect(op.Wait(ctx)).To(Succeed())

	getReq := &computepb.GetNetworkRequest{
		Network: networkName,
		Project: gcpProject,
	}
	network, err = networks.Get(ctx, getReq)
	Expect(err).NotTo(HaveOccurred())
	Expect(network.SelfLink).NotTo(BeNil())

	return network
}
