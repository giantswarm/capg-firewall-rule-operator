package tests

import (
	"context"
	"errors"
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

const (
	TestDescription = "test resource for capg-firewall-rule-operator"

	defaultNetworkName     = "default"
	backendServiceRegion   = "europe-west3"
	backendServiceProtocol = "TCP"
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

	_, err := firewalls.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))
}

func DeleteSecurityPolicy(securityPolicies *compute.SecurityPoliciesClient, gcpProject, name string) {
	req := &computepb.DeleteSecurityPolicyRequest{
		Project:        gcpProject,
		SecurityPolicy: name,
	}

	_, err := securityPolicies.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))
}

func GetDefaultNetwork(networks *compute.NetworksClient, gcpProject, networkName string) *computepb.Network {
	ctx := context.Background()

	getReq := &computepb.GetNetworkRequest{
		Network: defaultNetworkName,
		Project: gcpProject,
	}
	network, err := networks.Get(ctx, getReq)
	Expect(err).NotTo(HaveOccurred())
	Expect(network.SelfLink).NotTo(BeNil())

	return network
}

func CreateBackendService(backendServices *compute.BackendServicesClient, gcpProject, name string) *computepb.BackendService {
	ctx := context.Background()

	req := &computepb.InsertBackendServiceRequest{
		BackendServiceResource: &computepb.BackendService{
			Backends:    []*computepb.Backend{},
			Description: to.StringP(TestDescription),
			Name:        to.StringP(name),
			Protocol:    to.StringP(backendServiceProtocol),
			Region:      to.StringP(backendServiceRegion),
		},
		Project: gcpProject,
	}
	op, err := backendServices.Insert(ctx, req)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	waitOnOperation(op)

	getReq := &computepb.GetBackendServiceRequest{
		BackendService: name,
		Project:        gcpProject,
	}
	backendService, err := backendServices.Get(ctx, getReq)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())

	return backendService
}

func DeleteBackendService(backendServices *compute.BackendServicesClient, gcpProject, name string) {
	req := &computepb.DeleteBackendServiceRequest{
		BackendService: name,
		Project:        gcpProject,
	}

	var op *compute.Operation
	Eventually(func() error {
		var err error
		op, err = backendServices.Delete(context.Background(), req)
		return err
	}).WithOffset(1).Should(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))

	if op != nil {
		waitOnOperation(op)
	}
}

func waitOnOperation(operation *compute.Operation) {
	Eventually(func() error {
		err := operation.Poll(context.Background())
		if err != nil {
			return err
		}

		if operation.Done() {
			return nil
		}

		return errors.New("operation not done")
	}).Should(Succeed())
}
