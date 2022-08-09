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

const (
	TestDescription = "test resource for capg-firewall-rule-operator"

	instanceGroupZone = "europe-west3-a"
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

	op, err := firewalls.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))

	if op != nil {
		Expect(op.Wait(context.Background())).WithOffset(1).To(Succeed())
	}
}

func DeleteSecurityPolicy(securityPolicies *compute.SecurityPoliciesClient, gcpProject, name string) {
	req := &computepb.DeleteSecurityPolicyRequest{
		Project:        gcpProject,
		SecurityPolicy: name,
	}

	op, err := securityPolicies.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))

	if op != nil {
		Expect(op.Wait(context.Background())).WithOffset(1).To(Succeed())
	}
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
		Description:           to.StringP(TestDescription),
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

func CreateInstanceGroup(instanceGroups *compute.InstanceGroupsClient, gcpProject, name string) *computepb.InstanceGroup {
	ctx := context.Background()

	instanceGroupsReq := &computepb.InsertInstanceGroupRequest{
		InstanceGroupResource: &computepb.InstanceGroup{
			Description: to.StringP(TestDescription),
			Name:        to.StringP(name),
		},
		Project: gcpProject,
		Zone:    instanceGroupZone,
	}
	op, err := instanceGroups.Insert(ctx, instanceGroupsReq)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	Expect(op.Wait(ctx)).WithOffset(1).To(Succeed())

	getReq := &computepb.GetInstanceGroupRequest{
		InstanceGroup: name,
		Project:       gcpProject,
		Zone:          instanceGroupZone,
	}
	instanceGroup, err := instanceGroups.Get(ctx, getReq)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())

	return instanceGroup
}

func DeleteInstanceGroup(instanceGroups *compute.InstanceGroupsClient, gcpProject, name string) {
	req := &computepb.DeleteInstanceGroupRequest{
		InstanceGroup: name,
		Project:       gcpProject,
		Zone:          instanceGroupZone,
	}

	_, err := instanceGroups.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))
}

func CreateHealthCheck(healthChecks *compute.HealthChecksClient, gcpProject, name string) *computepb.HealthCheck {
	ctx := context.Background()

	req := &computepb.InsertHealthCheckRequest{
		HealthCheckResource: &computepb.HealthCheck{
			Name:        to.StringP(name),
			Description: to.StringP(TestDescription),
			TcpHealthCheck: &computepb.TCPHealthCheck{
				Port:              to.Int32P(8080),
				PortSpecification: new(string),
			},
			Type: to.StringP("TCP"),
		},
		Project: gcpProject,
	}
	op, err := healthChecks.Insert(ctx, req)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	Expect(op.Wait(ctx)).WithOffset(1).To(Succeed())

	getReq := &computepb.GetHealthCheckRequest{
		HealthCheck: name,
		Project:     gcpProject,
	}
	healthCheck, err := healthChecks.Get(ctx, getReq)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())

	return healthCheck
}

func DeleteHealthCheck(healthChecks *compute.HealthChecksClient, gcpProject, name string) {
	req := &computepb.DeleteHealthCheckRequest{
		HealthCheck: name,
		Project:     gcpProject,
	}

	_, err := healthChecks.Delete(context.Background(), req)
	Expect(err).WithOffset(1).To(Or(
		Not(HaveOccurred()),
		BeGoogleAPIErrorWithStatus(http.StatusNotFound),
	))
}

func CreateBackendService(backendServices *compute.BackendServicesClient, instanceGroup *computepb.InstanceGroup, healthCheck *computepb.HealthCheck, gcpProject, name string) *computepb.BackendService {
	ctx := context.Background()

	req := &computepb.InsertBackendServiceRequest{
		BackendServiceResource: &computepb.BackendService{
			Backends: []*computepb.Backend{{
				Description: to.StringP(TestDescription),
				Group:       instanceGroup.SelfLink,
			}},
			Description:         to.StringP(TestDescription),
			LoadBalancingScheme: to.StringP("EXTERNAL"),
			Name:                to.StringP(name),
			Protocol:            to.StringP("HTTP"),
			HealthChecks: []string{
				*healthCheck.SelfLink,
			},
		},
		Project: gcpProject,
	}
	op, err := backendServices.Insert(ctx, req)
	Expect(err).WithOffset(1).NotTo(HaveOccurred())
	Expect(op.Wait(context.Background())).WithOffset(1).To(Succeed())

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
		Expect(op.Wait(context.Background())).WithOffset(1).To(Succeed())
	}
}
