package firewall_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	compute "cloud.google.com/go/compute/apiv1"
	"github.com/googleapis/gax-go/v2/apierror"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	"google.golang.org/api/googleapi"
	computepb "google.golang.org/genproto/googleapis/cloud/compute/v1"

	"github.com/giantswarm/to"

	"github.com/giantswarm/capg-firewall-rule-operator/tests"
)

var gcpProject string

func TestFirewall(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Firewall Suite")
}

var _ = BeforeSuite(func() {
	tests.GetEnvOrSkip("GOOGLE_APPLICATION_CREDENTIALS")
	gcpProject = tests.GetEnvOrSkip("GCP_PROJECT_ID")
})

func deleteFirewall(firewalls *compute.FirewallsClient, firewallName string) {
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

func deleteNetwork(networks *compute.NetworksClient, networkName string) {
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

func createNetwork(networks *compute.NetworksClient, networkName string) *computepb.Network {
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

type beGoogleAPIErrorWithStatusMatcher struct {
	expected int
}

func BeGoogleAPIErrorWithStatus(expected int) types.GomegaMatcher {
	return &beGoogleAPIErrorWithStatusMatcher{expected: expected}
}

func (m *beGoogleAPIErrorWithStatusMatcher) Match(actual interface{}) (bool, error) {
	if actual == nil {
		return false, nil
	}

	actualError, isError := actual.(error)
	if !isError {
		return false, fmt.Errorf("%#v is not an error", actual)
	}

	var apiErr *apierror.APIError
	isAPIError := errors.As(actualError, &apiErr)
	if isAPIError {
		actualError = apiErr.Unwrap()
	}

	matches, err := BeAssignableToTypeOf(actualError).Match(&googleapi.Error{})
	if err != nil || !matches {
		return false, err
	}

	googleAPIError, isGoogleAPIError := actualError.(*googleapi.Error)
	if !isGoogleAPIError {
		return false, nil
	}
	return Equal(googleAPIError.Code).Match(m.expected)
}

func (m *beGoogleAPIErrorWithStatusMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(
		actual,
		fmt.Sprintf("to be a google api error with status code: %s", m.getExpectedStatusText()),
	)
}

func (m *beGoogleAPIErrorWithStatusMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(
		actual,
		fmt.Sprintf("to not be a google api error with status: %s", m.getExpectedStatusText()),
	)
}

func (m *beGoogleAPIErrorWithStatusMatcher) getExpectedStatusText() string {
	return fmt.Sprintf("%d %s", m.expected, http.StatusText(m.expected))
}
