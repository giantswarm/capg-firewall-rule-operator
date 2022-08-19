package security_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/giantswarm/capg-firewall-rule-operator/tests"
)

var gcpProject string

func TestFirewall(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Security Policy Suite")
}

var _ = BeforeSuite(func() {
	tests.GetEnvOrSkip("GOOGLE_APPLICATION_CREDENTIALS")
	gcpProject = tests.GetEnvOrSkip("GCP_PROJECT_ID")
})
