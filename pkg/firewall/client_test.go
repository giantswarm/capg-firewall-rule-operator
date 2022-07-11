package firewall_test

import (
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap/zapcore"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Firewall client test")
}

var _ = Describe("GetIPRangesFromAnnotation", func() {
	var cluster *capg.GCPCluster
	var logger logr.Logger
	BeforeEach(func() {
		cluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"bastion.gcp.giantswarm.io/whitelist": "1.2.3.4/32,12.13.14.15/32",
				},
			},
		}
		opts := zap.Options{
			Development: true,
			TimeEncoder: zapcore.RFC3339TimeEncoder,
		}

		logger = zap.New(zap.UseFlagOptions(&opts))

	})

	Describe("Get ranges", func() {
		It("1: should return 2 subnets", func() {
			ipRanges := firewall.GetIPRangesFromAnnotation(logger, cluster)

			Expect(len(ipRanges)).To(Equal(2))
			Expect(ipRanges).To(ConsistOf("1.2.3.4/32", "12.13.14.15/32"))
		})

		It("2: should return 1 subnet", func() {
			cluster.Annotations["bastion.gcp.giantswarm.io/whitelist"] = "1.2.3.4/32,xxxxx"
			ipRanges := firewall.GetIPRangesFromAnnotation(logger, cluster)

			Expect(len(ipRanges)).To(Equal(1))
			Expect(ipRanges).To(ConsistOf("1.2.3.4/32"))
		})

		It("3: should return 1 subnet", func() {
			cluster.Annotations["bastion.gcp.giantswarm.io/whitelist"] = "1.2.3.4/32"
			ipRanges := firewall.GetIPRangesFromAnnotation(logger, cluster)

			Expect(len(ipRanges)).To(Equal(1))
			Expect(ipRanges).To(ConsistOf("1.2.3.4/32"))
		})

		It("4: should return no subnet", func() {
			delete(cluster.Annotations, "bastion.gcp.giantswarm.io/whitelist")
			ipRanges := firewall.GetIPRangesFromAnnotation(logger, cluster)

			Expect(ipRanges).To(BeEmpty())
		})

	})
})
