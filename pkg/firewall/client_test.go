package firewall_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"

	"github.com/giantswarm/capg-firewall-rule-operator/pkg/firewall"
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Firewall client test")
}

var _ = Describe("GetIPRangesFromAnnotation", func() {
	var cluster *capg.GCPCluster
	BeforeEach(func() {
		cluster = &capg.GCPCluster{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"bastion.gcp.giantswarm.io/whitelist": "1.2.3.4/32,12.13.14.15/32",
				},
			},
		}
	})

	Describe("Get ranges", func() {
		It("1: should return 2 subnets", func() {
			ipRanges := firewall.GetIPRangesFromAnnotation(cluster)

			Expect(len(ipRanges)).To(Equal(2))
			Expect(ipRanges).To(ConsistOf("1.2.3.4/32", "12.13.14.15/32"))
		})

		It("2: should return 1 subnet", func() {
			cluster.Annotations["bastion.gcp.giantswarm.io/whitelist"] = "1.2.3.4/32,"
			ipRanges := firewall.GetIPRangesFromAnnotation(cluster)

			Expect(len(ipRanges)).To(Equal(1))
			Expect(ipRanges).To(ConsistOf("1.2.3.4/32"))
		})

		It("3: should return 1 subnet", func() {
			cluster.Annotations["bastion.gcp.giantswarm.io/whitelist"] = "1.2.3.4/32"
			ipRanges := firewall.GetIPRangesFromAnnotation(cluster)

			Expect(len(ipRanges)).To(Equal(1))
			Expect(ipRanges).To(ConsistOf("1.2.3.4/32"))
		})

		It("4: should return 0.0.0.0/0 subnet", func() {
			delete(cluster.Annotations, "bastion.gcp.giantswarm.io/whitelist")
			ipRanges := firewall.GetIPRangesFromAnnotation(cluster)

			Expect(len(ipRanges)).To(Equal(1))
			Expect(ipRanges).To(ConsistOf("0.0.0.0/0"))
		})

	})
})
