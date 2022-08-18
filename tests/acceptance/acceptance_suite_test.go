package acceptance_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	capg "sigs.k8s.io/cluster-api-provider-gcp/api/v1beta1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/giantswarm/capg-firewall-rule-operator/tests"
)

var (
	defaultAPIAllowList = []string{"185.102.95.187/32", "95.179.153.65/32"}

	k8sClient  client.Client
	gcpProject string

	managementClusterName types.NamespacedName

	namespace    string
	namespaceObj *corev1.Namespace
)

func TestAcceptance(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Acceptance Suite")
}

var _ = BeforeSuite(func() {
	tests.GetEnvOrSkip("KUBECONFIG")
	tests.GetEnvOrSkip("GOOGLE_APPLICATION_CREDENTIALS")
	gcpProject = tests.GetEnvOrSkip("GCP_PROJECT_ID")
	mcName := tests.GetEnvOrSkip("MANAGEMENT_CLUSTER_NAME")
	mcNamespace := tests.GetEnvOrSkip("MANAGEMENT_CLUSTER_NAMESPACE")

	managementClusterName = types.NamespacedName{
		Name:      mcName,
		Namespace: mcNamespace,
	}

	config, err := controllerruntime.GetConfig()
	Expect(err).NotTo(HaveOccurred())

	err = capg.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = capi.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(config, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
})

var _ = BeforeEach(func() {
	namespace = uuid.New().String()
	namespaceObj = &corev1.Namespace{}
	namespaceObj.Name = namespace
	Expect(k8sClient.Create(context.Background(), namespaceObj)).To(Succeed())
})

var _ = AfterEach(func() {
	Expect(k8sClient.Delete(context.Background(), namespaceObj)).To(Succeed())
})
