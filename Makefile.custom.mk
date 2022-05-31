
# Image URL to use all building/pushing image targets
IMG ?= quay.io/giantswarm/dns-operator-gcp:dev

# Substitute colon with space - this creates a list.
# Word selects the n-th element of the list
IMAGE_REPO = $(word 1,$(subst :, ,$(IMG)))
IMAGE_TAG = $(word 2,$(subst :, ,$(IMG)))

CLUSTER ?= dns-operator-gcp-acceptance
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.23

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

##@ Development

.PHONY: ensure-gcp-envs
ensure-gcp-envs:
ifndef GCP_PROJECT_ID
	$(error GCP_PROJECT_ID is undefined)
endif
ifndef CLOUD_DNS_BASE_DOMAIN
	$(error CLOUD_DNS_BASE_DOMAIN is undefined)
endif
ifndef CLOUD_DNS_PARENT_ZONE
	$(error CLOUD_DNS_PARENT_ZONE is undefined)
endif

.PHONY: ensure-deploy-envs
ensure-deploy-envs: ensure-gcp-envs
ifndef B64_GOOGLE_APPLICATION_CREDENTIALS
	$(error B64_GOOGLE_APPLICATION_CREDENTIALS is undefined)
endif

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: create-acceptance-cluster
create-acceptance-cluster: kind
	CLUSTER=$(CLUSTER) IMG=$(IMG) ./scripts/ensure-kind-cluster.sh

.PHONY: install-cluster-api
install-cluster-api: clusterctl
	GCP_B64ENCODED_CREDENTIALS="" $(CLUSTERCTL) init --kubeconfig "${HOME}/.kube/$(CLUSTER).yml" --infrastructure=gcp --wait-providers || true

.PHONY: deploy-acceptance-cluster
deploy-acceptance-cluster: docker-build create-acceptance-cluster install-cluster-api deploy

.PHONY: test-unit
test-unit: ginkgo generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" $(GINKGO) -p --nodes 8 -r -randomize-all --randomize-suites --skip-package=tests ./...

.PHONY: test-integration
test-integration: ginkgo ensure-gcp-envs ## Run integration tests
	$(eval GOOGLE_APPLICATION_CREDENTIALS=$(shell ${PWD}/scripts/create-gcp-credentials-file.sh))
	GOOGLE_APPLICATION_CREDENTIALS=$(GOOGLE_APPLICATION_CREDENTIALS) $(GINKGO) -p -r -randomize-all --randomize-suites tests/integration
	rm $(GOOGLE_APPLICATION_CREDENTIALS)

.PHONY: test-acceptance
test-acceptance: ginkgo ensure-gcp-envs deploy-acceptance-cluster ## Run acceptance testst
	KUBECONFIG="$(HOME)/.kube/$(CLUSTER).yml" $(GINKGO) -p -r -randomize-all --randomize-suites tests/acceptance

.PHONY: test-all
test-all: lint test-unit test-integration test-acceptance ## Run all tests and litner

##@ Build

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMG}

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: render
render: architect
	mkdir -p $(shell pwd)/helm/rendered
	cp -r $(shell pwd)/helm/dns-operator-gcp $(shell pwd)/helm/rendered/
	$(ARCHITECT) helm template --dir $(shell pwd)/helm/rendered/dns-operator-gcp

.PHONY: deploy
deploy: manifests render ensure-deploy-envs ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	helm upgrade --install \
		--set image.tag=$(IMAGE_TAG) \
		--set gcp.credentials=$(B64_GOOGLE_APPLICATION_CREDENTIALS) \
		--set baseDomain=$(CLOUD_DNS_BASE_DOMAIN) \
		--set parentDNSZone=$(CLOUD_DNS_PARENT_ZONE) \
		--set gcpProject=$(GCP_PROJECT_ID) \
		--wait \
		dns-operator-gcp helm/rendered/dns-operator-gcp

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.8.0)

ENVTEST = $(shell pwd)/bin/setup-envtest
.PHONY: envtest
envtest: ## Download envtest-setup locally if necessary.
	$(call go-get-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest@latest)

GINKGO = $(shell pwd)/bin/ginkgo
.PHONY: ginkgo
ginkgo: ## Download ginkgo locally if necessary.
	$(call go-get-tool,$(GINKGO),github.com/onsi/ginkgo/v2/ginkgo@latest)

ARCHITECT = $(shell pwd)/bin/architect
.PHONY: architect
architect: ## Download architect locally if necessary.
	$(call go-get-tool,$(ARCHITECT),github.com/giantswarm/architect@latest)

KIND = $(shell pwd)/bin/kind
.PHONY: kind
kind: ## Download kind locally if necessary.
	$(call go-get-tool,$(KIND),sigs.k8s.io/kind@latest)

CLUSTERCTL = $(shell pwd)/bin/clusterctl
.PHONY: clusterctl
clusterctl: ## Download clusterctl locally if necessary.
	$(eval LATEST_RELEASE = $(shell curl -s https://api.github.com/repos/kubernetes-sigs/cluster-api/releases/latest | jq -r '.tag_name'))
	curl -sL "https://github.com/kubernetes-sigs/cluster-api/releases/download/$(LATEST_RELEASE)/clusterctl-linux-amd64" -o $(CLUSTERCTL)
	chmod +x $(CLUSTERCTL)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
