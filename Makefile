CONTROLLER_TOOLS_VERSION := v0.18.0
ENVTEST_VERSION := release-0.19
ENVTEST_K8S_VERSION := 1.31.0
HELM_VALUES_SCHEMA_JSON_VERSION := v2.3.1

CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@$(ENVTEST_VERSION)
HELM_SCHEMA ?= go run github.com/losisin/helm-values-schema-json/v2@$(HELM_VALUES_SCHEMA_JSON_VERSION)

GO_MOD_SRCS := go.mod go.sum
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

ENVTEST_DIR ?= $(shell pwd)/.envtest

REGISTRY ?= ghcr.io
REPO ?= kubewarden/adm-controller
TAG ?= dev

# Detect architecture for Rust builds
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
	RUST_TARGET := x86_64-unknown-linux-musl
else ifeq ($(ARCH),amd64)
	RUST_TARGET := x86_64-unknown-linux-musl
else ifeq ($(ARCH),aarch64)
	RUST_TARGET := aarch64-unknown-linux-musl
else ifeq ($(ARCH),arm64)
	RUST_TARGET := aarch64-unknown-linux-musl
else
	$(error Unsupported architecture: $(ARCH))
endif

.PHONY: all
all: controller audit-scanner policy-server kwctl

.PHONY: test
test: test-go test-rust

.PHONY: test-go
test-go: vet
	$(GO_BUILD_ENV) CGO_ENABLED=1 KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" go test $$(go list ./... | grep -v /e2e) -race -test.v -coverprofile coverage/cover.out -covermode=atomic

.PHONY: test-rust
test-rust:
	$(MAKE) -C crates test

.PHONY: helm-unittest
helm-unittest:
	helm unittest charts/kubewarden-crds --file "tests/**/*_test.yaml"
	helm unittest charts/kubewarden-controller --file "tests/**/*_test.yaml"
	helm unittest charts/kubewarden-defaults --file "tests/**/*_test.yaml"

.PHONY: test-e2e
test-e2e: controller-image audit-scanner-image policy-server-image
	$(GO_BUILD_ENV) go test ./e2e/ -v

.PHONY: test-all
test-all: test helm-unittest test-e2e

.PHONY: fmt-go
fmt-go:
	$(GO_BUILD_ENV) go fmt ./...

.PHONY: lint-go
lint-go: golangci-lint
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --verbose

.PHONY: lint-go-fix
lint-go-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GO_BUILD_ENV) $(GOLANGCI_LINT) run --fix

.PHONY: vet
vet:
	$(GO_BUILD_ENV) go vet ./...

.PHONY: lint-rust
lint-rust:
	$(MAKE) -C crates lint

.PHONY: lint-rust-fix
lint-rust-fix:
	$(MAKE) -C crates lint-fix

.PHONY: fmt-rust
fmt-rust:
	$(MAKE) -C crates fmt

.PHONY: lint
lint: lint-go lint-rust

.PHONY: advisories-rust
advisories-rust:
	cargo deny check advisories

.PHONY: coverage-rust
coverage-rust:
	cargo llvm-cov --ignore-run-fail --doctests --html --output-dir coverage/rust/

CONTROLLER_SRC_DIRS := cmd/controller api internal/controller
CONTROLLER_GO_SRCS := $(shell find $(CONTROLLER_SRC_DIRS) -type f -name '*.go')
CONTROLLER_SRCS := $(GO_MOD_SRCS) $(CONTROLLER_GO_SRCS)
.PHONY: controller
controller: $(CONTROLLER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/controller ./cmd/controller

.PHONY: controller-image
controller-image:
	docker build -f ./Dockerfile.controller \
		-t "$(REGISTRY)/$(REPO)/controller:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/controller:$(TAG)"

AUDIT_SCANNER_SRC_DIRS := cmd/audit-scanner api internal/audit-scanner
AUDIT_SCANNER_GO_SRCS := $(shell find $(AUDIT_SCANNER_SRC_DIRS) -type f -name '*.go')
AUDIT_SCANNER_SRCS := $(GO_MOD_SRCS) $(AUDIT_SCANNER_GO_SRCS)
.PHONY: audit-scanner
audit-scanner: $(AUDIT_SCANNER_SRCS) vet
	$(GO_BUILD_ENV) go build -o ./bin/audit-scanner ./cmd/audit-scanner

.PHONY: audit-scanner-image
audit-scanner-image:
	docker build -f ./Dockerfile.audit-scanner \
		-t "$(REGISTRY)/$(REPO)/audit-scanner:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/audit-scanner:$(TAG)"

POLICY_SERVER_SRC_DIRS := crates/policy-server crates/policy-evaluator crates/policy-fetcher crates/burrego
POLICY_SERVER_SRCS := $(shell find $(POLICY_SERVER_SRC_DIRS) -type f -name '*.rs') Cargo.toml Cargo.lock $(shell find crates -name 'Cargo.*')
.PHONY: policy-server
policy-server: $(POLICY_SERVER_SRCS) lint-rust
	cross build --target $(RUST_TARGET) --release -p policy-server
	cp ./target/$(RUST_TARGET)/release/policy-server ./bin/policy-server

.PHONY: policy-server-image
policy-server-image:
	docker build -f ./Dockerfile.policy-server \
		-t "$(REGISTRY)/$(REPO)/policy-server:$(TAG)" .
	@echo "Built $(REGISTRY)/$(REPO)/policy-server:$(TAG)"

KWCTL_SRC_DIRS := crates/kwctl
KWCTL_SRCS := $(shell find $(KWCTL_SRC_DIRS) -type f -name '*.rs') Cargo.toml Cargo.lock $(shell find crates -name 'Cargo.*')
.PHONY: kwctl
kwctl: $(KWCTL_SRCS) lint-rust
	cross build --target $(RUST_TARGET) --release -p kwctl
	cp ./target/$(RUST_TARGET)/release/kwctl ./bin/kwctl

.PHONY: generate
generate: generate-controller generate-chart generate-crd-docs generate-kwctl-cli-docs generate-policyserver-cli-docs

.PHONY: generate-controller
generate-controller: manifests  ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) object paths="./api/policies/v1" paths="./api/policies/v1alpha2"
	
.PHONY: generate-crd-docs
generate-crd-docs:
	$(MAKE) -C docs/crds all
	
.PHONY: generate-kwctl-cli-docs
generate-kwctl-cli-docs:
	$(MAKE) -C crates/kwctl build-docs
	
.PHONY: generate-policyserver-cli-docs
generate-policyserver-cli-docs:
	$(MAKE) -C crates/policy-server build-docs

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(GO_BUILD_ENV) $(CONTROLLER_GEN) rbac:roleName=kubewarden-controller-manager,fileName=controller-rbac-roles.yaml crd webhook \
			paths="./api/policies/v1" paths="./api/policies/v1alpha2" \
			paths="./internal/controller" paths="./cmd/controller" \
			output:crd:artifacts:config=charts/kubewarden-crds/templates/crds \
			output:rbac:artifacts:config=charts/kubewarden-controller/templates \
			output:webhook:artifacts:config=charts
	echo "# to be merged manually into kubewarden-controller/templates/webhooks.yaml" | cat - charts/manifests.yaml > temp && mv temp charts/manifests.yaml
	mv charts/manifests.yaml charts/generated-webhooks-manifests.yaml
	sed -i '/^metadata:/a\  labels:\n    {{- include "kubewarden-controller.labels" . | nindent 4 }}\n  annotations:\n    {{- include "kubewarden-controller.annotations" . | nindent 4 }}' charts/kubewarden-controller/templates/controller-rbac-roles.yaml
	sed -i 's/  namespace: kubewarden/  namespace: {{ .Release.Namespace }}/' charts/kubewarden-controller/templates/controller-rbac-roles.yaml

.PHONY: generate-chart
generate-chart: ## Generate Helm chart values schema.
	$(HELM_SCHEMA) --values charts/kubewarden-controller/values.yaml --output charts/kubewarden-controller/values.schema.json

.PHONY: check-generate
check-generate: generate
	@./hack/check-for-auto-generated-changes.sh

.PHONY: charts-check-common-values
charts-check-common-values:
	@./scripts/charts-check-common-values.sh

.PHONY: charts-generate-images-file
charts-generate-images-file:
	@./scripts/charts-extract-images.sh ./charts

.PHONY: charts-generate-policies-file
charts-generate-policies-file:
	@./scripts/charts-extract-policies.sh ./charts

.PHONY: charts-generate-changelog-files
charts-generate-changelog-files:
	@./scripts/charts-generate-changelog-files.sh ./charts imagelist.txt

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Versions
GOLANGCI_LINT_VERSION ?= v2.12.1
ZIZMOR_VERSION ?= 1.23.1

## Tool Binaries
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint-$(GOLANGCI_LINT_VERSION)
ZIZMOR_LINT = $(LOCALBIN)/zizmor-$(ZIZMOR_VERSION)

.PHONY: zizmor
zizmor: $(ZIZMOR_LINT) ## Run zizmor static analysis on GitHub Actions workflows
	$(ZIZMOR_LINT) .github/
$(ZIZMOR_LINT): $(LOCALBIN)
	@[ -f $(ZIZMOR_LINT) ] || { \
	set -e; \
	echo "Installing zizmor@$(ZIZMOR_VERSION)" ;\
	cargo install --locked --root $(shell pwd) zizmor@$(ZIZMOR_VERSION) ;\
	mv $(LOCALBIN)/zizmor $(ZIZMOR_LINT) ;\
	}


.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv "$$(echo "$(1)" | sed "s/-$(3)$$//")" $(1) ;\
}
endef
