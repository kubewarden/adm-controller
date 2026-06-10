SHELL := /bin/bash
IMG ?= policy-server:latest
CONTAINER_PLATFORM?=linux/amd64 # or linux/arm64


SOURCE_FILES := $(shell test -e src/ && find src -type f)

target/release/policy-server: $(SOURCE_FILES) Cargo.*
	cargo build --release

.PHONY: build
build: target/release/policy-server

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: typos
typos:
	typos # run typo checker from crate-ci/typos

.PHONY: test
test: fmt lint
	cargo test

.PHONY: unit-tests
unit-tests:
	cargo test --lib

.PHONY: integration-tests
integration-tests:
	cargo test --test '*'
	cargo test --features otel_tests -- test_otel

.PHONY: e2e-tests-sigstore
e2e-tests-sigstore:
	cargo test --test 'sigstore' --features sigstore-testing

.PHONY: coverage
coverage: coverage-unit-tests coverage-integration-tests
	
.PHONY: coverage-unit-tests
coverage-unit-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--all-features --lib --bin --implicit-test-threads \
		--out xml --out html --output-dir coverage/unit-tests
	
.PHONY: coverage-integration-tests
coverage-integration-tests:
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--implicit-test-threads --test integration_test \
		--out xml --out html --output-dir coverage/integration-tests
	cargo tarpaulin --verbose --skip-clean --engine=llvm \
		--features otel_tests --implicit-test-threads --test integration_test \
		--out xml --out html --output-dir coverage/otel-integration-tests -- test_otel

.PHONY: clean
clean:
	cargo clean
	make -C e2e-tests clean

.PHONY: tag
tag:
	@git tag "${TAG}" || (echo "Tag ${TAG} already exists. If you want to retag, delete it manually and re-run this command" && exit 1)
	@git tag -s -a -m "${TAG}"  "${TAG}"

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build --platform $(CONTAINER_PLATFORM) -t ${IMG} .

.PHONY:build-docs
build-docs:
	cargo run --release -- docs --output cli-docs.adoc
