.PHONY: build
build: build-release build-docs

.PHONY: build-release
build-release:
	cargo build --release

.PHONY:build-docs
build-docs:
	cargo run --release -- docs --output cli-docs.adoc

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
	cargo test --bins

.PHONY: unit-tests
unit-tests:
	cargo test --bins

.PHONY: e2e-tests
e2e-tests:
	cargo test --test '*'
	
.PHONY: e2e-tests-sigstore
e2e-tests-sigstore:
	cargo test --test 'sigstore' --features sigstore-testing
	
.PHONY: coverage
coverage:
	cargo llvm-cov --html

.PHONY: clean
clean:
	cargo clean

.PHONY: tag
tag:
	@git tag "${TAG}" || (echo "Tag ${TAG} already exists. If you want to retag, delete it manually and re-run this command" && exit 1)
	@git-chglog --output CHANGELOG.md
	@git commit -m 'Update CHANGELOG.md' -- CHANGELOG.md
	@git tag -f "${TAG}"

.PHONY: check
check:
	cargo check
