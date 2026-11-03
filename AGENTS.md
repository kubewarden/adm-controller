# AGENTS.md

## Project overview

- Kubewarden is a CNCF dynamic admission controller for Kubernetes.
- It evaluates policies that are compiled to WebAssembly.
- This repository is a monorepo. It contains these components:

- `controller` — Go — `cmd/controller`, `internal/controller`
- `audit-scanner` — Go — `cmd/audit-scanner`, `internal/audit-scanner`
- `policy-server` — Rust — `crates/policy-server`
- `kwctl` — Rust — `crates/kwctl`
- Helm chart — YAML — `charts/admission-controller`

## Structure

- `api/policies/v1/` — CRD types (storage version) and admission webhooks
- `api/policies/v1alpha2/` — deprecated CRD types. New fields go in v1.
- `cmd/` — entrypoints of the controller and the audit scanner
- `internal/controller/` — reconcilers and the envtest integration suite
- `internal/audit-scanner/` — the audit scanner
- `internal/certs/` — generation of the CA and the serving certificates
- `crates/` — Rust workspace (policy-server, kwctl, policy-evaluator,
  policy-fetcher, burrego, context-aware-test-policy)
- `charts/admission-controller/` — the single unified Helm chart
- `e2e/` — Go end-to-end tests that run against a kind cluster
- `docs/` — generated and hand-written documentation
- `hack/` — helpers for code generation and CI checks
- `scripts/` — shell utilities that shellcheck examines

- The API server sends the admission requests to the policy server. The policy
  server evaluates the policies and answers with a decision.
- The controller watches the policy resources and writes the configuration of
  the policy server. A change of that configuration starts a new rollout of the
  policy server. The policy server does not read the configuration again while
  it runs.
- The audit scanner sends the resources that are already in the cluster to the
  policy server. It writes the results into the report resources.
- The controller manages the certificates. It creates and rotates the CA and the
  serving certificate of each policy server, and it keeps the CA current in the
  webhook configurations.
- `kwctl` is not in the path of the data. It is a local CLI.

## Commands

Run these commands from the root of the repository.

- `make all` — Build the controller, the audit scanner, policy-server and kwctl
- `make controller` — `go build -o ./bin/controller ./cmd/controller`
- `make audit-scanner` — `go build -o ./bin/audit-scanner ./cmd/audit-scanner`
- `make policy-server` — `cross build --release -p policy-server`. It needs `cross`.
- `make kwctl` — `cross build --release -p kwctl`. It needs `cross`.
- `make test` — `test-go` and then `test-rust`
- `make test-go` — `go vet`, then all Go tests except `e2e/`, with envtest and `-race`
- `make test-rust` — Delegate to `crates/Makefile`
- `make helm-unittest` — Run the unit tests of the Helm chart
- `make test-e2e` — Build the three images, then run `go test ./e2e/ -v`
- `make test-all` — `test`, `helm-unittest` and `test-e2e`
- `make fmt-go` — `go fmt ./...`
- `make lint-go` — Run golangci-lint. The Makefile pins the version and downloads it into `bin/`.
- `make lint-go-fix` — Run golangci-lint with `--fix`
- `make lint` — `lint-go` and `lint-rust`
- `make generate` — Generate all the generated files again. Read the section that follows.
- `make manifests` — Generate the CRDs, the RBAC rules and the webhook manifests again
- `make check-generate` — `check-questions`, `generate`, then fail if the tree is dirty
- `make typos` — Examine the spelling with `typos-cli`
- `make zizmor` — Do a static analysis of the GitHub Actions workflows
- `make advisories-rust` — `cargo deny check advisories`

## Testing strategy

- The project has four levels of tests. Write the test at the lowest level
  that can find the defect.
- Go unit — beside the code that it tests — `make test-go` — The default. Use it for logic that needs no API server.
- Controller integration — `internal/controller/` — `make test-go` — The behavior of a reconciler against a real API server.
- Helm chart unit — `charts/admission-controller/tests/` — `make helm-unittest` — Any change of a template or of a value.
- Go end to end — `e2e/` — `make test-e2e` — Only the behavior of the full installation.

## Development principles

- Generated files come from their markers. Change the marker, then generate the
  file again.
- Test your change. Run the lint and the tests of the component that you
  touched.
- Code has a place. The CRD types go in `api/policies/v1`. The reconcilers go in
  `internal/controller`. The evaluation of the policies stays in `crates/`. The
  chart holds only the packaging.
- Prefer the narrow RBAC rule and the explicit failure to the convenient default.

## Generated code — the primary rule

- Never edit a generated file by hand.
- Run `make generate`, then run `make check-generate`, after a change to one
  of these:
  - A file in `api/policies/`
  - A `+kubebuilder:` marker
  - `charts/admission-controller/values.yaml`

Two conditions need your attention:

- `make manifests` writes the CRDs and the RBAC rules directly into the Helm
  chart. It does not write them into a `config/` directory. The webhook output
  goes to `internal/bootstrap/manifests.yaml`. The controller embeds that file,
  and creates its webhook configurations from it at startup. The chart does
  not hold them.
- The envtest suite loads the CRDs from the chart. Thus a chart that is not
  current breaks the tests in `internal/controller`. Generate the chart again
  before you run `make test-go`.

## Commits

- Write the commit message in the Conventional Commits format:
  `type(scope): subject`. For example: `feat(resolver): add a new solver
  strategy`.
- The usual types are `feat`, `fix`, `perf`, `refactor`, `chore`, `ci` and
  `docs`.
- Each commit needs a DCO sign-off. Use `git commit -s`.
- Each commit that an AI helped to write needs an `Assisted-by:` trailer.

Example commit message:

```
feat(controller): reconcile policy server PDBs

Signed-off-by: Jane Doe <jane@example.com>
Assisted-by: Claude Opus 4.5
```
