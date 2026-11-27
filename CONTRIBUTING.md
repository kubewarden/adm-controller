# Contributing

## Code conventions

Check out our global [CONTRIBUTING
guidelines](https://github.com/kubewarden/community/blob/main/CONTRIBUTING.md#rust-code-conventions)
for Rust code conventions

## Requirements

The following tools are required to build and run this project:

- **Docker**: for building and running containerized workloads.
- **Go**: required by the `audit-scanner` and `controller` components.
- **Rust**: required by the `policy-server` and `kwctl` components. The exact version and required
  targets are defined in `rust-toolchain.toml`.
- **[cross](https://github.com/cross-rs/cross)**: required to cross-compile Rust code for different architectures.
- **Make**: the build tool controlling various build tasks.
- **[Tilt](https://docs.tilt.dev/)**: a development tool for multi-service applications.
- **Kubernetes cluster**: a running Kubernetes cluster, used for development. [kind](https://kind.sigs.k8s.io/)
  or a similar solution.
- **[Helm](https://helm.sh/)**: required for deploying and testing charts.

## Code Layout

The repository is organized as follows:

- `charts`: contains the Helm charts for managing deployments.
- `cmd`: main entry points for the `audit-scanner` and `kubewarden-controller` executables.
- `crates`: all Rust components of the project.
- `docs`: developer-focused documentation and README files for various components.
- `e2e`: end-to-end tests. A real Kubernetes cluster is created using Docker and Kind.
- `internal`: contains the entire Go codebase.

## Linting and Formatting

### Go

Format Go code:

```console
make fmt-go
```

Run the Go linter ([golangci-lint](https://golangci-lint.run/)):

```console
make lint-go
```

Automatically fix linting issues when possible:

```console
make lint-go-fix
```

### Rust

Check Rust code formatting:

```console
make fmt-rust
```

Run the Rust linter (clippy):

```console
make lint-rust
```

Automatically fix linting issues when possible:

```console
make lint-rust-fix
```

### Security Auditing

Check Rust dependencies for known security vulnerabilities using
[cargo-deny](https://embarkstudios.github.io/cargo-deny/):

```console
make advisories-rust
```

## Building

### Build All Components

Build all components (controller, audit-scanner, policy-server, kwctl):

```console
make all
```

### Build Individual Components

Build only the Go components:

```console
make controller
make audit-scanner
```

Build only the Rust components:

```console
make policy-server
make kwctl
```

### Build Container Images

Build Docker images for each component:

```console
make controller-image
make audit-scanner-image
make policy-server-image
```

You can customize the registry, repository, and tag using environment variables:

```console
make controller-image REGISTRY=ghcr.io REPO=your-username TAG=dev
```

## Development

To run the controller for development purposes, you can use
[Tilt](https://tilt.dev/).

### Settings

The `tilt-settings.yaml.example` acts as a template for the
`tilt-settings.yaml` file that you need to create in the root of this
repository. Copy the example file and edit it to match your environment. The
`tilt-settings.yaml` file is ignored by git, so you can edit it without concern
about committing it by mistake.

The following settings can be configured:

- `registry`: the container registry to push the controller image to. If you
  don't have a private registry, you can use `ghcr.io` provided your cluster has
  access to it.

- `audit-scanner`: the name of the audit-scanner image. If you are using
  `ghcr.io` as your registry, you need to prefix the image name with your GitHub
  username.

- `controller`: the name of the controller image. If you are using `ghcr.io` as
  your registry, you need to prefix the image name with your GitHub username.

- `policy-server`: the name of the policy-server image. If you are using
  `ghcr.io` as your registry, you need to prefix the image name with your GitHub
  username.

Example:

```yaml
registry: ghcr.io
audit-scanner: your-github-username/kubewarden/audit-scanner
controller: your-github-username/kubewarden/controller
policy-server: your-github-username/kubewarden/policy-server
```

### Running

The `Tiltfile` included in this repository takes care of the following:

- Creates the `kubewarden` namespace.
- Installs the `kubewarden-crds` and `kubewarden-controller` Helm charts from
  the `charts` folder.
- Injects the development images into the running Pods.
- Automatically reloads the controller/audit-scanner/policy-server when you
  make changes to the code.

To run the controller, you just need to run the following command against an
empty cluster:

```console
tilt up
```

Use the web interface of Tilt to monitor the log streams of the different components and,
if needed, manually trigger restarts.

## Changes to CRDs

After changing a CRD, run the following command:

```console
make generate
```

This will:

- Update all the generated Go code
- Update the CRDs shipped by our Helm chart

## Testing

### Running Tests

Run all unit tests, regardless of the language:

```console
make test
```

Run e2e tests:

```console
make test-e2e
```

### Helm Chart Tests

Run Helm chart unit tests:

```console
make helm-unittest
```

### Writing (controller) integration tests

The controller integration tests are written using the
[Ginkgo](https://onsi.github.io/ginkgo/) and
[Gomega](https://onsi.github.io/gomega/) testing frameworks. The tests are
located in the `internal/controller` package.

By default, the tests are run using
[envtest](https://book.kubebuilder.io/reference/envtest), which sets up an
instance of etcd and the Kubernetes API server, without kubelet,
controller-manager, or other components.

However, some tests require a real Kubernetes cluster to run. These tests are
defined under the `e2e` folder using the
[e2e-framework](https://github.com/kubernetes-sigs/e2e-framework).

The suite setup will start a cluster using [kind](https://kind.sigs.k8s.io/)
and run the tests against it. It will also stop and remove the container when
the tests finish.

Note that the `e2e` tests are slower than the `envtest` tests; therefore, it is
recommended to keep their number to a minimum. An example of a test that
requires a real cluster is the `AdmissionPolicy` test suite, since at the time
of writing, we wait for the `PolicyServer` Pod to be ready before reconciling
the webhook configuration.

### Focusing on Specific Tests

You can focus on a specific test or spec by using a [Focused
Spec](https://onsi.github.io/ginkgo/#focused-specs).

Example:

```go
var _ = Describe("Controller test", func() {
    FIt("should do something", func() {
        // This spec will be the only one executed
    })
})
```

### Testing with Sigstore

The script `scripts/test-sigstore-e2e.sh` provides an script allowing the test of
Kubewarden with a private Sigstore instance. It runs three sequential stages:

1. **Setup** — Spins up a KinD cluster with the full Sigstore stack (Fulcio,
   Rekor, CTLog, TUF) using
   [sigstore/scaffolding](https://github.com/sigstore/scaffolding), and
   generates trust configuration files in the current directory
   (`trusted_root.json`, `trust_config.json`, `verification_config.yaml`, etc.).
2. **Sign** — Copies a test policy to the local registry, signs it with cosign
   against the private Sigstore instance, then verifies with both cosign and
   kwctl.
3. **Deploy** — Installs Kubewarden from local charts, configures the
   PolicyServer with the private Sigstore trust root, deploys a
   ClusterAdmissionPolicy, and exercises the webhook to confirm allow/deny
   behaviour.

#### Usage

Run all three stages end-to-end:

```console
./scripts/test-sigstore-e2e.sh
```

Each stage can be skipped independently, which is useful when iterating
without recreating the full environment:

```console
# Cluster already running — skip setup
./scripts/test-sigstore-e2e.sh --skip-setup

# Policy already signed — skip signing
./scripts/test-sigstore-e2e.sh --skip-sign

# Only set up the Sigstore stack, skip Kubewarden
./scripts/test-sigstore-e2e.sh --skip-kubewarden
```

To learn more about the script, refer to its `--help` cli flag or read the
file.

## Commit subjects

The commit messages may follow the [conventional commits
standard](https://www.conventionalcommits.org/en/v1.0.0/). For example:

- `type: free form subject`

Where `type` can be:

- `feat`: used by commits introducing a new feature
- `fix`: used by commits fix an issue
- `perf`: used by commits improving performance
- `refactor`: used by commits doing some code refactoring

Some examples:

- `feat: this is a new feature`
- `fix: this is fixing a reported bug`

It's also possible to specify a component if this commit targets one component
specifically.

- `feat(resolver): this adds a new solver strategy`

## Releasing

1. Check that `:latest` builds of kubewarden-controller for main are fine,
   including kwctl
1. Open an automated release PR with
   https://github.com/kubewarden/adm-controller/actions/workflows/open-release-pr.yml
   Set the desired kubewarden version.
1. Review & merge automated PR
   - If needed, add `docs/migration-guides/X-to-Y.md` as needed, drop `latest-to-main.md`.
1. Tag version in kubewarden-controller repo
1. Wait for images to be built, so e2e tests can work
1. Trigger automated PR that syncs adm controller charts with helm-chart repo
   https://github.com/kubewarden/helm-charts/actions/workflows/update-adm-controller.yaml
1. Merge automated PR on helm-chart repo
1. chart-releaser releases the charts on Helm chart repo.

## Additional Resources

- **Developer Documentation**: The `docs/` folder contains additional
  documentation for each component (`audit-scanner`, `controller`, `kwctl`,
  `policy-server`, and `crds`).
- **RFCs**: Design proposals and architectural decisions are tracked in a
  separate repository at <https://github.com/kubewarden/rfc>.
