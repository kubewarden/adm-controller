[![Artifact HUB](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubewarden-defaults)](https://artifacthub.io/packages/helm/kubewarden/kubewarden-defaults)

# policy-server

`policy-server` is a
[Kubernetes dynamic admission controller](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
that uses Kubewarden Policies to validate admission requests.

Kubewarden Policies are simple [WebAssembly](https://webassembly.org/)
modules.

# Deployment

We recommend to rely on the [Kubewarden admission controller](https://github.com/kubewarden/adm-controller)
and the [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
provided by it to deploy the Kubewarden stack.

## Configuring policies

A single instance of `policy-server` can load multiple Kubewarden policies. The list
of policies to load, how to expose them and their runtime settings are handled
through a policies file.

By default `policy-server` will load the `policies.yml` file, unless the user
provides a different value via the `--policies` flag.

This is an example of the policies file:

```yml
psp-apparmor:
  module: registry://ghcr.io/kubewarden/policies/psp-apparmor:v0.1.3
psp-capabilities:
  module: registry://ghcr.io/kubewarden/policies/psp-capabilities:v0.1.3
namespace_simple:
  module: file:///tmp/namespace-validate-policy.wasm
  settings:
    valid_namespace: kubewarden-approved
```

The YAML file contains a dictionary with strings as keys, and policy objects as values.

The key that identifies a policy is used by `policy-server` to expose the policy
through its web interface. Policies are exposed under `/validate/<policy id>.

For example, given the configuration file from above, the following API endpoint
would be created:

- `/validate/psp-apparmor`: this exposes the `psp-apparmor:v0.1.3`
  policy. The Wasm module is downloaded from the OCI registry of GitHub.
- `/validate/psp-capabilities`: this exposes the `psp-capabilities:v0.1.3`
  policy. The Wasm module is downloaded from the OCI registry of GitHub.
- `/validate/namespace_simple`: this exposes the `namespace-validate-policy`
  policy. The Wasm module is loaded from a local file located under `/tmp/namespace-validate-policy.wasm`.

It's common for policies to allow users to tune their behaviour via ad-hoc settings.
These customization parameters are provided via the `settings` dictionary.

For example, given the configuration file from above, the `namespace_simple` policy
will be invoked with the `valid_namespace` parameter set to `kubewarden-approved`.

Note well: it's possible to expose the same policy multiple times, each time with
a different set of parameters.

The Wasm file providing the Kubewarden Policy can be either loaded from
the local filesystem or it can be fetched from a remote location. The behaviour
depends on the URL format provided by the user:

- `file:///some/local/program.wasm`: load the policy from the local filesystem
- `https://some-host.com/some/remote/program.wasm`: download the policy from the
  remote http(s) server
- `registry://localhost:5000/project/artifact:some-version` download the policy
  from a OCI registry. The policy must have been pushed as an OCI artifact

### Using a proxy

When downloading policies from remote locations, `policy-server` respects standard proxy environment variables:

- `HTTP_PROXY` or `http_proxy`: proxy server for HTTP requests
- `HTTPS_PROXY` or `https_proxy`: proxy server for HTTPS requests
- `NO_PROXY` or `no_proxy`: comma-separated list of hosts to exclude from proxying

These environment variables should be set in the policy-server container environment.

### Policy Group

Multiple policies can be grouped together and are evaluated using a user provided boolean expression.

The motivation for this feature is to enable users to create complex policies by combining simpler ones.
This allows users to avoid the need to create custom policies from scratch and instead leverage existing policies.
This reduces the need to duplicate policy logic across different policies, increases reusability, removes
the cognitive load of managing complex policy logic, and enables the creation of custom policies using
a DSL-like configuration.

Policy groups are added to the same policy configuration file as individual policies.

This is an example of the policies file with a policy group:

```yml
pod-image-signatures: # policy group
  policies:
    - name: sigstore_pgp
      module: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.8
      settings:
        signatures:
          - image: "*"
            pubKeys:
              - "-----BEGIN PUBLIC KEY-----xxxxx-----END PUBLIC KEY-----"
              - "-----BEGIN PUBLIC KEY-----xxxxx-----END PUBLIC KEY-----"
    - name: sigstore_gh_action
      module: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.8
      settings:
        signatures:
          - image: "*"
            githubActions:
            owner: "kubewarden"
    - name: reject_latest_tag
      module: ghcr.io/kubewarden/policies/trusted-repos-policy:v0.1.12
      settings:
        tags:
          reject:
            - latest
  expression: "sigstore_pgp() || (sigstore_gh_action() && reject_latest_tag())"
  message: "The group policy is rejected."
```

This will lead to the exposure of a validation endpoint `/validate/pod-image-signatures`
that will accept the incoming request if the image is signed with the given public keys or
if the image is built by the given GitHub Actions and the image tag is not `latest`.

Each policy in the group can have its own settings and its own list of Kubernetes resources
that is allowed to access:

```yml
strict-ingress-checks:
  policies:
    - name: unique_ingress
      module: ghcr.io/kubewarden/policies/cel-policy:latest
      contextAwareResources:
        - apiVersion: networking.k8s.io/v1
          kind: Ingress
      settings:
        variables:
          - name: knownIngresses
            expression: kw.k8s.apiVersion("networking.k8s.io/v1").kind("Ingress").list().items
          - name: knownHosts
            expression: |
              variables.knownIngresses
              .filter(i, (i.metadata.name != object.metadata.name) && (i.metadata.namespace != object.metadata.namespace))
              .map(i, i.spec.rules.map(r, r.host))
          - name: desiredHosts
            expression: |
              object.spec.rules.map(r, r.host)
        validations:
          - expression: |
              !variables.knownHost.exists_one(hosts, sets.intersects(hosts, variables.desiredHosts))
            message: "Cannot reuse a host across multiple ingresses"
    - name: https_only
      module: ghcr.io/kubewarden/policies/ingress:latest
      settings:
        requireTLS: true
        allowPorts: [443]
        denyPorts: [80]
    - name: http_only
      module: ghcr.io/kubewarden/policies/ingress:latest
      settings:
        requireTLS: false
        allowPorts: [80]
        denyPorts: [443]

  expression: "unique_ingress() && (https_only() || http_only())"
  message: "The group policy is rejected."
```

For more details, please refer to the Kubewarden documentation.

## Logging and distributed tracing

The verbosity of policy-server can be configured via the `--log-level` flag.
The default log level used is `info`, but `trace`, `debug`, `warn` and `error`
levels are available too.

Policy server can produce logs events using different formats. The `--log-fmt`
flag is used to choose the format to be used.

### Standard output

By default, log messages are printed on the standard output using the
`text` format. Logs can be printed as JSON objects using the `json` format type.

### Open Telemetry Collector

The open Telemetry project provides a [collector](https://opentelemetry.io/docs/collector/)
component that can be used to receive, process and export telemetry data
in a vendor agnostic way.

Policy server can send trace events to the Open Telemetry Collector using the
`--log-fmt otlp` flag.

Current limitations:

- Traces can be sent to the collector only via grpc. The HTTP transport
  layer is not supported.
- The Open Telemetry Collector must be listening on localhost. When deployed
  on Kubernetes, policy-server must have the Open Telemetry Collector
  running as a sidecar.
- Policy server doesn't expose any configuration setting for Open Telemetry
  (e.g.: endpoint URL, encryption, authentication,...). All of the tuning
  has to be done on the collector process that runs as a sidecar.

More details about OpenTelemetry and tracing can be found inside of
our [official docs](https://docs.kubewarden.io/admission-controller/latest/en/howtos/telemetry/20-tracing-qs.html).

# Building

You can use the container image we maintain inside of our
[GitHub Container Registry](https://github.com/orgs/kubewarden/packages/container/package/policy-server).

Alternatively, the `policy-server` binary can be built in this way:

```shell
$ make build
```

# CLI documentation

If you want a complete list of the available commands, you can read the
[cli-docs.md](../../crates/policy-server/cli-docs.md) file.
