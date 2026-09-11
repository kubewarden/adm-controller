# AGENTS.md — the Helm chart

- This file applies to all the files in `charts/admission-controller/`. The
  root [`AGENTS.md`](../AGENTS.md) holds the rules for the full monorepo.
- This is the single unified chart. It installs the controller, the audit
  scanner and the defaults of the policy server.

## Structure

- `templates/controller/` — the deployment, the service, the RBAC rules, the
  webhooks and the hooks of the controller and the audit scanner
- `templates/crds/` — the CRDs of Kubewarden and the imported report CRDs
- `templates/defaults/` — the default policy server and its RBAC rules
- `tests/` — the unit tests of the chart
- `values.yaml` — the values that the user can set
- `questions.yaml` — the form of the Rancher user interface

## Testing strategy

- Run `make helm-unittest`.
- A new value needs a test that renders it.
- The test must show the effect of the value on the manifest, not only its
  presence in `values.yaml`.

## Development principles

- `questions.yaml` follows `values.yaml`. A value that the user can set needs
  an entry in both files.
- Every template must render with the default values. A value with no default
  must fail with a message that names the value.
- The chart holds the packaging. Behavior belongs to the controller or to the
  policy server.

## Generated files — do not edit them by hand

- `templates/crds/policies.kubewarden.io_*.yaml` — the `+kubebuilder:` markers in `api/policies/`
- `templates/controller/controller-rbac-roles.yaml` — the `+kubebuilder:rbac:` markers in `internal/controller/`
- `values.schema.json` — `values.yaml`

- To generate these files again, run `make manifests` and `make generate-chart`
  from the root of the repository.
- `make generate` runs both. Then run `make check-generate`.
- To change a field of a CRD or an RBAC rule, edit the marker in the Go code.
  Never edit the YAML.
- `make manifests` also processes `controller-rbac-roles.yaml` with `sed`. It
  is safe to run the target again.
- The files `templates/crds/policyreports.yaml` and
  `templates/crds/clusterpolicyreports.yaml` are different. They are
  third-party CRDs inside Helm conditionals. controller-gen does not produce
  them.

## The webhook manifests need a manual merge

- `make manifests` writes the webhook configuration to
  `charts/generated-webhooks-manifests.yaml`.
- That file is outside this directory, and the chart does not use it.
- Read it and merge the changes by hand into
  `templates/controller/webhooks.yaml`.
- That file is a template. A command cannot overwrite it.

## Conditions that need your attention

- The envtest suite in `internal/controller/` loads the CRDs directly from
  `templates/crds/`. Thus a chart that is not current breaks the Go tests.
  Generate the chart again before you run `make test-go`.
- The CRDs carry the annotation `helm.sh/resource-policy: keep`. Thus
  `helm uninstall` keeps them, and this behavior is intentional. To install again
  with a different release name or namespace, use
  `helm install ... --take-ownership`. This flag needs Helm 3.18 or later.
- The file `Chart.lock` pins the subcharts in `charts/*.tgz`. To update one,
  change `Chart.yaml` and write the lock file again. Do not edit the archives.
