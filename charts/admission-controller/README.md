[![Kubewarden Core Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-core.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#core-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)
[![Artifact HUB](https://img.shields.io/badge/ArtifactHub-Helm_Charts-blue?style=flat&logo=artifacthub&link=https%3A%2F%2Fartifacthub.io%2Fpackages%2Fsearch%3Frepo%3Dkubewarden%26kind%3D0%26verified_publisher%3Dtrue%26official%3Dtrue%26cncf%3Dtrue%26sort%3Drelevance%26page%3D1)](https://artifacthub.io/packages/search?repo=kubewarden&kind=0&verified_publisher=true&official=true&cncf=true&sort=relevance&page=1)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/6502/badge)](https://www.bestpractices.dev/projects/6502)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fadm-controller.svg?type=shield&issueType=license)](https://app.fossa.com/projects/custom%2B25850%2Fgithub.com%2Fkubewarden%2Fadm-controller?ref=badge_shield&issueType=license)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/kubewarden/adm-controller/badge)](https://scorecard.dev/viewer/?uri=github.com/kubewarden/adm-controller)
[![CLOMonitor](https://img.shields.io/endpoint?url=https://clomonitor.io/api/projects/cncf/kubewarden/badge)](https://clomonitor.io/projects/cncf/kubewarden)

Kubewarden is a Kubernetes Dynamic Admission Controller that uses policies written
in WebAssembly.

For more information refer to the [official Kubewarden website](https://kubewarden.io/).

# Kubewarden Admission Controller - Monorepo

This repository is a monorepo containing the source code for all the different
components of the Kubewarden Admission Controller:

- **adm-controller**: A Kubernetes controller that allows you to dynamically register Kubewarden admission policies and reconcile them with the Kubernetes webhooks of the cluster where it's deployed
- **policy-server**: The runtime component that evaluates admission policies written in WebAssembly
- **audit-scanner**: A component that scans existing resources in the cluster against registered policies
- **kwctl**: A CLI tool for testing and managing Kubewarden policies

## Documentation

The full and exhaustive documentation is available at [docs.kubewarden.io](https://docs.kubewarden.io).

The [`docs/`](./docs) folder contains README files for each component:

- [Controller](./docs/controller)
- [Policy Server](./docs/policy-server)
- [Audit Scanner](./docs/audit-scanner)
- [kwctl](./docs/kwctl)
- [CRDs](./docs/crds)

## Installation

The adm-controller can be deployed using a Helm chart. For instructions, see
https://charts.kubewarden.io.

Please refer to our [quickstart](https://docs.kubewarden.io/quick-start) for
more details.

> **Note:** This chart replaces the three separate charts that were used
> previously: `kubewarden-crds`, `kubewarden-controller`, and
> `kubewarden-defaults`.

## Migration from three-chart setup

Please refer to the [migration
guide](https://docs.kubewarden.io/admission-controller/howtos/chart-migration)
in the documentation for instructions on migrating from the legacy
`kubewarden-crds`, `kubewarden-controller`, and `kubewarden-defaults` charts to
the unified `admission-controller` chart.

## Configuration

### Defaults

The chart can deploy a default Policy Server and recommended policies:

```yaml
policyServer:
  enabled: true
  replicaCount: 1
  # ... (see values.yaml for full options)

recommendedPolicies:
  enabled: false # disabled by default
  defaultPolicyMode: "monitor"
  allowPrivilegeEscalationPolicy:
    # ... (see values.yaml)
```

These resources are owned and reconciled by the controller. Manual
changes are reverted on the next reconciliation. Setting `enabled`
to `false` removes all managed resources.

### Resources that namespaced policies can target

Namespaced policies (`AdmissionPolicy` and `AdmissionPolicyGroup`) can
target only the resources listed in `namespacedPoliciesAllowedResources`.
`ClusterAdmissionPolicy` and `ClusterAdmissionPolicyGroup` are not affected.
A policy that targets both permitted and not permitted resources is
rejected as a whole.

```yaml
namespacedPoliciesAllowedResources:
  - apiGroups: [""]
    resources: [pods, configmaps, secrets]
  - apiGroups: ["apps"]
    resources: [deployments, statefulsets]
```

Each entry has the same shape as the `apiGroups` and `resources` fields of a
policy rule. Wildcards (`*`) and subresources (`pods/exec`) are not permitted
in this list. The controller skips these items and logs them. A policy rule
that targets a subresource of a permitted resource is permitted.

The controller accepts a namespaced policy that targets other resources, but
it does not deploy the policy. The policy status is `rejected`. The
`PolicyActive` condition lists the resources that are not permitted. When you
add these resources to the list, the controller deploys the policy.

The chart comes with a default list of Kubernetes resources that are considered
safe to be validated or mutated by namespaced policies.

### CRDs

CRDs are installed with the `helm.sh/resource-policy: keep` annotation:

- `helm upgrade` updates CRDs normally
- `helm uninstall` does not delete CRDs, which prevents cascade-deletion of all PolicyServers and policies in the cluster

#### Reinstalling under a different release name or namespace

Because the CRDs are kept on uninstall, they survive with the Helm
ownership metadata of the release that created them
(`meta.helm.sh/release-name` and `meta.helm.sh/release-namespace`). Helm
checks this metadata on the next install:

- Same release name **and** namespace: Helm adopts the existing CRDs and
  the install succeeds.
- Different release name **or** namespace: Helm refuses to take over the
  CRDs and the install fails with:

  ```
  Error: ... invalid ownership metadata; annotation
  meta.helm.sh/release-name must equal "<new>": current value is "<old>"
  ```

This is expected: the CRDs still belong to the previous release. To adopt
them into the new release, install with `--take-ownership` (Helm 3.18+ or
Helm 4), which re-stamps the ownership metadata:

```sh
helm install <release> <chart> -n <namespace> --take-ownership
```

## Uninstall

```sh
helm uninstall kubewarden-controller -n kubewarden
```

This removes:

- The controller Deployment
- Managed defaults (resources labeled `kubewarden.io/managed-by=kubewarden-controller-defaults`)
- ConfigMaps, Secrets, Services

It does not remove:

- CRDs (kept by `helm.sh/resource-policy: keep`)
- User-managed PolicyServers and policies

To remove CRDs after uninstall:

```sh
kubectl delete crd policyservers.policies.kubewarden.io
kubectl delete crd clusteradmissionpolicies.policies.kubewarden.io
kubectl delete crd admissionpolicies.policies.kubewarden.io
kubectl delete crd clusteradmissionpolicygroups.policies.kubewarden.io
kubectl delete crd admissionpolicygroups.policies.kubewarden.io
```

# Software bill of materials & provenance

Every release publishes a software bill of materials (SBOM) and build
[provenance](https://slsa.dev/spec/v1.0/provenance) for each Kubewarden
component. The SBOM follows the [SPDX](https://spdx.dev/) format. The
provenance follows the [SLSA](https://slsa.dev/spec/v1.0/provenance) provenance
schema. [Docker buildx](https://docs.docker.com/build/metadata/attestations/)
generates both files during the build. It stores them in the container registry
next to the container image. The release also uploads them as release assets.

Kubewarden publishes three images: `controller`, `audit-scanner` and
`policy-server`. The release assets follow the pattern
`<component>-attestation-<arch>-<provenance|sbom>.<ext>`.

Kubewarden signs the container images and the SBOM and provenance files in the
[release assets](https://github.com/kubewarden/adm-controller/releases). The
signatures use keyless signing with the GitHub Actions OIDC identity of the
shared `container-release.yml` reusable workflow in the
`kubewarden/github-actions` repository. The `@<ref>` part of that identity is
the commit of the reusable workflow, not the Kubewarden tag, so the commands
match it with `--certificate-identity-regexp`. That identity alone names the
builder, not the release. The commands also pin the caller repository and the
release tag with `--certificate-github-workflow-repository` and
`--certificate-github-workflow-ref`, so a signed file from another repository
or another release does not pass. The flags do not bind the component. Every
component of one release shares these certificate values, so a blob and its
bundle from one component verify under another component's filename. To check
which image a file describes, read the `subject` field inside the file.

The same workflow runs `actions/attest` on each multi-architecture image. That
attestation gives the images SLSA Build L3. To verify it, run:

```shell
gh attestation verify oci://ghcr.io/kubewarden/adm-controller/controller:<TAG TO VERIFY> \
    --repo kubewarden/adm-controller \
    --signer-workflow kubewarden/github-actions/.github/workflows/container-release.yml
```

To verify the cosign signature of an image, run:

```shell
cosign verify --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity-regexp='^https://github\.com/kubewarden/github-actions/\.github/workflows/container-release\.yml@' \
    --certificate-github-workflow-repository=kubewarden/adm-controller \
    --certificate-github-workflow-ref='refs/tags/<TAG TO VERIFY>' \
    ghcr.io/kubewarden/adm-controller/controller:<TAG TO VERIFY>
```

The command works with a tag and with a digest. The release signs the
multi-architecture image and each single-architecture image.

To verify the provenance file from the release assets, run:

```shell
cosign verify-blob --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity-regexp='^https://github\.com/kubewarden/github-actions/\.github/workflows/container-release\.yml@' \
    --certificate-github-workflow-repository=kubewarden/adm-controller \
    --certificate-github-workflow-ref='refs/tags/<TAG TO VERIFY>' \
    --bundle controller-attestation-amd64-provenance.intoto.jsonl.bundle.sigstore \
    controller-attestation-amd64-provenance.intoto.jsonl
```

To verify the SBOM file, use the same command with the `sbom.json` files:

```shell
cosign verify-blob --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity-regexp='^https://github\.com/kubewarden/github-actions/\.github/workflows/container-release\.yml@' \
    --certificate-github-workflow-repository=kubewarden/adm-controller \
    --certificate-github-workflow-ref='refs/tags/<TAG TO VERIFY>' \
    --bundle controller-attestation-amd64-sbom.json.bundle.sigstore \
    controller-attestation-amd64-sbom.json
```

> [!NOTE]
> The commands in this section use the `controller` image. The same commands
> work for the `audit-scanner` and `policy-server` images.

The SBOM and provenance files are also attached to the image in the registry.
Docker buildx stores them in one attestation manifest per architecture, as
JSON documents that follow the [in-toto SPDX
predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/spdx.md)
format. The registry copy is not signed. The signed copies are the release
assets. You can inspect the registry copy with
[`crane`](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md)
or [`docker buildx imagetools
inspect`](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect).

To list the attestation manifests of a tag, run:

```shell
crane manifest ghcr.io/kubewarden/adm-controller/controller:<TAG TO VERIFY> | jq '.manifests[] | select(.annotations["vnd.docker.reference.type"]=="attestation-manifest")'
```

Each attestation manifest has one layer per SBOM or provenance file. To list
the layers, run:

```shell
crane manifest ghcr.io/kubewarden/adm-controller/controller@sha256:<ATTESTATION MANIFEST DIGEST>
```

To download one file, use the digest of its layer:

```shell
crane blob ghcr.io/kubewarden/adm-controller/controller@sha256:<LAYER DIGEST>
```

## Security disclosure

See [SECURITY.md](https://github.com/kubewarden/community/blob/main/SECURITY.md) on the kubewarden/community repo.

# Changelog

See [GitHub Releases content](https://github.com/kubewarden/adm-controller/releases).
