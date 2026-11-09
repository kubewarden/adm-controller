# Release automation

You can trigger the pipeline and open the PR from your local machine
as needed.

## Configuration Structure

The updatecli configuration uses a modular structure with shared values:

- **`values/scms.yaml`** - GitHub authentication and repository settings
- **`values/artifacts.yaml`** - Shared Kubewarden images and Helm charts definitions (used by all pipelines)
- **`values/update-deps-pr-values.yaml`** - PR configuration for weekly dependency updates
- **`values/release-pr-values.yaml`** - PR configuration for release PRs

This structure ensures a single source of truth for artifact definitions while allowing different PR configurations per pipeline.

## Running Release PR Locally

Change `updatecli/values/scms.yaml` as needed to target forks.

The release pipeline computes the `version` of
`charts/admission-controller/Chart.yaml` with `go run
./hack/release-chart-version RELEASE_VERSION`. The helper uses the current
`version`, the current `appVersion`, and `RELEASE_VERSION`:

| Current `version` | Current `appVersion` | `RELEASE_VERSION` | New `version` |
|---|---|---|---|
| `6.1.0` | `v1.38.2` | `v1.39.0-rc.1` | `6.2.0-rc.1` |
| `6.2.0-rc.2` | `v1.39.0-rc.2` | `v1.39.0-rc.3` | `6.2.0-rc.3` |
| `6.2.0-rc.3` | `v1.39.0-rc.3` | `v1.39.0` | `6.2.0` |
| `6.2.0` | `v1.39.0` | `v1.39.1` | `6.2.1` |
| `6.2.0` | `v1.39.0` | `v2.0.0-rc.1` | `7.0.0-rc.1` |

`updatecli/open-release-pr.yaml` runs the release policy first, and then the
Hauler policy on the same branch. The release policy writes the new versions
into the chart. The Hauler policy copies them from the chart into
`charts/hauler_manifest.yaml`.

```console
$ cd adm-controller/
$ export UPDATECLI_GITHUB_TOKEN=<your token>
$ export UPDATECLI_GITHUB_OWNER=kubewarden
$ updatecli compose apply --file updatecli/open-release-pr.yaml

(...)

Run Summary
===========
Pipeline(s) run:
  * Changed:    1
  * Failed:     0
  * Skipped:    0
  * Succeeded:  0
  * Total:      1

One action to follow up:
  * https://github.com/kubewarden/adm-controller/pull/XXX
```

## Dependency Updates

### Renovate

Renovate updates:
- Policy image tags in the Helm chart values
- kuberlr-kubectl image
- openreports chart

Renovate puts each update into one PR, which changes the Helm chart values,
`charts/admission-controller/Chart.yaml`, `Chart.lock`, the openreports archive
in `charts/admission-controller/charts/`, and the Hauler manifest together.

### Weekly Updatecli Dependency Updates

via `.github/workflows/update-dependencies.yaml`, Updatecli updates:
- The policy-reporter chart version
- Hauler manifest with the Kubewarden and policy-reporter versions
- The `artifacthub.io/images` annotation in `charts/admission-controller/Chart.yaml`

Renovate cannot do these updates. The policy-reporter and policy-reporter-ui
image tags come from the policy-reporter chart, and Renovate cannot read them
from the new chart version.

### Running Updates Manually
For manual runs of all dependency updates:
```console
$ export UPDATECLI_GITHUB_TOKEN=<your token>
$ export UPDATECLI_GITHUB_OWNER=kubewarden
$ updatecli compose diff --file updatecli/update-deps.yaml
```

### Adding New Dependencies

To add a new container image or Helm chart, add a custom manager or a
package rule to `renovate.json`. Use updatecli only for a dependency that
Renovate cannot update.
