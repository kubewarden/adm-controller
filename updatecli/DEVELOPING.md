# Release automation

You can trigger the pipeline and open the PR from your local machine
as needed.

## Configuration Structure

The updatecli configuration uses a modular structure with shared values:

- **`values/scms.yaml`** - GitHub authentication and repository settings
- **`values/artifacts.yaml`** - Shared OCI artifacts and Helm charts definitions (used by all pipelines)
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

If `RELEASE_VERSION` changes the major version of the stack, the helper fails.

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

All dependency updates are consolidated into a single weekly workflow.

### Weekly Dependency Updates
Runs weekly (Monday 3:30 AM) via `.github/workflows/update-dependencies.yaml` using `update-deps.yaml`.

Updates the following dependencies:
- Policy image tags in Helm chart values
- Policy-reporter and openreports chart versions
- Kuberlr-kubectl image version
- Hauler manifest with all component versions
- The `artifacthub.io/images` annotation in `charts/admission-controller/Chart.yaml`

### Running Updates Manually
For manual runs of all dependency updates:
```console
$ export UPDATECLI_GITHUB_TOKEN=<your token>
$ export UPDATECLI_GITHUB_OWNER=kubewarden
$ updatecli compose diff --file updatecli/update-deps.yaml
```

### Adding New Dependencies

To add a new OCI artifact or Helm chart:
1. Edit `updatecli/values/artifacts.yaml`
2. Add the artifact to the `ociArtifacts` or `helmCharts` list
3. Test with `updatecli compose diff` before committing
