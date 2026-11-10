// release-chart-version prints the version of the admission-controller Helm
// chart for a new release of the Kubewarden stack. The updatecli release
// pipeline (updatecli/updatecli.release.d/open-release-pr.yaml) runs it.
//
// Usage:
//
//	go run ./hack/release-chart-version RELEASE_VERSION
//
// It reads the current version and appVersion from Chart.yaml. See
// nextChartVersion for the rules.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"
)

const chartFile = "charts/admission-controller/Chart.yaml"

type chart struct {
	Version    string `yaml:"version"`
	AppVersion string `yaml:"appVersion"`
}

// nextChartVersion returns the chart version for releaseVersion:
//   - If chartVersion is a prerelease, keep its X.Y.Z.
//     For example: 6.2.0-rc.2, v1.39.0-rc.2 and v1.39.0-rc.3 give 6.2.0-rc.3.
//   - If chartVersion is stable, increment the same level (major, minor or
//     patch) that the stack increments.
//     For example: 6.1.0, v1.38.2 and v1.39.0-rc.1 give 6.2.0-rc.1.
//   - Copy the prerelease part of releaseVersion.
func nextChartVersion(chartVersion, appVersion, releaseVersion string) (string, error) {
	chartV, err := parse("chart version", chartVersion)
	if err != nil {
		return "", err
	}
	app, err := parse("appVersion", appVersion)
	if err != nil {
		return "", err
	}
	rel, err := parse("release version", releaseVersion)
	if err != nil {
		return "", err
	}

	if !rel.GreaterThan(app) {
		return "", fmt.Errorf("release version %s is not later than appVersion %s", releaseVersion, appVersion)
	}

	var next semver.Version
	switch {
	case chartV.Prerelease() != "":
		if rel.Major() != app.Major() || rel.Minor() != app.Minor() || rel.Patch() != app.Patch() {
			return "", fmt.Errorf("chart version %s is a prerelease, but release version %s does not continue appVersion %s",
				chartVersion, releaseVersion, appVersion)
		}
		next = *semver.New(chartV.Major(), chartV.Minor(), chartV.Patch(), "", "")
	case rel.Major() > app.Major():
		next = chartV.IncMajor()
	case rel.Major() == app.Major() && rel.Minor() > app.Minor():
		next = chartV.IncMinor()
	case rel.Major() == app.Major() && rel.Minor() == app.Minor() && rel.Patch() > app.Patch():
		next = chartV.IncPatch()
	default:
		return "", fmt.Errorf("chart version %s is stable, but appVersion %s is a prerelease", chartVersion, appVersion)
	}

	next, err = next.SetPrerelease(rel.Prerelease())
	if err != nil {
		return "", fmt.Errorf("setting prerelease %q: %w", rel.Prerelease(), err)
	}
	return next.String(), nil
}

func parse(name, version string) (*semver.Version, error) {
	v, err := semver.StrictNewVersion(strings.TrimPrefix(version, "v"))
	if err != nil {
		return nil, fmt.Errorf("%s %q is not a semantic version: %w", name, version, err)
	}
	return v, nil
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: release-chart-version RELEASE_VERSION")
	}
	data, err := os.ReadFile(chartFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", chartFile, err)
	}
	var c chart
	if err = yaml.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("parsing %s: %w", chartFile, err)
	}
	next, err := nextChartVersion(c.Version, c.AppVersion, args[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, next)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
