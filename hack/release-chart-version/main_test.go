package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextChartVersion(t *testing.T) {
	tests := []struct {
		name           string
		chartVersion   string
		appVersion     string
		releaseVersion string
		want           string
	}{
		{"first release candidate", "6.1.0", "v1.38.2", "v1.39.0-rc.1", "6.2.0-rc.1"},
		{"next release candidate", "6.2.0-rc.2", "v1.39.0-rc.2", "v1.39.0-rc.3", "6.2.0-rc.3"},
		{"final release after release candidates", "6.2.0-rc.3", "v1.39.0-rc.3", "v1.39.0", "6.2.0"},
		{"minor release without release candidate", "6.1.0", "v1.38.2", "v1.39.0", "6.2.0"},
		{"patch release", "6.2.0", "v1.39.0", "v1.39.1", "6.2.1"},
		{"patch release candidate", "6.2.1", "v1.39.1", "v1.39.2-rc.1", "6.2.2-rc.1"},
		{"major release candidate", "6.2.0", "v1.39.0", "v2.0.0-rc.1", "7.0.0-rc.1"},
		{"major release without release candidate", "6.2.0", "v1.39.0", "v2.0.0", "7.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextChartVersion(tt.chartVersion, tt.appVersion, tt.releaseVersion)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNextChartVersionErrors(t *testing.T) {
	tests := []struct {
		name           string
		chartVersion   string
		appVersion     string
		releaseVersion string
		wantErr        string
	}{
		{"older major release version", "6.2.0", "v1.39.0", "v0.40.0", "is not later than"},
		{"same release version", "6.2.0-rc.2", "v1.39.0-rc.2", "v1.39.0-rc.2", "is not later than"},
		{"older release candidate", "6.2.0-rc.2", "v1.39.0-rc.2", "v1.39.0-rc.1", "is not later than"},
		{"release candidate after the final release", "6.2.0", "v1.39.0", "v1.39.0-rc.4", "is not later than"},
		{"older release version", "6.2.0", "v1.39.0", "v1.38.3", "is not later than"},
		{"stable chart with a prerelease appVersion", "6.2.0", "v1.39.0-rc.3", "v1.39.0", "is a prerelease"},
		{"prerelease chart with a new stack X.Y.Z", "6.2.0-rc.1", "v1.38.2", "v1.39.0-rc.2", "does not continue"},
		{"invalid release version", "6.2.0", "v1.39.0", "v1.40", "is not a semantic version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := nextChartVersion(tt.chartVersion, tt.appVersion, tt.releaseVersion)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
