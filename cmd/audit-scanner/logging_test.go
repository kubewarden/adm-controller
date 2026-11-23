package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLogLevelRejectsUnsupportedLevel(t *testing.T) {
	_, err := ParseLogLevel("nope")
	require.ErrorContains(t, err, "invalid loglevel 'nope'")
}
