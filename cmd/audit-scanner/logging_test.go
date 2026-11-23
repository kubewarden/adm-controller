package main

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogLevelRejectsUnsupportedLevel(t *testing.T) {
	_, err := ParseLogLevel("nope")
	require.ErrorContains(t, err, "invalid loglevel 'nope'")
}

func TestNewHandlerSendsErrorsToStderrAndLowerLevelsToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	logger := slog.New(NewHandler(&stdout, &stderr, slog.LevelDebug)).With("component", "scanner")

	logger.Info("info message")
	logger.Warn("warning message")
	logger.Error("error message")

	assert.Contains(t, stdout.String(), "info message")
	assert.Contains(t, stdout.String(), "warning message")
	assert.NotContains(t, stdout.String(), "error message")

	assert.Contains(t, stderr.String(), "error message")
	assert.NotContains(t, stderr.String(), "info message")
	assert.NotContains(t, stderr.String(), "warning message")
}
