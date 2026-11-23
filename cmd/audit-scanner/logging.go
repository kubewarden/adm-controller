package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

// string representation of custom slog.Level levels; defining them as constants is
// recommended at: https://pkg.go.dev/log/slog#example-HandlerOptions-CustomLevels.
const (
	LevelDebugString = "debug"
	LevelInfoString  = "info"
	LevelWarnString  = "warning"
	LevelErrorString = "error"
)

func SupportedLogLevels() [4]string {
	return [4]string{LevelDebugString, LevelInfoString, LevelWarnString, LevelErrorString}
}

// ParseLogLevel returns the slog.Level of one of the SupportedLogLevels.
func ParseLogLevel(level string) (slog.Level, error) {
	switch level {
	case LevelDebugString:
		return slog.LevelDebug, nil
	case LevelInfoString:
		return slog.LevelInfo, nil
	case LevelWarnString:
		return slog.LevelWarn, nil
	case LevelErrorString:
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid loglevel '%s': supported values are %v", level, SupportedLogLevels())
	}
}

// NewHandler returns a log handler that writes JSON records of the error
// level and higher to stderr, and records of the lower levels to stdout.
func NewHandler(stdout, stderr io.Writer, level slog.Level) slog.Handler {
	return slog.NewMultiHandler(
		&belowLevelHandler{Handler: newJSONHandler(stdout, level), limit: slog.LevelError},
		newJSONHandler(stderr, slog.LevelError),
	)
}

// belowLevelHandler drops the records at the limit level and higher.
// slog.HandlerOptions can set only a minimum level.
type belowLevelHandler struct {
	slog.Handler
	limit slog.Level
}

func (h *belowLevelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level < h.limit && h.Handler.Enabled(ctx, level)
}

func (h *belowLevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &belowLevelHandler{Handler: h.Handler.WithAttrs(attrs), limit: h.limit}
}

func (h *belowLevelHandler) WithGroup(name string) slog.Handler {
	return &belowLevelHandler{Handler: h.Handler.WithGroup(name), limit: h.limit}
}

func newJSONHandler(out io.Writer, level slog.Level) *slog.JSONHandler {
	jh := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: level,

		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				// Handle custom values
				recordLevel, _ := a.Value.Any().(slog.Level)

				switch {
				case recordLevel < slog.LevelInfo:
					a.Value = slog.StringValue(LevelDebugString)
				case recordLevel < slog.LevelWarn:
					a.Value = slog.StringValue(LevelInfoString)
				case recordLevel < slog.LevelError:
					a.Value = slog.StringValue(LevelWarnString)
				default:
					a.Value = slog.StringValue(LevelErrorString)
				}
			}

			if a.Key == slog.MessageKey {
				a.Key = "message"
			}
			return a
		},
	})

	return jh
}
