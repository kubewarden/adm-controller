package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateModuleURL(t *testing.T) {
	tests := []struct {
		name     string
		module   string
		rejected bool
	}{
		{"https", "https://example.com/policy.wasm", false},
		{"http with port", "http://example.com:8080/path/to/policy.wasm", false},
		{"registry", "registry://ghcr.io/org/policy:v1", false},
		{"file", "file:///tmp/policy.wasm", false},
		{"no scheme", "ghcr.io/org/p:v1", false},
		{"query", "https://example.com/policy.wasm?id=1", true},
		{"empty query", "https://example.com/policy.wasm?", true},
		{"fragment", "https://example.com/policy.wasm#a", true},
		{"empty fragment", "https://example.com/policy.wasm#", true},
		{"user name", "https://user@example.com/policy.wasm", true},
		{"user name and password", "https://user:secret@example.com/policy.wasm", true},
		{"empty path", "https://example.com", true},
		{"root path", "https://example.com/", true},
		{"trailing slash", "https://example.com/path/", true},
		{"empty segment at start", "https://example.com//policy.wasm", true},
		{"empty segment in the middle", "https://example.com/a//policy.wasm", true},
		{"upper case scheme", "HTTPS://example.com/policy.wasm?id=1", true},
		{"dot dot at the end", "https://h/a/..", true},
		{"dot at the end", "https://h/a/.", true},
		{"encoded dot dot", "https://h/a/%2e%2e", true},
		{"upper case encoded dot dot", "https://h/a/%2E%2E", true},
		{"dot dot in the middle", "https://h/a/../p.wasm", true},
		{"backslash", `https://h/\p.wasm`, true},
		{"leading space", " https://h/p.wasm", true},
		{"trailing space", "https://h/p.wasm ", true},
		{"tab before query", "https://h/p.wasm\t?x", true},
		{"newline inside", "https://h/p\n.wasm", true},
		{"opaque", "https:h/p.wasm", true},
		{"no host", "https:///p.wasm", true},
		{"unparsable", "https://h:bad/p.wasm", true},
		{"control character at the start", "\x01https://h/p.wasm?x", true},
		{"tab inside the scheme", "ht\ttps://h/p.wasm?x", true},
		{"port too big", "https://h:70000/p.wasm", true},
		{"empty host with port", "https://:80/p.wasm", true},
		{"opaque with password", "https:user:secret@h/p.wasm", true},
		{"one slash with password", "https:/user:secret@h/p.wasm", true},
		{"three slashes with password", "https:///user:secret@h/p.wasm", true},
		{"token as user name", "https://TOKEN@h/p.wasm", true},
		{"unparsable other scheme", "ftp://h:bad/p.wasm", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fldPath := field.NewPath("spec").Child("module")
			err := validateModuleURL(test.module, fldPath)
			if !test.rejected {
				require.Nil(t, err)
				return
			}
			require.NotNil(t, err)
			require.Equal(t, "spec.module", err.Field)
			require.Equal(t, "the module URL is not valid. An http or https module URL must have only "+
				"the host, an optional port, and the full path to the file.", err.Detail)
			require.NotContains(t, err.Error(), "secret")
			require.NotContains(t, err.Error(), "TOKEN")
			require.NotContains(t, err.Error(), "example.com")
		})
	}
}
