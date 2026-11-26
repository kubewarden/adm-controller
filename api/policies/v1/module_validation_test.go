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
		{"encoded dot at the end", "https://h/a/%2e", true},
		{"mixed case encoded dot dot", "https://h/a/.%2E", true},
		{"dot dot at the start", "https://h/../p.wasm", true},
		{"password only", "https://:secret@h/p.wasm", true},
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
		{"port too big", "https://h:70000/p.wasm", false},
		{"empty host with port", "https://:80/p.wasm", true},
		{"opaque with password", "https:user:secret@h/p.wasm", true},
		{"one slash with password", "https:/user:secret@h/p.wasm", true},
		{"three slashes with password", "https:///user:secret@h/p.wasm", true},
		{"token as user name", "https://TOKEN@h/p.wasm", true},
		{"unparsable other scheme", "ftp://h:bad/p.wasm", false},
		{"default http port", "http://example.com:80/p.wasm", false},
		{"default https port", "https://example.com:443/p.wasm", false},
		{"https port on http", "http://example.com:443/p.wasm", false},
		{"other https port", "https://example.com:8443/p.wasm", false},
		{"upper case host", "https://Example.com/p.wasm", false},
		{"unicode host", "https://ex\u00e4mple.com/p.wasm", false},
		{"encoded host", "https://%65xample.com/p.wasm", true},
		{"decimal IPv4", "http://2130706433/p.wasm", false},
		{"hex IPv4", "http://0x7f.0.0.1/p.wasm", false},
		{"short IPv4", "http://127.1/p.wasm", false},
		{"octal IPv4", "http://0177.0.0.1/p.wasm", false},
		{"canonical IPv4", "http://127.0.0.1/p.wasm", false},
		{"canonical IPv6", "http://[::1]/p.wasm", false},
		{"canonical IPv6 with port", "http://[::1]:8080/p.wasm", false},
		{"non canonical IPv6", "http://[0:0::1]/p.wasm", false},
		{"upper case IPv4 in IPv6", "http://[::FFFF:1.2.3.4]/p.wasm", false},
		{"IPv6 with zone", "http://[fe80::1%25eth0]/p.wasm", true},
		{"port zero", "https://h:0/p.wasm", false},
		{"empty port", "https://h:/p.wasm", false},
		{"host ends in a number", "http://example.1/p.wasm", false},
		{"trailing dot in host", "http://example.com./p.wasm", false},
		{"leading zero in port", "http://h:080/p.wasm", false},
		{"leading zero in https port", "https://h:0443/p.wasm", false},
		{"leading zero in other port", "http://h:08080/p.wasm", false},
		{"IPv4-mapped IPv6 dotted", "http://[::ffff:1.2.3.4]/p.wasm", false},
		{"IPv4-mapped IPv6 hex", "http://[::ffff:102:304]/p.wasm", false},
		{"invalid punycode", "https://xn--a/p.wasm", false},
		{"punycode label", "https://xn--zz.com/p.wasm", false},
		{"underscore in host", "https://my_host/p.wasm", false},
		{"empty hex last label", "http://example.0x/p.wasm", false},
		{"IPv4 with leading zero", "http://01.2.3.4/p.wasm", false},
		{"character that Go escapes in path", "https://h/a{b}.wasm", true},
		{"encoded slash in path", "https://h/a%2Fb.wasm", false},
		{"canonical IPv4 with port", "http://127.0.0.1:8080/p.wasm", false},
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
