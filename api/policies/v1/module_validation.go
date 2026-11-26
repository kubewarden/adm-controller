package v1

import (
	"net/url"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

const moduleURLInvalidMessage = "the module URL is not valid. " +
	"An http or https module URL must have only the host, " +
	"an optional port, and the full path to the file."

// validateModuleURL rejects http and https module URLs that can collide in the
// store of the policy server. For the rules that prevent a collision, it is at
// least as strict as policy-fetcher.
//
// The check accepts only scheme://host[:port]/path. If the input has any
// other part, for example a user name or a query, it is not equal to this
// form and the check rejects it. The check does not reject most host and
// port spellings that the Rust url crate reads as the same server, for
// example an uppercase host, a default port, or another IP form. They point
// to the same file. It also accepts some hosts and ports that the Rust url
// crate cannot parse, for example port 70000. The download of such a module
// fails, the same as for a wrong host name.
//
// The error does not show the URL, because url.Parse does not always put a
// password in User, and its errors hold the full URL.
func validateModuleURL(module string, fldPath *field.Path) *field.Error {
	withoutEdges := strings.TrimFunc(module, func(char rune) bool { return char <= ' ' })
	cleaned := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(withoutEdges)
	normalized := strings.ToLower(cleaned)
	if !strings.HasPrefix(normalized, "http:") && !strings.HasPrefix(normalized, "https:") {
		return nil
	}
	if !moduleURLRejected(module) {
		return nil
	}
	return field.Invalid(fldPath, field.OmitValueType{}, moduleURLInvalidMessage)
}

func moduleURLRejected(module string) bool {
	moduleURL, err := url.Parse(module)
	if err != nil || moduleURL.Opaque != "" || moduleURL.Hostname() == "" {
		return true
	}
	path := moduleURL.EscapedPath()
	if path == "" || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return true
	}
	// The Rust url crate removes "." and ".." segments, also when written as
	// %2e. Go does not remove them. In Rust, a dot segment at the end becomes
	// a trailing "/", and policy-fetcher rejects it.
	for _, segment := range strings.Split(path, "/") {
		decoded, unescapeErr := url.PathUnescape(segment)
		if unescapeErr != nil || decoded == "." || decoded == ".." {
			return true
		}
	}
	return moduleURL.Scheme+"://"+moduleURL.Host+path != module
}
