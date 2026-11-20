package v1

import (
	"net/url"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

const moduleURLInvalidMessage = "the module URL is not valid. " +
	"An http or https module URL must have only the host, " +
	"an optional port, and the full path to the file."

// validateModuleURL rejects http and https module URLs that can collide in the
// store of the policy server. The check must be at least as strict as the
// check of policy-fetcher, which reads the URL with the rules of WHATWG.
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
	if !moduleURLRejected(module, cleaned) {
		return nil
	}
	return field.Invalid(fldPath, field.OmitValueType{}, moduleURLInvalidMessage)
}

func moduleURLRejected(module, cleaned string) bool {
	if cleaned != module {
		return true
	}
	moduleURL, err := url.Parse(module)
	if err != nil {
		return true
	}
	if moduleURL.Opaque != "" || moduleURL.Hostname() == "" {
		return true
	}
	if strings.Contains(module, `\`) {
		return true
	}
	if port := moduleURL.Port(); port != "" {
		if _, portErr := strconv.ParseUint(port, 10, 16); portErr != nil {
			return true
		}
	}
	if moduleURL.RawQuery != "" || moduleURL.ForceQuery || moduleURL.User != nil {
		return true
	}
	// Go keeps no flag for an empty fragment, so look at the raw string.
	if strings.Contains(module, "#") {
		return true
	}
	path := moduleURL.EscapedPath()
	if path == "" || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		decoded, unescapeErr := url.PathUnescape(segment)
		if unescapeErr != nil || decoded == "." || decoded == ".." {
			return true
		}
	}
	return false
}
