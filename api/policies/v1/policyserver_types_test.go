package v1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Check that NamespacedPoliciesCapabilities is correctly marshalled: an empty
// list denies all host capabilities, and a nil list allows all of them.
//
// The encoder must keep this difference, done with omitzero. With omitempty
// tag, the controller drops the empty list when it writes the PolicyServer.
// Without a tag, a nil list encodes as null, and server-side apply rejects it.
func TestPolicyServerSpecNamespacedPoliciesCapabilitiesJSON(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []string
		expected     string
	}{
		{
			name:         "empty list stays empty list",
			capabilities: []string{},
			expected:     `[]`,
		},
		{
			name:         "nil list is omitted",
			capabilities: nil,
		},
		{
			name:         "list with values",
			capabilities: []string{"oci/*"},
			expected:     `["oci/*"]`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(PolicyServerSpec{NamespacedPoliciesCapabilities: test.capabilities})
			require.NoError(t, err)

			fields := map[string]json.RawMessage{}
			require.NoError(t, json.Unmarshal(encoded, &fields))

			if test.capabilities == nil {
				assert.NotContains(t, fields, "namespacedPoliciesCapabilities")
				return
			}
			require.Contains(t, fields, "namespacedPoliciesCapabilities")
			assert.JSONEq(t, test.expected, string(fields["namespacedPoliciesCapabilities"]))
		})
	}
}
