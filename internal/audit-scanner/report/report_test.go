package report

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestReportsMarshalTheInnerReport(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetUID("uid")
	resource.SetNamespace("namespace")
	resource.SetName("test-pod")

	reports := map[string]Report{
		"PolicyReport":        NewPolicyReport("runUID", resource),
		"ClusterPolicyReport": NewClusterPolicyReport("runUID", resource),
		"OpenReport":          NewOpenReport("runUID", resource),
		"OpenClusterReport":   NewClusterOpenReport("runUID", resource),
	}

	for name, report := range reports {
		t.Run(name, func(t *testing.T) {
			reportJSON, err := json.Marshal(report)
			require.NoError(t, err)

			var decoded struct {
				Metadata metav1.ObjectMeta `json:"metadata"`
			}
			require.NoError(t, json.Unmarshal(reportJSON, &decoded))
			assert.Equal(t, "uid", decoded.Metadata.Name)
		})
	}
}
