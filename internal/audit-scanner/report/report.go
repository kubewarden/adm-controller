package report

import (
	"encoding/json"
	"fmt"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/constants"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// CrdKind represents the kind of report to use to store audit results.
type CrdKind int

const (
	ReportKindOpenReport CrdKind = iota
	ReportKindPolicyReport
)

// Report interface to abstract which kind of report are under use. This is useful
// to support both PolicyReport and OpenReport without duplicating code.
type Report interface {
	json.Marshaler
	SetSkipPolicies(n int)
	SetErrorPolicies(n int)
	AddResult(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview, errored bool)
}

func marshalReport(report any) ([]byte, error) {
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}
	return reportJSON, nil
}

func getCategoryAndMessage(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview) (string, string) {
	var category string
	if c, present := policy.GetCategory(); present {
		category = c
	}

	var message string
	// We need to check if Result is not nil because this field is
	// optional. If the policy returns "allowed" to the admissionReview,
	// the Result field is not checked by Kubernetes.
	// https://pkg.go.dev/k8s.io/api@v0.29.2/admission/v1#AdmissionResponse
	if admissionReview != nil &&
		admissionReview.Response != nil &&
		admissionReview.Response.Result != nil {
		// Message contains the human-readable error message if Response.Result.Code == 500
		// or the reason why the policy returned a failure
		message = admissionReview.Response.Result.Message
	}
	return category, message
}

func computePolicyResult(errored bool, admissionReview *admissionv1.AdmissionReview) string {
	if errored {
		return statusError
	}
	if admissionReview.Response.Allowed {
		return statusPass
	}
	return statusFail
}

func computePolicyResultSeverity(policy policiesv1.Policy) string {
	if policy.GetPolicyMode() == policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor) {
		return severityInfo
	}

	if s, present := policy.GetSeverity(); present {
		return s
	}

	return ""
}

func computeProperties(policy policiesv1.Policy) map[string]string {
	properties := map[string]string{}
	if policy.IsMutating() {
		properties[typeMutating] = valueTypeTrue
	} else {
		properties[typeValidating] = valueTypeTrue
	}
	if policy.IsContextAware() {
		properties[typeContextAware] = valueTypeTrue
	}
	// The policy resource version and the policy UID are used to check if the
	// same result can be reused in the next scan
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#concurrency-control-and-consistency
	properties[propertyPolicyResourceVersion] = policy.GetResourceVersion()
	properties[propertyPolicyUID] = string(policy.GetUID())
	properties[propertyPolicyName] = policy.GetName()
	if policy.GetNamespace() != "" {
		properties[propertyPolicyNamespace] = policy.GetNamespace()
	}

	return properties
}

func getReportObjectMeta(runUID string, resource unstructured.Unstructured) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: string(resource.GetUID()),
		Labels: map[string]string{
			labelAppManagedBy:                 labelApp,
			labelPolicyReportVersion:          labelPolicyReportVersionValue,
			constants.AuditScannerRunUIDLabel: runUID,
		},
		OwnerReferences: []metav1.OwnerReference{
			{
				APIVersion: resource.GetAPIVersion(),
				Kind:       resource.GetKind(),
				Name:       resource.GetName(),
				UID:        resource.GetUID(),
			},
		},
	}
}

func getReportScope(resource unstructured.Unstructured) *corev1.ObjectReference {
	return &corev1.ObjectReference{
		APIVersion:      resource.GetAPIVersion(),
		Kind:            resource.GetKind(),
		Namespace:       resource.GetNamespace(),
		Name:            resource.GetName(),
		UID:             resource.GetUID(),
		ResourceVersion: resource.GetResourceVersion(),
	}
}
