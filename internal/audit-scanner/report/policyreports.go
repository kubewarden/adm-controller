package report

import (
	"time"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

type PolicyReport struct {
	report *wgpolicy.PolicyReport
}

type ClusterPolicyReport struct {
	report *wgpolicy.ClusterPolicyReport
}

func NewReportOfKind(kind CrdKind, runUID string, resource unstructured.Unstructured) Report {
	if kind == ReportKindPolicyReport {
		return NewPolicyReport(runUID, resource)
	}
	return NewOpenReport(runUID, resource)
}

func NewClusterReportOfKind(kind CrdKind, runUID string, resource unstructured.Unstructured) Report {
	if kind == ReportKindPolicyReport {
		return NewClusterPolicyReport(runUID, resource)
	}
	return NewClusterOpenReport(runUID, resource)
}

// NewPolicyReport creates a new PolicyReport from a given resource.
//
// Deprecated: use NewReport instead. wgpolicy.PolicyReport is deprecated in favor of openreports.Report.
func NewPolicyReport(runUID string, resource unstructured.Unstructured) *PolicyReport {
	objMeta := getReportObjectMeta(runUID, resource)
	objMeta.Namespace = resource.GetNamespace()
	return &PolicyReport{
		report: &wgpolicy.PolicyReport{
			ObjectMeta: objMeta,
			Scope:      getReportScope(resource),
			Summary: wgpolicy.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
		},
	}
}

func (r *PolicyReport) AddResult(
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newPolicyReportResult(policy, admissionReview, errored, now)
	switch result.Result {
	case statusFail:
		r.report.Summary.Fail++
	case statusError:
		r.report.Summary.Error++
	case statusPass:
		r.report.Summary.Pass++
	}
	r.report.Results = append(r.report.Results, result)
}

func (r *PolicyReport) SetSkipPolicies(skippedPoliciesNumber int) {
	r.report.Summary.Skip = skippedPoliciesNumber
}

func (r *PolicyReport) SetErrorPolicies(erroredPoliciesNumber int) {
	r.report.Summary.Error = erroredPoliciesNumber
}

func (r *PolicyReport) MarshalJSON() ([]byte, error) {
	return marshalReport(r.report)
}

// NewClusterPolicyReport creates a new ClusterPolicyReport from a given resource.
//
// Deprecated: use NewClusterReport instead. wgpolicy.ClusterPolicyReport is deprecated in favor of openreports.ClusterReport.
func NewClusterPolicyReport(runUID string, resource unstructured.Unstructured) *ClusterPolicyReport {
	return &ClusterPolicyReport{
		report: &wgpolicy.ClusterPolicyReport{
			ObjectMeta: getReportObjectMeta(runUID, resource),
			Scope:      getReportScope(resource),
			Summary: wgpolicy.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
		},
	}
}

func (r *ClusterPolicyReport) AddResult(
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newPolicyReportResult(policy, admissionReview, errored, now)
	switch result.Result {
	case statusFail:
		r.report.Summary.Fail++
	case statusError:
		r.report.Summary.Error++
	case statusPass:
		r.report.Summary.Pass++
	}
	r.report.Results = append(r.report.Results, result)
}

func (r *ClusterPolicyReport) SetSkipPolicies(skippedPoliciesNumber int) {
	r.report.Summary.Skip = skippedPoliciesNumber
}

func (r *ClusterPolicyReport) SetErrorPolicies(erroredPoliciesNumber int) {
	r.report.Summary.Error = erroredPoliciesNumber
}

func (r *ClusterPolicyReport) MarshalJSON() ([]byte, error) {
	return marshalReport(r.report)
}

func newPolicyReportResult(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview, errored bool, timestamp metav1.Timestamp) *wgpolicy.PolicyReportResult {
	category, message := getCategoryAndMessage(policy, admissionReview)

	return &wgpolicy.PolicyReportResult{
		Source:          policyReportSource,
		Policy:          policy.GetUniqueName(),
		Category:        category,
		Severity:        wgpolicy.PolicyResultSeverity(computePolicyResultSeverity(policy)),   // either info for monitor or empty
		Timestamp:       timestamp,                                                            // time the result was computed
		Result:          wgpolicy.PolicyResult(computePolicyResult(errored, admissionReview)), // pass, fail, error
		Scored:          true,
		SubjectSelector: &metav1.LabelSelector{},
		// This field is marshalled to `message`
		Description: message,
		Properties:  computeProperties(policy),
	}
}
