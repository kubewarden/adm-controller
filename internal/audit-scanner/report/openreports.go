package report

import (
	"time"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type OpenReport struct {
	report *openreports.Report
}

type OpenClusterReport struct {
	report *openreports.ClusterReport
}

// NewOpenReport creates a new OpenReport from a given resource.
func NewOpenReport(runUID string, resource unstructured.Unstructured) *OpenReport {
	objMeta := getReportObjectMeta(runUID, resource)
	objMeta.Namespace = resource.GetNamespace()
	return &OpenReport{
		report: &openreports.Report{
			ObjectMeta: objMeta,
			Scope:      getReportScope(resource),
			Summary: openreports.ReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
		},
	}
}

func (r *OpenReport) AddResult(
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newReportResult(policy, admissionReview, errored, now)
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

func (r *OpenReport) SetSkipPolicies(skippedPoliciesNumber int) {
	r.report.Summary.Skip = skippedPoliciesNumber
}

func (r *OpenReport) SetErrorPolicies(erroredPoliciesNumber int) {
	r.report.Summary.Error = erroredPoliciesNumber
}

func (r *OpenReport) MarshalJSON() ([]byte, error) {
	return marshalReport(r.report)
}

func (r *OpenClusterReport) AddResult(
	policy policiesv1.Policy,
	admissionReview *admissionv1.AdmissionReview,
	errored bool,
) {
	now := metav1.Timestamp{Seconds: time.Now().Unix()}
	result := newReportResult(policy, admissionReview, errored, now)
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

func (r *OpenClusterReport) SetSkipPolicies(skippedPoliciesNumber int) {
	r.report.Summary.Skip = skippedPoliciesNumber
}

func (r *OpenClusterReport) SetErrorPolicies(erroredPoliciesNumber int) {
	r.report.Summary.Error = erroredPoliciesNumber
}

func (r *OpenClusterReport) MarshalJSON() ([]byte, error) {
	return marshalReport(r.report)
}

// NewClusterOpenReport creates a new ClusterPolicyReport from a given resource.
func NewClusterOpenReport(runUID string, resource unstructured.Unstructured) *OpenClusterReport {
	return &OpenClusterReport{
		report: &openreports.ClusterReport{
			ObjectMeta: getReportObjectMeta(runUID, resource),
			Scope:      getReportScope(resource),
			Summary: openreports.ReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
		},
	}
}

func newReportResult(policy policiesv1.Policy, admissionReview *admissionv1.AdmissionReview, errored bool, timestamp metav1.Timestamp) openreports.ReportResult {
	category, message := getCategoryAndMessage(policy, admissionReview)

	return openreports.ReportResult{
		Source:           policyReportSource,
		Policy:           policy.GetUniqueName(),
		Category:         category,
		Severity:         openreports.ResultSeverity(computePolicyResultSeverity(policy)),   // either info for monitor or empty
		Timestamp:        timestamp,                                                         // time the result was computed
		Result:           openreports.Result(computePolicyResult(errored, admissionReview)), // pass, fail, error
		Scored:           true,
		ResourceSelector: &metav1.LabelSelector{},
		// This field is marshalled to `message`
		Description: message,
		Properties:  computeProperties(policy),
	}
}
