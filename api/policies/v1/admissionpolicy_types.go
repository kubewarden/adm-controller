/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AdmissionPolicySpec defines the desired state of AdmissionPolicy.
type AdmissionPolicySpec struct {
	PolicySpec `json:""`
}

// AdmissionPolicy is the Schema for the admissionpolicies API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ap
// +kubebuilder:storageversion
// +kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"
// +kubebuilder:printcolumn:name="Policy Server",type=string,JSONPath=`.spec.policyServer`,description="Bound to Policy Server"
// +kubebuilder:printcolumn:name="Mutating",type=boolean,JSONPath=`.spec.mutating`,description="Whether the policy is mutating"
// +kubebuilder:printcolumn:name="BackgroundAudit",type=boolean,JSONPath=`.spec.backgroundAudit`,description="Whether the policy is used in audit checks"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`,description="Policy deployment mode"
// +kubebuilder:printcolumn:name="Observed mode",type=string,JSONPath=`.status.mode`,description="Policy deployment mode observed on the assigned Policy Server"
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.policyStatus`,description="Status of the policy"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=".metadata.annotations['io\\.kubewarden\\.policy\\.severity']",priority=1
// +kubebuilder:printcolumn:name="Category",type=string,JSONPath=".metadata.annotations['io\\.kubewarden\\.policy\\.category']",priority=1
type AdmissionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AdmissionPolicySpec `json:"spec,omitempty"`
	Status PolicyStatus        `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AdmissionPolicyList contains a list of AdmissionPolicy.
type AdmissionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdmissionPolicy `json:"items"`
}

func (r *AdmissionPolicy) SetStatus(status PolicyStatusEnum) {
	r.Status.PolicyStatus = status
}

func (r *AdmissionPolicy) GetPolicyMode() PolicyMode {
	return r.Spec.Mode
}

func (r *AdmissionPolicy) SetPolicyModeStatus(policyMode PolicyModeStatus) {
	r.Status.PolicyMode = policyMode
}

func (r *AdmissionPolicy) GetModule() string {
	return r.Spec.Module
}

func (r *AdmissionPolicy) IsMutating() bool {
	return r.Spec.Mutating
}

func (r *AdmissionPolicy) IsContextAware() bool {
	return false
}

func (r *AdmissionPolicy) GetSettings() runtime.RawExtension {
	return r.Spec.Settings
}

func (r *AdmissionPolicy) GetStatus() *PolicyStatus {
	return &r.Status
}

func (r *AdmissionPolicy) CopyInto(policy *Policy) {
	*policy = r.DeepCopy()
}

func (r *AdmissionPolicy) GetSideEffects() *admissionregistrationv1.SideEffectClass {
	return r.Spec.SideEffects
}

// GetRules returns all rules. Scope is namespaced since AdmissionPolicy just watches for namespace resources.
func (r *AdmissionPolicy) GetRules() []admissionregistrationv1.RuleWithOperations {
	namespacedScopeV1 := admissionregistrationv1.NamespacedScope
	rules := make([]admissionregistrationv1.RuleWithOperations, 0)
	for _, rule := range r.Spec.Rules {
		rule.Scope = &namespacedScopeV1
		rules = append(rules, rule)
	}

	return rules
}

func (r *AdmissionPolicy) GetFailurePolicy() *admissionregistrationv1.FailurePolicyType {
	return r.Spec.FailurePolicy
}

func (r *AdmissionPolicy) GetMatchPolicy() *admissionregistrationv1.MatchPolicyType {
	return r.Spec.MatchPolicy
}

func (r *AdmissionPolicy) GetMatchConditions() []admissionregistrationv1.MatchCondition {
	return r.Spec.MatchConditions
}

// GetNamespaceSelector returns the namespace of the AdmissionPolicy since it is the only namespace we want the policy to be applied to.
func (r *AdmissionPolicy) GetNamespaceSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{"kubernetes.io/metadata.name": r.ObjectMeta.Namespace},
	}
}

func (r *AdmissionPolicy) GetAllowInsideAdmissionControllerNamespace() bool {
	return false
}

func (r *AdmissionPolicy) GetObjectSelector() *metav1.LabelSelector {
	return r.Spec.ObjectSelector
}

func (r *AdmissionPolicy) GetTimeoutSeconds() *int32 {
	return r.Spec.TimeoutSeconds
}

func (r *AdmissionPolicy) GetTimeoutEvalSeconds() *int32 {
	return r.Spec.TimeoutEvalSeconds
}

func (r *AdmissionPolicy) GetObjectMeta() *metav1.ObjectMeta {
	return &r.ObjectMeta
}

func (r *AdmissionPolicy) GetPolicyServer() string {
	return r.Spec.PolicyServer
}

func (r *AdmissionPolicy) GetUniqueName() string {
	return "namespaced-" + r.Namespace + "-" + r.Name
}

func (r *AdmissionPolicy) GetContextAwareResources() []ContextAwareResource {
	return []ContextAwareResource{}
}

func (r *AdmissionPolicy) GetBackgroundAudit() bool {
	return r.Spec.BackgroundAudit
}

func (r *AdmissionPolicy) GetSeverity() (string, bool) {
	severity, present := r.Annotations[AnnotationSeverity]
	return severity, present
}

func (r *AdmissionPolicy) GetCategory() (string, bool) {
	category, present := r.Annotations[AnnotationCategory]
	return category, present
}

func (r *AdmissionPolicy) GetTitle() (string, bool) {
	title, present := r.Annotations[AnnotationTitle]
	return title, present
}

func (r *AdmissionPolicy) GetDescription() (string, bool) {
	desc, present := r.Annotations[AnnotationDescription]
	return desc, present
}

func (r *AdmissionPolicy) GetMessage() string {
	return r.Spec.Message
}
