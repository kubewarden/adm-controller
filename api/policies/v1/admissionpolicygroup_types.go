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

// AdmissionPolicyGroupSpec defines the desired state of AdmissionPolicyGroup.
type AdmissionPolicyGroupSpec struct {
	PolicyGroupSpec `json:""`
}

// AdmissionPolicyGroup is the Schema for the AdmissionPolicyGroups API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=apg
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
type AdmissionPolicyGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AdmissionPolicyGroupSpec `json:"spec,omitempty"`
	Status PolicyStatus             `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AdmissionPolicyGroupList contains a list of AdmissionPolicyGroup.
type AdmissionPolicyGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AdmissionPolicyGroup `json:"items"`
}

func (r *AdmissionPolicyGroup) SetStatus(status PolicyStatusEnum) {
	r.Status.PolicyStatus = status
}

func (r *AdmissionPolicyGroup) GetPolicyMode() PolicyMode {
	return r.Spec.Mode
}

func (r *AdmissionPolicyGroup) SetPolicyModeStatus(policyMode PolicyModeStatus) {
	r.Status.PolicyMode = policyMode
}

func (r *AdmissionPolicyGroup) IsContextAware() bool {
	// We return false here because AdmissionPolicyGroup have no access to context aware resources.
	return false
}

func (r *AdmissionPolicyGroup) GetStatus() *PolicyStatus {
	return &r.Status
}

func (r *AdmissionPolicyGroup) GetModule() string {
	return ""
}

func (r *AdmissionPolicyGroup) GetPolicyGroupMembersWithContext() PolicyGroupMembersWithContext {
	policies := make(PolicyGroupMembersWithContext)
	for name, policy := range r.Spec.Policies {
		policies[name] = PolicyGroupMemberWithContext{
			PolicyGroupMember: policy,
			// AdmissionPolicyGroup does not have access to context aware resources.
			ContextAwareResources: []ContextAwareResource{},
		}
	}

	return policies
}

func (r *AdmissionPolicyGroup) GetSettings() runtime.RawExtension {
	return runtime.RawExtension{}
}

func (r *AdmissionPolicyGroup) IsMutating() bool {
	// By design, AdmissionPolicyGroup is always non-mutating.
	// Policy groups can be used only for validating admission requests
	return false
}

func (r *AdmissionPolicyGroup) GetExpression() string {
	return r.Spec.Expression
}

func (r *AdmissionPolicyGroup) GetMessage() string {
	return r.Spec.Message
}

func (r *AdmissionPolicyGroup) CopyInto(policy *Policy) {
	*policy = r.DeepCopy()
}

func (r *AdmissionPolicyGroup) GetSideEffects() *admissionregistrationv1.SideEffectClass {
	return r.Spec.SideEffects
}

// GetRules returns all rules. Scope is namespaced since AdmissionPolicyGroup just watches for namespace resources.
func (r *AdmissionPolicyGroup) GetRules() []admissionregistrationv1.RuleWithOperations {
	namespacedScopeV1 := admissionregistrationv1.NamespacedScope
	rules := make([]admissionregistrationv1.RuleWithOperations, 0)
	for _, rule := range r.Spec.Rules {
		rule.Scope = &namespacedScopeV1
		rules = append(rules, rule)
	}

	return rules
}

func (r *AdmissionPolicyGroup) GetFailurePolicy() *admissionregistrationv1.FailurePolicyType {
	return r.Spec.FailurePolicy
}

func (r *AdmissionPolicyGroup) GetMatchPolicy() *admissionregistrationv1.MatchPolicyType {
	return r.Spec.MatchPolicy
}

func (r *AdmissionPolicyGroup) GetMatchConditions() []admissionregistrationv1.MatchCondition {
	return r.Spec.MatchConditions
}

// GetNamespaceSelector returns the namespace of the AdmissionPolicyGroup since it is the only namespace we want the policy to be applied to.
func (r *AdmissionPolicyGroup) GetNamespaceSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{"kubernetes.io/metadata.name": r.ObjectMeta.Namespace},
	}
}

func (r *AdmissionPolicyGroup) GetAllowInsideAdmissionControllerNamespace() bool {
	return false
}

func (r *AdmissionPolicyGroup) GetObjectSelector() *metav1.LabelSelector {
	return r.Spec.ObjectSelector
}

func (r *AdmissionPolicyGroup) GetTimeoutSeconds() *int32 {
	return r.Spec.TimeoutSeconds
}

func (r *AdmissionPolicyGroup) GetTimeoutEvalSeconds() *int32 {
	// Only policy group members have timeoutEvalSeconds
	return nil
}

func (r *AdmissionPolicyGroup) GetObjectMeta() *metav1.ObjectMeta {
	return &r.ObjectMeta
}

func (r *AdmissionPolicyGroup) GetPolicyServer() string {
	return r.Spec.PolicyServer
}

func (r *AdmissionPolicyGroup) GetUniqueName() string {
	return "namespaced-group-" + r.Namespace + "-" + r.Name
}

func (r *AdmissionPolicyGroup) GetContextAwareResources() []ContextAwareResource {
	// We return an empty slice here because the policy members have the
	// context aware resources. Therefore, the policy group does not need
	// to have them.
	return []ContextAwareResource{}
}

func (r *AdmissionPolicyGroup) GetBackgroundAudit() bool {
	return r.Spec.BackgroundAudit
}

func (r *AdmissionPolicyGroup) GetSeverity() (string, bool) {
	severity, present := r.Annotations[AnnotationSeverity]
	return severity, present
}

func (r *AdmissionPolicyGroup) GetCategory() (string, bool) {
	category, present := r.Annotations[AnnotationCategory]
	return category, present
}

func (r *AdmissionPolicyGroup) GetTitle() (string, bool) {
	title, present := r.Annotations[AnnotationTitle]
	return title, present
}

func (r *AdmissionPolicyGroup) GetDescription() (string, bool) {
	desc, present := r.Annotations[AnnotationDescription]
	return desc, present
}
