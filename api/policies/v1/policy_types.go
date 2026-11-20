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

// maxWebhookTimeoutSeconds is a magic number on Kubernetes, there's no API to set or get it.
// Example: https://github.com/kubernetes/kubernetes/blob/7c48c2bd72b9bf5c44d21d7338cc7bea77d0ad2a/pkg/apis/admissionregistration/validation/validation.go#L364
const maxWebhookTimeoutSeconds = 30

// +kubebuilder:validation:Enum=protect;monitor
type PolicyMode string

type PolicySpec struct {
	// PolicyServer identifies an existing PolicyServer resource.
	// +kubebuilder:default:=default
	// +optional
	PolicyServer string `json:"policyServer"`

	// Mode defines the execution mode of this policy. Can be set to
	// either "protect" or "monitor". If it's empty, it is defaulted to
	// "protect".
	// Transitioning this setting from "monitor" to "protect" is
	// allowed, but is disallowed to transition from "protect" to
	// "monitor". To perform this transition, the policy should be
	// recreated in "monitor" mode instead.
	// +kubebuilder:default:=protect
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`

	// Module is the location of the WASM module to be loaded. Can be a
	// local file (file://), a remote file served by an HTTP server
	// (http://, https://), or an artifact served by an OCI-compatible
	// registry (registry://).
	// If prefix is missing, it will default to registry:// and use that
	// internally.
	// An http or https URL must have only the host, an optional port, and
	// the full path to the file. It must not have a query, a fragment, a
	// user name, a password, or a backslash (`\`). Its path must not have
	// two slashes in a row (`//`) or a `.` or `..` part.
	// +kubebuilder:validation:Required
	Module string `json:"module"`

	// Settings is a free-form object that contains the policy configuration
	// values.
	// +optional
	// +nullable
	// +kubebuilder:pruning:PreserveUnknownFields
	// x-kubernetes-embedded-resource: false
	Settings runtime.RawExtension `json:"settings,omitempty"`

	// Rules describes what operations on what resources/subresources the webhook cares about.
	// The webhook cares about an operation if it matches _any_ Rule.
	Rules []admissionregistrationv1.RuleWithOperations `json:"rules"`

	// FailurePolicy defines how unrecognized errors and timeout errors from the
	// policy are handled. Allowed values are "Ignore" or "Fail".
	// * "Ignore" means that an error calling the webhook is ignored and the API
	//   request is allowed to continue.
	// * "Fail" means that an error calling the webhook causes the admission to
	//   fail and the API request to be rejected.
	// The default behaviour is "Fail"
	// +optional
	FailurePolicy *admissionregistrationv1.FailurePolicyType `json:"failurePolicy,omitempty"`

	// Mutating indicates whether a policy has the ability to mutate
	// incoming requests or not.
	Mutating bool `json:"mutating"`

	// BackgroundAudit indicates whether a policy should be used or skipped when
	// performing audit checks. If false, the policy cannot produce meaningful
	// evaluation results during audit checks and will be skipped.
	// The default is "true".
	// +kubebuilder:default:=true
	// +optional
	BackgroundAudit bool `json:"backgroundAudit"`

	// matchPolicy defines how the "rules" list is used to match incoming requests.
	// Allowed values are "Exact" or "Equivalent".
	//
	// * `Exact`: Match a request only if it exactly matches a specified rule.
	// For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
	// but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
	// a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
	// * `Equivalent`: Match a request that modifies a listed resource through an equivalent API group or version.
	// For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
	// and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
	// a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
	//
	// Defaults to "Equivalent"
	// +optional
	MatchPolicy *admissionregistrationv1.MatchPolicyType `json:"matchPolicy,omitempty"`

	// MatchConditions are a list of conditions that must be met for a request to be
	// validated. Match conditions filter requests that have already been matched by
	// the rules, namespaceSelector, and objectSelector. An empty list of
	// matchConditions matches all requests. There are a maximum of 64 match
	// conditions allowed. If a parameter object is provided, it can be accessed via
	// the `params` handle in the same manner as validation expressions. The exact
	// matching logic is (in order): 1. If ANY matchCondition evaluates to FALSE,
	// the policy is skipped. 2. If ALL matchConditions evaluate to TRUE, the policy
	// is evaluated. 3. If any matchCondition evaluates to an error (but none are
	// FALSE): - If failurePolicy=Fail, reject the request - If
	// failurePolicy=Ignore, the policy is skipped.
	// Only available if the feature gate AdmissionWebhookMatchConditions is enabled.
	// +optional
	MatchConditions []admissionregistrationv1.MatchCondition `json:"matchConditions,omitempty"`

	// ObjectSelector decides whether to run the webhook based on if the
	// object has matching labels. objectSelector is evaluated against both
	// the oldObject and newObject that would be sent to the webhook, and
	// is considered to match if either object matches the selector. A null
	// object (oldObject in the case of create, or newObject in the case of
	// delete) or an object that cannot have labels (like a
	// DeploymentRollback or a PodProxyOptions object) is not considered to
	// match.
	// Use the object selector only if the webhook is opt-in, because end
	// users may skip the admission webhook by setting the labels.
	// Default to the empty LabelSelector, which matches everything.
	// +optional
	ObjectSelector *metav1.LabelSelector `json:"objectSelector,omitempty"`

	// SideEffects states whether this webhook has side effects.
	// Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
	// Webhooks with side effects MUST implement a reconciliation system, since a request may be
	// rejected by a future step in the admission change and the side effects therefore need to be undone.
	// Requests with the dryRun attribute will be auto-rejected if they match a webhook with
	// sideEffects == Unknown or Some.
	SideEffects *admissionregistrationv1.SideEffectClass `json:"sideEffects,omitempty"`

	// TimeoutSeconds specifies the timeout for the policy webhook. After the timeout passes,
	// the webhook call will be ignored or the API call will fail based on the
	// failure policy.
	// The timeout value must be between 2 and 30 seconds.
	// Default to 10 seconds.
	// +optional
	// +kubebuilder:default:=10
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=30
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// TimeoutEvalSeconds specifies the timeout for the policy evaluation. After
	// the timeout passes, the policy evaluation call will fail based on the
	// failure policy.
	// The timeout value must be between 2 and 30 seconds.
	// +optional
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=30
	TimeoutEvalSeconds *int32 `json:"timeoutEvalSeconds,omitempty"`

	// Message overrides the rejection message of the policy.
	// When provided, the policy's rejection message can be found
	// inside of the `.status.details.causes` field of the
	// AdmissionResponse object
	// +optional
	Message string `json:"message,omitempty"`
}

type PolicyGroupMembers map[string]PolicyGroupMember

type PolicyGroupMember struct {
	// Module is the location of the WASM module to be loaded. Can be a
	// local file (file://), a remote file served by an HTTP server
	// (http://, https://), or an artifact served by an OCI-compatible
	// registry (registry://).
	// If prefix is missing, it will default to registry:// and use that
	// internally.
	// An http or https URL must have only the host, an optional port, and
	// the full path to the file. It must not have a query, a fragment, a
	// user name, a password, or a backslash (`\`). Its path must not have
	// two slashes in a row (`//`) or a `.` or `..` part.
	// +kubebuilder:validation:Required
	Module string `json:"module"`

	// Settings is a free-form object that contains the policy configuration
	// values.
	// +optional
	// +nullable
	// +kubebuilder:pruning:PreserveUnknownFields
	// x-kubernetes-embedded-resource: false
	Settings runtime.RawExtension `json:"settings,omitempty"`

	// TimeoutEvalSeconds specifies the timeout for the policy evaluation. After
	// the timeout passes, the policy evaluation call will fail based on the
	// failure policy.
	// The timeout value must be between 2 and 30 seconds.
	// +optional
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=30
	TimeoutEvalSeconds *int32 `json:"timeoutEvalSeconds,omitempty"`
}

type PolicyGroupMembersWithContext map[string]PolicyGroupMemberWithContext

type PolicyGroupMemberWithContext struct {
	PolicyGroupMember `json:""`

	// List of Kubernetes resources the policy is allowed to access at evaluation time.
	// Access to these resources is done using the `ServiceAccount` of the PolicyServer
	// the policy is assigned to.
	// +optional
	ContextAwareResources []ContextAwareResource `json:"contextAwareResources,omitempty"`
}

type GroupSpec struct {
	// PolicyServer identifies an existing PolicyServer resource.
	// +kubebuilder:default:=default
	// +optional
	PolicyServer string `json:"policyServer"`

	// Mode defines the execution mode of this policy. Can be set to
	// either "protect" or "monitor". If it's empty, it is defaulted to
	// "protect".
	// Transitioning this setting from "monitor" to "protect" is
	// allowed, but is disallowed to transition from "protect" to
	// "monitor". To perform this transition, the policy should be
	// recreated in "monitor" mode instead.
	// +kubebuilder:default:=protect
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`

	// Rules describes what operations on what resources/subresources the webhook cares about.
	// The webhook cares about an operation if it matches _any_ Rule.
	Rules []admissionregistrationv1.RuleWithOperations `json:"rules"`

	// FailurePolicy defines how unrecognized errors and timeout errors from the
	// policy are handled. Allowed values are "Ignore" or "Fail".
	// * "Ignore" means that an error calling the webhook is ignored and the API
	//   request is allowed to continue.
	// * "Fail" means that an error calling the webhook causes the admission to
	//   fail and the API request to be rejected.
	// The default behaviour is "Fail"
	// +optional
	FailurePolicy *admissionregistrationv1.FailurePolicyType `json:"failurePolicy,omitempty"`

	// BackgroundAudit indicates whether a policy should be used or skipped when
	// performing audit checks. If false, the policy cannot produce meaningful
	// evaluation results during audit checks and will be skipped.
	// The default is "true".
	// +kubebuilder:default:=true
	// +optional
	BackgroundAudit bool `json:"backgroundAudit"`

	// matchPolicy defines how the "rules" list is used to match incoming requests.
	// Allowed values are "Exact" or "Equivalent".
	//
	// * `Exact`: Match a request only if it exactly matches a specified rule.
	// For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
	// but "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
	// a request to apps/v1beta1 or extensions/v1beta1 would not be sent to the webhook.
	// * `Equivalent`: Match a request that modifies a listed resource through an equivalent API group or version.
	// For example, if deployments can be modified via apps/v1, apps/v1beta1, and extensions/v1beta1,
	// and "rules" only included `apiGroups:["apps"], apiVersions:["v1"], resources: ["deployments"]`,
	// a request to apps/v1beta1 or extensions/v1beta1 would be converted to apps/v1 and sent to the webhook.
	//
	// Defaults to "Equivalent"
	// +optional
	MatchPolicy *admissionregistrationv1.MatchPolicyType `json:"matchPolicy,omitempty"`

	// MatchConditions are a list of conditions that must be met for a request to be
	// validated. Match conditions filter requests that have already been matched by
	// the rules, namespaceSelector, and objectSelector. An empty list of
	// matchConditions matches all requests. There are a maximum of 64 match
	// conditions allowed. If a parameter object is provided, it can be accessed via
	// the `params` handle in the same manner as validation expressions. The exact
	// matching logic is (in order): 1. If ANY matchCondition evaluates to FALSE,
	// the policy is skipped. 2. If ALL matchConditions evaluate to TRUE, the policy
	// is evaluated. 3. If any matchCondition evaluates to an error (but none are
	// FALSE): - If failurePolicy=Fail, reject the request - If
	// failurePolicy=Ignore, the policy is skipped.
	// Only available if the feature gate AdmissionWebhookMatchConditions is enabled.
	// +optional
	MatchConditions []admissionregistrationv1.MatchCondition `json:"matchConditions,omitempty"`

	// ObjectSelector decides whether to run the webhook based on if the
	// object has matching labels. objectSelector is evaluated against both
	// the oldObject and newObject that would be sent to the webhook, and
	// is considered to match if either object matches the selector. A null
	// object (oldObject in the case of create, or newObject in the case of
	// delete) or an object that cannot have labels (like a
	// DeploymentRollback or a PodProxyOptions object) is not considered to
	// match.
	// Use the object selector only if the webhook is opt-in, because end
	// users may skip the admission webhook by setting the labels.
	// Default to the empty LabelSelector, which matches everything.
	// +optional
	ObjectSelector *metav1.LabelSelector `json:"objectSelector,omitempty"`

	// SideEffects states whether this webhook has side effects.
	// Acceptable values are: None, NoneOnDryRun (webhooks created via v1beta1 may also specify Some or Unknown).
	// Webhooks with side effects MUST implement a reconciliation system, since a request may be
	// rejected by a future step in the admission change and the side effects therefore need to be undone.
	// Requests with the dryRun attribute will be auto-rejected if they match a webhook with
	// sideEffects == Unknown or Some.
	SideEffects *admissionregistrationv1.SideEffectClass `json:"sideEffects,omitempty"`

	// TimeoutSeconds specifies the timeout for this webhook. After the timeout passes,
	// the webhook call will be ignored or the API call will fail based on the
	// failure policy.
	// The timeout value must be between 2 and 30 seconds.
	// Default to 10 seconds.
	// +optional
	// +kubebuilder:default:=10
	// +kubebuilder:validation:Minimum=2
	// +kubebuilder:validation:Maximum=30
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`

	// Expression is the evaluation expression to accept or reject the
	// admission request under evaluation. This field uses CEL as the
	// expression language for the policy groups. Each policy in the group
	// will be represented as a function call in the expression with the
	// same name as the policy defined in the group. The expression field
	// should be a valid CEL expression that evaluates to a boolean value.
	// If the expression evaluates to true, the group policy will be
	// considered as accepted, otherwise, it will be considered as
	// rejected. This expression allows grouping policies calls and perform
	// logical operations on the results of the policies. See Kubewarden
	// documentation to learn about all the features available.
	// +kubebuilder:validation:Required
	Expression string `json:"expression"`

	// Message is  used to specify the message that will be returned when
	// the policy group is rejected. The specific policy results will be
	// returned in the warning field of the response.
	// +kubebuilder:validation:Required
	Message string `json:"message"`
}

type PolicyGroupSpec struct {
	GroupSpec `json:""`

	// Policies is a list of policies that are part of the group that will
	// be available to be called in the evaluation expression field.
	// Each policy in the group should be a Kubewarden policy.
	// +kubebuilder:validation:Required
	Policies PolicyGroupMembers `json:"policies"`
}
