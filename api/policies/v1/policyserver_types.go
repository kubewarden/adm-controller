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
	"github.com/kubewarden/adm-controller/internal/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// PolicyServerSecurity defines securityContext configuration to be used in the Policy Server workload.
type PolicyServerSecurity struct {
	// securityContext definition to be used in the policy server container
	// +optional
	Container *corev1.SecurityContext `json:"container,omitempty"`
	// podSecurityContext definition to be used in the policy server Pod
	// +optional
	Pod *corev1.PodSecurityContext `json:"pod,omitempty"`
}

// PolicyServerSpec defines the desired state of PolicyServer.
type PolicyServerSpec struct {
	// Docker image name.
	Image string `json:"image"`

	// Replicas is the number of desired replicas.
	Replicas int32 `json:"replicas"`

	// Number of policy server replicas that must be still available after the
	// eviction. The value can be an absolute number or a percentage. Only one of
	// MinAvailable or Max MaxUnavailable can be set.
	MinAvailable *intstr.IntOrString `json:"minAvailable,omitempty"`

	// Number of policy server replicas that can be unavailable after the
	// eviction. The value can be an absolute number or a percentage. Only one of
	// MinAvailable or Max MaxUnavailable can be set.
	MaxUnavailable *intstr.IntOrString `json:"maxUnavailable,omitempty"`

	// Annotations is an unstructured key value map stored with a resource that may be
	// set by external tools to store and retrieve arbitrary metadata. They are not
	// queryable and should be preserved when modifying objects.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels is a map of custom labels to be applied to the Deployment created by the
	// PolicyServer and to the Pods managed by that Deployment. System labels set by
	// the controller always take precedence over user-defined labels with the same key.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// List of environment variables to set in the container.
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// Name of the service account associated with the policy server.
	// Namespace service account will be used if not specified.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// Name of ImagePullSecret secret in the same namespace, used for pulling
	// policies from repositories.
	// +optional
	ImagePullSecret string `json:"imagePullSecret,omitempty"`

	// List of insecure URIs to policy repositories. The `insecureSources`
	// content format corresponds with the contents of the `insecure_sources`
	// key in `sources.yaml`. Reference for `sources.yaml` is found in the
	// Kubewarden documentation in the reference section.
	// +optional
	InsecureSources []string `json:"insecureSources,omitempty"`

	// Key value map of registry URIs endpoints to a list of their associated
	// PEM encoded certificate authorities that have to be used to verify the
	// certificate used by the endpoint. The `sourceAuthorities` content format
	// corresponds with the contents of the `source_authorities` key in
	// `sources.yaml`. Reference for `sources.yaml` is found in the Kubewarden
	// documentation in the reference section.
	// +optional
	SourceAuthorities map[string][]string `json:"sourceAuthorities,omitempty"`

	// Name of VerificationConfig configmap in the kubewarden namespace (same
	// namespace as the controller deployment), containing Sigstore verification
	// configuration. The configuration must be under a key named
	// verification-config in the ConfigMap.
	// +optional
	VerificationConfig string `json:"verificationConfig,omitempty"`

	// Name of SigstoreTrustConfig configmap in the kubewarden namespace (same
	// namespace as the controller deployment), containing Sigstore trust
	// configuration (ClientTrustConfig JSON). The configuration must be under a
	// key named sigstore-trust-config in the ConfigMap. This is used to configure
	// a custom Sigstore instance instead of the default public Sigstore infrastructure.
	// WARNING: This feature requires strict access control. Users with write access
	// to this ConfigMap can influence policy signature verification.
	// +optional
	SigstoreTrustConfig string `json:"sigstoreTrustConfig,omitempty"`

	// Security configuration to be used in the Policy Server workload.
	// The field allows different configurations for the pod and containers.
	// If set for the containers, this configuration will not be used in
	// containers added by other controllers (e.g. telemetry sidecars)
	// +optional
	SecurityContexts PolicyServerSecurity `json:"securityContexts,omitempty"`

	// Affinity rules for the associated Policy Server pods.
	// +optional
	Affinity corev1.Affinity `json:"affinity,omitempty"`

	// Limits describes the maximum amount of compute resources allowed.
	// +optional
	Limits corev1.ResourceList `json:"limits,omitempty"`

	// Requests describes the minimum amount of compute resources required.
	// If Request is omitted for, it defaults to Limits if that is explicitly specified,
	// otherwise to an implementation-defined value
	// +optional
	Requests corev1.ResourceList `json:"requests,omitempty"`

	// Tolerations describe the policy server pod's tolerations. It can be
	// used to ensure that the policy server pod is not scheduled onto a
	// node with a taint.
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// PriorityClassName is the name of the PriorityClass to be used for the
	// policy server pods. Useful to schedule policy server pods with higher
	// priority to ensure their availability over other cluster workload
	// resources.
	// Note: If the referenced PriorityClass is deleted, existing pods
	// remain unchanged, but new pods that reference it cannot be created.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// NamespacedPoliciesCapabilities lists host capability API calls allowed
	// for namespaced policies running on this PolicyServer. When not set,
	// all host capabilities are granted to namespaced policies.
	// Supported wildcard patterns:
	// - "*": allow all host capabilities
	// - "category/*": allow all capabilities in a category (e.g. "oci/*")
	// - "category/version/*": allow all capabilities of a specific version (e.g. "oci/v1/*")
	// - Specific capability paths (e.g. "oci/v1/verify", "net/v1/dns_lookup_host")
	// +optional
	NamespacedPoliciesCapabilities []string `json:"namespacedPoliciesCapabilities,omitempty"`

	// Port where the policy server listens for incoming webhook requests.
	// When unset, defaults to 8443. This is the port the Kubernetes API server
	// reaches when evaluating admission requests.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	WebhookPort *int32 `json:"webhookPort,omitempty"`

	// Port used by the policy server to expose the readiness probe endpoint.
	// When unset, defaults to 8081.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	ReadinessProbePort *int32 `json:"readinessProbePort,omitempty"`

	// Port exposed by the metrics Service for this policy server.
	// When unset, defaults to the controller-wide default
	// (KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT env var, or 8080).
	// Only relevant when metrics are enabled.
	//
	// Use this field to customize which port Prometheus scrapes for this
	// PolicyServer's metrics Service (e.g. to match naming conventions or
	// avoid Service-level port collisions).
	//
	// NOTE: this field controls only the Service Port (the externally visible
	// scrape port). The Service TargetPort — the port the pod actually listens
	// on — is always the controller-wide default and is not affected by this
	// field. This is intentional: when the OpenTelemetry sidecar mode is
	// enabled, each pod gets its own injected sidecar, but the pod-side
	// Prometheus listener port is determined by controller-wide/injection
	// configuration, not per PolicyServer. Therefore, changing this field does
	// not change the pod listener port and will not resolve pod-port conflicts
	// such as those caused by hostNetwork.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	MetricsPort *int32 `json:"metricsPort,omitempty"`
}

type ReconciliationTransitionReason string

const (
	// ReconciliationFailed represents a reconciliation failure.
	ReconciliationFailed ReconciliationTransitionReason = "ReconciliationFailed"
	// ReconciliationSucceeded represents a reconciliation success.
	ReconciliationSucceeded ReconciliationTransitionReason = "ReconciliationSucceeded"
)

type PolicyServerConditionType string

const (
	// PolicyServerCertSecretReconciled represents the condition of the
	// Policy Server Secret reconciliation.
	PolicyServerCertSecretReconciled PolicyServerConditionType = "CertSecretReconciled"
	// CARootSecretReconciled represents the condition of the
	// Policy Server CA Root Secret reconciliation.
	CARootSecretReconciled PolicyServerConditionType = "CARootSecretReconciled"
	// PolicyServerConfigMapReconciled represents the condition of the
	// Policy Server ConfigMap reconciliation.
	PolicyServerConfigMapReconciled PolicyServerConditionType = "ConfigMapReconciled"
	// PolicyServerDeploymentReconciled represents the condition of the
	// Policy Server Deployment reconciliation.
	PolicyServerDeploymentReconciled PolicyServerConditionType = "DeploymentReconciled"
	// PolicyServerServiceReconciled represents the condition of the
	// Policy Server Service reconciliation.
	PolicyServerServiceReconciled PolicyServerConditionType = "ServiceReconciled"
	// PolicyServerPodDisruptionBudgetReconciled represents the condition of the
	// Policy Server PodDisruptionBudget reconciliation.
	PolicyServerPodDisruptionBudgetReconciled PolicyServerConditionType = "PodDisruptionBudgetReconciled"
	// PolicyServerPolicyWebhooksCleanedUp represents the condition signalling
	// whether the webhook configurations of the policies bound to a
	// PolicyServer being deleted have been cleaned up. The PolicyServer's
	// finalizer is only removed once this condition becomes True.
	PolicyServerPolicyWebhooksCleanedUp PolicyServerConditionType = "PolicyWebhooksCleanedUp"
)

// PolicyServerStatus defines the observed state of PolicyServer.
type PolicyServerStatus struct {
	// Conditions represent the observed conditions of the
	// PolicyServer resource.  Known .status.conditions.types are:
	// "CertSecretReconciled", "CARootSecretReconciled",
	// "ConfigMapReconciled", "DeploymentReconciled",
	// "ServiceReconciled", "PodDisruptionBudgetReconciled" and
	// "PolicyWebhooksCleanedUp"
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster,shortName=ps
//+kubebuilder:printcolumn:name="Replicas",type=string,JSONPath=`.spec.replicas`,description="Policy Server replicas"
//+kubebuilder:printcolumn:name="Image",type=string,JSONPath=`.spec.image`,description="Policy Server image"
//+kubebuilder:storageversion
//+kubebuilder:metadata:annotations="helm.sh/resource-policy=keep"

// PolicyServer is the Schema for the policyservers API.
type PolicyServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyServerSpec   `json:"spec,omitempty"`
	Status PolicyServerStatus `json:"status,omitempty"`
}

func (ps *PolicyServer) NameWithPrefix() string {
	return "policy-server-" + ps.Name
}

func (ps *PolicyServer) AppLabel() string {
	return "kubewarden-" + ps.NameWithPrefix()
}

// EffectiveWebhookPort returns the port the policy server listens on for
// admission webhook requests, using the CRD field when set or the default constant.
func (ps *PolicyServer) EffectiveWebhookPort() int32 {
	if ps.Spec.WebhookPort != nil {
		return *ps.Spec.WebhookPort
	}
	return constants.PolicyServerListenPort
}

// EffectiveReadinessProbePort returns the port used for the readiness probe,
// using the CRD field when set or the default constant.
func (ps *PolicyServer) EffectiveReadinessProbePort() int32 {
	if ps.Spec.ReadinessProbePort != nil {
		return *ps.Spec.ReadinessProbePort
	}
	return constants.PolicyServerReadinessProbePort
}

// EffectiveMetricsPort returns the port used to expose the metrics endpoint.
// It returns the CRD-level override when set, otherwise it falls back to defaultPort
// (which is typically the controller-wide default configured via environment variable).
func (ps *PolicyServer) EffectiveMetricsPort(defaultPort int32) int32 {
	if ps.Spec.MetricsPort != nil {
		return *ps.Spec.MetricsPort
	}
	return defaultPort
}

// CommonLabels returns the common labels to be used with the resources
// associated to a Policy Server. The labels defined follow
// Kubernetes guidelines: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels
func (ps *PolicyServer) CommonLabels() map[string]string {
	return map[string]string{
		constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
		constants.InstanceLabelKey:  ps.NameWithPrefix(),
		constants.PartOfLabelKey:    constants.PartOfLabelValue,
		constants.ManagedByKey:      "kubewarden-controller",
	}
}

//+kubebuilder:object:root=true

// PolicyServerList contains a list of PolicyServer.
type PolicyServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyServer `json:"items"`
}
