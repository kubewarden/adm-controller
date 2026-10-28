package constants

import "time"

const (
	// DefaultPolicyServer is the default policy server name to be used when
	// policies does not have a policy server name defined.
	DefaultPolicyServer = "default"

	PolicyServerEnableMetricsEnvVar                 = "KUBEWARDEN_ENABLE_METRICS"
	PolicyServerDeploymentConfigVersionAnnotation   = "kubewarden/config-version"
	PolicyServerDeploymentPodSpecConfigVersionLabel = "kubewarden/config-version"
	PolicyServerListenPort                          = 8443
	PolicyServerServicePort                         = 443
	PolicyServerMetricsPortEnvVar                   = "KUBEWARDEN_POLICY_SERVER_SERVICES_METRICS_PORT"
	PolicyServerMetricsPort                         = 8080
	PolicyServerReadinessProbePort                  = 8081
	PolicyServerReadinessProbe                      = "/readiness"
	PolicyServerLogFmtEnvVar                        = "KUBEWARDEN_LOG_FMT"

	PolicyServerConfigPoliciesEntry         = "policies.yml"
	PolicyServerDeploymentRestartAnnotation = "kubectl.kubernetes.io/restartedAt"
	PolicyServerConfigSourcesEntry          = "sources.yml"
	PolicyServerSourcesConfigContainerPath  = "/sources"

	PolicyServerVerificationConfigEntry         = "verification-config"
	PolicyServerVerificationConfigContainerPath = "/verification"

	PolicyServerSigstoreTrustConfigEntry         = "sigstore-trust-config"
	PolicyServerSigstoreTrustConfigContainerPath = "/sigstore-trust"
	PolicyServerSigstoreTrustConfigVolumeName    = "sigstore-trust-config"
	PolicyServerSigstoreTrustConfigFilename      = "sigstore-trust-config.json"
	PolicyServerSigstoreTrustConfigEnvVar        = "KUBEWARDEN_SIGSTORE_TRUST_CONFIG_PATH"

	// Policy Server Labels.

	// AppLabelKey is the label used to identify the pod template in the deployment
	//
	// Deprecated: use the other standard labels.
	AppLabelKey                     = "app"
	PolicyServerLabelKey            = "kubewarden/policy-server"
	ComponentPolicyServerLabelValue = "policy-server"
	InstanceLabelKey                = "app.kubernetes.io/instance"
	ComponentLabelKey               = "app.kubernetes.io/component"
	PartOfLabelKey                  = "app.kubernetes.io/part-of"
	PartOfLabelValue                = "kubewarden"

	// ComponentControllerLabelValue is set via Helm chart templates.
	ComponentControllerLabelValue = "controller"

	ManagedByKey = "app.kubernetes.io/managed-by"
	// ManagedByKeyLabelValue is set via Helm chart templates.
	ManagedByKeyLabelValue = "kubewarden-controller"

	// HelmResourcePolicy and others re Helm annotations.
	HelmResourcePolicy       = "helm.sh/resource-policy"
	HelmMetaReleaseName      = "meta.helm.sh/release-name"
	HelmMetaReleaseNamespace = "meta.helm.sh/release-namespace"

	// DefaultsManagedByLabelKey is the label key for resources managed by DefaultsApplier.
	DefaultsManagedByLabelKey = "kubewarden.io/managed-by"
	// DefaultsManagedByLabelValue is the label value for resources managed by DefaultsApplier.
	DefaultsManagedByLabelValue = "kubewarden-controller-defaults"

	// DefaultDefaultsConfigMapName is the default name of the ConfigMap containing default resources.
	DefaultDefaultsConfigMapName = "kubewarden-defaults"

	// DefaultControllerConfigMapName is the default name of the ConfigMap
	// that holds the controller configuration.
	DefaultControllerConfigMapName = "kubewarden-controller-config"
	// ControllerConfigKey is the key of the controller configuration
	// ConfigMap that holds the configuration file. The file is a YAML
	// object. For example, the key namespacedPoliciesAllowedResources of
	// this object holds the list of resources that namespaced policies can
	// target.
	ControllerConfigKey = "config.yaml"
	// ControllerConfigNamespacedPoliciesAllowedResourcesKey is the key of
	// the controller configuration file that holds the list of resources
	// that namespaced policies can target.
	ControllerConfigNamespacedPoliciesAllowedResourcesKey = "namespacedPoliciesAllowedResources"

	PolicyServerIndexKey = ".spec.policyServer"

	KubewardenPoliciesGroup = "policies.kubewarden.io"

	KubewardenFinalizerPre114 = "kubewarden"
	KubewardenFinalizer       = "kubewarden.io/finalizer"

	KubernetesRevisionAnnotation = "deployment.kubernetes.io/revision"

	OptelInjectAnnotation = "sidecar.opentelemetry.io/inject"

	// ManagedAnnotationKeysAnnotation is the annotation used to track which annotation keys on
	// an object are managed by the controller. On each reconcile the controller removes keys
	// that were previously managed but are no longer desired, without touching annotations set
	// by Kubernetes itself or other tooling.
	ManagedAnnotationKeysAnnotation = "kubewarden.io/managed-annotation-keys"

	// ManagedLabelKeysAnnotation is the annotation used to track which label keys on an object
	// are managed by the controller. On each reconcile the controller removes keys that were
	// previously managed but are no longer desired, without touching labels set by Kubernetes
	// itself or other tooling.
	ManagedLabelKeysAnnotation = "kubewarden.io/managed-label-keys"

	WebhookConfigurationPolicyNameAnnotationKey      = "kubewardenPolicyName"
	WebhookConfigurationPolicyNamespaceAnnotationKey = "kubewardenPolicyNamespace"

	// WebhookNameSuffix is appended to a policy's unique name to build the
	// name of the individual webhook entry inside a Mutating/Validating
	// WebhookConfiguration. The resulting string cannot exceed the
	// DNS1123Subdomain length limit, which bounds how long a policy's
	// unique name is allowed to be.
	WebhookNameSuffix = ".kubewarden.admission"

	NamespacePolicyScope = "namespace"
	ClusterPolicyScope   = "cluster"

	// TimeToRequeuePolicyReconciliation is the Duration to be used when a policy should be reconciliation should be requeued.
	TimeToRequeuePolicyReconciliation = 2 * time.Second
	MetricsShutdownTimeout            = 5 * time.Second

	WebhookServerCertSecretName      = "kubewarden-webhook-server-cert" //nolint:gosec // This is not a credential
	ServerCert                       = "tls.crt"
	ServerPrivateKey                 = "tls.key"
	ServerCertSecretFormatVersion    = "1"
	ServerCertSecretFormatAnnotation = "kubewarden.io/cert-format-version" //nolint:gosec // This is not a credential

	AuditScannerClientCertSecretName = "kubewarden-audit-scanner-client-cert"
	// AuditScannerClientCertCommonName is the same as the cert CN that the Helm chart sets, so that a rotated
	// certificate has the same subject as the first one. No component reads the CN.
	AuditScannerClientCertCommonName = "audit-scanner-client"

	CARootSecretName = "kubewarden-ca"
	CARootCert       = "ca.crt"
	CARootPrivateKey = "ca.key"
	OldCARootCert    = "old-ca.crt"

	ClientCACert = "client-ca.crt"

	// WebhookServerCertDir is the directory where the webhook server of the controller reads its certificate. The
	// Helm chart mounts the Secret WebhookServerCertSecretName there, in the init container and in the controller
	// container.
	WebhookServerCertDir = "/tmp/k8s-webhook-server/serving-certs"

	// ControllerValidatingWebhookConfigurationName is the name of the validating webhook configuration of the
	// controller. The controller creates it at startup.
	ControllerValidatingWebhookConfigurationName = "kubewarden-controller-validating-webhook-configuration"
	// ControllerMutatingWebhookConfigurationName is the name of the mutating webhook configuration of the controller.
	// The controller creates it at startup.
	ControllerMutatingWebhookConfigurationName = "kubewarden-controller-mutating-webhook-configuration"

	CertExpirationYears  = 10
	CACertExpiration     = 10 * 365 * 24 * time.Hour
	ServerCertExpiration = 1 * 365 * 24 * time.Hour
	CertLookahead        = 60 * 24 * time.Hour
)
