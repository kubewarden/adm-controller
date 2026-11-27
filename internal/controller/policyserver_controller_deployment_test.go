package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// TestGetPolicyServerContainerEnvOrdering verifies the env var precedence
// contract for the policy-server container: user-provided vars (Spec.Env) come
// first, and controller-managed vars are appended last so that, under
// kubelet's "last wins" semantics for duplicate names, the controller's values
// always take precedence.
func TestGetPolicyServerContainerEnvOrdering(t *testing.T) {
	const kubewardenPortEnv = "KUBEWARDEN_PORT"
	const userOverrideValue = "9999"

	ps := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: policiesv1.PolicyServerSpec{
			Image: "ghcr.io/kubewarden/policy-server:latest",
			Env: []corev1.EnvVar{
				{Name: "USER_VAR", Value: "user-val"},
				// Deliberately collides with a controller-managed var.
				{Name: kubewardenPortEnv, Value: userOverrideValue},
			},
		},
	}

	container := getPolicyServerContainer(ps)

	// User vars come first.
	if len(container.Env) == 0 || container.Env[0].Name != "USER_VAR" {
		t.Fatalf("expected first env var to be the user-provided USER_VAR, got %+v", container.Env)
	}

	// Controller-managed vars win: the LAST occurrence of KUBEWARDEN_PORT
	// must be the controller's value, not the user's override.
	var lastPort string
	for _, e := range container.Env {
		if e.Name == kubewardenPortEnv {
			lastPort = e.Value
		}
	}
	if lastPort == userOverrideValue {
		t.Fatalf("expected controller-managed %s to override user value %q, but user value won", kubewardenPortEnv, userOverrideValue)
	}
}

// TestUpdatePolicyServerDeploymentRemoteOtelCollector verifies that,
// when metrics and tracing are enabled without the OpenTelemetry sidecar,
// the policy server Deployment gets the same OpenTelemetry settings as the controller:
// the controller's OTEL_EXPORTER_OTLP_* env vars,
// and the CA and client certificate Secrets mounted in the directories of the certificate paths.
// This is the configuration that the Helm chart sets for the controller.
func TestUpdatePolicyServerDeploymentRemoteOtelCollector(t *testing.T) {
	const (
		otelEndpoint          = "https://otel-collector:4317"
		otelCertificate       = "/otel/tls/ca/ca.crt"
		otelClientCertificate = "/otel/tls/client/tls.crt"
		otelClientKey         = "/otel/tls/client/tls.key"
		otelCASecret          = "otel-ca"
		otelClientSecret      = "otel-client"
	)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", otelEndpoint)
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", otelCertificate)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", otelClientCertificate)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", otelClientKey)

	scheme := newTestScheme()
	reconciler := &PolicyServerReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		TelemetryConfiguration: TelemetryConfiguration{
			MetricsEnabled:              true,
			TracingEnabled:              true,
			OtelSidecarEnabled:          false,
			OtelCertificateSecret:       otelCASecret,
			OtelClientCertificateSecret: otelClientSecret,
		},
		DeploymentsNamespace: "kubewarden",
		Scheme:               scheme,
	}

	ps := newPolicyServer("test-ps", nil)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ps.NameWithPrefix(),
			Namespace: "kubewarden",
		},
	}

	err := reconciler.updatePolicyServerDeployment(t.Context(), ps, deployment, "1")
	require.NoError(t, err)

	podSpec := deployment.Spec.Template.Spec
	require.Len(t, podSpec.Containers, 1)
	container := podSpec.Containers[0]

	// The Secrets are mounted in the directories of the certificate paths,
	// so the replicated env vars point to files that exist in the policy server.
	secretVolumes := map[string]string{}
	for _, volume := range podSpec.Volumes {
		if volume.Secret != nil {
			secretVolumes[volume.Name] = volume.Secret.SecretName
		}
	}
	mountPaths := map[string]string{}
	for _, mount := range container.VolumeMounts {
		mountPaths[mount.Name] = mount.MountPath
	}
	assert.Equal(t, otelCASecret, secretVolumes[otelCertificateVolumeName])
	assert.Equal(t, "/otel/tls/ca", mountPaths[otelCertificateVolumeName])
	assert.Equal(t, otelClientSecret, secretVolumes[otelClientCertificateVolumeName])
	assert.Equal(t, "/otel/tls/client", mountPaths[otelClientCertificateVolumeName])

	// The controller's OTEL_EXPORTER_OTLP_* settings are copied,
	// and metrics and tracing are enabled in the policy server.
	env := map[string]string{}
	for _, envVar := range container.Env {
		env[envVar.Name] = envVar.Value
	}
	assert.Equal(t, otelEndpoint, env["OTEL_EXPORTER_OTLP_ENDPOINT"])
	assert.Equal(t, otelCertificate, env["OTEL_EXPORTER_OTLP_CERTIFICATE"])
	assert.Equal(t, otelClientCertificate, env["OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"])
	assert.Equal(t, otelClientKey, env["OTEL_EXPORTER_OTLP_CLIENT_KEY"])
	assert.Equal(t, "true", env[constants.PolicyServerEnableMetricsEnvVar])
	assert.Equal(t, "otlp", env[constants.PolicyServerLogFmtEnvVar])

	// Without the sidecar, the OpenTelemetry Operator must not inject one.
	assert.NotContains(t, deployment.Spec.Template.Annotations, constants.OptelInjectAnnotation)
}
