package upgrade

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kubewarden/adm-controller/internal/constants"
)

const namespace = "kubewarden"

func newClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestKeepControllerObjectsAddsTheAnnotations(t *testing.T) {
	otherAnnotations := map[string]string{"meta.helm.sh/release-name": "kubewarden"}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        constants.CARootSecretName,
			Annotations: otherAnnotations,
		},
		Data: map[string][]byte{constants.CARootCert: []byte("ca")},
	}
	webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.ControllerValidatingWebhookConfigurationName,
			Annotations: otherAnnotations,
		},
	}
	k8sClient := newClient(t, secret, webhookConfiguration)

	require.NoError(t, KeepControllerObjects(t.Context(), k8sClient, logr.Discard(), namespace))

	wantAnnotations := map[string]string{
		"meta.helm.sh/release-name":  "kubewarden",
		constants.HelmResourcePolicy: constants.HelmResourcePolicyKeep,
		constants.ArgoCDSyncOptions:  constants.ArgoCDSyncOptionNoPrune,
	}
	gotSecret := &corev1.Secret{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(secret), gotSecret))
	require.Equal(t, wantAnnotations, gotSecret.GetAnnotations())
	require.Equal(t, secret.Data, gotSecret.Data, "the data of the secret does not change")

	gotWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(webhookConfiguration), gotWebhookConfiguration))
	require.Equal(t, wantAnnotations, gotWebhookConfiguration.GetAnnotations())
}

func TestKeepControllerObjectsSkipsMissingObjects(t *testing.T) {
	k8sClient := newClient(t)

	require.NoError(t, KeepControllerObjects(t.Context(), k8sClient, logr.Discard(), namespace))

	secrets := &corev1.SecretList{}
	require.NoError(t, k8sClient.List(t.Context(), secrets))
	require.Empty(t, secrets.Items, "nothing is created")
	webhookConfigurations := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	require.NoError(t, k8sClient.List(t.Context(), webhookConfigurations))
	require.Empty(t, webhookConfigurations.Items, "nothing is created")
}

func TestKeepControllerObjectsDoesNotChangeKeptObjects(t *testing.T) {
	webhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: constants.ControllerMutatingWebhookConfigurationName,
			Annotations: map[string]string{
				constants.HelmResourcePolicy: constants.HelmResourcePolicyKeep,
				constants.ArgoCDSyncOptions:  "ServerSideApply=true," + constants.ArgoCDSyncOptionNoPrune,
			},
		},
	}
	k8sClient := newClient(t, webhookConfiguration)
	before := &admissionregistrationv1.MutatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(webhookConfiguration), before))

	require.NoError(t, KeepControllerObjects(t.Context(), k8sClient, logr.Discard(), namespace))

	after := &admissionregistrationv1.MutatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(webhookConfiguration), after))
	require.Equal(t, before.ResourceVersion, after.ResourceVersion, "a kept object is not written")
}

func TestWithNoPrune(t *testing.T) {
	tests := []struct {
		name        string
		syncOptions string
		expected    string
	}{
		{
			name:        "no sync options",
			syncOptions: "",
			expected:    "Prune=false",
		},
		{
			name:        "other sync options",
			syncOptions: "ServerSideApply=true,Replace=true",
			expected:    "ServerSideApply=true,Replace=true,Prune=false",
		},
		{
			name:        "another prune option",
			syncOptions: "Prune=confirm, ServerSideApply=true",
			expected:    "ServerSideApply=true,Prune=false",
		},
		{
			name:        "the prune option already",
			syncOptions: "Prune=false",
			expected:    "Prune=false",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, withNoPrune(tc.syncOptions))
		})
	}
}
