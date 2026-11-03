package upgrade

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

func TestKeepControllerObjectsStopsAtAFailure(t *testing.T) {
	forbidden := func(obj client.Object) error {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), nil)
	}

	tests := []struct {
		name          string
		funcs         interceptor.Funcs
		expectedError string
	}{
		{
			name: "the read of an object fails",
			funcs: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if key.Name == constants.CARootSecretName {
						return forbidden(obj)
					}
					return c.Get(ctx, key, obj, opts...)
				},
			},
			expectedError: "failed to get",
		},
		{
			name: "the patch of an object fails",
			funcs: interceptor.Funcs{
				Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
					if obj.GetName() == constants.CARootSecretName {
						return forbidden(obj)
					}
					return c.Patch(ctx, obj, patch, opts...)
				},
			},
			expectedError: "failed to add the keep annotations",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.CARootSecretName}}
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: constants.ControllerValidatingWebhookConfigurationName},
			}
			scheme := runtime.NewScheme()
			require.NoError(t, clientgoscheme.AddToScheme(scheme))
			k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret, webhookConfiguration).WithInterceptorFuncs(tc.funcs).Build()

			err := KeepControllerObjects(t.Context(), k8sClient, logr.Discard(), namespace)

			require.ErrorContains(t, err, tc.expectedError)
			require.ErrorContains(t, err, constants.CARootSecretName)
			// The hook fails, and Helm stops the upgrade before it deletes anything. The objects after the failure
			// keep their state.
			after := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(webhookConfiguration), after))
			require.NotContains(t, after.GetAnnotations(), constants.HelmResourcePolicy)
		})
	}
}
