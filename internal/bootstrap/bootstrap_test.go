package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

const (
	testNamespace          = "kubewarden"
	testWebhookServiceName = "kubewarden-controller-webhook-service"
)

func getSecret(t *testing.T, c client.Client, name string) *corev1.Secret {
	t.Helper()
	secret := &corev1.Secret{}
	require.NoError(t, c.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: name}, secret))
	return secret
}

func TestEnsureCertificateSecretsCreatesTheMissingSecrets(t *testing.T) {
	k8sClient := fake.NewClientBuilder().Build()

	caRootSecret, err := EnsureCertificateSecrets(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName)
	require.NoError(t, err)

	require.Equal(t, getSecret(t, k8sClient, constants.CARootSecretName).Data, caRootSecret.Data)
	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	require.NoError(t, err)
	require.NoError(t, certs.VerifyCA(caCert, caPrivateKey, time.Now().Add(constants.CertLookahead)))
	pool, err := certs.NewCertPool(caCert)
	require.NoError(t, err)

	webhookServerCertSecret := getSecret(t, k8sClient, constants.WebhookServerCertSecretName)
	require.NoError(t, certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey],
		pool, certs.DNSName(testWebhookServiceName, testNamespace), time.Now().Add(constants.CertLookahead)))

	auditScannerClientCertSecret := getSecret(t, k8sClient, constants.AuditScannerClientCertSecretName)
	require.NoError(t, certs.VerifyCert(auditScannerClientCertSecret.Data[constants.ServerCert], auditScannerClientCertSecret.Data[constants.ServerPrivateKey],
		pool, "", time.Now().Add(constants.CertLookahead)))

	for _, secret := range []*corev1.Secret{caRootSecret, webhookServerCertSecret, auditScannerClientCertSecret} {
		require.Equal(t, constants.PartOfLabelValue, secret.Labels[constants.PartOfLabelKey], "the cert controller selects the secrets by this label")
	}
}

func TestEnsureCertificateSecretsKeepsTheSecretsThatExist(t *testing.T) {
	existing := map[string]map[string][]byte{
		constants.CARootSecretName:                 {constants.CARootCert: []byte("ca"), constants.CARootPrivateKey: []byte("key")},
		constants.WebhookServerCertSecretName:      {constants.ServerCert: []byte("server"), constants.ServerPrivateKey: []byte("key")},
		constants.AuditScannerClientCertSecretName: {constants.ServerCert: []byte("client"), constants.ServerPrivateKey: []byte("key")},
	}
	builder := fake.NewClientBuilder()
	for name, data := range existing {
		builder = builder.WithObjects(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
			Data:       data,
		})
	}
	k8sClient := builder.Build()

	_, err := EnsureCertificateSecrets(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName)
	require.NoError(t, err)

	for name, data := range existing {
		require.Equal(t, data, getSecret(t, k8sClient, name).Data, "secret %q must not change", name)
	}
}

func TestEnsureCertificateSecretsReadsTheSecretOfAnotherReplica(t *testing.T) {
	winnerCACert, winnerCAPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	require.NoError(t, err)

	// Another replica creates the CA root Secret between the Get and the Create of this one.
	k8sClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetName() != constants.CARootSecretName {
				return c.Create(ctx, obj, opts...)
			}
			winner := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: constants.CARootSecretName},
				Data: map[string][]byte{
					constants.CARootCert:       winnerCACert,
					constants.CARootPrivateKey: winnerCAPrivateKey,
				},
			}
			if err := c.Create(ctx, winner); err != nil {
				return err
			}
			return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, constants.CARootSecretName)
		},
	}).Build()

	caRootSecret, err := EnsureCertificateSecrets(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName)
	require.NoError(t, err)

	require.Equal(t, winnerCACert, caRootSecret.Data[constants.CARootCert])
	pool, err := certs.NewCertPool(winnerCACert)
	require.NoError(t, err)
	webhookServerCertSecret := getSecret(t, k8sClient, constants.WebhookServerCertSecretName)
	require.NoError(t, certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey],
		pool, certs.DNSName(testWebhookServiceName, testNamespace), time.Now()), "the certificates are signed by the CA root of the other replica")
}

func TestControllerWebhookConfigurationsManifest(t *testing.T) {
	validating, mutating, err := controllerWebhookConfigurations()
	require.NoError(t, err)
	require.NotEmpty(t, validating.Webhooks)
	require.NotEmpty(t, mutating.Webhooks)
}

func TestEnsureControllerWebhookConfigurationsCreatesThem(t *testing.T) {
	k8sClient := fake.NewClientBuilder().Build()
	caRootSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCert: []byte("ca")}}

	require.NoError(t, ensureControllerWebhookConfigurations(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName, caRootSecret))

	validatingTemplate, mutatingTemplate, err := controllerWebhookConfigurations()
	require.NoError(t, err)

	validating := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerValidatingWebhookConfigurationName}, validating))
	require.Len(t, validating.Webhooks, len(validatingTemplate.Webhooks))
	mutating := &admissionregistrationv1.MutatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerMutatingWebhookConfigurationName}, mutating))
	require.Len(t, mutating.Webhooks, len(mutatingTemplate.Webhooks))

	clientConfigs := []admissionregistrationv1.WebhookClientConfig{}
	for _, webhook := range validating.Webhooks {
		clientConfigs = append(clientConfigs, webhook.ClientConfig)
	}
	for _, webhook := range mutating.Webhooks {
		clientConfigs = append(clientConfigs, webhook.ClientConfig)
	}
	for _, clientConfig := range clientConfigs {
		require.Equal(t, testNamespace, clientConfig.Service.Namespace)
		require.Equal(t, testWebhookServiceName, clientConfig.Service.Name)
		require.Equal(t, []byte("ca"), clientConfig.CABundle)
	}

	for _, labels := range []map[string]string{validating.Labels, mutating.Labels} {
		require.Equal(t, constants.PartOfLabelValue, labels[constants.PartOfLabelKey], "the cert controller selects the webhook configurations by this label")
	}
}

func TestEnsureControllerWebhookConfigurationsUpdatesThem(t *testing.T) {
	validatingTemplate, _, err := controllerWebhookConfigurations()
	require.NoError(t, err)
	keptWebhookName := validatingTemplate.Webhooks[0].Name
	newWebhookName := validatingTemplate.Webhooks[1].Name

	// The live object comes from an older version: it misses a webhook, it has a webhook that this version does not
	// have, and it points at another Service.
	live := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.ControllerValidatingWebhookConfigurationName,
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "Helm"},
			Annotations: map[string]string{"team": "platform"},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: keptWebhookName,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &admissionregistrationv1.ServiceReference{Namespace: "old", Name: "old"},
					CABundle: []byte("live"),
				},
			},
			{
				Name: "removed.kubewarden.test",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: []byte("live"),
				},
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithObjects(live).Build()
	caRootSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCert: []byte("ca")}}

	require.NoError(t, ensureControllerWebhookConfigurations(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName, caRootSecret))

	validating := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerValidatingWebhookConfigurationName}, validating))
	require.Len(t, validating.Webhooks, len(validatingTemplate.Webhooks), "the webhooks are the webhooks of this version")

	webhooks := map[string]admissionregistrationv1.ValidatingWebhook{}
	for _, webhook := range validating.Webhooks {
		webhooks[webhook.Name] = webhook
		require.Equal(t, testWebhookServiceName, webhook.ClientConfig.Service.Name)
	}
	require.NotContains(t, webhooks, "removed.kubewarden.test")
	require.Equal(t, []byte("live"), webhooks[keptWebhookName].ClientConfig.CABundle, "a webhook that exists keeps its CA bundle")
	require.Equal(t, []byte("ca"), webhooks[newWebhookName].ClientConfig.CABundle, "a new webhook gets the CA bundle of the CA root secret")

	require.Equal(t, "Helm", validating.Labels["app.kubernetes.io/managed-by"], "the labels of other tools stay")
	require.Equal(t, constants.PartOfLabelValue, validating.Labels[constants.PartOfLabelKey])
	require.Equal(t, "platform", validating.Annotations["team"], "the annotations of other tools stay")
}

// writeCertificateFiles writes a valid certificate and key of the webhook server into directory, as the kubelet does.
func writeCertificateFiles(directory string) error {
	caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	if err != nil {
		return err
	}
	cert, privateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), "webhook.kubewarden.svc")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(directory, constants.ServerCert), cert, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, constants.ServerPrivateKey), privateKey, 0o600)
}

func TestWaitForCertificateFiles(t *testing.T) {
	t.Run("the files are already there", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, writeCertificateFiles(directory))

		require.NoError(t, waitForCertificateFiles(t.Context(), logr.Discard(), directory, time.Second))
	})

	t.Run("the files appear during the wait", func(t *testing.T) {
		directory := t.TempDir()
		go func() {
			time.Sleep(500 * time.Millisecond)
			assert.NoError(t, writeCertificateFiles(directory))
		}()

		require.NoError(t, waitForCertificateFiles(t.Context(), logr.Discard(), directory, time.Minute))
	})

	t.Run("the files do not appear", func(t *testing.T) {
		require.Error(t, waitForCertificateFiles(t.Context(), logr.Discard(), t.TempDir(), time.Second))
	})
}

// TestEnsureControllerWebhookConfigurationsAgainstTheAPIServer shows that the API server accepts the webhook
// configurations of the embedded manifest, and that a second run changes nothing.
func TestEnsureControllerWebhookConfigurationsAgainstTheAPIServer(t *testing.T) {
	testEnv := &envtest.Environment{}
	restConfig, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, testEnv.Stop())
	})
	k8sClient, err := client.New(restConfig, client.Options{})
	require.NoError(t, err)

	caCert, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	require.NoError(t, err)
	caRootSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCert: caCert}}

	require.NoError(t, ensureControllerWebhookConfigurations(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName, caRootSecret))
	validating := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerValidatingWebhookConfigurationName}, validating))
	mutating := &admissionregistrationv1.MutatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerMutatingWebhookConfigurationName}, mutating))

	require.NoError(t, ensureControllerWebhookConfigurations(t.Context(), k8sClient, logr.Discard(), testNamespace, testWebhookServiceName, caRootSecret))
	validatingAfter := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerValidatingWebhookConfigurationName}, validatingAfter))
	mutatingAfter := &admissionregistrationv1.MutatingWebhookConfiguration{}
	require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: constants.ControllerMutatingWebhookConfigurationName}, mutatingAfter))
	require.Equal(t, validating.ResourceVersion, validatingAfter.ResourceVersion, "a second run must not write")
	require.Equal(t, mutating.ResourceVersion, mutatingAfter.ResourceVersion, "a second run must not write")
}

func runOptions(certificateDirectory string, certificateFilesTimeout time.Duration) Options {
	return Options{
		DeploymentsNamespace:    testNamespace,
		WebhookServiceName:      testWebhookServiceName,
		CertificateDirectory:    certificateDirectory,
		CertificateFilesTimeout: certificateFilesTimeout,
	}
}

func getControllerWebhookConfigurations(t *testing.T, c client.Client) (*admissionregistrationv1.ValidatingWebhookConfiguration, *admissionregistrationv1.MutatingWebhookConfiguration) {
	t.Helper()
	validating := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: constants.ControllerValidatingWebhookConfigurationName}, validating))
	mutating := &admissionregistrationv1.MutatingWebhookConfiguration{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: constants.ControllerMutatingWebhookConfigurationName}, mutating))
	return validating, mutating
}

func TestRunPreparesAnEmptyCluster(t *testing.T) {
	k8sClient := fake.NewClientBuilder().Build()
	directory := t.TempDir()
	require.NoError(t, writeCertificateFiles(directory))

	require.NoError(t, Run(t.Context(), k8sClient, logr.Discard(), runOptions(directory, time.Second)))

	getSecret(t, k8sClient, constants.WebhookServerCertSecretName)
	getSecret(t, k8sClient, constants.AuditScannerClientCertSecretName)
	caBundle := certs.CABundleFromSecret(getSecret(t, k8sClient, constants.CARootSecretName))
	validating, mutating := getControllerWebhookConfigurations(t, k8sClient)
	require.NotEmpty(t, validating.Webhooks)
	require.NotEmpty(t, mutating.Webhooks)
	for _, webhook := range validating.Webhooks {
		require.Equal(t, caBundle, webhook.ClientConfig.CABundle, "webhook %q must trust the CA that Run created", webhook.Name)
	}
	for _, webhook := range mutating.Webhooks {
		require.Equal(t, caBundle, webhook.ClientConfig.CABundle, "webhook %q must trust the CA that Run created", webhook.Name)
	}
}

func TestRunKeepsWhatExists(t *testing.T) {
	k8sClient := fake.NewClientBuilder().Build()
	directory := t.TempDir()
	require.NoError(t, writeCertificateFiles(directory))
	require.NoError(t, Run(t.Context(), k8sClient, logr.Discard(), runOptions(directory, time.Second)))
	caRootSecret := getSecret(t, k8sClient, constants.CARootSecretName)
	validating, mutating := getControllerWebhookConfigurations(t, k8sClient)

	require.NoError(t, Run(t.Context(), k8sClient, logr.Discard(), runOptions(directory, time.Second)))

	caRootSecretAfter := getSecret(t, k8sClient, constants.CARootSecretName)
	require.Equal(t, caRootSecret.ResourceVersion, caRootSecretAfter.ResourceVersion, "a second run must keep the CA root secret")
	validatingAfter, mutatingAfter := getControllerWebhookConfigurations(t, k8sClient)
	require.Equal(t, validating.ResourceVersion, validatingAfter.ResourceVersion, "a second run must not write")
	require.Equal(t, mutating.ResourceVersion, mutatingAfter.ResourceVersion, "a second run must not write")
}

func TestRunStopsAtTheFirstFailure(t *testing.T) {
	t.Run("the certificate secrets cannot be created", func(t *testing.T) {
		k8sClient := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), nil)
				}
				return c.Create(ctx, obj, opts...)
			},
		}).Build()

		err := Run(t.Context(), k8sClient, logr.Discard(), runOptions(t.TempDir(), time.Minute))

		require.ErrorContains(t, err, "failed to prepare the certificate secrets")
		validatingList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
		require.NoError(t, k8sClient.List(t.Context(), validatingList))
		require.Empty(t, validatingList.Items, "no webhook configuration without the certificate secrets")
	})

	t.Run("the certificate files do not appear", func(t *testing.T) {
		k8sClient := fake.NewClientBuilder().Build()

		err := Run(t.Context(), k8sClient, logr.Discard(), runOptions(t.TempDir(), time.Second))

		require.ErrorContains(t, err, "failed to wait for the certificate of the webhook server")
	})
}

func TestRunRequiresItsOptions(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Options)
	}{
		{name: "no deployments namespace", modify: func(o *Options) { o.DeploymentsNamespace = "" }},
		{name: "no webhook service name", modify: func(o *Options) { o.WebhookServiceName = "" }},
		{name: "no certificate directory", modify: func(o *Options) { o.CertificateDirectory = "" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().Build()
			opts := runOptions(t.TempDir(), time.Second)
			tc.modify(&opts)

			require.Error(t, Run(t.Context(), k8sClient, logr.Discard(), opts))

			secrets := &corev1.SecretList{}
			require.NoError(t, k8sClient.List(t.Context(), secrets))
			require.Empty(t, secrets.Items, "nothing is created with invalid options")
		})
	}
}
