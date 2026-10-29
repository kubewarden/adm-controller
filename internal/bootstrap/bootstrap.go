// Package bootstrap prepares what the webhook server of the controller needs before it starts: the certificate
// Secrets, and the webhook configurations of the controller. The init mode of the controller binary runs it in the
// init container of every controller pod.
package bootstrap

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

const (
	// CertificateFilesTimeout is the time that the init container waits for the kubelet to copy the certificate of the
	// webhook server. The kubelet copies a Secret into the volume of a pod on its sync period, about one minute.
	CertificateFilesTimeout = 5 * time.Minute

	certificateFilesPollInterval = 2 * time.Second
)

// webhookManifests holds the webhook configurations that controller-gen generates from the +kubebuilder:webhook
// markers. Run make manifests to generate the file again.
//
//go:embed manifests.yaml
var webhookManifests []byte

// Options configures Run.
type Options struct {
	// DeploymentsNamespace is the namespace of the controller and of its certificate Secrets.
	DeploymentsNamespace string
	// WebhookServiceName is the name of the Service of the webhooks of the controller.
	WebhookServiceName string
	// CertificateDirectory is the directory where the kubelet copies the certificate of the webhook server.
	CertificateDirectory string
	// CertificateFilesTimeout is the time that Run waits for the certificate of the webhook server.
	CertificateFilesTimeout time.Duration
}

// Run prepares what the webhook server needs before the controller starts:
//  1. It creates the certificate Secrets that are missing.
//  2. It creates the webhook configurations of the controller, or updates them to this version. A new webhook trusts
//     the CA root Secret of step 1.
//  3. It waits until the kubelet copies the certificate of the webhook server into opts.CertificateDirectory.
//
// It stops at the first step that fails. Every replica runs it, and it is safe to run it many times.
func Run(ctx context.Context, c client.Client, log logr.Logger, opts Options) error {
	switch {
	case opts.DeploymentsNamespace == "":
		return errors.New("the deployments namespace must be provided")
	case opts.WebhookServiceName == "":
		return errors.New("the webhook service name must be provided")
	case opts.CertificateDirectory == "":
		return errors.New("the certificate directory must be provided")
	}

	caRootSecret, err := EnsureCertificateSecrets(ctx, c, log, opts.DeploymentsNamespace, opts.WebhookServiceName)
	if err != nil {
		return fmt.Errorf("failed to prepare the certificate secrets: %w", err)
	}
	if err = ensureControllerWebhookConfigurations(ctx, c, log, opts.DeploymentsNamespace, opts.WebhookServiceName, caRootSecret); err != nil {
		return fmt.Errorf("failed to prepare the webhook configurations of the controller: %w", err)
	}
	if err = waitForCertificateFiles(ctx, log, opts.CertificateDirectory, opts.CertificateFilesTimeout); err != nil {
		return fmt.Errorf("failed to wait for the certificate of the webhook server: %w", err)
	}

	log.Info("init completed")
	return nil
}

// EnsureCertificateSecrets makes sure that the certificate Secrets of the controller exist in namespace: the CA root,
// the certificate of the webhook server, and the client certificate of the audit scanner. It creates the ones that
// are missing, and returns the CA root Secret. It does not change a Secret that exists: the cert controller renews
// and rotates the certificates.
//
// Many replicas can run it at the same time. If another replica creates a Secret first, this one reads it.
func EnsureCertificateSecrets(ctx context.Context, c client.Client, log logr.Logger, namespace, webhookServiceName string) (*corev1.Secret, error) {
	caRootSecret, err := EnsureCARootSecret(ctx, c, log, namespace)
	if err != nil {
		return nil, err
	}
	if err = EnsureSignedCertificateSecrets(ctx, c, log, namespace, webhookServiceName, caRootSecret); err != nil {
		return nil, err
	}
	return caRootSecret, nil
}

// EnsureCARootSecret makes sure that the CA root Secret exists in namespace. If it is missing, it creates it with a
// new CA root. It returns the CA root Secret.
func EnsureCARootSecret(ctx context.Context, c client.Client, log logr.Logger, namespace string) (*corev1.Secret, error) {
	return ensureSecret(ctx, c, log, namespace, constants.CARootSecretName, func() (map[string][]byte, error) {
		caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
		if err != nil {
			return nil, fmt.Errorf("failed to generate the CA root: %w", err)
		}
		return map[string][]byte{
			constants.CARootCert:       caCert,
			constants.CARootPrivateKey: caPrivateKey,
		}, nil
	})
}

// EnsureSignedCertificateSecrets makes sure that the certificate Secret of the webhook server and the client
// certificate Secret of the audit scanner exist in namespace. It signs a missing certificate with the CA root of
// caRootSecret. The caller must make sure that the API server trusts that CA root before it calls this function.
func EnsureSignedCertificateSecrets(ctx context.Context, c client.Client, log logr.Logger, namespace, webhookServiceName string, caRootSecret *corev1.Secret) error {
	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	if err != nil {
		return fmt.Errorf("failed to extract the CA root from secret %q: %w", constants.CARootSecretName, err)
	}
	// The audit scanner certificate is a client certificate, so its name is not a DNS name. The cert controller signs
	// it again with the same name.
	newCertData := func(name string) func() (map[string][]byte, error) {
		return func() (map[string][]byte, error) {
			cert, privateKey, generateErr := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), name)
			if generateErr != nil {
				return nil, fmt.Errorf("failed to generate the certificate of %q: %w", name, generateErr)
			}
			return map[string][]byte{
				constants.ServerCert:       cert,
				constants.ServerPrivateKey: privateKey,
			}, nil
		}
	}

	if _, err = ensureSecret(ctx, c, log, namespace, constants.WebhookServerCertSecretName,
		newCertData(certs.DNSName(webhookServiceName, namespace))); err != nil {
		return err
	}
	if _, err = ensureSecret(ctx, c, log, namespace, constants.AuditScannerClientCertSecretName,
		newCertData(constants.AuditScannerClientCertCommonName)); err != nil {
		return err
	}

	return nil
}

// ensureSecret returns the Secret name in namespace. If it does not exist, it creates it with the data that newData
// returns.
func ensureSecret(ctx context.Context, c client.Client, log logr.Logger, namespace, name string, newData func() (map[string][]byte, error)) (*corev1.Secret, error) {
	key := types.NamespacedName{Namespace: namespace, Name: name}

	secret := &corev1.Secret{}
	err := c.Get(ctx, key, secret)
	if err == nil {
		return secret, nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get secret %q: %w", name, err)
	}

	data, err := newData()
	if err != nil {
		return nil, err
	}
	secret = &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    controllerLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
	err = c.Create(ctx, secret)
	if err == nil {
		log.Info("Created the secret", "name", name)
		return secret, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("failed to create secret %q: %w", name, err)
	}

	// Another replica created the Secret first.
	secret = &corev1.Secret{}
	if err = c.Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret %q: %w", name, err)
	}
	return secret, nil
}

// ensureControllerWebhookConfigurations creates the two webhook configurations of the controller, or updates the ones
// that exist to the webhooks of this version of the controller. The webhooks send the requests to the Service
// webhookServiceName in namespace.
//
// A webhook that exists keeps its caBundle, because the cert controller owns that field. A new webhook gets the CA
// bundle of caRootSecret, so that the API server trusts the webhook server from the first call. The labels and the
// annotations that other tools set stay.
func ensureControllerWebhookConfigurations(ctx context.Context, c client.Client, log logr.Logger, namespace, webhookServiceName string, caRootSecret *corev1.Secret) error {
	validatingTemplate, mutatingTemplate, err := controllerWebhookConfigurations()
	if err != nil {
		return err
	}
	caBundle := certs.CABundleFromSecret(caRootSecret)

	validating := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: constants.ControllerValidatingWebhookConfigurationName},
	}
	result, err := controllerutil.CreateOrUpdate(ctx, c, validating, func() error {
		liveCABundles := map[string][]byte{}
		for _, webhook := range validating.Webhooks {
			liveCABundles[webhook.Name] = webhook.ClientConfig.CABundle
		}
		validating.Labels = withControllerLabels(validating.Labels)
		validating.Webhooks = validatingTemplate.DeepCopy().Webhooks
		for i := range validating.Webhooks {
			setClientConfig(&validating.Webhooks[i].ClientConfig, namespace, webhookServiceName, liveCABundles[validating.Webhooks[i].Name], caBundle)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update the validating webhook configuration %q: %w", validating.Name, err)
	}
	log.Info("Reconciled the webhook configuration", "kind", "ValidatingWebhookConfiguration", "name", validating.Name, "result", result)

	mutating := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: constants.ControllerMutatingWebhookConfigurationName},
	}
	result, err = controllerutil.CreateOrUpdate(ctx, c, mutating, func() error {
		liveCABundles := map[string][]byte{}
		for _, webhook := range mutating.Webhooks {
			liveCABundles[webhook.Name] = webhook.ClientConfig.CABundle
		}
		mutating.Labels = withControllerLabels(mutating.Labels)
		mutating.Webhooks = mutatingTemplate.DeepCopy().Webhooks
		for i := range mutating.Webhooks {
			setClientConfig(&mutating.Webhooks[i].ClientConfig, namespace, webhookServiceName, liveCABundles[mutating.Webhooks[i].Name], caBundle)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create or update the mutating webhook configuration %q: %w", mutating.Name, err)
	}
	log.Info("Reconciled the webhook configuration", "kind", "MutatingWebhookConfiguration", "name", mutating.Name, "result", result)

	return nil
}

// setClientConfig points a webhook at the Service of the webhook server. It keeps liveCABundle if it is not empty,
// and writes caBundle otherwise.
func setClientConfig(clientConfig *admissionregistrationv1.WebhookClientConfig, namespace, webhookServiceName string, liveCABundle, caBundle []byte) {
	if clientConfig.Service == nil {
		clientConfig.Service = &admissionregistrationv1.ServiceReference{}
	}
	clientConfig.Service.Namespace = namespace
	clientConfig.Service.Name = webhookServiceName
	if len(liveCABundle) > 0 {
		clientConfig.CABundle = liveCABundle
	} else {
		clientConfig.CABundle = caBundle
	}
}

// controllerWebhookConfigurations returns the webhook configurations of the embedded manifest.
func controllerWebhookConfigurations() (*admissionregistrationv1.ValidatingWebhookConfiguration, *admissionregistrationv1.MutatingWebhookConfiguration, error) {
	var validating *admissionregistrationv1.ValidatingWebhookConfiguration
	var mutating *admissionregistrationv1.MutatingWebhookConfiguration

	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(webhookManifests)))
	decoder := scheme.Codecs.UniversalDeserializer()
	for {
		document, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read the webhook manifests: %w", err)
		}
		if len(bytes.TrimSpace(document)) == 0 {
			continue
		}

		object, _, err := decoder.Decode(document, nil, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode the webhook manifests: %w", err)
		}
		switch typed := object.(type) {
		case *admissionregistrationv1.ValidatingWebhookConfiguration:
			validating = typed
		case *admissionregistrationv1.MutatingWebhookConfiguration:
			mutating = typed
		default:
			return nil, nil, fmt.Errorf("unexpected object %T in the webhook manifests", object)
		}
	}

	if validating == nil || mutating == nil {
		return nil, nil, errors.New("the webhook manifests must hold a validating and a mutating webhook configuration")
	}
	return validating, mutating, nil
}

// waitForCertificateFiles waits until the certificate and the key of the webhook server are in directory, and form a
// valid key pair. The kubelet copies the Secret into the volume of the pod on its sync period. It returns an error
// after timeout.
func waitForCertificateFiles(ctx context.Context, log logr.Logger, directory string, timeout time.Duration) error {
	certFile := filepath.Join(directory, constants.ServerCert)
	keyFile := filepath.Join(directory, constants.ServerPrivateKey)

	logged := false
	err := wait.PollUntilContextTimeout(ctx, certificateFilesPollInterval, timeout, true, func(context.Context) (bool, error) {
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			if !logged {
				log.Info("Waiting for the kubelet to copy the certificate of the webhook server", "directory", directory)
				logged = true
			}
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("the certificate of the webhook server is not in %s after %s: %w", directory, timeout, err)
	}
	return nil
}

func controllerLabels() map[string]string {
	return map[string]string{
		constants.PartOfLabelKey:    constants.PartOfLabelValue,
		constants.ComponentLabelKey: constants.ComponentControllerLabelValue,
	}
}

// withControllerLabels returns labels with the labels of the controller added. It keeps the other labels.
func withControllerLabels(labels map[string]string) map[string]string {
	if labels == nil {
		labels = map[string]string{}
	}
	for key, value := range controllerLabels() {
		labels[key] = value
	}
	return labels
}
