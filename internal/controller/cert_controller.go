package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

const tickerDuration = 12 * time.Hour

const (
	startupReconcileFirstDelay = 5 * time.Second
	startupReconcileFactor     = 2
	startupReconcileJitter     = 0.1
	startupReconcileTries      = 8
	startupReconcileMaxDelay   = time.Minute
)

const (
	// caBundlePublicationTimeout is the time that one pass waits, in total, for the webhook configurations to trust
	// the CA root before it signs server certificates with it. The owners of the webhook configurations usually
	// write the CA bundle a few seconds after the CA root secret changes.
	caBundlePublicationTimeout      = 2 * time.Minute
	caBundlePublicationPollInterval = 2 * time.Second
)

// startupReconcileBackoff makes up to 8 tries in about 4 minutes: it waits 5s, 10s, 20s, 40s, then 1m between tries.
func startupReconcileBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: startupReconcileFirstDelay,
		Factor:   startupReconcileFactor,
		Jitter:   startupReconcileJitter,
		Steps:    startupReconcileTries,
		Cap:      startupReconcileMaxDelay,
	}
}

// CertReconciler owns the certificate Secrets of the stack, all in DeploymentsNamespace:
//   - the CA root secret CARootSecretName (ca.crt, ca.key, and old-ca.crt for 60 days after a rotation of the CA root)
//   - the secret WebhookServerCertSecretName of the webhook server of the controller (the one for Kubewarden CRDs),
//     for the DNS name of its service WebhookServiceName.
//   - the audit scanner client secret AuditScannerClientCertSecretName
//   - the secret of every policy server, found by the label app.kubernetes.io/component: policy-server. The webhook
//     configurations of the policies send the requests to the policy servers.
//
// It is a Runnable, not a controller: it watches nothing. It runs on the leader, at startup and every 12 hours. It
// replaces each certificate that expires within constants.CertLookahead or that the current CA root did not sign.
//
// Before it signs any certificate, it writes the CA bundle of the CA root secret into every webhook configuration with
// the label app.kubernetes.io/part-of: kubewarden: the webhook configurations of the controller, and those of the
// policies. Then the API server trusts a new CA root before any server presents a certificate from it.
//
// Other components also write caBundle:
//   - WebhookCABundleReconciler for the webhook configurations of the controller
//   - the policy reconcilers for the webhook configurations of the policies.
//
// All of them write certs.CABundleFromSecret, so they agree. Before it signs a server certificate, it waits until every
// webhook configuration that sends requests to that server trusts the CA root. If they do not trust it in time, it
// keeps the current certificate and tries again on the next pass.
type CertReconciler struct {
	client.Client
	Log                              logr.Logger
	DeploymentsNamespace             string
	WebhookServiceName               string
	CARootSecretName                 string
	WebhookServerCertSecretName      string
	AuditScannerClientCertSecretName string

	// caBundlePublicationTimeout overrides the default caBundlePublicationTimeout. The tests set it.
	caBundlePublicationTimeout time.Duration
}

// Start begins the periodic reconciler.
// Implements the Runnable interface, see https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/manager#Runnable.
func (r *CertReconciler) Start(ctx context.Context) error {
	r.Log.Info("Starting CertController ticker")

	// The certificates can be expired when the controller starts, for example
	// after a long downtime. Then the webhooks with failurePolicy Fail block
	// admission until the certificates rotate. Do not wait for the first tick.
	// A failed pass at startup must not wait 12 hours for the next tick.
	// The writes of the secrets already retry on a conflict. This backoff
	// covers the other failures: the API server is not reachable, or a
	// conflict lasts longer than the retry of one write.
	// Retry for a few minutes before the ticker takes over.
	if err := wait.ExponentialBackoffWithContext(ctx, startupReconcileBackoff(), func(ctx context.Context) (bool, error) {
		if err := r.reconcile(ctx); err != nil {
			r.Log.Error(err, "Failed to reconcile certificates at startup, retrying")
			return false, nil
		}
		return true, nil
	}); err != nil {
		r.Log.Error(err, "Failed to reconcile certificates at startup, waiting for the next tick", "tick", tickerDuration)
	}

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("Stopping CertController")
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				r.Log.Error(err, "Failed to reconcile certificates")
			}
		}
	}
}

// NeedLeaderElection returns true to ensure that only one instance of the controller is running at a time.
// Implements the LeaderElectionRunnable interface, see https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/manager#LeaderElectionRunnable.
func (r *CertReconciler) NeedLeaderElection() bool {
	return true
}

func (r *CertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	return nil
}

// reconcile reconciles the CA root and server certificates by rotating them if they are about to expire.
func (r *CertReconciler) reconcile(ctx context.Context) error {
	caCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.CARootSecretName, Namespace: r.DeploymentsNamespace}, caCertSecret); err != nil {
		return fmt.Errorf("failed to get CA cert secret: %w", err)
	}

	if err := r.reconcileCARoot(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile CA root: %w", err)
	}
	if err := r.reconcileOldCARoot(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile old CA root: %w", err)
	}
	// No certificate is signed before the API server trusts the CA root that signs it.
	if err := r.reconcileCABundles(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile the CA bundle of the webhook configurations: %w", err)
	}
	// A server certificate waits until the webhook configurations trust the CA root. That wait must not hold back
	// the client certificate of the audit scanner, which no webhook configuration verifies.
	var errs []error
	if err := r.reconcileServerCerts(ctx, caCertSecret); err != nil {
		errs = append(errs, fmt.Errorf("failed to reconcile server certs: %w", err))
	}
	if err := r.reconcileAuditScannerClientCert(ctx, caCertSecret); err != nil {
		errs = append(errs, fmt.Errorf("failed to reconcile audit scanner client cert: %w", err))
	}

	return errors.Join(errs...)
}

// updateSecretWithRetry updates a secret. If the API server reports a conflict, it tries again.
// On each try it reads the secret again and applies mutate to the fresh copy. As a result, the update
// uses the latest resourceVersion. The PolicyServer reconciler runs on the same leader and writes
// the same secrets when its informers sync, so a conflict is possible, in particular at startup.
// After a successful call, secret holds the state that the API server stored.
func (r *CertReconciler) updateSecretWithRetry(ctx context.Context, secret *corev1.Secret, mutate func(secret *corev1.Secret)) error {
	key := client.ObjectKeyFromObject(secret)

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		if err := r.Get(ctx, key, secret); err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		mutate(secret)

		return r.Update(ctx, secret)
	})
	if err != nil {
		return fmt.Errorf("failed to update secret %q: %w", key, err)
	}

	return nil
}

// reconcileCARoot reconciles the CA root certificate by rotating it if it is about to expire.
// It saves the old CA root certificate in the secret so that we can remove it after it is no longer valid.
func (r *CertReconciler) reconcileCARoot(ctx context.Context, caRootSecret *corev1.Secret) error {
	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA root from secret: %w", err)
	}

	if err = certs.VerifyCA(caCert, caPrivateKey, time.Now().Add(constants.CertLookahead)); err != nil {
		r.Log.Info("CA root certificate verification failed, rotating CA root the certificate", "verification error", err)

		oldCACert := caCert
		caCert, caPrivateKey, err = certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
		if err != nil {
			return fmt.Errorf("failed to generate CA cert: %w", err)
		}

		err = r.updateSecretWithRetry(ctx, caRootSecret, func(secret *corev1.Secret) {
			secret.Data[constants.CARootCert] = caCert
			secret.Data[constants.CARootPrivateKey] = caPrivateKey
			secret.Data[constants.OldCARootCert] = oldCACert
		})
		if err != nil {
			return fmt.Errorf("failed to update CA root secret: %w", err)
		}

		r.Log.Info("CA root certificate rotated successfully")
	}

	return nil
}

// reconcileOldCARoot reconciles the old CA root certificate by removing it if it is no longer valid.
func (r *CertReconciler) reconcileOldCARoot(ctx context.Context, caRootSecret *corev1.Secret) error {
	oldCACert, ok := caRootSecret.Data[constants.OldCARootCert]
	if !ok {
		return nil
	}

	if err := certs.VerifyCA(oldCACert, nil, time.Now()); err != nil {
		r.Log.Info("Old CA root certificate is not valid anymore, removing the old CA root certificate", "verification error", err)

		err = r.updateSecretWithRetry(ctx, caRootSecret, func(secret *corev1.Secret) {
			delete(secret.Data, constants.OldCARootCert)
		})
		if err != nil {
			return fmt.Errorf("failed to update CA root secret: %w", err)
		}

		r.Log.Info("Old CA root certificate removed successfully")
	}

	return nil
}

// reconcileCABundles writes the CA bundle of the CA root secret into every webhook configuration with the label
// app.kubernetes.io/part-of: kubewarden, if its caBundle differs. A webhook configuration that is deleted during the
// pass is skipped.
func (r *CertReconciler) reconcileCABundles(ctx context.Context, caRootSecret *corev1.Secret) error {
	caBundle := certs.CABundleFromSecret(caRootSecret)
	kubewardenLabels := client.MatchingLabels{constants.PartOfLabelKey: constants.PartOfLabelValue}

	validatingWebhookConfigurations := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, validatingWebhookConfigurations, kubewardenLabels); err != nil {
		return fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}
	mutatingWebhookConfigurations := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := r.List(ctx, mutatingWebhookConfigurations, kubewardenLabels); err != nil {
		return fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	webhookConfigurations := make([]client.Object, 0, len(validatingWebhookConfigurations.Items)+len(mutatingWebhookConfigurations.Items))
	for i := range validatingWebhookConfigurations.Items {
		webhookConfigurations = append(webhookConfigurations, &validatingWebhookConfigurations.Items[i])
	}
	for i := range mutatingWebhookConfigurations.Items {
		webhookConfigurations = append(webhookConfigurations, &mutatingWebhookConfigurations.Items[i])
	}

	for _, webhookConfiguration := range webhookConfigurations {
		if err := injectCABundle(ctx, r.Client, r.Log, webhookConfiguration, caBundle); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return err
		}
	}

	return nil
}

// reconcileServerCerts reconciles the webhook server and policy server certificates by rotating them if they are about to expire.
// A certificate that cannot rotate does not stop the rotation of the others.
func (r *CertReconciler) reconcileServerCerts(ctx context.Context, caRootSecret *corev1.Secret) error {
	publicationDeadline := time.Now().Add(r.publicationTimeout())
	var errs []error

	webhookServerCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.WebhookServerCertSecretName, Namespace: r.DeploymentsNamespace}, webhookServerCertSecret); err != nil {
		errs = append(errs, fmt.Errorf("failed to get webhook server cert secret: %w", err))
	} else if err = r.reconcileServerCert(ctx, webhookServerCertSecret, caRootSecret, r.WebhookServiceName, publicationDeadline); err != nil {
		errs = append(errs, fmt.Errorf("failed to rotate server cert: %w", err))
	}

	serverCertSecretList := &corev1.SecretList{}
	err := r.List(
		ctx,
		serverCertSecretList,
		client.InNamespace(r.DeploymentsNamespace),
		client.MatchingLabels{
			constants.PartOfLabelKey:    constants.PartOfLabelValue,
			constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
		},
	)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to list policy server cert secrets: %w", err))
		return errors.Join(errs...)
	}

	// The name of the secret of a policy server is the name of its service.
	for _, serverCertSecret := range serverCertSecretList.Items {
		if err = r.reconcileServerCert(ctx, &serverCertSecret, caRootSecret, serverCertSecret.GetName(), publicationDeadline); err != nil {
			errs = append(errs, fmt.Errorf("failed to rotate server cert: %w", err))
		}
	}

	return errors.Join(errs...)
}

// reconcileServerCert reconciles the certificate of the server behind the service serviceName by rotating it if it is
// about to expire. Before it signs a new certificate, it waits until publicationDeadline for the webhook
// configurations that send requests to the service to trust the CA root.
func (r *CertReconciler) reconcileServerCert(ctx context.Context, serverCertSecret *corev1.Secret, caRootSecret *corev1.Secret, serviceName string, publicationDeadline time.Time) error {
	dnsName := certs.DNSName(serviceName, r.DeploymentsNamespace)

	cert, privateKey, err := certs.ExtractServerCertFromSecret(serverCertSecret)
	if err != nil {
		return fmt.Errorf("failed to extract server cert from secret: %w", err)
	}

	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA root from secret: %w", err)
	}

	pool, err := certs.NewCertPool(caCert)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	if err = certs.VerifyCert(cert, privateKey, pool, dnsName, time.Now().Add(constants.CertLookahead)); err != nil {
		r.Log.Info("Certificate verification failed, rotating the certificate", "dnsName", dnsName, "verification error", err)

		if err = r.waitForCABundlePublication(ctx, serviceName, caCert, publicationDeadline); err != nil {
			return fmt.Errorf("failed to rotate the certificate for %s: %w", dnsName, err)
		}

		var newCert, newPrivateKey []byte
		newCert, newPrivateKey, err = certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), dnsName)
		if err != nil {
			return fmt.Errorf("failed to generate cert: %w", err)
		}

		err = r.updateSecretWithRetry(ctx, serverCertSecret, func(secret *corev1.Secret) {
			secret.Data[constants.ServerCert] = newCert
			secret.Data[constants.ServerPrivateKey] = newPrivateKey
		})
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		r.Log.Info("Certificate rotated successfully", "dnsName", dnsName)
	}

	return nil
}

// waitForCABundlePublication waits until every webhook configuration that sends requests to the service serviceName
// has caCert in each of its CA bundles, or until deadline. A server must not serve a certificate that the API server
// cannot verify with the CA bundle of its webhook configuration.
func (r *CertReconciler) waitForCABundlePublication(ctx context.Context, serviceName string, caCert []byte, deadline time.Time) error {
	untrusted, err := r.webhookConfigurationsWithoutCA(ctx, serviceName, caCert)
	if err != nil {
		return err
	}
	if len(untrusted) == 0 {
		return nil
	}
	r.Log.Info("Waiting for the webhook configurations to trust the CA root before rotating the certificate",
		"service", serviceName, "webhookConfigurations", untrusted)

	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	err = wait.PollUntilContextCancel(pollCtx, caBundlePublicationPollInterval, false, func(context.Context) (bool, error) {
		var listErr error
		untrusted, listErr = r.webhookConfigurationsWithoutCA(ctx, serviceName, caCert)
		if listErr != nil {
			return false, listErr
		}
		return len(untrusted) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("the webhook configurations %s do not trust the CA root yet, keeping the current certificate: %w",
			strings.Join(untrusted, ", "), err)
	}

	return nil
}

// webhookConfigurationsWithoutCA returns the webhook configurations that send requests to the service serviceName in
// DeploymentsNamespace from a webhook whose CA bundle does not contain caCert. Every writer of a CA bundle concatenates
// the PEM certificates, so the PEM bytes of caCert appear in a bundle that trusts it.
func (r *CertReconciler) webhookConfigurationsWithoutCA(ctx context.Context, serviceName string, caCert []byte) ([]string, error) {
	validatingWebhookConfigurations := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, validatingWebhookConfigurations); err != nil {
		return nil, fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}
	mutatingWebhookConfigurations := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := r.List(ctx, mutatingWebhookConfigurations); err != nil {
		return nil, fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	webhookConfigurations := make([]client.Object, 0, len(validatingWebhookConfigurations.Items)+len(mutatingWebhookConfigurations.Items))
	for i := range validatingWebhookConfigurations.Items {
		webhookConfigurations = append(webhookConfigurations, &validatingWebhookConfigurations.Items[i])
	}
	for i := range mutatingWebhookConfigurations.Items {
		webhookConfigurations = append(webhookConfigurations, &mutatingWebhookConfigurations.Items[i])
	}

	var untrusted []string
	for _, webhookConfiguration := range webhookConfigurations {
		kind, clientConfigs, err := webhookClientConfigs(webhookConfiguration)
		if err != nil {
			return nil, err
		}
		for _, clientConfig := range clientConfigs {
			service := clientConfig.Service
			if service != nil && service.Namespace == r.DeploymentsNamespace && service.Name == serviceName &&
				!bytes.Contains(clientConfig.CABundle, caCert) {
				untrusted = append(untrusted, kind+"/"+webhookConfiguration.GetName())
				break
			}
		}
	}

	return untrusted, nil
}

func (r *CertReconciler) publicationTimeout() time.Duration {
	if r.caBundlePublicationTimeout > 0 {
		return r.caBundlePublicationTimeout
	}
	return caBundlePublicationTimeout
}

// reconcileAuditScannerClientCert rotates the client certificate of the audit scanner if it is about to expire,
// or if it is not signed by the current CA root.
// The Helm chart creates the secret. If the secret does not exist, there is nothing to rotate.
func (r *CertReconciler) reconcileAuditScannerClientCert(ctx context.Context, caRootSecret *corev1.Secret) error {
	clientCertSecret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: r.AuditScannerClientCertSecretName, Namespace: r.DeploymentsNamespace}, clientCertSecret)
	if apierrors.IsNotFound(err) {
		r.Log.Info("Audit scanner client cert secret not found, skipping its rotation", "secret", r.AuditScannerClientCertSecretName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get audit scanner client cert secret: %w", err)
	}

	cert, privateKey, err := certs.ExtractServerCertFromSecret(clientCertSecret)
	if err != nil {
		return fmt.Errorf("failed to extract client cert from secret: %w", err)
	}

	caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
	if err != nil {
		return fmt.Errorf("failed to extract CA root from secret: %w", err)
	}

	pool, err := certs.NewCertPool(caCert)
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}

	// The audit scanner certificate is a client certificate. An empty DNS name skips the check of the name, because
	// a server does not match the name of a client. VerifyCert still requires the serverAuth usage. That is not a
	// problem: the Helm chart and GenerateCert both create the certificate with serverAuth and clientAuth.
	if err = certs.VerifyCert(cert, privateKey, pool, "", time.Now().Add(constants.CertLookahead)); err != nil {
		r.Log.Info("Audit scanner client certificate verification failed, rotating the certificate", "verification error", err)

		var newCert, newPrivateKey []byte
		newCert, newPrivateKey, err = certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
		if err != nil {
			return fmt.Errorf("failed to generate client cert: %w", err)
		}

		err = r.updateSecretWithRetry(ctx, clientCertSecret, func(secret *corev1.Secret) {
			secret.Data[constants.ServerCert] = newCert
			secret.Data[constants.ServerPrivateKey] = newPrivateKey
		})
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		r.Log.Info("Audit scanner client certificate rotated successfully")
	}

	return nil
}
