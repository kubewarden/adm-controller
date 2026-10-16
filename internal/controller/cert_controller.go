package controller

import (
	"context"
	"fmt"
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

type CertReconciler struct {
	client.Client
	Log                              logr.Logger
	DeploymentsNamespace             string
	WebhookServiceName               string
	CARootSecretName                 string
	WebhookServerCertSecretName      string
	AuditScannerClientCertSecretName string
}

// Start begins the periodic reconciler.
// Implements the Runnable interface, see https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/manager#Runnable.
func (r *CertReconciler) Start(ctx context.Context) error {
	r.Log.Info("Starting CertController ticker")

	// The certificates can be expired when the controller starts, for example
	// after a long downtime. Then the webhooks with failurePolicy Fail block
	// admission until the certificates rotate. Do not wait for the first tick.
	// A failed pass at startup must not wait 12 hours for the next tick.
	// The writes of the secrets and of the webhook configurations already retry
	// on a conflict. This backoff covers the other failures: the API server is
	// not reachable, or a conflict lasts longer than the retry of one write.
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
	if err := r.reconcileServerCerts(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile server certs: %w", err)
	}
	if err := r.reconcileAuditScannerClientCert(ctx, caCertSecret); err != nil {
		return fmt.Errorf("failed to reconcile audit scanner client cert: %w", err)
	}

	return nil
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
// Also, it updates the webhook configurations by injecting a bundle containing the new and old CA root certificates.
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

		err = r.reconcileWebhookConfigurations(ctx, append(caCert, oldCACert...))
		if err != nil {
			return fmt.Errorf("failed to reconcile webhook configurations: %w", err)
		}

		r.Log.Info("CA root certificate rotated successfully")
	}

	return nil
}

// reconcileOldCARoot reconciles the old CA root certificate by removing it if it is no longer valid.
// It also updates the webhook configurations by removing the old CA root certificate from the CA bundle.
func (r *CertReconciler) reconcileOldCARoot(ctx context.Context, caRootSecret *corev1.Secret) error {
	oldCACert, ok := caRootSecret.Data[constants.OldCARootCert]
	if !ok {
		return nil
	}

	if err := certs.VerifyCA(oldCACert, nil, time.Now()); err != nil {
		r.Log.Info("Old CA root certificate is not valid anymore, removing the old CA root certificate", "verification error", err)

		var caCert []byte
		caCert, _, err = certs.ExtractCARootFromSecret(caRootSecret)
		if err != nil {
			return fmt.Errorf("failed to extract CA root from secret: %w", err)
		}

		err = r.updateSecretWithRetry(ctx, caRootSecret, func(secret *corev1.Secret) {
			delete(secret.Data, constants.OldCARootCert)
		})
		if err != nil {
			return fmt.Errorf("failed to update CA root secret: %w", err)
		}

		err = r.reconcileWebhookConfigurations(ctx, caCert)
		if err != nil {
			return fmt.Errorf("failed to reconcile webhook configurations: %w", err)
		}

		r.Log.Info("Old CA root certificate removed successfully")
	}

	return nil
}

// reconcileWebhookConfigurations injects the CA bundle into the webhook configurations.
// It uses RetryOnConflict because the policy reconcilers update the same webhook configurations.
func (r *CertReconciler) reconcileWebhookConfigurations(ctx context.Context, caBundle []byte) error {
	validatingWebhookConfigurationList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := r.List(ctx, validatingWebhookConfigurationList, client.MatchingLabels{
		constants.PartOfLabelKey: constants.PartOfLabelValue,
	}); err != nil {
		return fmt.Errorf("failed to list validating webhook configurations: %w", err)
	}

	for _, validatingWebhookConfiguration := range validatingWebhookConfigurationList.Items {
		original := validatingWebhookConfiguration.DeepCopy()
		for i := range validatingWebhookConfiguration.Webhooks {
			validatingWebhookConfiguration.Webhooks[i].ClientConfig.CABundle = caBundle
		}

		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			return r.Patch(ctx, &validatingWebhookConfiguration, client.MergeFrom(original))
		})
		if err != nil {
			return fmt.Errorf("failed to patch validating webhook configuration: %w", err)
		}
	}

	mutatingWebhookConfigurationList := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := r.List(ctx, mutatingWebhookConfigurationList, client.MatchingLabels{
		constants.PartOfLabelKey: constants.PartOfLabelValue,
	}); err != nil {
		return fmt.Errorf("failed to list mutating webhook configurations: %w", err)
	}

	for _, mutatingWebhookConfiguration := range mutatingWebhookConfigurationList.Items {
		original := mutatingWebhookConfiguration.DeepCopy()
		for i := range mutatingWebhookConfiguration.Webhooks {
			mutatingWebhookConfiguration.Webhooks[i].ClientConfig.CABundle = caBundle
		}

		err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			return r.Patch(ctx, &mutatingWebhookConfiguration, client.MergeFrom(original))
		})
		if err != nil {
			return fmt.Errorf("failed to patch mutating webhook configuration: %w", err)
		}
	}

	return nil
}

// reconcileServerCerts reconciles the webhook server and policy server certificates by rotating them if they are about to expire.
func (r *CertReconciler) reconcileServerCerts(ctx context.Context, caRootSecret *corev1.Secret) error {
	webhookServerCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.WebhookServerCertSecretName, Namespace: r.DeploymentsNamespace}, webhookServerCertSecret); err != nil {
		return fmt.Errorf("failed to get webhook server cert secret: %w", err)
	}
	dnsName := certs.DNSName(r.WebhookServiceName, r.DeploymentsNamespace)
	if err := r.reconcileServerCert(ctx, webhookServerCertSecret, caRootSecret, dnsName); err != nil {
		return fmt.Errorf("failed to rotate server cert: %w", err)
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
		return fmt.Errorf("failed to list policy server cert secrets: %w", err)
	}

	for _, serverCertSecret := range serverCertSecretList.Items {
		dnsName = certs.DNSName(serverCertSecret.GetName(), r.DeploymentsNamespace)
		if err = r.reconcileServerCert(ctx, &serverCertSecret, caRootSecret, dnsName); err != nil {
			return fmt.Errorf("failed to rotate server cert: %w", err)
		}
	}

	return nil
}

// reconcileServerCert reconciles the server certificate by rotating it if it is about to expire.
func (r *CertReconciler) reconcileServerCert(ctx context.Context, serverCertSecret *corev1.Secret, caRootSecret *corev1.Secret, dnsName string) error {
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
