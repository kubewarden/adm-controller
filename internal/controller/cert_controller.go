package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// reconcileInterval is the time between two passes when nothing changes. A pass renews a certificate 60 days before
// its end, so a pass every 12 hours is enough.
const reconcileInterval = 12 * time.Hour

// CertReconciler owns the certificate Secrets of the stack, all in DeploymentsNamespace:
//   - the CA root secret CARootSecretName (ca.crt, ca.key, and old-ca.crt for 60 days after a rotation of the CA root)
//   - the secret WebhookServerCertSecretName of the webhook server of the controller (the one for Kubewarden CRDs),
//     for the DNS name of its service WebhookServiceName.
//   - the audit scanner client secret AuditScannerClientCertSecretName
//   - the secret of every policy server, found by the label app.kubernetes.io/component: policy-server. The webhook
//     configurations of the policies send the requests to the policy servers.
//
// It is a controller that runs on the leader. One pass rotates the CA root and replaces each certificate that expires
// within constants.CertLookahead or that the current CA root did not sign. A pass runs:
//   - at startup
//   - every reconcileInterval
//   - when a Secret with the label app.kubernetes.io/part-of: kubewarden in DeploymentsNamespace changes
//   - when a webhook configuration with that label is created, or its caBundle changes
//   - again, with the backoff of the work queue, after a failed pass.
//
// Before it signs any certificate, it writes the CA bundle of the CA root secret into every webhook configuration with
// the label app.kubernetes.io/part-of: kubewarden: the webhook configurations of the controller, and those of the
// policies. Then the API server trusts a new CA root before any server presents a certificate from it.
//
// Other components also write caBundle:
//   - WebhookCABundleReconciler for the webhook configurations of the controller
//   - the policy reconcilers for the webhook configurations of the policies.
//
// All of them write certs.CABundleFromSecret, so they agree.
type CertReconciler struct {
	client.Client
	Log                              logr.Logger
	DeploymentsNamespace             string
	WebhookServiceName               string
	CARootSecretName                 string
	WebhookServerCertSecretName      string
	AuditScannerClientCertSecretName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Every event maps to the same request, because every pass handles every certificate and every webhook
	// configuration. The work queue merges the duplicate requests, so at most one pass waits in the queue.
	enqueuePass := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: r.DeploymentsNamespace, Name: r.CARootSecretName}}}
	})

	err := ctrl.NewControllerManagedBy(mgr).
		Named("cert").
		Watches(
			&corev1.Secret{},
			enqueuePass,
			builder.WithPredicates(kubewardenObjectPredicate(r.DeploymentsNamespace, secretDataChanged)),
		).
		Watches(
			&admissionregistrationv1.ValidatingWebhookConfiguration{},
			enqueuePass,
			builder.WithPredicates(kubewardenObjectPredicate("", caBundleChanged)),
		).
		Watches(
			&admissionregistrationv1.MutatingWebhookConfiguration{},
			enqueuePass,
			builder.WithPredicates(kubewardenObjectPredicate("", caBundleChanged)),
		).
		Complete(r)
	if err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	return nil
}

// Reconcile runs one pass. After a successful pass, it runs the next one after reconcileInterval. After a failed pass,
// the work queue runs it again with a backoff.
func (r *CertReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	if err := r.reconcile(ctx); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: reconcileInterval}, nil
}

// kubewardenObjectPredicate passes the events of an object with the label app.kubernetes.io/part-of: kubewarden that
// can need a pass: a creation, an update that adds the label, and an update where changed returns true. If namespace
// is not empty, it passes only the objects in that namespace. A deletion does not pass: there is nothing to write into
// an object that is gone.
func kubewardenObjectPredicate(namespace string, changed func(oldObject, newObject client.Object) bool) predicate.Funcs {
	isKubewardenObject := func(object client.Object) bool {
		if namespace != "" && object.GetNamespace() != namespace {
			return false
		}
		return object.GetLabels()[constants.PartOfLabelKey] == constants.PartOfLabelValue
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isKubewardenObject(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if !isKubewardenObject(e.ObjectNew) {
				return false
			}
			return !isKubewardenObject(e.ObjectOld) || changed(e.ObjectOld, e.ObjectNew)
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(event.GenericEvent) bool {
			return false
		},
	}
}

// secretDataChanged returns true if the data of two versions of a Secret differ.
func secretDataChanged(oldObject, newObject client.Object) bool {
	oldSecret, ok := oldObject.(*corev1.Secret)
	if !ok {
		return false
	}
	newSecret, ok := newObject.(*corev1.Secret)
	if !ok {
		return false
	}
	return !maps.EqualFunc(oldSecret.Data, newSecret.Data, bytes.Equal)
}

// caBundleChanged returns true if a caBundle differs between two versions of a webhook configuration.
func caBundleChanged(oldObject, newObject client.Object) bool {
	_, oldClientConfigs, err := webhookClientConfigs(oldObject)
	if err != nil {
		return false
	}
	_, newClientConfigs, err := webhookClientConfigs(newObject)
	if err != nil {
		return false
	}
	if len(oldClientConfigs) != len(newClientConfigs) {
		return true
	}
	for i := range newClientConfigs {
		if !bytes.Equal(oldClientConfigs[i].CABundle, newClientConfigs[i].CABundle) {
			return true
		}
	}
	return false
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
	// A server certificate that cannot rotate must not hold back the others.
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
	var errs []error

	webhookServerCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: r.WebhookServerCertSecretName, Namespace: r.DeploymentsNamespace}, webhookServerCertSecret); err != nil {
		errs = append(errs, fmt.Errorf("failed to get webhook server cert secret: %w", err))
	} else if err = r.reconcileServerCert(ctx, webhookServerCertSecret, caRootSecret, r.WebhookServiceName); err != nil {
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
		if err = r.reconcileServerCert(ctx, &serverCertSecret, caRootSecret, serverCertSecret.GetName()); err != nil {
			errs = append(errs, fmt.Errorf("failed to rotate server cert: %w", err))
		}
	}

	return errors.Join(errs...)
}

// reconcileServerCert reconciles the certificate of the server behind the service serviceName by rotating it if it is
// about to expire, or if the current CA root did not sign it.
func (r *CertReconciler) reconcileServerCert(ctx context.Context, serverCertSecret *corev1.Secret, caRootSecret *corev1.Secret, serviceName string) error {
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
