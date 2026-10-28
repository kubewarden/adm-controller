package controller

import (
	"context"
	"time"

	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Cert controller", func() {
	ctx := context.Background()

	Context("Server certificates rotation", Ordered, func() {
		const (
			webhookServerServiceName    = "server-cert-rotation-test-webhook-service"
			caRootSecretName            = "server-cert-rotation-test-ca-root"
			webhookServerCertSecretName = "server-cert-rotation-test-webhook-server-cert"
			policyServerName            = "server-cert-rotation-test-policy-server"
		)

		BeforeAll(func() {
			certController := CertReconciler{
				Client:                           k8sClient,
				DeploymentsNamespace:             deploymentsNamespace,
				WebhookServiceName:               webhookServerServiceName,
				CARootSecretName:                 caRootSecretName,
				WebhookServerCertSecretName:      webhookServerCertSecretName,
				AuditScannerClientCertSecretName: "server-cert-rotation-test-audit-scanner-client-cert",
			}

			By("generating the CA cert")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			Expect(err).ToNot(HaveOccurred())
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      caRootSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating webhook server cert that is about to expire")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("generating a policy server cert that is about to expire")
			policyServerDNSName := certs.DNSName(policyServerName, deploymentsNamespace)
			policyServerCert, policyServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), policyServerDNSName)
			Expect(err).ToNot(HaveOccurred())
			policyServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      policyServerName,
					Labels: map[string]string{
						constants.PartOfLabelKey:    constants.PartOfLabelValue,
						constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       policyServerCert,
					constants.ServerPrivateKey: policyServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, policyServerCertSecret)).To(Succeed())

			By("reconciling")
			Expect(certController.reconcile(ctx)).To(Succeed())
		})

		It("should rotate the webhook server certificate", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			By("fetching the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: webhookServerCertSecretName, Namespace: deploymentsNamespace}, webhookServerCertSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the webhook server cert secret has been rotated")
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			err = certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("should rotate the policy server certificates", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			By("fetching the policy server cert secrets")
			policyServerSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: "server-cert-rotation-test-policy-server", Namespace: deploymentsNamespace}, policyServerSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the policy server cert secret has been rotated")
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(policyServerSecret.GetName(), deploymentsNamespace)
			err = certs.VerifyCert(policyServerSecret.Data[constants.ServerCert], policyServerSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("CA root rotation", Ordered, func() {
		const (
			webhookServerServiceName    = "ca-root-rotation-test-webhook-service"
			caRootSecretName            = "ca-root-rotation-test-ca-root"
			webhookServerCertSecretName = "ca-root-rotation-test-webhook-server-cert"
			policyServerName            = "ca-root-rotation-test-policy-server"
		)

		var webhookServerCert, webhookServerPrivateKey, oldCACert []byte
		var kubewardenWebhookConfigurationKey, otherWebhookConfigurationKey client.ObjectKey

		BeforeAll(func() {
			certController := CertReconciler{
				Client:                           k8sClient,
				DeploymentsNamespace:             deploymentsNamespace,
				WebhookServiceName:               webhookServerServiceName,
				CARootSecretName:                 caRootSecretName,
				WebhookServerCertSecretName:      webhookServerCertSecretName,
				AuditScannerClientCertSecretName: "ca-root-rotation-test-audit-scanner-client-cert",
			}

			By("generating a CA cert that is about to expire")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
			Expect(err).ToNot(HaveOccurred())
			oldCACert = caCert
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      caRootSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating a webhook server cert")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err = certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("creating a policy server cert secret")
			policyServerDNSName := certs.DNSName(policyServerName, deploymentsNamespace)
			policyServerCert, policyServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), policyServerDNSName)
			Expect(err).ToNot(HaveOccurred())
			policyServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      policyServerName,
					Labels: map[string]string{
						constants.PartOfLabelKey:    constants.PartOfLabelValue,
						constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       policyServerCert,
					constants.ServerPrivateKey: policyServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, policyServerCertSecret)).To(Succeed())

			// The webhook configurations have no rules, so they intercept no request of the other specs.
			By("creating a webhook configuration with the Kubewarden label that trusts only the old CA root")
			kubewardenWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "ca-root-rotation-test-kubewarden-webhook-configuration",
					Labels: map[string]string{constants.PartOfLabelKey: constants.PartOfLabelValue},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "kubewarden.ca-root-rotation.kubewarden.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: webhookServerServiceName},
							CABundle: caCert,
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, kubewardenWebhookConfiguration)).To(Succeed())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, kubewardenWebhookConfiguration))).To(Succeed())
			})
			kubewardenWebhookConfigurationKey = client.ObjectKeyFromObject(kubewardenWebhookConfiguration)

			By("creating a webhook configuration without the Kubewarden label")
			otherWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "ca-root-rotation-test-other-webhook-configuration"},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "other.ca-root-rotation.kubewarden.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: "ca-root-rotation-test-other-service"},
							CABundle: caCert,
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, otherWebhookConfiguration)).To(Succeed())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, otherWebhookConfiguration))).To(Succeed())
			})
			otherWebhookConfigurationKey = client.ObjectKeyFromObject(otherWebhookConfiguration)

			By("reconciling")
			Expect(certController.reconcile(ctx)).To(Succeed())
		})

		It("should write the CA bundle into the webhook configurations with the Kubewarden label in the same pass", func() {
			caRootSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)).To(Succeed())

			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			Expect(k8sClient.Get(ctx, kubewardenWebhookConfigurationKey, webhookConfiguration)).To(Succeed())
			Expect(webhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(certs.CABundleFromSecret(caRootSecret)))
		})

		It("should not touch a webhook configuration without the Kubewarden label", func() {
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			Expect(k8sClient.Get(ctx, otherWebhookConfigurationKey, webhookConfiguration)).To(Succeed())
			Expect(webhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(oldCACert))
		})

		It("should rotate the CA cert", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the CA cert has been rotated")
			caCert, caPrivateKey, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			err = certs.VerifyCA(caCert, caPrivateKey, time.Now())
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the old CA cert has been added to the secret")
			_, found := caRootSecret.Data[constants.OldCARootCert]
			Expect(found).To(BeTrue())
		})

		It("should keep the old CA in the CA bundle of the secret and rotate the webhook server cert", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			caBundle := certs.CABundleFromSecret(caRootSecret)

			By("checking whether the old webhook server cert is still valid against the combined CA bundle")
			pool, err := certs.NewCertPool(caBundle)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			err = certs.VerifyCert(webhookServerCert, webhookServerPrivateKey, pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())

			By("fetching the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: webhookServerCertSecretName, Namespace: deploymentsNamespace}, webhookServerCertSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether the webhook server cert secret has been rotated")
			err = certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})

		It("should rotate the policy server certificates", func() {
			By("fetching the CA cert secret")
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			By("fetching the policy server cert secrets")
			policyServerSecret := &corev1.Secret{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName, Namespace: deploymentsNamespace}, policyServerSecret)
			Expect(err).ToNot(HaveOccurred())

			By("checking whether policy server cert secret has been rotated")
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(policyServerSecret.GetName(), deploymentsNamespace)
			err = certs.VerifyCert(policyServerSecret.Data[constants.ServerCert], policyServerSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("Certificate already expired when the controller starts", Ordered, func() {
		const (
			webhookServerServiceName    = "startup-test-webhook-service"
			caRootSecretName            = "startup-test-ca-root"
			webhookServerCertSecretName = "startup-test-webhook-server-cert"
		)

		BeforeAll(func() {
			By("generating the CA cert")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			Expect(err).ToNot(HaveOccurred())
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      caRootSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating an expired webhook server cert")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(-24*time.Hour), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("starting the cert controller")
			certController := CertReconciler{
				Client:                           k8sClient,
				DeploymentsNamespace:             deploymentsNamespace,
				WebhookServiceName:               webhookServerServiceName,
				CARootSecretName:                 caRootSecretName,
				WebhookServerCertSecretName:      webhookServerCertSecretName,
				AuditScannerClientCertSecretName: "startup-test-audit-scanner-client-cert",
			}
			startCtx, cancel := context.WithCancel(ctx)
			done := make(chan error)
			go func() {
				done <- certController.Start(startCtx)
			}()
			DeferCleanup(func() {
				cancel()
				Eventually(done).WithTimeout(timeout).WithPolling(pollInterval).Should(Receive(Succeed()))
			})
		})

		It("should rotate the webhook server certificate without waiting for the ticker", func() {
			Expect(tickerDuration).To(BeNumerically(">", timeout),
				"the ticker must not fire during the test, or the test cannot show the reconcile at startup")

			caRootSecret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)).To(Succeed())
			caCert, _, err := certs.ExtractCARootFromSecret(caRootSecret)
			Expect(err).ToNot(HaveOccurred())
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			dnsName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)

			Eventually(func() error {
				webhookServerCertSecret := &corev1.Secret{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: webhookServerCertSecretName, Namespace: deploymentsNamespace}, webhookServerCertSecret); err != nil {
					return err
				}
				return certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())
			}).WithTimeout(timeout).WithPolling(pollInterval).Should(Succeed())
		})
	})

	Context("Server certificate rotation waits until the webhook configurations trust the CA root", func() {
		type rotationFixture struct {
			certController          CertReconciler
			oldCACert               []byte
			webhookServerCert       []byte
			auditScannerClientCert  []byte
			webhookConfigurationKey client.ObjectKey
		}

		// newRotationFixture creates a CA root that is about to expire, a valid webhook server certificate and audit
		// scanner client certificate from it, and a webhook configuration that sends requests to the webhook service
		// and trusts only that CA root. The webhook configuration has no owner in the test, so the test publishes the
		// CA bundle. It has no rules, so it intercepts no request of the other specs.
		newRotationFixture := func(prefix string) rotationFixture {
			webhookServerServiceName := prefix + "-webhook-service"
			caRootSecretName := prefix + "-ca-root"
			webhookServerCertSecretName := prefix + "-webhook-server-cert"
			auditScannerClientCertSecretName := prefix + "-audit-scanner-client-cert"

			oldCACert, oldCAPrivateKey, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: deploymentsNamespace, Name: caRootSecretName},
				Type:       corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       oldCACert,
					constants.CARootPrivateKey: oldCAPrivateKey,
				},
			})).To(Succeed())

			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(oldCACert, oldCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), certs.DNSName(webhookServerServiceName, deploymentsNamespace))
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: deploymentsNamespace, Name: webhookServerCertSecretName},
				Type:       corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			})).To(Succeed())

			auditScannerClientCert, auditScannerClientPrivateKey, err := certs.GenerateCert(oldCACert, oldCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
			Expect(err).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: deploymentsNamespace, Name: auditScannerClientCertSecretName},
				Type:       corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       auditScannerClientCert,
					constants.ServerPrivateKey: auditScannerClientPrivateKey,
				},
			})).To(Succeed())

			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: prefix + "-validating-webhook-configuration"},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "trust.cert-controller.kubewarden.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: webhookServerServiceName},
							CABundle: oldCACert,
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, webhookConfiguration)).To(Succeed())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, webhookConfiguration))).To(Succeed())
			})

			return rotationFixture{
				certController: CertReconciler{
					Client:                           k8sClient,
					DeploymentsNamespace:             deploymentsNamespace,
					WebhookServiceName:               webhookServerServiceName,
					CARootSecretName:                 caRootSecretName,
					WebhookServerCertSecretName:      webhookServerCertSecretName,
					AuditScannerClientCertSecretName: auditScannerClientCertSecretName,
				},
				oldCACert:               oldCACert,
				webhookServerCert:       webhookServerCert,
				auditScannerClientCert:  auditScannerClientCert,
				webhookConfigurationKey: client.ObjectKeyFromObject(webhookConfiguration),
			}
		}

		getSecret := func(name string) *corev1.Secret {
			secret := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: name}, secret)).To(Succeed())
			return secret
		}

		// publishCABundle does what an owner of the webhook configuration does after a change of the CA root secret.
		publishCABundle := func(f rotationFixture) {
			caBundle := certs.CABundleFromSecret(getSecret(f.certController.CARootSecretName))
			Eventually(func() error {
				webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
				if err := k8sClient.Get(ctx, f.webhookConfigurationKey, webhookConfiguration); err != nil {
					return err
				}
				webhookConfiguration.Webhooks[0].ClientConfig.CABundle = caBundle
				return k8sClient.Update(ctx, webhookConfiguration)
			}, timeout, pollInterval).Should(Succeed())
		}

		expectSignedByCurrentCARoot := func(f rotationFixture, secretName, dnsName string) {
			caCert, _, err := certs.ExtractCARootFromSecret(getSecret(f.certController.CARootSecretName))
			Expect(err).ToNot(HaveOccurred())
			pool, err := certs.NewCertPool(caCert)
			Expect(err).ToNot(HaveOccurred())
			secret := getSecret(secretName)
			Expect(certs.VerifyCert(secret.Data[constants.ServerCert], secret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now())).To(Succeed())
		}

		It("should keep the server certificate until the webhook configurations trust the rotated CA root", func() {
			f := newRotationFixture("trust-gate")
			f.certController.caBundlePublicationTimeout = 3 * time.Second
			webhookServerDNSName := certs.DNSName(f.certController.WebhookServiceName, deploymentsNamespace)

			By("creating a webhook configuration of another service that does not trust the CA root")
			otherWebhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "trust-gate-other-service-mutating-webhook-configuration"},
				Webhooks: []admissionregistrationv1.MutatingWebhook{
					{
						Name: "other.cert-controller.kubewarden.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: "trust-gate-other-service"},
							CABundle: f.oldCACert,
						},
						AdmissionReviewVersions: []string{"v1"},
						SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
					},
				},
			}
			Expect(k8sClient.Create(ctx, otherWebhookConfiguration)).To(Succeed())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, otherWebhookConfiguration))).To(Succeed())
			})

			By("reconciling while the webhook configuration trusts only the old CA root")
			err := f.certController.reconcile(ctx)
			Expect(err).To(MatchError(ContainSubstring("ValidatingWebhookConfiguration/" + f.webhookConfigurationKey.Name)))
			Expect(err).ToNot(MatchError(ContainSubstring(otherWebhookConfiguration.Name)))

			caRootSecret := getSecret(f.certController.CARootSecretName)
			Expect(caRootSecret.Data[constants.CARootCert]).ToNot(Equal(f.oldCACert), "the CA root rotates")
			Expect(caRootSecret.Data[constants.OldCARootCert]).To(Equal(f.oldCACert))
			Expect(getSecret(f.certController.WebhookServerCertSecretName).Data[constants.ServerCert]).To(Equal(f.webhookServerCert),
				"the server certificate must not change while its webhook configuration does not trust the new CA root")
			Expect(getSecret(f.certController.AuditScannerClientCertSecretName).Data[constants.ServerCert]).ToNot(Equal(f.auditScannerClientCert),
				"the audit scanner client certificate does not wait for the webhook configurations")

			By("publishing the CA bundle, then reconciling again")
			publishCABundle(f)
			Expect(f.certController.reconcile(ctx)).To(Succeed())
			expectSignedByCurrentCARoot(f, f.certController.WebhookServerCertSecretName, webhookServerDNSName)
		})

		It("should rotate the server certificate in the same pass when the CA bundle is published during the wait", func() {
			f := newRotationFixture("trust-wait")
			f.certController.caBundlePublicationTimeout = timeout
			webhookServerDNSName := certs.DNSName(f.certController.WebhookServiceName, deploymentsNamespace)

			done := make(chan error)
			go func() {
				done <- f.certController.reconcile(ctx)
			}()

			By("publishing the CA bundle after the CA root rotates")
			Eventually(func() []byte {
				return getSecret(f.certController.CARootSecretName).Data[constants.CARootCert]
			}, timeout, pollInterval).ShouldNot(Equal(f.oldCACert))
			Consistently(done, caBundlePublicationPollInterval, pollInterval).ShouldNot(Receive(), "the pass waits for the CA bundle")
			publishCABundle(f)

			Eventually(done, timeout, pollInterval).Should(Receive(Succeed()))
			expectSignedByCurrentCARoot(f, f.certController.WebhookServerCertSecretName, webhookServerDNSName)
		})
	})

	Context("Audit scanner client certificate rotation", func() {
		type clientCertFactory func(caCert, caPrivateKey []byte) ([]byte, []byte)

		DescribeTable("rotating the audit scanner client certificate",
			func(prefix string, generateClientCert clientCertFactory, expectRotated bool) {
				webhookServerServiceName := prefix + "-webhook-service"
				caRootSecretName := prefix + "-ca-root"
				webhookServerCertSecretName := prefix + "-webhook-server-cert"
				clientCertSecretName := prefix + "-audit-scanner-client-cert"

				By("creating the CA cert secret")
				caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
				Expect(err).ToNot(HaveOccurred())
				Expect(k8sClient.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: deploymentsNamespace, Name: caRootSecretName},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						constants.CARootCert:       caCert,
						constants.CARootPrivateKey: caPrivateKey,
					},
				})).To(Succeed())

				By("creating a valid webhook server cert secret")
				webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), certs.DNSName(webhookServerServiceName, deploymentsNamespace))
				Expect(err).ToNot(HaveOccurred())
				Expect(k8sClient.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: deploymentsNamespace, Name: webhookServerCertSecretName},
					Type:       corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						constants.ServerCert:       webhookServerCert,
						constants.ServerPrivateKey: webhookServerPrivateKey,
					},
				})).To(Succeed())

				By("creating the audit scanner client cert secret with the labels of the Helm chart")
				clientCert, clientPrivateKey := generateClientCert(caCert, caPrivateKey)
				Expect(k8sClient.Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: deploymentsNamespace,
						Name:      clientCertSecretName,
						Labels: map[string]string{
							constants.PartOfLabelKey:    constants.PartOfLabelValue,
							constants.ComponentLabelKey: "controller",
						},
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						constants.ServerCert:       clientCert,
						constants.ServerPrivateKey: clientPrivateKey,
					},
				})).To(Succeed())

				By("reconciling")
				certController := CertReconciler{
					Client:                           k8sClient,
					DeploymentsNamespace:             deploymentsNamespace,
					WebhookServiceName:               webhookServerServiceName,
					CARootSecretName:                 caRootSecretName,
					WebhookServerCertSecretName:      webhookServerCertSecretName,
					AuditScannerClientCertSecretName: clientCertSecretName,
				}
				Expect(certController.reconcile(ctx)).To(Succeed())

				By("checking the audit scanner client cert secret")
				clientCertSecret := &corev1.Secret{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Name: clientCertSecretName, Namespace: deploymentsNamespace}, clientCertSecret)).To(Succeed())
				pool, err := certs.NewCertPool(caCert)
				Expect(err).ToNot(HaveOccurred())
				Expect(certs.VerifyCert(clientCertSecret.Data[constants.ServerCert], clientCertSecret.Data[constants.ServerPrivateKey], pool, "", time.Now().Add(constants.CertLookahead))).To(Succeed())
				if expectRotated {
					Expect(clientCertSecret.Data[constants.ServerCert]).ToNot(Equal(clientCert))
				} else {
					Expect(clientCertSecret.Data[constants.ServerCert]).To(Equal(clientCert))
				}
			},
			Entry("a certificate that is about to expire is rotated", "audit-scanner-about-to-expire",
				clientCertFactory(func(caCert, caPrivateKey []byte) ([]byte, []byte) {
					cert, key, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), constants.AuditScannerClientCertCommonName)
					Expect(err).ToNot(HaveOccurred())
					return cert, key
				}), true),
			Entry("an expired certificate is rotated", "audit-scanner-expired",
				clientCertFactory(func(caCert, caPrivateKey []byte) ([]byte, []byte) {
					cert, key, err := certs.GenerateCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(-24*time.Hour), constants.AuditScannerClientCertCommonName)
					Expect(err).ToNot(HaveOccurred())
					return cert, key
				}), true),
			Entry("a certificate signed by another CA is rotated", "audit-scanner-other-ca",
				clientCertFactory(func(_, _ []byte) ([]byte, []byte) {
					otherCACert, otherCAPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
					Expect(err).ToNot(HaveOccurred())
					cert, key, err := certs.GenerateCert(otherCACert, otherCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
					Expect(err).ToNot(HaveOccurred())
					return cert, key
				}), true),
			Entry("a valid certificate is not rotated", "audit-scanner-valid",
				clientCertFactory(func(caCert, caPrivateKey []byte) ([]byte, []byte) {
					cert, key, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
					Expect(err).ToNot(HaveOccurred())
					return cert, key
				}), false),
		)
	})

	Context("Old CA root cleanup", Ordered, func() {
		const (
			webhookServerServiceName    = "old-ca-root-cleanup-test-webhook-service"
			caRootSecretName            = "old-ca-root-cleanup-test-ca-root"
			webhookServerCertSecretName = "old-ca-root-cleanup-test-webhook-server-cert"
			policyServerName            = "old-ca-root-cleanup-test-policy-server"
		)

		BeforeAll(func() {
			certController := CertReconciler{
				Client:                           k8sClient,
				DeploymentsNamespace:             deploymentsNamespace,
				WebhookServiceName:               webhookServerServiceName,
				CARootSecretName:                 caRootSecretName,
				WebhookServerCertSecretName:      webhookServerCertSecretName,
				AuditScannerClientCertSecretName: "old-ca-root-cleanup-test-audit-scanner-client-cert",
			}

			By("generating the CA cert")
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			Expect(err).ToNot(HaveOccurred())
			By("generating an expired old CA cert")
			oldCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(-24*time.Hour))
			Expect(err).ToNot(HaveOccurred())
			By("creating the CA cert secret")
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      "old-ca-root-cleanup-test-ca-root",
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
					constants.OldCARootCert:    oldCACert,
				},
			}
			Expect(k8sClient.Create(ctx, caRootSecret)).To(Succeed())

			By("generating a webhook server cert")
			webhookServiceDNSName := certs.DNSName(webhookServerServiceName, deploymentsNamespace)
			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), webhookServiceDNSName)
			Expect(err).ToNot(HaveOccurred())
			By("creating the webhook server cert secret")
			webhookServerCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: deploymentsNamespace,
					Name:      webhookServerCertSecretName,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					constants.ServerCert:       webhookServerCert,
					constants.ServerPrivateKey: webhookServerPrivateKey,
				},
			}
			Expect(k8sClient.Create(ctx, webhookServerCertSecret)).To(Succeed())

			By("reconciling")
			Expect(certController.reconcile(ctx)).To(Succeed())
		})

		It("should remove the old CA root from the secret", func() {
			caRootSecret := &corev1.Secret{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: caRootSecretName, Namespace: deploymentsNamespace}, caRootSecret)
			Expect(err).ToNot(HaveOccurred())

			_, found := caRootSecret.Data[constants.OldCARootCert]
			Expect(found).To(BeFalse())
		})
	})
})
