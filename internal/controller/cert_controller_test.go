package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// The suite runs one cert controller for the shared certificate Secrets. The specs change these Secrets, and the
// cert controller of the suite reacts to the change. The specs must not run in parallel with other specs.
var _ = Describe("Cert controller", Serial, func() {
	ctx := context.Background()
	caRootSecretKey := types.NamespacedName{Namespace: deploymentsNamespace, Name: constants.CARootSecretName}
	webhookServerDNSName := certs.DNSName(webhookServiceName, deploymentsNamespace)
	sharedSecretNames := []string{
		constants.CARootSecretName,
		constants.WebhookServerCertSecretName,
		constants.AuditScannerClientCertSecretName,
	}

	getSecret := func(name string) *corev1.Secret {
		secret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: name}, secret)).To(Succeed())
		return secret
	}

	updateSecretData := func(name string, mutate func(data map[string][]byte)) {
		Eventually(func() error {
			secret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: name}, secret); err != nil {
				return err
			}
			if secret.Data == nil {
				secret.Data = map[string][]byte{}
			}
			mutate(secret.Data)
			return k8sClient.Update(ctx, secret)
		}, timeout, pollInterval).Should(Succeed())
	}

	currentCARoot := func() ([]byte, []byte) {
		caRootSecret := getSecret(constants.CARootSecretName)
		return caRootSecret.Data[constants.CARootCert], caRootSecret.Data[constants.CARootPrivateKey]
	}

	currentCABundle := func() []byte {
		return certs.CABundleFromSecret(getSecret(constants.CARootSecretName))
	}

	newCA := func(notBefore, notAfter time.Time) ([]byte, []byte) {
		caCert, caPrivateKey, err := certs.GenerateCA(notBefore, notAfter)
		Expect(err).ToNot(HaveOccurred())
		return caCert, caPrivateKey
	}

	newCert := func(caCert, caPrivateKey []byte, notBefore, notAfter time.Time, dnsName string) ([]byte, []byte) {
		cert, privateKey, err := certs.GenerateCert(caCert, caPrivateKey, notBefore, notAfter, dnsName)
		Expect(err).ToNot(HaveOccurred())
		return cert, privateKey
	}

	// signedByCurrentCARoot returns a function that fails if the current CA root did not sign the certificate of the
	// Secret, or if the certificate ends within constants.CertLookahead.
	signedByCurrentCARoot := func(secretName, dnsName string) func() error {
		return func() error {
			caRootSecret := &corev1.Secret{}
			if err := k8sClient.Get(ctx, caRootSecretKey, caRootSecret); err != nil {
				return err
			}
			pool, err := certs.NewCertPool(caRootSecret.Data[constants.CARootCert])
			if err != nil {
				return err
			}
			secret := &corev1.Secret{}
			if err = k8sClient.Get(ctx, types.NamespacedName{Namespace: deploymentsNamespace, Name: secretName}, secret); err != nil {
				return err
			}
			return certs.VerifyCert(secret.Data[constants.ServerCert], secret.Data[constants.ServerPrivateKey], pool, dnsName, time.Now().Add(constants.CertLookahead))
		}
	}

	// caBundles returns a function that reads the caBundle of every webhook of the webhook configuration.
	caBundles := func(webhookConfiguration client.Object) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			current, ok := webhookConfiguration.DeepCopyObject().(client.Object)
			if !ok {
				return nil, errors.New("cannot copy the webhook configuration")
			}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(webhookConfiguration), current); err != nil {
				return nil, err
			}
			_, clientConfigs, err := webhookClientConfigs(current)
			if err != nil {
				return nil, err
			}
			caBundles := [][]byte{}
			for _, clientConfig := range clientConfigs {
				caBundles = append(caBundles, clientConfig.CABundle)
			}
			return caBundles, nil
		}
	}

	// createWebhookConfigurations creates a validating and a mutating webhook configuration that send requests to the
	// webhook service. The webhooks have no rules, so they intercept no request of the other specs.
	createWebhookConfigurations := func(prefix string, withKubewardenLabel bool, caBundle []byte) (*admissionregistrationv1.ValidatingWebhookConfiguration, *admissionregistrationv1.MutatingWebhookConfiguration) {
		var labels map[string]string
		if withKubewardenLabel {
			labels = map[string]string{constants.PartOfLabelKey: constants.PartOfLabelValue}
		}
		clientConfig := admissionregistrationv1.WebhookClientConfig{
			Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: webhookServiceName},
			CABundle: caBundle,
		}

		validating := &admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: newName(prefix + "-validating"), Labels: labels},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name:                    "first.cert-controller.kubewarden.test",
					ClientConfig:            clientConfig,
					AdmissionReviewVersions: []string{"v1"},
					SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				},
				{
					Name:                    "second.cert-controller.kubewarden.test",
					ClientConfig:            clientConfig,
					AdmissionReviewVersions: []string{"v1"},
					SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				},
			},
		}
		mutating := &admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: newName(prefix + "-mutating"), Labels: labels},
			Webhooks: []admissionregistrationv1.MutatingWebhook{
				{
					Name:                    "first.cert-controller.kubewarden.test",
					ClientConfig:            clientConfig,
					AdmissionReviewVersions: []string{"v1"},
					SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
				},
			},
		}
		for _, webhookConfiguration := range []client.Object{validating, mutating} {
			Expect(k8sClient.Create(ctx, webhookConfiguration)).To(Succeed())
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, webhookConfiguration))).To(Succeed())
			})
		}

		return validating, mutating
	}

	// createPolicyServerSecret creates the certificate Secret of a policy server, with the labels that the
	// PolicyServer reconciler sets.
	createPolicyServerSecret := func(name string, cert, privateKey []byte) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: deploymentsNamespace,
				Name:      name,
				Labels: map[string]string{
					constants.PartOfLabelKey:    constants.PartOfLabelValue,
					constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				constants.ServerCert:       cert,
				constants.ServerPrivateKey: privateKey,
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed())
		})
	}

	// Every spec changes the shared certificate Secrets. Restore them after the spec, so that the next spec starts
	// from the state that the suite created. The CA root goes first: a pass can then sign the other certificates
	// with it, and the restored certificates are signed by it too.
	BeforeEach(func() {
		saved := map[string]map[string][]byte{}
		for _, name := range sharedSecretNames {
			saved[name] = getSecret(name).Data
		}

		DeferCleanup(func() {
			for _, name := range sharedSecretNames {
				updateSecretData(name, func(data map[string][]byte) {
					for key := range data {
						delete(data, key)
					}
					for key, value := range saved[name] {
						data[key] = value
					}
				})
			}
			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
			Eventually(signedByCurrentCARoot(constants.AuditScannerClientCertSecretName, ""), timeout, pollInterval).Should(Succeed())
		})
	})

	Context("Renewal of a certificate", func() {
		It("should renew the webhook server certificate when it ends within 60 days", func() {
			caCert, caPrivateKey := currentCARoot()
			cert, privateKey := newCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), webhookServerDNSName)
			updateSecretData(constants.WebhookServerCertSecretName, func(data map[string][]byte) {
				data[constants.ServerCert] = cert
				data[constants.ServerPrivateKey] = privateKey
			})

			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
		})

		It("should renew an expired webhook server certificate", func() {
			caCert, caPrivateKey := currentCARoot()
			cert, privateKey := newCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(-24*time.Hour), webhookServerDNSName)
			updateSecretData(constants.WebhookServerCertSecretName, func(data map[string][]byte) {
				data[constants.ServerCert] = cert
				data[constants.ServerPrivateKey] = privateKey
			})

			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
		})

		It("should sign the webhook server certificate again when another CA signed it", func() {
			otherCACert, otherCAPrivateKey := newCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			cert, privateKey := newCert(otherCACert, otherCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), webhookServerDNSName)
			updateSecretData(constants.WebhookServerCertSecretName, func(data map[string][]byte) {
				data[constants.ServerCert] = cert
				data[constants.ServerPrivateKey] = privateKey
			})

			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
		})

		It("should renew a policy server certificate when it ends within 60 days", func() {
			policyServerSecretName := newName("cert-controller-policy-server")
			policyServerDNSName := certs.DNSName(policyServerSecretName, deploymentsNamespace)
			caCert, caPrivateKey := currentCARoot()
			cert, privateKey := newCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), policyServerDNSName)
			createPolicyServerSecret(policyServerSecretName, cert, privateKey)

			Eventually(signedByCurrentCARoot(policyServerSecretName, policyServerDNSName), timeout, pollInterval).Should(Succeed())
		})
	})

	Context("Audit scanner client certificate", func() {
		type clientCertFactory func(caCert, caPrivateKey []byte) ([]byte, []byte)

		DescribeTable("renewing the audit scanner client certificate",
			func(generateClientCert clientCertFactory, expectRenewed bool) {
				caCert, caPrivateKey := currentCARoot()
				clientCert, clientPrivateKey := generateClientCert(caCert, caPrivateKey)
				updateSecretData(constants.AuditScannerClientCertSecretName, func(data map[string][]byte) {
					data[constants.ServerCert] = clientCert
					data[constants.ServerPrivateKey] = clientPrivateKey
				})

				currentClientCert := func() []byte {
					return getSecret(constants.AuditScannerClientCertSecretName).Data[constants.ServerCert]
				}
				if expectRenewed {
					Eventually(currentClientCert, timeout, pollInterval).ShouldNot(Equal(clientCert))
					Eventually(signedByCurrentCARoot(constants.AuditScannerClientCertSecretName, ""), timeout, pollInterval).Should(Succeed())
				} else {
					Consistently(currentClientCert, consistencyTimeout, pollInterval).Should(Equal(clientCert))
				}
			},
			Entry("a certificate that ends within 60 days is renewed",
				clientCertFactory(func(caCert, caPrivateKey []byte) ([]byte, []byte) {
					return newCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(constants.CertLookahead), constants.AuditScannerClientCertCommonName)
				}), true),
			Entry("an expired certificate is renewed",
				clientCertFactory(func(caCert, caPrivateKey []byte) ([]byte, []byte) {
					return newCert(caCert, caPrivateKey, time.Now().Add(-constants.ServerCertExpiration), time.Now().Add(-24*time.Hour), constants.AuditScannerClientCertCommonName)
				}), true),
			Entry("a certificate signed by another CA is renewed",
				clientCertFactory(func(_, _ []byte) ([]byte, []byte) {
					otherCACert, otherCAPrivateKey := newCA(time.Now(), time.Now().Add(constants.CACertExpiration))
					return newCert(otherCACert, otherCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
				}), true),
			Entry("a valid certificate is not renewed",
				clientCertFactory(func(caCert, caPrivateKey []byte) ([]byte, []byte) {
					return newCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
				}), false),
		)
	})

	Context("CA root", func() {
		It("should rotate a CA root that ends within 60 days, write the CA bundle, and sign every certificate again", func() {
			validating, mutating := createWebhookConfigurations("cert-controller-rotation", true, currentCABundle())
			unlabelled, _ := createWebhookConfigurations("cert-controller-rotation-unlabelled", false, currentCABundle())
			unlabelledCABundle := currentCABundle()

			policyServerSecretName := newName("cert-controller-policy-server")
			policyServerDNSName := certs.DNSName(policyServerSecretName, deploymentsNamespace)
			caCert, caPrivateKey := currentCARoot()
			policyServerCert, policyServerPrivateKey := newCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), policyServerDNSName)
			createPolicyServerSecret(policyServerSecretName, policyServerCert, policyServerPrivateKey)

			By("writing a CA root that ends within 60 days")
			expiringCACert, expiringCAPrivateKey := newCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
			updateSecretData(constants.CARootSecretName, func(data map[string][]byte) {
				data[constants.CARootCert] = expiringCACert
				data[constants.CARootPrivateKey] = expiringCAPrivateKey
				delete(data, constants.OldCARootCert)
			})

			By("checking that the CA root rotates, and that the previous CA root becomes the old CA root")
			Eventually(func() []byte {
				return getSecret(constants.CARootSecretName).Data[constants.OldCARootCert]
			}, timeout, pollInterval).Should(Equal(expiringCACert))
			Expect(getSecret(constants.CARootSecretName).Data[constants.CARootCert]).ToNot(Equal(expiringCACert))
			rotatedCABundle := currentCABundle()

			By("checking that the webhook configurations with the Kubewarden label trust both CA roots")
			Eventually(caBundles(validating), timeout, pollInterval).Should(HaveEach(Equal(rotatedCABundle)))
			Eventually(caBundles(mutating), timeout, pollInterval).Should(HaveEach(Equal(rotatedCABundle)))

			By("checking that every certificate comes from the new CA root")
			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
			Eventually(signedByCurrentCARoot(policyServerSecretName, policyServerDNSName), timeout, pollInterval).Should(Succeed())
			Eventually(signedByCurrentCARoot(constants.AuditScannerClientCertSecretName, ""), timeout, pollInterval).Should(Succeed())

			By("checking that a webhook configuration without the Kubewarden label is not touched")
			Expect(caBundles(unlabelled)()).To(HaveEach(Equal(unlabelledCABundle)))
		})

		It("should remove an expired old CA root, and write the CA bundle without it", func() {
			validating, _ := createWebhookConfigurations("cert-controller-old-ca-removal", true, currentCABundle())

			By("adding an expired old CA root")
			expiredCACert, _ := newCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(-24*time.Hour))
			updateSecretData(constants.CARootSecretName, func(data map[string][]byte) {
				data[constants.OldCARootCert] = expiredCACert
			})

			Eventually(func() map[string][]byte {
				return getSecret(constants.CARootSecretName).Data
			}, timeout, pollInterval).ShouldNot(HaveKey(constants.OldCARootCert))
			caCert, _ := currentCARoot()
			Eventually(caBundles(validating), timeout, pollInterval).Should(HaveEach(Equal(caCert)))
		})

		It("should rotate an expired CA root and sign every certificate again, as after a long shutdown", func() {
			validating, _ := createWebhookConfigurations("cert-controller-expired-ca", true, currentCABundle())

			By("writing an expired CA root")
			expiredCACert, expiredCAPrivateKey := newCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(-24*time.Hour))
			updateSecretData(constants.CARootSecretName, func(data map[string][]byte) {
				data[constants.CARootCert] = expiredCACert
				data[constants.CARootPrivateKey] = expiredCAPrivateKey
				delete(data, constants.OldCARootCert)
			})

			By("checking that the CA root rotates, and that the expired CA root is not kept")
			Eventually(func(g Gomega) {
				data := getSecret(constants.CARootSecretName).Data
				g.Expect(data[constants.CARootCert]).ToNot(Equal(expiredCACert))
				g.Expect(data).ToNot(HaveKey(constants.OldCARootCert))
			}, timeout, pollInterval).Should(Succeed())

			By("checking that the webhook configurations trust the new CA root alone, and that it signs every certificate")
			caCert, _ := currentCARoot()
			Eventually(caBundles(validating), timeout, pollInterval).Should(HaveEach(Equal(caCert)))
			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
			Eventually(signedByCurrentCARoot(constants.AuditScannerClientCertSecretName, ""), timeout, pollInterval).Should(Succeed())
		})
	})

	Context("A deleted certificate Secret", func() {
		deleteSecret := func(name string) {
			Expect(k8sClient.Delete(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: deploymentsNamespace, Name: name},
			})).To(Succeed())
		}

		It("should create the webhook server certificate Secret again", func() {
			deleteSecret(constants.WebhookServerCertSecretName)

			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
			Expect(getSecret(constants.WebhookServerCertSecretName).Labels).To(HaveKeyWithValue(constants.PartOfLabelKey, constants.PartOfLabelValue))
		})

		It("should create the CA root Secret again, write the CA bundle, and sign every certificate again", func() {
			validating, _ := createWebhookConfigurations("cert-controller-deleted-ca", true, currentCABundle())
			deletedCACert, _ := currentCARoot()

			deleteSecret(constants.CARootSecretName)

			By("checking that a new CA root exists")
			Eventually(func(g Gomega) {
				caRootSecret := &corev1.Secret{}
				g.Expect(k8sClient.Get(ctx, caRootSecretKey, caRootSecret)).To(Succeed())
				g.Expect(caRootSecret.Data[constants.CARootCert]).ToNot(Equal(deletedCACert))
			}, timeout, pollInterval).Should(Succeed())

			By("checking that the webhook configurations trust the new CA root, and that it signs every certificate")
			caCert, _ := currentCARoot()
			Eventually(caBundles(validating), timeout, pollInterval).Should(HaveEach(Equal(caCert)))
			Eventually(signedByCurrentCARoot(constants.WebhookServerCertSecretName, webhookServerDNSName), timeout, pollInterval).Should(Succeed())
			Eventually(signedByCurrentCARoot(constants.AuditScannerClientCertSecretName, ""), timeout, pollInterval).Should(Succeed())
		})
	})

	Context("CA bundle of the webhook configurations", func() {
		It("should repair a webhook configuration with the Kubewarden label that is created with the CA bundle of another CA", func() {
			otherCACert, _ := newCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			validating, mutating := createWebhookConfigurations("cert-controller-repair-create", true, otherCACert)

			Eventually(caBundles(validating), timeout, pollInterval).Should(HaveEach(Equal(currentCABundle())))
			Eventually(caBundles(mutating), timeout, pollInterval).Should(HaveEach(Equal(currentCABundle())))
		})

		It("should repair a webhook configuration with the Kubewarden label whose CA bundle changes", func() {
			validating, _ := createWebhookConfigurations("cert-controller-repair-update", true, currentCABundle())

			By("writing the CA bundle of another CA")
			otherCACert, _ := newCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			Eventually(func() error {
				webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(validating), webhookConfiguration); err != nil {
					return err
				}
				webhookConfiguration.Webhooks[0].ClientConfig.CABundle = otherCACert
				return k8sClient.Update(ctx, webhookConfiguration)
			}, timeout, pollInterval).Should(Succeed())

			Eventually(caBundles(validating), timeout, pollInterval).Should(HaveEach(Equal(currentCABundle())))
		})

		It("should not touch a webhook configuration without the Kubewarden label", func() {
			otherCACert, _ := newCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			validating, _ := createWebhookConfigurations("cert-controller-unlabelled", false, otherCACert)

			Consistently(caBundles(validating), consistencyTimeout, pollInterval).Should(HaveEach(Equal(otherCACert)))
		})

		It("should not write a webhook configuration with the Kubewarden label that already has the CA bundle", func() {
			validating, _ := createWebhookConfigurations("cert-controller-no-change", true, currentCABundle())

			Consistently(func() (string, error) {
				webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(validating), webhookConfiguration); err != nil {
					return "", err
				}
				return webhookConfiguration.ResourceVersion, nil
			}, consistencyTimeout, pollInterval).Should(Equal(validating.ResourceVersion))
		})
	})
})

// TestReconcileWritesTheCABundleBeforeItSigns shows the order of one pass after a rotation of the CA root: the pass
// writes the CA bundle into the webhook configurations first, and signs certificates with the new CA root only if
// that write succeeds.
func TestReconcileWritesTheCABundleBeforeItSigns(t *testing.T) {
	const (
		namespace   = "kubewarden"
		serviceName = "kubewarden-controller-webhook-service"
	)

	tests := []struct {
		name       string
		patchFails bool
	}{
		{name: "the pass signs no certificate if the CA bundle cannot be written", patchFails: true},
		{name: "the pass signs the certificates after the CA bundle is written", patchFails: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldCACert, oldCAPrivateKey, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
			require.NoError(t, err)
			webhookServerCert, webhookServerPrivateKey, err := certs.GenerateCert(oldCACert, oldCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), certs.DNSName(serviceName, namespace))
			require.NoError(t, err)
			auditScannerClientCert, auditScannerClientPrivateKey, err := certs.GenerateCert(oldCACert, oldCAPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
			require.NoError(t, err)

			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "kubewarden-controller-validating-webhook-configuration",
					Labels: map[string]string{constants.PartOfLabelKey: constants.PartOfLabelValue},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "validate.kubewarden.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service:  &admissionregistrationv1.ServiceReference{Namespace: namespace, Name: serviceName},
							CABundle: oldCACert,
						},
					},
				},
			}
			k8sClient := fake.NewClientBuilder().
				WithObjects(
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.CARootSecretName},
						Data: map[string][]byte{
							constants.CARootCert:       oldCACert,
							constants.CARootPrivateKey: oldCAPrivateKey,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.WebhookServerCertSecretName},
						Data: map[string][]byte{
							constants.ServerCert:       webhookServerCert,
							constants.ServerPrivateKey: webhookServerPrivateKey,
						},
					},
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.AuditScannerClientCertSecretName},
						Data: map[string][]byte{
							constants.ServerCert:       auditScannerClientCert,
							constants.ServerPrivateKey: auditScannerClientPrivateKey,
						},
					},
					webhookConfiguration,
				).
				WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						if _, ok := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration); ok && tc.patchFails {
							return errors.New("the API server refuses the patch")
						}
						return c.Patch(ctx, obj, patch, opts...)
					},
				}).
				Build()

			certController := CertReconciler{
				Client:               k8sClient,
				Log:                  logr.Discard(),
				DeploymentsNamespace: namespace,
				WebhookServiceName:   serviceName,
			}

			err = certController.reconcile(t.Context())

			getSecret := func(name string) *corev1.Secret {
				secret := &corev1.Secret{}
				require.NoError(t, k8sClient.Get(t.Context(), types.NamespacedName{Namespace: namespace, Name: name}, secret))
				return secret
			}
			caRootSecret := getSecret(constants.CARootSecretName)
			require.NotEqual(t, oldCACert, caRootSecret.Data[constants.CARootCert], "the CA root rotates before the CA bundle is written")
			newCAPool, poolErr := certs.NewCertPool(caRootSecret.Data[constants.CARootCert])
			require.NoError(t, poolErr)

			if tc.patchFails {
				require.Error(t, err)
				require.Equal(t, webhookServerCert, getSecret(constants.WebhookServerCertSecretName).Data[constants.ServerCert])
				require.Equal(t, auditScannerClientCert, getSecret(constants.AuditScannerClientCertSecretName).Data[constants.ServerCert])
				return
			}

			require.NoError(t, err)
			current := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(webhookConfiguration), current))
			require.Equal(t, certs.CABundleFromSecret(caRootSecret), current.Webhooks[0].ClientConfig.CABundle)
			webhookServerCertSecret := getSecret(constants.WebhookServerCertSecretName)
			require.NoError(t, certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], newCAPool, certs.DNSName(serviceName, namespace), time.Now()))
		})
	}
}

// TestReconcileCreatesAMissingCertificateOnlyAfterTheCABundle shows the case of an earlier pass that rotated the CA
// root and failed to write the CA bundle. A certificate Secret that is deleted after that pass must not come back,
// signed by the new CA root, before the webhook configurations trust that CA root.
func TestReconcileCreatesAMissingCertificateOnlyAfterTheCABundle(t *testing.T) {
	const (
		namespace   = "kubewarden"
		serviceName = "kubewarden-controller-webhook-service"
	)

	tests := []struct {
		name       string
		patchFails bool
	}{
		{name: "the pass does not create the certificate if the CA bundle cannot be written", patchFails: true},
		{name: "the pass creates the certificate after the CA bundle is written", patchFails: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			previousCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
			require.NoError(t, err)
			caCert, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
			require.NoError(t, err)
			auditScannerClientCert, auditScannerClientPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, time.Now(), time.Now().Add(constants.ServerCertExpiration), constants.AuditScannerClientCertCommonName)
			require.NoError(t, err)

			// The state after a pass that rotated the CA root and failed to write the CA bundle: the CA root Secret
			// holds the new CA root, and the webhook configuration trusts the previous one alone. The Secret of the
			// webhook server certificate is deleted.
			caRootSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.CARootSecretName},
				Data: map[string][]byte{
					constants.CARootCert:       caCert,
					constants.CARootPrivateKey: caPrivateKey,
					constants.OldCARootCert:    previousCACert,
				},
			}
			webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "kubewarden-controller-validating-webhook-configuration",
					Labels: map[string]string{constants.PartOfLabelKey: constants.PartOfLabelValue},
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					{
						Name: "validate.kubewarden.test",
						ClientConfig: admissionregistrationv1.WebhookClientConfig{
							Service:  &admissionregistrationv1.ServiceReference{Namespace: namespace, Name: serviceName},
							CABundle: previousCACert,
						},
					},
				},
			}
			k8sClient := fake.NewClientBuilder().
				WithObjects(
					caRootSecret,
					&corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.AuditScannerClientCertSecretName},
						Data: map[string][]byte{
							constants.ServerCert:       auditScannerClientCert,
							constants.ServerPrivateKey: auditScannerClientPrivateKey,
						},
					},
					webhookConfiguration,
				).
				WithInterceptorFuncs(interceptor.Funcs{
					Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						if _, ok := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration); ok && tc.patchFails {
							return errors.New("the API server refuses the patch")
						}
						return c.Patch(ctx, obj, patch, opts...)
					},
				}).
				Build()

			certController := CertReconciler{
				Client:               k8sClient,
				Log:                  logr.Discard(),
				DeploymentsNamespace: namespace,
				WebhookServiceName:   serviceName,
			}

			err = certController.reconcile(t.Context())

			webhookServerCertSecret := &corev1.Secret{}
			getErr := k8sClient.Get(t.Context(), types.NamespacedName{Namespace: namespace, Name: constants.WebhookServerCertSecretName}, webhookServerCertSecret)
			if tc.patchFails {
				require.Error(t, err)
				require.True(t, apierrors.IsNotFound(getErr), "no certificate is created before the webhook configurations trust its CA root")
				return
			}

			require.NoError(t, err)
			current := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKeyFromObject(webhookConfiguration), current))
			require.Equal(t, certs.CABundleFromSecret(caRootSecret), current.Webhooks[0].ClientConfig.CABundle)
			require.NoError(t, getErr, "the certificate Secret is created again")
			pool, poolErr := certs.NewCertPool(caCert)
			require.NoError(t, poolErr)
			require.NoError(t, certs.VerifyCert(webhookServerCertSecret.Data[constants.ServerCert], webhookServerCertSecret.Data[constants.ServerPrivateKey], pool, certs.DNSName(serviceName, namespace), time.Now()))
		})
	}
}
