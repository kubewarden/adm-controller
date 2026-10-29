package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// The spec changes the shared CA root secret, so it must not run in parallel with other specs.
var _ = Describe("Policy webhook configuration CA bundle of a policy server that is not uniquely reachable", Serial, func() {
	ctx := context.Background()

	It("should follow a rotation of the CA root", func() {
		// Envtest runs no pods, so the policy server is never uniquely reachable. That is the state of a stalled
		// rollout, where the old pods still serve and load the certificates of a new CA root. The cert controller
		// writes the CA bundle with no check of the readiness.
		policyServerName := newName("policy-server")
		createPolicyServerAndWaitForItsService(ctx, policiesv1.NewPolicyServerFactory().WithName(policyServerName).Build())
		Eventually(func() error {
			_, err := getTestPolicyServerDeployment(ctx, policyServerName)
			return err
		}, timeout, pollInterval).Should(Succeed())

		policy := policiesv1.NewClusterAdmissionPolicyFactory().WithPolicyServer(policyServerName).Build()

		caRootSecret := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.CARootSecretName}, caRootSecret)).To(Succeed())

		By("creating the webhook configuration of the policy, as before the rollout stalled")
		// The controller writes the webhook configuration only when the policy server is uniquely reachable, so the
		// spec creates it, with the label that the policy reconcilers set. It has no rules, so it intercepts no
		// request of the other specs.
		webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   policy.GetUniqueName(),
				Labels: map[string]string{constants.PartOfLabelKey: constants.PartOfLabelValue},
			},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{
				{
					Name: policy.GetUniqueName() + constants.WebhookNameSuffix,
					ClientConfig: admissionregistrationv1.WebhookClientConfig{
						Service:  &admissionregistrationv1.ServiceReference{Namespace: deploymentsNamespace, Name: getPolicyServerNameWithPrefix(policyServerName)},
						CABundle: certs.CABundleFromSecret(caRootSecret),
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

		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
			return getTestClusterAdmissionPolicy(ctx, policy.Name)
		}, timeout, pollInterval).Should(HaveField("Status.Conditions", ContainElement(And(
			HaveField("Type", string(policiesv1.PolicyUniquelyReachable)),
			HaveField("Status", metav1.ConditionFalse),
		))))

		By("rotating the CA root")
		oldCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
		Expect(err).ToNot(HaveOccurred())
		updateCARootSecret := func(mutate func(secret *corev1.Secret)) {
			Eventually(func() error {
				secret := &corev1.Secret{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.CARootSecretName}, secret); err != nil {
					return err
				}
				mutate(secret)
				return k8sClient.Update(ctx, secret)
			}, timeout, pollInterval).Should(Succeed())
		}
		DeferCleanup(func() {
			updateCARootSecret(func(secret *corev1.Secret) {
				delete(secret.Data, constants.OldCARootCert)
			})
		})
		updateCARootSecret(func(secret *corev1.Secret) {
			secret.Data[constants.OldCARootCert] = oldCACert
		})
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: deploymentsNamespace, Name: constants.CARootSecretName}, caRootSecret)).To(Succeed())
		expectedCABundle := certs.CABundleFromSecret(caRootSecret)

		Eventually(func() ([]byte, error) {
			current := &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(webhookConfiguration), current); err != nil {
				return nil, err
			}
			return current.Webhooks[0].ClientConfig.CABundle, nil
		}, timeout, pollInterval).Should(Equal(expectedCABundle))
	})
})

const testDeploymentsNamespace = "kubewarden"

// expectedExcludeExpr is the LabelSelectorRequirement that must be present
// in the NamespaceSelector to exclude the deployments namespace.
var expectedExcludeExpr = metav1.LabelSelectorRequirement{
	Key:      "kubernetes.io/metadata.name",
	Operator: metav1.LabelSelectorOpNotIn,
	Values:   []string{testDeploymentsNamespace},
}

func TestNamespaceSelectorClusterAdmissionTypePolicies(t *testing.T) {
	tests := []struct {
		name                                    string
		allowInsideAdmissionControllerNamespace bool
		policyNSSel                             *metav1.LabelSelector
		expected                                *metav1.LabelSelector
	}{
		{
			name:                                    "adds NotIn expression when allowInsideAdmissionControllerNamespace is false and policy has no NamespaceSelector",
			allowInsideAdmissionControllerNamespace: false,
			policyNSSel:                             nil,
			expected: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					expectedExcludeExpr,
				},
			},
		},
		{
			name:                                    "merges existing MatchExpressions with the NotIn expression when allowInsideAdmissionControllerNamespace is false",
			allowInsideAdmissionControllerNamespace: false,
			policyNSSel: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
			expected: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					expectedExcludeExpr,
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
		},
		{
			name:                                    "preserves MatchLabels and adds the NotIn expression when allowInsideAdmissionControllerNamespace is false",
			allowInsideAdmissionControllerNamespace: false,
			policyNSSel: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "demo"},
			},
			expected: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/metadata.name": "demo"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					expectedExcludeExpr,
				},
			},
		},
		{
			name:                                    "preserves both MatchLabels and MatchExpressions when allowInsideAdmissionControllerNamespace is false",
			allowInsideAdmissionControllerNamespace: false,
			policyNSSel: &metav1.LabelSelector{
				MatchLabels: map[string]string{"team": "platform"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
			expected: &metav1.LabelSelector{
				MatchLabels: map[string]string{"team": "platform"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					expectedExcludeExpr,
					{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				},
			},
		},
		{
			name:                                    "returns the policy NamespaceSelector unchanged when allowInsideAdmissionControllerNamespace is true",
			allowInsideAdmissionControllerNamespace: true,
			policyNSSel: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
			expected: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
		{
			name:                                    "returns nil when allowInsideAdmissionControllerNamespace is true and policy has no NamespaceSelector",
			allowInsideAdmissionControllerNamespace: true,
			policyNSSel:                             nil,
			expected:                                nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &policySubReconciler{
				deploymentsNamespace: testDeploymentsNamespace,
			}
			policy := policiesv1.NewClusterAdmissionPolicyFactory().Build()
			policy.Spec.NamespaceSelector = tc.policyNSSel.DeepCopy()
			policy.Spec.AllowInsideAdmissionControllerNamespace = tc.allowInsideAdmissionControllerNamespace

			got := r.namespaceSelector(policy)
			require.Equal(t, tc.expected, got)
			require.Equal(t, tc.policyNSSel, policy.Spec.NamespaceSelector, "the policy selector must not be mutated")

			policyGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().Build()
			policyGroup.Spec.NamespaceSelector = tc.policyNSSel.DeepCopy()
			policyGroup.Spec.AllowInsideAdmissionControllerNamespace = tc.allowInsideAdmissionControllerNamespace

			got = r.namespaceSelector(policyGroup)
			require.Equal(t, tc.expected, got)
			require.Equal(t, tc.policyNSSel, policyGroup.Spec.NamespaceSelector, "the policy selector must not be mutated")
		})
	}
}

func TestPolicyWebhookConfigurationCABundle(t *testing.T) {
	caCert, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	require.NoError(t, err)
	oldCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
	require.NoError(t, err)
	liveCABundle, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	require.NoError(t, err)
	caRootSecret := &corev1.Secret{Data: map[string][]byte{
		constants.CARootCert:    caCert,
		constants.OldCARootCert: oldCACert,
	}}
	secretCABundle := append(append([]byte{}, caCert...), oldCACert...)

	tests := []struct {
		name     string
		mutating bool
		// existing is true if the webhook configuration exists, with liveCABundle as its caBundle, before the
		// reconcile.
		existing         bool
		liveCABundle     []byte
		expectedCABundle []byte
	}{
		{
			name:             "a new validating webhook configuration gets the CA certificate and the old CA certificate",
			expectedCABundle: secretCABundle,
		},
		{
			name:             "a new mutating webhook configuration gets the CA certificate and the old CA certificate",
			mutating:         true,
			expectedCABundle: secretCABundle,
		},
		{
			name:             "an existing validating webhook configuration keeps its CA bundle",
			existing:         true,
			liveCABundle:     liveCABundle,
			expectedCABundle: liveCABundle,
		},
		{
			name:             "an existing mutating webhook configuration keeps its CA bundle",
			mutating:         true,
			existing:         true,
			liveCABundle:     liveCABundle,
			expectedCABundle: liveCABundle,
		},
		{
			name:             "an existing webhook configuration with an empty CA bundle gets the CA bundle of the CA root secret",
			existing:         true,
			expectedCABundle: secretCABundle,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().Build()
			r := &policySubReconciler{Client: k8sClient, Log: logr.Discard(), deploymentsNamespace: testDeploymentsNamespace}
			policy := policiesv1.NewClusterAdmissionPolicyFactory().WithMutating(tc.mutating).Build()

			var webhookConfiguration client.Object = &admissionregistrationv1.ValidatingWebhookConfiguration{}
			reconcileWebhookConfiguration := r.reconcileValidatingWebhookConfiguration
			if tc.mutating {
				webhookConfiguration = &admissionregistrationv1.MutatingWebhookConfiguration{}
				reconcileWebhookConfiguration = r.reconcileMutatingWebhookConfiguration
			}
			key := client.ObjectKey{Name: policy.GetUniqueName()}

			if tc.existing {
				require.NoError(t, reconcileWebhookConfiguration(t.Context(), policy, caRootSecret, "policy-server-default"))
				require.NoError(t, k8sClient.Get(t.Context(), key, webhookConfiguration))
				_, clientConfigs, err := webhookClientConfigs(webhookConfiguration)
				require.NoError(t, err)
				for _, clientConfig := range clientConfigs {
					clientConfig.CABundle = tc.liveCABundle
				}
				require.NoError(t, k8sClient.Update(t.Context(), webhookConfiguration))
			}

			require.NoError(t, reconcileWebhookConfiguration(t.Context(), policy, caRootSecret, "policy-server-default"))

			require.NoError(t, k8sClient.Get(t.Context(), key, webhookConfiguration))
			_, clientConfigs, err := webhookClientConfigs(webhookConfiguration)
			require.NoError(t, err)
			require.Len(t, clientConfigs, 1)
			require.Equal(t, tc.expectedCABundle, clientConfigs[0].CABundle)
		})
	}
}

// TestPolicyWebhookConfigurationKeepsAConcurrentCABundle shows the race of a rotation of the CA root: the cert
// controller writes the caBundle between the read and the update of the policy reconciler. The policy reconciler must
// not undo that write.
func TestPolicyWebhookConfigurationKeepsAConcurrentCABundle(t *testing.T) {
	caRootSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCert: []byte("ca")}}
	rotatedCABundle := []byte("rotated-ca")

	for _, mutating := range []bool{false, true} {
		t.Run(fmt.Sprintf("mutating=%t", mutating), func(t *testing.T) {
			concurrentWrite := &concurrentCABundleWrite{caBundle: rotatedCABundle}
			k8sClient := fake.NewClientBuilder().WithInterceptorFuncs(concurrentWrite.interceptor()).Build()
			r := &policySubReconciler{Client: k8sClient, Log: logr.Discard(), deploymentsNamespace: testDeploymentsNamespace}
			reconcileWebhookConfiguration := r.reconcileValidatingWebhookConfiguration
			var webhookConfiguration client.Object = &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if mutating {
				reconcileWebhookConfiguration = r.reconcileMutatingWebhookConfiguration
				webhookConfiguration = &admissionregistrationv1.MutatingWebhookConfiguration{}
			}

			policy := policiesv1.NewClusterAdmissionPolicyFactory().WithMutating(mutating).Build()
			require.NoError(t, reconcileWebhookConfiguration(t.Context(), policy, caRootSecret, "policy-server-default"))

			// Change a rule of the policy while the cert controller writes the caBundle.
			newRules := []admissionregistrationv1.RuleWithOperations{newRule([]string{""}, []string{"configmaps"})}
			changedPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithName(policy.GetName()).
				WithMutating(mutating).
				WithRules(newRules).
				Build()
			concurrentWrite.armed = true
			err := reconcileWebhookConfiguration(t.Context(), changedPolicy, caRootSecret, "policy-server-default")
			require.True(t, apierrors.IsConflict(err), "the API server rejects the update with the old caBundle, got: %v", err)
			require.True(t, concurrentWrite.done)

			// The work queue runs the reconcile again, and the reconcile reads the object again.
			require.NoError(t, reconcileWebhookConfiguration(t.Context(), changedPolicy, caRootSecret, "policy-server-default"))
			require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: policy.GetUniqueName()}, webhookConfiguration))
			_, clientConfigs, err := webhookClientConfigs(webhookConfiguration)
			require.NoError(t, err)
			require.Len(t, clientConfigs, 1)
			require.Equal(t, rotatedCABundle, clientConfigs[0].CABundle, "the caBundle of the cert controller survives")
			require.Equal(t, newRules, webhookRules(webhookConfiguration))
		})
	}
}

// concurrentCABundleWrite writes caBundle into every webhook of a webhook configuration, right before the first update
// or patch after armed becomes true, as a write of the cert controller between the read and the write of another
// writer.
type concurrentCABundleWrite struct {
	caBundle []byte
	armed    bool
	done     bool
}

func (w *concurrentCABundleWrite) interceptor() interceptor.Funcs {
	return interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := w.writeOnce(ctx, c, obj); err != nil {
				return err
			}
			return c.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := w.writeOnce(ctx, c, obj); err != nil {
				return err
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
}

func (w *concurrentCABundleWrite) writeOnce(ctx context.Context, c client.WithWatch, obj client.Object) error {
	if !w.armed || w.done {
		return nil
	}
	w.done = true
	live, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return errors.New("cannot copy the webhook configuration")
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(obj), live); err != nil {
		return err
	}
	_, clientConfigs, err := webhookClientConfigs(live)
	if err != nil {
		return err
	}
	for _, clientConfig := range clientConfigs {
		clientConfig.CABundle = w.caBundle
	}
	return c.Update(ctx, live)
}

// webhookRules returns the rules of the first webhook of a validating or a mutating webhook configuration.
func webhookRules(webhookConfiguration client.Object) []admissionregistrationv1.RuleWithOperations {
	switch typed := webhookConfiguration.(type) {
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		return typed.Webhooks[0].Rules
	case *admissionregistrationv1.MutatingWebhookConfiguration:
		return typed.Webhooks[0].Rules
	default:
		return nil
	}
}
