package controller

import (
	"context"
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

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// The spec changes the shared CA root secret, so it must not run in parallel with other specs.
var _ = Describe("Policy webhook configuration CA bundle of a policy server that is not uniquely reachable", Serial, func() {
	ctx := context.Background()

	It("should follow a rotation of the CA root", func() {
		// Envtest runs no pods, so the policy server is never uniquely reachable. That is the state of a stalled
		// rollout, where the old pods still serve and load the certificates of a new CA root.
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
		// spec creates it. It has no rules, so it intercepts no request of the other specs.
		webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: policy.GetUniqueName()},
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
	caRootSecret := &corev1.Secret{Data: map[string][]byte{
		constants.CARootCert:    caCert,
		constants.OldCARootCert: oldCACert,
	}}
	expectedCABundle := append(append([]byte{}, caCert...), oldCACert...)

	k8sClient := fake.NewClientBuilder().Build()
	r := &policySubReconciler{Client: k8sClient, Log: logr.Discard(), deploymentsNamespace: testDeploymentsNamespace}

	t.Run("the validating webhook configuration of a policy has the CA certificate and the old CA certificate", func(t *testing.T) {
		policy := policiesv1.NewClusterAdmissionPolicyFactory().Build()
		require.NoError(t, r.reconcileValidatingWebhookConfiguration(t.Context(), policy, caRootSecret, "policy-server-default"))

		webhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: policy.GetUniqueName()}, webhookConfiguration))
		require.Len(t, webhookConfiguration.Webhooks, 1)
		require.Equal(t, expectedCABundle, webhookConfiguration.Webhooks[0].ClientConfig.CABundle)
	})

	t.Run("the mutating webhook configuration of a policy has the CA certificate and the old CA certificate", func(t *testing.T) {
		policy := policiesv1.NewClusterAdmissionPolicyFactory().WithMutating(true).Build()
		require.NoError(t, r.reconcileMutatingWebhookConfiguration(t.Context(), policy, caRootSecret, "policy-server-default"))

		webhookConfiguration := &admissionregistrationv1.MutatingWebhookConfiguration{}
		require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: policy.GetUniqueName()}, webhookConfiguration))
		require.Len(t, webhookConfiguration.Webhooks, 1)
		require.Equal(t, expectedCABundle, webhookConfiguration.Webhooks[0].ClientConfig.CABundle)
	})
}

func TestReconcileWebhookConfigurationCABundle(t *testing.T) {
	caCert, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	require.NoError(t, err)
	oldCACert, _, err := certs.GenerateCA(time.Now().Add(-constants.CACertExpiration), time.Now().Add(constants.CertLookahead))
	require.NoError(t, err)
	caRootSecret := &corev1.Secret{Data: map[string][]byte{constants.CARootCert: caCert}}
	rotatedCARootSecret := &corev1.Secret{Data: map[string][]byte{
		constants.CARootCert:    caCert,
		constants.OldCARootCert: oldCACert,
	}}

	k8sClient := fake.NewClientBuilder().Build()
	r := &policySubReconciler{Client: k8sClient, Log: logr.Discard(), deploymentsNamespace: testDeploymentsNamespace}

	t.Run("refreshes only the CA bundle of an existing webhook configuration", func(t *testing.T) {
		policy := policiesv1.NewClusterAdmissionPolicyFactory().WithMutating(true).Build()
		require.NoError(t, r.reconcileMutatingWebhookConfiguration(t.Context(), policy, caRootSecret, "policy-server-default"))
		before := &admissionregistrationv1.MutatingWebhookConfiguration{}
		require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: policy.GetUniqueName()}, before))

		require.NoError(t, r.reconcileWebhookConfigurationCABundle(t.Context(), policy, rotatedCARootSecret))

		after := &admissionregistrationv1.MutatingWebhookConfiguration{}
		require.NoError(t, k8sClient.Get(t.Context(), client.ObjectKey{Name: policy.GetUniqueName()}, after))
		require.Len(t, after.Webhooks, 1)
		require.Equal(t, certs.CABundleFromSecret(rotatedCARootSecret), after.Webhooks[0].ClientConfig.CABundle)
		require.Equal(t, before.Webhooks[0].ClientConfig.Service, after.Webhooks[0].ClientConfig.Service)
		require.Equal(t, before.Webhooks[0].Rules, after.Webhooks[0].Rules)
		require.Equal(t, before.Labels, after.Labels)
		require.Equal(t, before.Annotations, after.Annotations)
	})

	t.Run("creates no webhook configuration for a policy that has none", func(t *testing.T) {
		policy := policiesv1.NewClusterAdmissionPolicyFactory().Build()
		require.NoError(t, r.reconcileWebhookConfigurationCABundle(t.Context(), policy, rotatedCARootSecret))

		err := k8sClient.Get(t.Context(), client.ObjectKey{Name: policy.GetUniqueName()}, &admissionregistrationv1.ValidatingWebhookConfiguration{})
		require.True(t, apierrors.IsNotFound(err))
	})
}
