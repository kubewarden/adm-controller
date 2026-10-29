package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	sigsyaml "sigs.k8s.io/yaml"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

func marshalPolicyServer(ps *policiesv1.PolicyServer) string {
	ps.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("PolicyServer"))
	data, err := sigsyaml.Marshal(ps)
	Expect(err).ToNot(HaveOccurred())
	return string(data)
}

func marshalClusterAdmissionPolicy(policy *policiesv1.ClusterAdmissionPolicy) string {
	policy.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("ClusterAdmissionPolicy"))
	data, err := sigsyaml.Marshal(policy)
	Expect(err).ToNot(HaveOccurred())
	return string(data)
}

// marshalClusterAdmissionPolicyWithoutBackgroundAudit renders a ClusterAdmissionPolicy to YAML
// with the spec.backgroundAudit field removed entirely, mimicking a chart template that omits it.
// This lets us assert that the applier lets the API server apply the CRD default (true) instead of
// clobbering it with the Go zero value (false).
func marshalClusterAdmissionPolicyWithoutBackgroundAudit(policy *policiesv1.ClusterAdmissionPolicy) string {
	policy.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("ClusterAdmissionPolicy"))
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(policy)
	Expect(err).ToNot(HaveOccurred())
	unstructured.RemoveNestedField(obj, "spec", "backgroundAudit")
	unstructured.RemoveNestedField(obj, "status")
	data, err := sigsyaml.Marshal(obj)
	Expect(err).ToNot(HaveOccurred())
	return string(data)
}

var _ = Describe("DefaultsApplierReconciler", func() {
	var (
		ctx              context.Context
		configMapName    string
		configMapNsName  types.NamespacedName
		policyServerName string
		policyName       string
	)

	BeforeEach(func() {
		ctx = context.Background()
		configMapName = constants.DefaultDefaultsConfigMapName
		configMapNsName = types.NamespacedName{
			Name:      configMapName,
			Namespace: deploymentsNamespace,
		}
		policyServerName = "test-default-policyserver"
		policyName = "test-default-policy"
	})

	AfterEach(func() {
		cm := &corev1.ConfigMap{}
		err := k8sClient.Get(ctx, configMapNsName, cm)
		if err == nil {
			Expect(k8sClient.Delete(ctx, cm)).To(Succeed())
		}

		managedSelector := client.MatchingLabels{
			constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue,
		}
		for _, obj := range []client.Object{
			&policiesv1.PolicyServer{},
			&policiesv1.ClusterAdmissionPolicy{},
		} {
			Expect(k8sClient.DeleteAllOf(ctx, obj, managedSelector)).To(Succeed())
		}
	})

	Context("when ConfigMap is deleted", func() {
		It("should delete all managed resources", func() {
			// First create all the managed resources by creating the ConfigMap with one entry
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
			}, timeout, pollInterval).Should(Succeed())

			// Now delete the ConfigMap and verify that the managed PolicyServer is also deleted
			Expect(k8sClient.Delete(ctx, cm)).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
				return apierrors.IsNotFound(err)
			}, timeout, pollInterval).Should(BeTrue(), "managed PolicyServer should be deleted")
		})
	})

	Context("when ConfigMap has one PolicyServer", func() {
		It("should create the PolicyServer with ownership label", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPS := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
			}, timeout, pollInterval).Should(Succeed())

			Expect(createdPS.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
			Expect(createdPS.Spec.Image).To(Equal(ps.Spec.Image))
		})
	})

	Context("when a policy omits backgroundAudit", func() {
		It("should apply the CRD default of true instead of the Go zero value", func() {
			policy := policiesv1.NewClusterAdmissionPolicyFactory().WithName(policyName).WithoutFinalizers().Build()
			policyYAML := marshalClusterAdmissionPolicyWithoutBackgroundAudit(policy)

			// Guard: the ConfigMap entry must not carry a backgroundAudit field at all,
			// otherwise this test would not exercise server-side defaulting.
			Expect(policyYAML).ToNot(ContainSubstring("backgroundAudit"))

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policy": policyYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPolicy := &policiesv1.ClusterAdmissionPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, createdPolicy)
			}, timeout, pollInterval).Should(Succeed())

			Expect(createdPolicy.Spec.BackgroundAudit).To(BeTrue(),
				"server-side defaulting should set backgroundAudit=true when the field is omitted")
		})
	})

	Context("when ConfigMap is updated", func() {
		It("should update the PolicyServer spec", func() {
			initialPS := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			initialPS.Spec.Image = "ghcr.io/kubewarden/policy-server:v1.0.0"
			initialYAML := marshalPolicyServer(initialPS)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": initialYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPS := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
			}, timeout, pollInterval).Should(Succeed())
			Expect(createdPS.Spec.Image).To(Equal("ghcr.io/kubewarden/policy-server:v1.0.0"))

			updatedPS := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			updatedPS.Spec.Image = "ghcr.io/kubewarden/policy-server:v2.0.0"
			updatedYAML := marshalPolicyServer(updatedPS)

			Expect(k8sClient.Get(ctx, configMapNsName, cm)).To(Succeed())
			cm.Data["policyserver-default"] = updatedYAML
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())

			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
				if err != nil {
					return ""
				}
				return createdPS.Spec.Image
			}, timeout, pollInterval).Should(Equal("ghcr.io/kubewarden/policy-server:v2.0.0"))
		})
	})

	Context("when a key is removed from ConfigMap", func() {
		It("should delete the corresponding managed resource", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			clusterPolicy := policiesv1.NewClusterAdmissionPolicyFactory().WithName(policyName).WithoutFinalizers().Build()
			policyYAML := marshalClusterAdmissionPolicy(clusterPolicy)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
					"policy":               policyYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})
			}, timeout, pollInterval).Should(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, &policiesv1.ClusterAdmissionPolicy{})
			}, timeout, pollInterval).Should(Succeed())

			// Now remove the "policy" key from the ConfigMap and verify that the
			// corresponding ClusterAdmissionPolicy is deleted while the PolicyServer
			// remains
			Expect(k8sClient.Get(ctx, configMapNsName, cm)).To(Succeed())
			delete(cm.Data, "policy")
			Expect(k8sClient.Update(ctx, cm)).To(Succeed())

			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: policyName}, &policiesv1.ClusterAdmissionPolicy{})
				return apierrors.IsNotFound(err)
			}, timeout, pollInterval).Should(BeTrue(), "managed policy should be deleted")

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, &policiesv1.PolicyServer{})).To(Succeed())
		})
	})

	Context("resource safety", func() {
		It("should never delete resources without the ownership label", func() {
			unmanagedPS := policiesv1.NewPolicyServerFactory().WithName("unmanaged-policyserver").WithoutFinalizers().Build()
			Expect(k8sClient.Create(ctx, unmanagedPS)).To(Succeed())

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: unmanagedPS.Name}, &policiesv1.PolicyServer{})
			}, consistencyTimeout, pollInterval).Should(Succeed())

			Expect(k8sClient.Delete(ctx, unmanagedPS)).To(Succeed())
		})
	})

	Context("when a previously Helm-managed PolicyServer is adopted by the controller", func() {
		It("should remove Helm annotations and update the managed-by label on reconcile", func() {
			// Simulate a PolicyServer that was created by Helm before the 1.37 migration.
			// It carries Helm bookkeeping annotations and managed-by label.
			helmPS := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			helmPS.Labels = map[string]string{
				"app.kubernetes.io/managed-by": "Helm",
			}
			helmPS.Annotations = map[string]string{
				constants.HelmResourcePolicy:       "keep",
				constants.HelmMetaReleaseName:      "kubewarden-defaults",
				constants.HelmMetaReleaseNamespace: "kubewarden",
			}
			Expect(k8sClient.Create(ctx, helmPS)).To(Succeed())

			// Now the ConfigMap is created, triggering the controller to adopt the resource.
			// Mirror the behavior of the chart: the ConfigMap YAML sets  `app.kubernetes.io/managed-by`
			// to `kubewarden-controller`, so when we reconcile, applyManagedKeys overwrites the
			// Helm value during the same reconcile that strips the Helm annotations.
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			ps.Labels = map[string]string{
				constants.ManagedByKey: constants.ManagedByKeyLabelValue,
			}
			policyServerYAML := marshalPolicyServer(ps)

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			adoptedPS := &policiesv1.PolicyServer{}
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, adoptedPS)).To(Succeed())
				// Helm annotations must be gone.
				g.Expect(adoptedPS.Annotations).NotTo(HaveKey(constants.HelmResourcePolicy))
				g.Expect(adoptedPS.Annotations).NotTo(HaveKey(constants.HelmMetaReleaseName))
				g.Expect(adoptedPS.Annotations).NotTo(HaveKey(constants.HelmMetaReleaseNamespace))
				// managed-by label must be updated to the controller value.
				g.Expect(adoptedPS.Labels).To(HaveKeyWithValue(constants.ManagedByKey, constants.ManagedByKeyLabelValue))
				// Ownership label must be stamped.
				g.Expect(adoptedPS.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
			}, timeout, pollInterval).Should(Succeed())
		})
	})

	Context("when ConfigMap has malformed YAML", func() {
		It("should skip the malformed entry and continue with others", func() {
			ps := policiesv1.NewPolicyServerFactory().WithName(policyServerName).WithoutFinalizers().Build()
			policyServerYAML := marshalPolicyServer(ps)

			malformedYAML := `this is not: valid: yaml: at: all`

			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      configMapName,
					Namespace: deploymentsNamespace,
				},
				Data: map[string]string{
					"policyserver-default": policyServerYAML,
					"malformed":            malformedYAML,
				},
			}
			Expect(k8sClient.Create(ctx, cm)).To(Succeed())

			createdPS := &policiesv1.PolicyServer{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: policyServerName}, createdPS)
			}, timeout, pollInterval).Should(Succeed())

			Expect(createdPS.Labels).To(HaveKeyWithValue(constants.DefaultsManagedByLabelKey, constants.DefaultsManagedByLabelValue))
		})
	})
})

func TestWebhookServiceIsReady(t *testing.T) {
	const (
		namespace   = "kubewarden"
		serviceName = "kubewarden-controller-webhook-service"
	)
	newEndpointSlice := func(service string, ready *bool) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      service + "-slice",
				Namespace: namespace,
				Labels:    map[string]string{discoveryv1.LabelServiceName: service},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: ready},
			}},
		}
	}

	tests := []struct {
		name           string
		endpointSlices []client.Object
		expected       bool
	}{
		{
			name:     "the service has no endpoint slice",
			expected: false,
		},
		{
			name:           "the service has an endpoint that is not ready",
			endpointSlices: []client.Object{newEndpointSlice(serviceName, ptr.To(false))},
			expected:       false,
		},
		{
			name:           "another service has a ready endpoint",
			endpointSlices: []client.Object{newEndpointSlice("other-service", ptr.To(true))},
			expected:       false,
		},
		{
			name:           "the service has a ready endpoint",
			endpointSlices: []client.Object{newEndpointSlice(serviceName, ptr.To(true))},
			expected:       true,
		},
		{
			name:           "the service has an endpoint with an unknown state",
			endpointSlices: []client.Object{newEndpointSlice(serviceName, nil)},
			expected:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().WithObjects(tc.endpointSlices...).Build()
			r := &DefaultsApplierReconciler{
				Client:               k8sClient,
				APIReader:            k8sClient,
				Log:                  logr.Discard(),
				DeploymentsNamespace: namespace,
				WebhookServiceName:   serviceName,
			}

			ready, err := r.webhookServiceIsReady(t.Context())

			require.NoError(t, err)
			require.Equal(t, tc.expected, ready)
		})
	}
}

func TestDefaultsApplierWaitsForTheWebhookService(t *testing.T) {
	const namespace = "kubewarden"
	policyServer := policiesv1.NewPolicyServerFactory().WithName("default").Build()
	policyServer.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("PolicyServer"))
	policyServerYAML, err := sigsyaml.Marshal(policyServer)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, policiesv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: constants.DefaultDefaultsConfigMapName, Namespace: namespace},
		Data:       map[string]string{"policyserver-default.yaml": string(policyServerYAML)},
	}).Build()
	r := &DefaultsApplierReconciler{
		Client:               k8sClient,
		APIReader:            k8sClient,
		Scheme:               scheme,
		Log:                  logr.Discard(),
		DeploymentsNamespace: namespace,
		ConfigMapName:        constants.DefaultDefaultsConfigMapName,
		WebhookServiceName:   "kubewarden-controller-webhook-service",
	}

	result, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: namespace, Name: constants.DefaultDefaultsConfigMapName},
	})

	require.NoError(t, err, "a webhook service with no ready endpoint is not an error")
	require.Equal(t, webhookServiceWaitInterval, result.RequeueAfter)
	policyServers := &policiesv1.PolicyServerList{}
	require.NoError(t, k8sClient.List(t.Context(), policyServers))
	require.Empty(t, policyServers.Items, "nothing is applied before the webhook service is ready")
}
