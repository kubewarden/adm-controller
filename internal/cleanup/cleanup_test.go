package cleanup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// k8sClient is the client for the envtest environment shared by all the
// tests. The tests are isolated from each other by using dedicated
// namespaces and unique names for the cluster-scoped resources.
var k8sClient client.Client

// thirdPartyFinalizer simulates a finalizer set by other tooling on a
// Kubewarden custom resource. The cleanup must not remove it.
const thirdPartyFinalizer = "example.com/third-party-finalizer"

func TestMain(m *testing.M) {
	crdsDir := filepath.Join("..", "..", "charts", "admission-controller", "templates", "crds")
	testEnv := &envtest.Environment{
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{
				filepath.Join(crdsDir, "policies.kubewarden.io_admissionpolicies.yaml"),
				filepath.Join(crdsDir, "policies.kubewarden.io_admissionpolicygroups.yaml"),
				filepath.Join(crdsDir, "policies.kubewarden.io_clusteradmissionpolicies.yaml"),
				filepath.Join(crdsDir, "policies.kubewarden.io_clusteradmissionpolicygroups.yaml"),
				filepath.Join(crdsDir, "policies.kubewarden.io_policyservers.yaml"),
			},
		},
	}

	restConfig, err := testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start the test environment: %v\n", err)
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add the client-go types to the scheme: %v\n", err)
		os.Exit(1)
	}
	if err := policiesv1.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "failed to add the Kubewarden types to the scheme: %v\n", err)
		os.Exit(1)
	}

	k8sClient, err = client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create the client: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop the test environment: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func TestRunOptionsValidation(t *testing.T) {
	err := Run(t.Context(), nil, logr.Discard(), Options{
		ControllerDeploymentName: "kubewarden-controller",
	})
	require.ErrorContains(t, err, "deployments namespace")

	err = Run(t.Context(), nil, logr.Discard(), Options{
		DeploymentsNamespace: "kubewarden",
	})
	require.ErrorContains(t, err, "controller deployment name")
}

func TestDeleteControllerDeployment(t *testing.T) {
	ctx := t.Context()
	namespace := "cleanup-test-controller-deployment"
	deploymentName := "kubewarden-controller"
	createNamespace(ctx, t, namespace)
	shortenPodsGoneWait(t)

	createDeployment(ctx, t, namespace, deploymentName, map[string]string{
		constants.ComponentLabelKey: constants.ComponentControllerLabelValue,
	})

	// A controller pod that never terminates: envtest has no kubelet, so the
	// pod object stays around until it is forcefully deleted.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "controller-pod",
			Namespace: namespace,
			Labels: map[string]string{
				constants.ComponentLabelKey: constants.ComponentControllerLabelValue,
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "controller", Image: "controller:test"},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, pod))

	opts := Options{DeploymentsNamespace: namespace, ControllerDeploymentName: deploymentName}

	// While a controller pod is still around, the wait must time out: the
	// following cleanup steps are only safe once no controller process can
	// recreate resources or re-add finalizers.
	err := deleteControllerDeployment(ctx, k8sClient, opts)
	require.ErrorContains(t, err, "failed to wait for the controller pods to be gone")

	// The Deployment deletion itself must have been issued regardless.
	assertNotFound(ctx, t, &appsv1.Deployment{}, namespace, deploymentName)

	require.NoError(t, k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0)))
	require.NoError(t, deleteControllerDeployment(ctx, k8sClient, opts))

	// Must be idempotent
	require.NoError(t, deleteControllerDeployment(ctx, k8sClient, opts))
}

func TestDeleteWebhookConfigurations(t *testing.T) {
	ctx := t.Context()

	partOfKubewardenLabels := map[string]string{
		constants.PartOfLabelKey: constants.PartOfLabelValue,
	}
	require.NoError(t, k8sClient.Create(ctx, &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "cleanup-test-webhook-validating",
			Labels: partOfKubewardenLabels,
		},
	}))
	require.NoError(t, k8sClient.Create(ctx, &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "cleanup-test-webhook-mutating",
			Labels: partOfKubewardenLabels,
		},
	}))
	// A webhook configuration not related to Kubewarden must be kept.
	require.NoError(t, k8sClient.Create(ctx, &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cleanup-test-webhook-unrelated",
		},
	}))

	require.NoError(t, deleteWebhookConfigurations(ctx, k8sClient))

	assertNotFound(ctx, t, &admissionregistrationv1.ValidatingWebhookConfiguration{}, "", "cleanup-test-webhook-validating")
	assertNotFound(ctx, t, &admissionregistrationv1.MutatingWebhookConfiguration{}, "", "cleanup-test-webhook-mutating")
	assertFound(ctx, t, &admissionregistrationv1.ValidatingWebhookConfiguration{}, "", "cleanup-test-webhook-unrelated")

	// Must be idempotent
	require.NoError(t, deleteWebhookConfigurations(ctx, k8sClient))
}

func TestStripKubewardenFinalizers(t *testing.T) {
	ctx := t.Context()
	namespace := "cleanup-test-strip"
	createNamespace(ctx, t, namespace)

	policyServer := policiesv1.NewPolicyServerFactory().
		WithName("cleanup-test-strip-policy-server").
		Build()
	policyServer.SetFinalizers([]string{
		constants.KubewardenFinalizer,
		constants.KubewardenFinalizerPre114,
		thirdPartyFinalizer,
	})
	require.NoError(t, k8sClient.Create(ctx, policyServer))

	clusterPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
		WithName("cleanup-test-strip-cluster-policy").
		Build()
	clusterPolicy.SetFinalizers([]string{constants.KubewardenFinalizer})
	require.NoError(t, k8sClient.Create(ctx, clusterPolicy))

	namespacedPolicy := policiesv1.NewAdmissionPolicyFactory().
		WithName("cleanup-test-strip-policy").
		WithNamespace(namespace).
		Build()
	namespacedPolicy.SetFinalizers([]string{constants.KubewardenFinalizer})
	require.NoError(t, k8sClient.Create(ctx, namespacedPolicy))

	clusterGroup := policiesv1.NewClusterAdmissionPolicyGroupFactory().
		WithName("cleanup-test-strip-cluster-group").
		Build()
	clusterGroup.SetFinalizers([]string{constants.KubewardenFinalizerPre114})
	require.NoError(t, k8sClient.Create(ctx, clusterGroup))

	namespacedGroup := policiesv1.NewAdmissionPolicyGroupFactory().
		WithName("cleanup-test-strip-group").
		WithNamespace(namespace).
		Build()
	namespacedGroup.SetFinalizers([]string{
		constants.KubewardenFinalizer,
		constants.KubewardenFinalizerPre114,
	})
	require.NoError(t, k8sClient.Create(ctx, namespacedGroup))

	// A resource with only third-party finalizers must be left untouched.
	untouchedPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
		WithName("cleanup-test-strip-untouched-policy").
		Build()
	untouchedPolicy.SetFinalizers([]string{thirdPartyFinalizer})
	require.NoError(t, k8sClient.Create(ctx, untouchedPolicy))

	require.NoError(t, stripKubewardenFinalizers(ctx, k8sClient))

	assertFinalizers(ctx, t, &policiesv1.PolicyServer{}, "", policyServer.GetName(), []string{thirdPartyFinalizer})
	assertFinalizers(ctx, t, &policiesv1.ClusterAdmissionPolicy{}, "", clusterPolicy.GetName(), nil)
	assertFinalizers(ctx, t, &policiesv1.AdmissionPolicy{}, namespace, namespacedPolicy.GetName(), nil)
	assertFinalizers(ctx, t, &policiesv1.ClusterAdmissionPolicyGroup{}, "", clusterGroup.GetName(), nil)
	assertFinalizers(ctx, t, &policiesv1.AdmissionPolicyGroup{}, namespace, namespacedGroup.GetName(), nil)
	assertFinalizers(ctx, t, &policiesv1.ClusterAdmissionPolicy{}, "", untouchedPolicy.GetName(), []string{thirdPartyFinalizer})

	// Must be idempotent
	require.NoError(t, stripKubewardenFinalizers(ctx, k8sClient))
}

func TestDeleteDefaultsResources(t *testing.T) {
	ctx := t.Context()

	defaultsLabels := map[string]string{
		constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue,
	}

	// A defaults resource without finalizers: it must be deleted right away.
	defaultPolicyServer := policiesv1.NewPolicyServerFactory().
		WithName("cleanup-test-defaults-policy-server").
		WithoutFinalizers().
		Build()
	defaultPolicyServer.SetLabels(defaultsLabels)
	require.NoError(t, k8sClient.Create(ctx, defaultPolicyServer))

	// A defaults resource with the Kubewarden finalizer still set: the
	// deletion is issued but does not complete. This documents why Run
	// must strip the Kubewarden finalizers before deleting the defaults.
	defaultPolicy := policiesv1.NewClusterAdmissionPolicyFactory().
		WithName("cleanup-test-defaults-policy").
		Build()
	defaultPolicy.SetLabels(defaultsLabels)
	defaultPolicy.SetFinalizers([]string{constants.KubewardenFinalizer})
	require.NoError(t, k8sClient.Create(ctx, defaultPolicy))

	// A user resource, not labeled as managed defaults: it must be kept.
	userPolicyServer := policiesv1.NewPolicyServerFactory().
		WithName("cleanup-test-defaults-user-policy-server").
		WithoutFinalizers().
		Build()
	require.NoError(t, k8sClient.Create(ctx, userPolicyServer))

	require.NoError(t, deleteDefaultsResources(ctx, k8sClient))

	assertNotFound(ctx, t, &policiesv1.PolicyServer{}, "", defaultPolicyServer.GetName())

	terminatingPolicy := &policiesv1.ClusterAdmissionPolicy{}
	assertFound(ctx, t, terminatingPolicy, "", defaultPolicy.GetName())
	require.NotNil(t, terminatingPolicy.GetDeletionTimestamp(),
		"the deletion of a defaults resource with finalizers should be issued but not complete")

	keptPolicyServer := &policiesv1.PolicyServer{}
	assertFound(ctx, t, keptPolicyServer, "", userPolicyServer.GetName())
	require.Nil(t, keptPolicyServer.GetDeletionTimestamp(), "user resources should be kept")

	// Must be idempotent
	require.NoError(t, deleteDefaultsResources(ctx, k8sClient))
}

func TestDeletePolicyServerResources(t *testing.T) {
	ctx := t.Context()
	namespace := "cleanup-test-policy-server-resources"
	resourcesName := "policy-server-cleanup-test"
	createNamespace(ctx, t, namespace)

	policyServerLabels := map[string]string{
		constants.PartOfLabelKey:       constants.PartOfLabelValue,
		constants.ComponentLabelKey:    constants.ComponentPolicyServerLabelValue,
		constants.PolicyServerLabelKey: "cleanup-test",
	}

	createDeployment(ctx, t, namespace, resourcesName, policyServerLabels)

	require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourcesName,
			Namespace: namespace,
			Labels:    policyServerLabels,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 443}},
		},
	}))

	require.NoError(t, k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourcesName,
			Namespace: namespace,
			Labels: map[string]string{
				constants.PartOfLabelKey:    constants.PartOfLabelValue,
				constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
			},
		},
	}))

	require.NoError(t, k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourcesName,
			Namespace: namespace,
			Labels:    policyServerLabels,
		},
	}))

	// A ConfigMap created by an older version of the controller, carrying
	// only the "kubewarden/policy-server" label.
	require.NoError(t, k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy-server-old-labels",
			Namespace: namespace,
			Labels: map[string]string{
				constants.PolicyServerLabelKey: "cleanup-test",
			},
		},
	}))

	minAvailable := intstr.FromInt32(1)
	require.NoError(t, k8sClient.Create(ctx, &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourcesName,
			Namespace: namespace,
			Labels:    policyServerLabels,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvailable,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "policy-server"},
			},
		},
	}))

	// Resources not related to Kubewarden must be kept.
	require.NoError(t, k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated-configmap", Namespace: namespace},
	}))
	require.NoError(t, k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "unrelated-secret", Namespace: namespace},
	}))

	// Chart-managed resources are part of Kubewarden but do not back a
	// policy server: they must be left for Helm to delete, not swept here.
	require.NoError(t, k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubewarden-ca",
			Namespace: namespace,
			Labels: map[string]string{
				constants.PartOfLabelKey:    constants.PartOfLabelValue,
				constants.ComponentLabelKey: constants.ComponentControllerLabelValue,
			},
		},
	}))
	require.NoError(t, k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubewarden-defaults",
			Namespace: namespace,
			Labels: map[string]string{
				constants.PartOfLabelKey: constants.PartOfLabelValue,
			},
		},
	}))

	// A policy server resource with a third-party finalizer: the deletion is
	// issued and the cleanup moves on without waiting or failing. Completing
	// the deletion is the responsibility of whoever owns the finalizer.
	require.NoError(t, k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "policy-server-third-party-finalizer",
			Namespace:  namespace,
			Labels:     policyServerLabels,
			Finalizers: []string{thirdPartyFinalizer},
		},
	}))

	require.NoError(t, deletePolicyServerResources(ctx, k8sClient, namespace))

	assertNotFound(ctx, t, &appsv1.Deployment{}, namespace, resourcesName)
	assertNotFound(ctx, t, &corev1.Service{}, namespace, resourcesName)
	assertNotFound(ctx, t, &corev1.Secret{}, namespace, resourcesName)
	assertNotFound(ctx, t, &corev1.ConfigMap{}, namespace, resourcesName)
	assertNotFound(ctx, t, &corev1.ConfigMap{}, namespace, "policy-server-old-labels")
	assertNotFound(ctx, t, &policyv1.PodDisruptionBudget{}, namespace, resourcesName)
	assertFound(ctx, t, &corev1.ConfigMap{}, namespace, "unrelated-configmap")
	assertFound(ctx, t, &corev1.Secret{}, namespace, "unrelated-secret")
	assertFound(ctx, t, &corev1.Secret{}, namespace, "kubewarden-ca")
	assertFound(ctx, t, &corev1.ConfigMap{}, namespace, "kubewarden-defaults")

	terminatingConfigMap := &corev1.ConfigMap{}
	assertFound(ctx, t, terminatingConfigMap, namespace, "policy-server-third-party-finalizer")
	require.NotNil(t, terminatingConfigMap.GetDeletionTimestamp(),
		"the deletion of a resource with a third-party finalizer should be issued but not complete")

	// Must be idempotent
	require.NoError(t, deletePolicyServerResources(ctx, k8sClient, namespace))
}

func TestDeleteControllerCertificateSecrets(t *testing.T) {
	ctx := t.Context()
	namespace := "cleanup-test-certificate-secrets"
	createNamespace(ctx, t, namespace)

	for _, name := range []string{
		constants.CARootSecretName,
		constants.WebhookServerCertSecretName,
		constants.AuditScannerClientCertSecretName,
	} {
		require.NoError(t, k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		}))
	}
	// A Secret that does not hold a certificate of the controller must be kept.
	require.NoError(t, k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "cleanup-test-unrelated"},
	}))

	require.NoError(t, deleteControllerCertificateSecrets(ctx, k8sClient, namespace))

	assertNotFound(ctx, t, &corev1.Secret{}, namespace, constants.CARootSecretName)
	assertNotFound(ctx, t, &corev1.Secret{}, namespace, constants.WebhookServerCertSecretName)
	assertNotFound(ctx, t, &corev1.Secret{}, namespace, constants.AuditScannerClientCertSecretName)
	assertFound(ctx, t, &corev1.Secret{}, namespace, "cleanup-test-unrelated")

	// Must be idempotent
	require.NoError(t, deleteControllerCertificateSecrets(ctx, k8sClient, namespace))
}

// TestRun verifies the composition of the cleanup steps, with one resource
// per category. The behavior of every step is covered by the per-step tests.
func TestRun(t *testing.T) {
	ctx := t.Context()
	namespace := "cleanup-test-run"
	deploymentName := "kubewarden-controller"
	createNamespace(ctx, t, namespace)
	shortenPodsGoneWait(t)

	createDeployment(ctx, t, namespace, deploymentName, map[string]string{
		constants.ComponentLabelKey: constants.ComponentControllerLabelValue,
	})

	require.NoError(t, k8sClient.Create(ctx, &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cleanup-test-run-webhook",
			Labels: map[string]string{
				constants.PartOfLabelKey: constants.PartOfLabelValue,
			},
		},
	}))

	// A defaults resource with the Kubewarden finalizer: its full removal
	// proves that Run strips the finalizers before deleting the defaults.
	defaultPolicyServer := policiesv1.NewPolicyServerFactory().
		WithName("cleanup-test-run-default-policy-server").
		Build()
	defaultPolicyServer.SetLabels(map[string]string{
		constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue,
	})
	defaultPolicyServer.SetFinalizers([]string{constants.KubewardenFinalizer})
	require.NoError(t, k8sClient.Create(ctx, defaultPolicyServer))

	userPolicyServer := policiesv1.NewPolicyServerFactory().
		WithName("cleanup-test-run-user-policy-server").
		Build()
	userPolicyServer.SetFinalizers([]string{constants.KubewardenFinalizer, thirdPartyFinalizer})
	require.NoError(t, k8sClient.Create(ctx, userPolicyServer))

	createDeployment(ctx, t, namespace, "policy-server-cleanup-test-run", map[string]string{
		constants.PartOfLabelKey:    constants.PartOfLabelValue,
		constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
	})

	require.NoError(t, k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.CARootSecretName},
	}))

	opts := Options{DeploymentsNamespace: namespace, ControllerDeploymentName: deploymentName}
	require.NoError(t, Run(ctx, k8sClient, logr.Discard(), opts))

	assertNotFound(ctx, t, &appsv1.Deployment{}, namespace, deploymentName)
	assertNotFound(ctx, t, &admissionregistrationv1.ValidatingWebhookConfiguration{}, "", "cleanup-test-run-webhook")
	assertNotFound(ctx, t, &policiesv1.PolicyServer{}, "", defaultPolicyServer.GetName())
	assertFinalizers(ctx, t, &policiesv1.PolicyServer{}, "", userPolicyServer.GetName(), []string{thirdPartyFinalizer})
	assertNotFound(ctx, t, &appsv1.Deployment{}, namespace, "policy-server-cleanup-test-run")
	assertNotFound(ctx, t, &corev1.Secret{}, namespace, constants.CARootSecretName)

	// The cleanup must be idempotent.
	require.NoError(t, Run(ctx, k8sClient, logr.Discard(), opts))
}

// createNamespace creates the given namespace. Namespaces are never deleted:
// envtest cannot garbage collect them, so every test uses a dedicated one.
func createNamespace(ctx context.Context, t *testing.T, name string) {
	t.Helper()

	require.NoError(t, k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}))
}

// createDeployment creates a minimal valid Deployment with the given labels.
func createDeployment(ctx context.Context, t *testing.T, namespace, name string, labels map[string]string) {
	t.Helper()

	require.NoError(t, k8sClient.Create(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "container", Image: "image:test"},
					},
				},
			},
		},
	}))
}

// shortenPodsGoneWait shrinks the controller pods wait tuning for the
// duration of the test, restoring it afterwards.
func shortenPodsGoneWait(t *testing.T) {
	t.Helper()

	originalTimeout := controllerPodsGoneTimeout
	originalPollInterval := controllerPodsGonePollInterval
	controllerPodsGoneTimeout = 2 * time.Second
	controllerPodsGonePollInterval = 50 * time.Millisecond
	t.Cleanup(func() {
		controllerPodsGoneTimeout = originalTimeout
		controllerPodsGonePollInterval = originalPollInterval
	})
}

func assertNotFound(ctx context.Context, t *testing.T, obj client.Object, namespace, name string) {
	t.Helper()

	err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj)
	require.Truef(t, apierrors.IsNotFound(err), "%T %s/%s should be deleted, got: %v", obj, namespace, name, err)
}

func assertFound(ctx context.Context, t *testing.T, obj client.Object, namespace, name string) {
	t.Helper()

	err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj)
	require.NoErrorf(t, err, "%T %s/%s should be kept", obj, namespace, name)
}

// assertFinalizers asserts that the object exists and carries exactly the
// given finalizers.
func assertFinalizers(ctx context.Context, t *testing.T, obj client.Object, namespace, name string, finalizers []string) {
	t.Helper()

	assertFound(ctx, t, obj, namespace, name)
	require.Equalf(t, finalizers, obj.GetFinalizers(), "unexpected finalizers on %T %s/%s", obj, namespace, name)
}
