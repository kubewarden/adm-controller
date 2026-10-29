/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/certs"
	"github.com/kubewarden/adm-controller/internal/constants"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var k8sClient client.Client

const (
	timeout              = 180 * time.Second
	pollInterval         = 250 * time.Millisecond
	consistencyTimeout   = 5 * time.Second
	deploymentsNamespace = "kubewarden-integration-tests"
	webhookServiceName   = "kubewarden-integration-tests-webhook-service"
)

// kubewardenCRDPaths returns the paths to the Kubewarden admission controller
// CRD files in the Helm chart. The imported policy-report CRDs are excluded
// because they are wrapped in Helm conditionals and cannot be parsed as plain
// YAML by envtest.
func kubewardenCRDPaths() []string {
	dir := filepath.Join("..", "..", "charts", "admission-controller", "templates", "crds")
	return []string{
		filepath.Join(dir, "policies.kubewarden.io_admissionpolicies.yaml"),
		filepath.Join(dir, "policies.kubewarden.io_admissionpolicygroups.yaml"),
		filepath.Join(dir, "policies.kubewarden.io_clusteradmissionpolicies.yaml"),
		filepath.Join(dir, "policies.kubewarden.io_clusteradmissionpolicygroups.yaml"),
		filepath.Join(dir, "policies.kubewarden.io_policyservers.yaml"),
	}
}

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = SynchronizedBeforeSuite(func() []byte {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	var ctx context.Context
	ctx, cancel := context.WithCancel(context.TODO())

	testEnv := &envtest.Environment{
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: kubewardenCRDPaths(),
		},
	}

	restConfig, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(restConfig).NotTo(BeNil())

	err = policiesv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(restConfig, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme.Scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	Expect(err).ToNot(HaveOccurred())

	err = (&AdmissionPolicyReconciler{
		Client:                  k8sManager.GetClient(),
		Scheme:                  k8sManager.GetScheme(),
		DeploymentsNamespace:    deploymentsNamespace,
		ControllerConfigMapName: constants.DefaultControllerConfigMapName,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&ClusterAdmissionPolicyReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&AdmissionPolicyGroupReconciler{
		Client:                  k8sManager.GetClient(),
		Scheme:                  k8sManager.GetScheme(),
		DeploymentsNamespace:    deploymentsNamespace,
		ControllerConfigMapName: constants.DefaultControllerConfigMapName,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&ClusterAdmissionPolicyGroupReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: true,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&PolicyServerReconciler{
		Client:                  k8sManager.GetClient(),
		Scheme:                  k8sManager.GetScheme(),
		DeploymentsNamespace:    deploymentsNamespace,
		ClientCAConfigMapName:   clientCAConfigMapName,
		ControllerConfigMapName: constants.DefaultControllerConfigMapName,
		ImagePullSecrets:        []corev1.LocalObjectReference{{Name: reconcilerImagePullSecret}},
		PolicyServerMetricsPort: constants.PolicyServerMetricsPort,
		TelemetryConfiguration: TelemetryConfiguration{
			MetricsEnabled: true,
		},
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&WebhookCABundleReconciler{
		Client:               k8sManager.GetClient(),
		Log:                  ctrl.Log.WithName("webhook-cabundle-test"),
		DeploymentsNamespace: deploymentsNamespace,
		CARootSecretName:     constants.CARootSecretName,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&DefaultsApplierReconciler{
		Client:               k8sManager.GetClient(),
		APIReader:            k8sManager.GetAPIReader(),
		Scheme:               k8sManager.GetScheme(),
		Log:                  ctrl.Log.WithName("defaults-applier-test"),
		DeploymentsNamespace: deploymentsNamespace,
		ConfigMapName:        constants.DefaultDefaultsConfigMapName,
		WebhookServiceName:   webhookServiceName,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	// Create the integration tests deployments namespace
	err = k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: deploymentsNamespace,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	// Create the CA root secret
	caCertBytes, caPrivateKey, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	Expect(err).NotTo(HaveOccurred())
	err = k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.CARootSecretName,
			Namespace: deploymentsNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			constants.CARootCert:       caCertBytes,
			constants.CARootPrivateKey: caPrivateKey,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	// Envtest runs no controller pod and no EndpointSlice controller. Create the ready endpoint that the webhook
	// Service of a running controller has, so that the defaults applier applies the defaults.
	err = k8sClient.Create(ctx, &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webhookServiceName,
			Namespace: deploymentsNamespace,
			Labels:    map[string]string{discoveryv1.LabelServiceName: webhookServiceName},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{{
			Addresses:  []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr.To(true)},
		}},
	})
	Expect(err).NotTo(HaveOccurred())

	// Create the controller configuration ConfigMap. The configuration holds
	// the allow list of resources for namespaced policies
	err = k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.DefaultControllerConfigMapName,
			Namespace: deploymentsNamespace,
		},
		Data: map[string]string{
			constants.ControllerConfigKey: testControllerConfigYAML,
		},
	})
	Expect(err).NotTo(HaveOccurred())

	// Create the client CA config map
	clientCACertBytes, _, err := certs.GenerateCA(time.Now(), time.Now().Add(constants.CACertExpiration))
	Expect(err).NotTo(HaveOccurred())
	err = k8sClient.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clientCAConfigMapName,
			Namespace: deploymentsNamespace,
		},
		Data: map[string]string{
			constants.ClientCACert: string(clientCACertBytes),
		},
	})
	Expect(err).NotTo(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err := k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred(), "failed to run manager")
	}()

	DeferCleanup(func() {
		By("tearing down the test environment")
		cancel()

		err := testEnv.Stop()
		Expect(err).ToNot(HaveOccurred(), "failed to tear down the test environment")
	})

	// Convert rest.Config in api.Config so we write it to bytes
	config := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"default": {
				Server:                   restConfig.Host,
				CertificateAuthorityData: restConfig.CAData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"default": {
				ClientCertificateData: restConfig.CertData,
				ClientKeyData:         restConfig.KeyData,
				Username:              restConfig.Username,
				Password:              restConfig.Password,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"default": {
				Cluster:  "default",
				AuthInfo: "default",
			},
		},
		CurrentContext: "default",
	}
	configBytes, err := clientcmd.Write(config)
	Expect(err).NotTo(HaveOccurred())

	return configBytes
}, func(configBytes []byte) {
	By("connecting to the test environment")
	if k8sClient != nil {
		return
	}

	config, err := clientcmd.Load(configBytes)
	Expect(err).NotTo(HaveOccurred())
	restConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
	restConfig.QPS = 1000.0
	restConfig.Burst = 2000.0
	Expect(err).NotTo(HaveOccurred())

	err = policiesv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(restConfig, client.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).NotTo(HaveOccurred())
})
