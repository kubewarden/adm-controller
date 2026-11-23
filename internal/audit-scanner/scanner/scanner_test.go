package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	auditConstants "github.com/kubewarden/adm-controller/internal/audit-scanner/constants"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/k8s"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/policies"
	"github.com/kubewarden/adm-controller/internal/audit-scanner/report"
	auditscheme "github.com/kubewarden/adm-controller/internal/audit-scanner/scheme"
	openreports "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apimachineryErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	testingclient "k8s.io/client-go/testing"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"

	"github.com/kubewarden/adm-controller/internal/audit-scanner/testutils"
)

const (
	parallelNamespacesAudits = 1
	parallelResourcesAudits  = 10
	parallelPoliciesAudits   = 2
	pageSize                 = 100
)

func newTestConfig(policiesClient *policies.Client, k8sClient *k8s.Client, reportStore report.Store) Config {
	return Config{
		PoliciesClient: policiesClient,
		K8sClient:      k8sClient,
		ReportStore:    reportStore,
		Parallelization: ParallelizationConfig{
			ParallelNamespacesAudits: parallelNamespacesAudits,
			ParallelResourcesAudits:  parallelResourcesAudits,
			PoliciesAudits:           parallelPoliciesAudits,
		},
		OutputScan:   false,
		DisableStore: false,
		Logger:       slog.Default(),
		ReportKind:   report.ReportKindPolicyReport,
	}
}

func newMockPolicyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)

		admissionReview := admissionv1.AdmissionReview{
			Response: &admissionv1.AdmissionResponse{
				Allowed: true,
				Result:  nil,
			},
		}
		response, err := json.Marshal(admissionReview)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}

		_, err = writer.Write(response)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func newMockPolicyServerWithErrors() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
	}))
}

func newMockPolicyServerWithMTLS(caCert, serverCert, serverKey []byte) *httptest.Server {
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		panic("failed to load server certificate: " + err.Error())
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		panic("failed to parse root certificate")
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		writer.WriteHeader(http.StatusOK)

		admissionReview := admissionv1.AdmissionReview{
			Response: &admissionv1.AdmissionResponse{
				Allowed: true,
				Result:  nil,
			},
		}
		response, err := json.Marshal(admissionReview)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)

			return
		}

		_, err = writer.Write(response)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()

	return server
}

// TODO: drop once we support only OpenReports
func TestScanAllNamespacesWithPolicyReport(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			UID:       "pod1-uid",
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
			UID:       "pod2-uid",
		},
	}

	deployment1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment1",
			Namespace: "namespace1",
			UID:       "deployment1-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	deployment2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment2",
			Namespace: "namespace2",
			UID:       "deployment2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// an AdmissionPolicy targeting pods in namespace1
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy1").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting deployments in namespace2
	admissionPolicy2 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy2").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that matches deployment1 in namespace1
	admissionPolicy3 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy3").
		Namespace("namespace1").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that does not match any deployment in namespace2
	admissionPolicy4 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy4").
		Namespace("namespace2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting an unknown GVR, should be counted as error
	admissionPolicy5 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy5").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting a GVR with *, should be skipped
	admissionPolicy6 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy6").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting pods and deployments in all namespaces
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicyGroup targeting pods
	clusterAdmissionPolicyGroup := testutils.
		NewClusterAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicyGroup targeting deployments in namespace2
	admissionPolicyGroup := testutils.
		NewAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldPolicyReportRunUID := uuid.New().String()
	oldPolicyReport := testutils.NewPolicyReportFactory().
		Name("oldPolicyReport").
		Namespace(namespace1.GetName()).
		WithAppLabel().
		RunUID(oldPolicyReportRunUID).
		Build()

	auditScheme, err := auditscheme.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		auditScheme,
		deployment1,
		deployment2,
		pod1,
		pod2,
		namespace1,
		oldPolicyReport)
	clientset := fake.NewClientset(
		namespace1,
		namespace2,
	)
	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		admissionPolicy5,
		admissionPolicy6,
		clusterAdmissionPolicy,
		clusterAdmissionPolicyGroup,
		admissionPolicyGroup,
		oldPolicyReport,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)

	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)

	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanAllNamespaces(t.Context(), runUID)
	require.NoError(t, err)

	policyReport := wgpolicy.PolicyReport{}

	err = client.Get(t.Context(), types.NamespacedName{Name: oldPolicyReport.GetName(), Namespace: oldPolicyReport.GetNamespace()}, oldPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod1.GetUID()), Namespace: "namespace1"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 3, policyReport.Summary.Pass)
	assert.Equal(t, 1, policyReport.Summary.Error)
	assert.Equal(t, 1, policyReport.Summary.Skip)
	assert.Len(t, policyReport.Results, 3)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod2.GetUID()), Namespace: "namespace2"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 3, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 3)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(deployment1.GetUID()), Namespace: "namespace1"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Equal(t, 1, policyReport.Summary.Error)
	assert.Equal(t, 1, policyReport.Summary.Skip)
	assert.Len(t, policyReport.Results, 2)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(deployment2.GetUID()), Namespace: "namespace2"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 2)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}

// TODO: drop once we support only OpenReports
func TestScanClusterWideResourcesWithPolicyReport(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			UID:  "namespace1-uid",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
			UID:  "namespace2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// a ClusterAdmissionPolicy targeting namespaces
	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that matches namespace2
	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that does not match any namespace
	clusterAdmissionPolicy3 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy3").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting an unknown GVR, should be counted as error
	clusterAdmissionPolicy4 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy4").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"foo"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting a GVR with *, should be counted as skipped
	clusterAdmissionPolicy5 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy5").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicyGroup targeting namespaces
	clusterAdmissionPolicyGroup := testutils.
		NewClusterAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldClusterPolicyReportRunUID := uuid.New().String()
	oldClusterPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("oldClusterPolicyReport").
		WithAppLabel().
		RunUID(oldClusterPolicyReportRunUID).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		namespace1,
		namespace2,
		oldClusterPolicyReport,
	)
	clientset := fake.NewClientset(
		namespace1,
		namespace2,
	)
	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
		clusterAdmissionPolicy4,
		clusterAdmissionPolicy5,
		clusterAdmissionPolicyGroup,
		oldClusterPolicyReport,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)

	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)

	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanClusterWideResources(t.Context(), runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: oldClusterPolicyReport.GetName()}, oldClusterPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	clusterPolicyReport := wgpolicy.ClusterPolicyReport{}

	err = client.Get(t.Context(), types.NamespacedName{Name: string(namespace1.GetUID())}, &clusterPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, clusterPolicyReport.Summary.Pass)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Error)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Skip)
	assert.Len(t, clusterPolicyReport.Results, 2)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(namespace2.GetUID())}, &clusterPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 3, clusterPolicyReport.Summary.Pass)
	assert.Len(t, clusterPolicyReport.Results, 3)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}

func TestScanWithHTTPErrors(t *testing.T) {
	mockPolicyServerWithErrors := newMockPolicyServerWithErrors()
	defer mockPolicyServerWithErrors.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace",
			UID:  "namespace-uid",
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod",
			Namespace: "namespace",
			UID:       "pod-uid",
		},
	}

	// an AdmissionPolicy targeting pods
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods", "namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	auditScheme, err := auditscheme.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		auditScheme,
		namespace,
		pod,
	)
	clientset := fake.NewClientset(
		namespace,
	)
	client, err := testutils.NewFakeClient(
		namespace,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)

	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServerWithErrors.URL, logger)

	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanAllNamespaces(t.Context(), runUID)
	require.NoError(t, err)
	err = scanner.ScanClusterWideResources(t.Context(), runUID)
	require.NoError(t, err)

	podPolicyReport := wgpolicy.PolicyReport{}
	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod.GetUID()), Namespace: "namespace"}, &podPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 0, podPolicyReport.Summary.Pass)
	assert.Equal(t, 1, podPolicyReport.Summary.Error)
	assert.Equal(t, 0, podPolicyReport.Summary.Skip)
	assert.Len(t, podPolicyReport.Results, 1)

	namespacePolicyReport := wgpolicy.ClusterPolicyReport{}
	err = client.Get(t.Context(), types.NamespacedName{Name: string(namespace.GetUID())}, &namespacePolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 0, namespacePolicyReport.Summary.Pass)
	assert.Equal(t, 1, namespacePolicyReport.Summary.Error)
	assert.Equal(t, 0, namespacePolicyReport.Summary.Skip)
	assert.Len(t, namespacePolicyReport.Results, 1)
}

func TestScanWithMTLS(t *testing.T) {
	caCertPEM, caKeyPEM, err := testutils.GenerateTestCA()
	require.NoError(t, err)
	serverCertPEM, serverKeyPEM, err := testutils.GenerateTestCert(caCertPEM, caKeyPEM, "server")
	require.NoError(t, err)
	clientCertPEM, clientKeyPEM, err := testutils.GenerateTestCert(caCertPEM, caKeyPEM, "client")
	require.NoError(t, err)

	caCertFile, err := testutils.WriteTempFile(caCertPEM)
	require.NoError(t, err)
	clientCertFile, err := testutils.WriteTempFile(clientCertPEM)
	require.NoError(t, err)
	clientKeyFile, err := testutils.WriteTempFile(clientKeyPEM)
	require.NoError(t, err)

	mockPolicyServer := newMockPolicyServerWithMTLS(caCertPEM, serverCertPEM, serverKeyPEM)
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace",
			UID:  "namespace-uid",
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod",
			Namespace: "namespace",
			UID:       "pod-uid",
		},
	}

	// a ClusterAdmissionPolicy targeting pods
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	auditScheme, err := auditscheme.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		auditScheme,
		namespace,
		pod,
	)
	clientset := fake.NewClientset(
		namespace,
	)
	client, err := testutils.NewFakeClient(
		namespace,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)

	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)

	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	config.TLS = TLSConfig{
		CAFile:         caCertFile,
		ClientCertFile: clientCertFile,
		ClientKeyFile:  clientKeyFile,
	}
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanAllNamespaces(t.Context(), runUID)
	require.NoError(t, err)

	podPolicyReport := wgpolicy.PolicyReport{}
	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod.GetUID()), Namespace: "namespace"}, &podPolicyReport)
	require.NoError(t, err)

	logger.Debug("podPolicyReport",
		slog.Any("podPolicyReport", podPolicyReport))

	assert.Equal(t, 1, podPolicyReport.Summary.Pass)
	assert.Equal(t, 0, podPolicyReport.Summary.Error)
	assert.Equal(t, 0, podPolicyReport.Summary.Skip)
	assert.Len(t, podPolicyReport.Results, 1)
}

// This test has been created to ensure that the scanner can handle
// failures when scanning resources.
func TestScanFailureClusterWideResources(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			UID:  "namespace1-uid",
		},
	}
	webhook1 := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "webhook1",
			UID:  "webhook1-uid",
		},
	}
	webhook2 := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "webhook2",
			UID:  "webhook2-uid",
		},
	}

	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{admissionregistrationv1.GroupName},
			APIVersions: []string{"v1"},
			Resources:   []string{"validatingwebhookconfigurations"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldClusterPolicyReportRunUID := uuid.New().String()
	oldClusterPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("oldClusterPolicyReport").
		WithAppLabel().
		RunUID(oldClusterPolicyReportRunUID).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		namespace1,
		webhook1,
		webhook2,
		oldClusterPolicyReport,
	)
	clientset := fake.NewClientset()
	client, err := testutils.NewFakeClient(
		namespace1,
		webhook1,
		webhook2,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		oldClusterPolicyReport,
	)
	require.NoError(t, err)

	// Simulate a failure when listing ValidatingWebhookConfigurations
	dynamicClient.PrependReactor("list", "validatingwebhookconfigurations", func(action testingclient.Action) (bool, runtime.Object, error) {
		return true, nil, apimachineryErrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("reactor error"))
	})

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, 1, logger)
	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanClusterWideResources(t.Context(), runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: oldClusterPolicyReport.GetName()}, oldClusterPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	clusterPolicyReportList := &wgpolicy.ClusterPolicyReportList{}
	err = client.List(t.Context(), clusterPolicyReportList)
	require.NoError(t, err)
	assert.Len(t, clusterPolicyReportList.Items, 1)

	clusterPolicyReport := clusterPolicyReportList.Items[0]
	require.NoError(t, err)
	assert.Equal(t, string(namespace1.GetUID()), clusterPolicyReport.GetName())
	assert.Equal(t, 1, clusterPolicyReport.Summary.Pass)
	assert.Equal(t, 0, clusterPolicyReport.Summary.Error)
	assert.Equal(t, 0, clusterPolicyReport.Summary.Skip)
	assert.Len(t, clusterPolicyReport.Results, 1)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}

func TestScanFailureAllNamespaces(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			UID:       "pod1-uid",
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
			UID:       "pod2-uid",
		},
	}

	deployment1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment1",
			Namespace: "namespace1",
			UID:       "deployment1-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	deployment2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment2",
			Namespace: "namespace2",
			UID:       "deployment2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// an AdmissionPolicy targeting pods in namespace1
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy1").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting deployments in namespace2
	admissionPolicy2 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy2").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that matches deployment1 in namespace1
	admissionPolicy3 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy3").
		Namespace("namespace1").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that does not match any deployment in namespace2
	admissionPolicy4 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy4").
		Namespace("namespace2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting an unknown GVR, should be counted as error
	admissionPolicy5 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy5").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting a GVR with *, should be skipped
	admissionPolicy6 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy6").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting pods and deployments in all namespaces
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicyGroup targeting pods
	clusterAdmissionPolicyGroup := testutils.
		NewClusterAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicyGroup targeting deployments in namespace2
	admissionPolicyGroup := testutils.
		NewAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldPolicyReportRunUID := uuid.New().String()
	oldPolicyReport := testutils.NewPolicyReportFactory().
		Name("oldPolicyReport").
		Namespace(namespace1.GetName()).
		WithAppLabel().
		RunUID(oldPolicyReportRunUID).
		Build()

	auditScheme, err := auditscheme.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		auditScheme,
		deployment1,
		deployment2,
		pod1,
		pod2,
		namespace1,
		oldPolicyReport)
	clientset := fake.NewClientset(
		namespace1,
		namespace2,
	)

	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		admissionPolicy5,
		admissionPolicy6,
		clusterAdmissionPolicy,
		clusterAdmissionPolicyGroup,
		admissionPolicyGroup,
		oldPolicyReport,
	)
	require.NoError(t, err)

	// Simulate a failure when getting one of the namespaces.
	clientset.PrependReactor("get", "namespaces", func(action testingclient.Action) (bool, runtime.Object, error) {
		getAction, ok := action.(testingclient.GetActionImpl)
		if !ok {
			return false, nil, nil
		}
		if getAction.GetName() == "namespace2" {
			return true, nil, apimachineryErrors.NewBadRequest("reactor error")
		}

		get, err := clientset.Tracker().Get(getAction.GetResource(), getAction.GetNamespace(), getAction.GetName(), getAction.GetOptions)
		if err != nil {
			return false, nil, err
		}
		return true, get, nil
	})

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanAllNamespaces(t.Context(), runUID)
	require.Error(t, err)
	require.ErrorContains(t, err, "reactor error")

	policyReport := wgpolicy.PolicyReport{}

	err = client.Get(t.Context(), types.NamespacedName{Name: oldPolicyReport.GetName(), Namespace: oldPolicyReport.GetNamespace()}, oldPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod1.GetUID()), Namespace: "namespace1"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 3, policyReport.Summary.Pass)
	assert.Equal(t, 1, policyReport.Summary.Error)
	assert.Equal(t, 1, policyReport.Summary.Skip)
	assert.Len(t, policyReport.Results, 3)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(deployment1.GetUID()), Namespace: "namespace1"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Equal(t, 1, policyReport.Summary.Error)
	assert.Equal(t, 1, policyReport.Summary.Skip)
	assert.Len(t, policyReport.Results, 2)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	// List all policy report from the namespace1
	reports := &wgpolicy.PolicyReportList{}
	err = client.List(t.Context(), reports)
	require.NoError(t, err)
	require.Len(t, reports.Items, 2)
}

func TestScanAllNamespacesFailsWhenNamespacesCannotBeListed(t *testing.T) {
	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme)
	clientset := fake.NewClientset()
	client, err := testutils.NewFakeClient()
	require.NoError(t, err)

	// Simulate a failure when listing the namespaces.
	clientset.PrependReactor("list", "namespaces", func(_ testingclient.Action) (bool, runtime.Object, error) {
		return true, nil, apimachineryErrors.NewServiceUnavailable("reactor error")
	})

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", "", logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	err = scanner.ScanAllNamespaces(t.Context(), uuid.New().String())
	require.Error(t, err)
	require.ErrorContains(t, err, "reactor error")
}

func TestScanAllNamespacesWithOpenReport(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			UID:       "pod1-uid",
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
			UID:       "pod2-uid",
		},
	}

	deployment1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment1",
			Namespace: "namespace1",
			UID:       "deployment1-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	deployment2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment2",
			Namespace: "namespace2",
			UID:       "deployment2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// an AdmissionPolicy targeting pods in namespace1
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy1").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting deployments in namespace2
	admissionPolicy2 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy2").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that matches deployment1 in namespace1
	admissionPolicy3 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy3").
		Namespace("namespace1").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that does not match any deployment in namespace2
	admissionPolicy4 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy4").
		Namespace("namespace2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting an unknown GVR, should be counted as error
	admissionPolicy5 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy5").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting a GVR with *, should be skipped
	admissionPolicy6 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy6").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting pods and deployments in all namespaces
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicyGroup targeting pods
	clusterAdmissionPolicyGroup := testutils.
		NewClusterAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicyGroup targeting deployments in namespace2
	admissionPolicyGroup := testutils.
		NewAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldPolicyReportRunUID := uuid.New().String()
	oldPolicyReport := testutils.NewPolicyReportFactory().
		Name("oldPolicyReport").
		Namespace(namespace1.GetName()).
		WithAppLabel().
		RunUID(oldPolicyReportRunUID).
		BuildOpenReports()

	auditScheme, err := auditscheme.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		auditScheme,
		deployment1,
		deployment2,
		pod1,
		pod2,
		namespace1,
		oldPolicyReport)
	clientset := fake.NewClientset(
		namespace1,
		namespace2,
	)
	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		admissionPolicy5,
		admissionPolicy6,
		clusterAdmissionPolicy,
		clusterAdmissionPolicyGroup,
		admissionPolicyGroup,
		oldPolicyReport,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)

	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)

	openReportStore := report.NewOpenReportStore(client, logger)
	config := newTestConfig(policiesClient, k8sClient, openReportStore)
	config.ReportKind = report.ReportKindOpenReport
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanAllNamespaces(t.Context(), runUID)
	require.NoError(t, err)

	report := openreports.Report{}

	err = client.Get(t.Context(), types.NamespacedName{Name: oldPolicyReport.GetName(), Namespace: oldPolicyReport.GetNamespace()}, oldPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod1.GetUID()), Namespace: "namespace1"}, &report)
	require.NoError(t, err)
	assert.Equal(t, 3, report.Summary.Pass)
	assert.Equal(t, 1, report.Summary.Error)
	assert.Equal(t, 1, report.Summary.Skip)
	assert.Len(t, report.Results, 3)
	assert.Equal(t, runUID, report.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod2.GetUID()), Namespace: "namespace2"}, &report)
	require.NoError(t, err)
	assert.Equal(t, 3, report.Summary.Pass)
	assert.Len(t, report.Results, 3)
	assert.Equal(t, runUID, report.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(deployment1.GetUID()), Namespace: "namespace1"}, &report)
	require.NoError(t, err)
	assert.Equal(t, 2, report.Summary.Pass)
	assert.Equal(t, 1, report.Summary.Error)
	assert.Equal(t, 1, report.Summary.Skip)
	assert.Len(t, report.Results, 2)
	assert.Equal(t, runUID, report.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(deployment2.GetUID()), Namespace: "namespace2"}, &report)
	require.NoError(t, err)
	assert.Equal(t, 2, report.Summary.Pass)
	assert.Len(t, report.Results, 2)
	assert.Equal(t, runUID, report.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}

func TestScanClusterWideResourcesWithOpenReport(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app.kubernetes.io/instance": "policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			UID:  "namespace1-uid",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
			UID:  "namespace2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// a ClusterAdmissionPolicy targeting namespaces
	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that matches namespace2
	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that does not match any namespace
	clusterAdmissionPolicy3 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy3").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting an unknown GVR, should be counted as error
	clusterAdmissionPolicy4 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy4").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"foo"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting a GVR with *, should be counted as skipped
	clusterAdmissionPolicy5 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("clusterAdmissionPolicy5").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicyGroup targeting namespaces
	clusterAdmissionPolicyGroup := testutils.
		NewClusterAdmissionPolicyGroupFactory().
		Name("clusterAdmissionPolicyGroup").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldClusterPolicyReportRunUID := uuid.New().String()
	oldClusterPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("oldClusterPolicyReport").
		WithAppLabel().
		RunUID(oldClusterPolicyReportRunUID).
		BuildOpenReports()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		namespace1,
		namespace2,
		oldClusterPolicyReport,
	)
	clientset := fake.NewClientset(
		namespace1,
		namespace2,
	)
	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
		clusterAdmissionPolicy4,
		clusterAdmissionPolicy5,
		clusterAdmissionPolicyGroup,
		oldClusterPolicyReport,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)

	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)

	openReportStore := report.NewOpenReportStore(client, logger)
	config := newTestConfig(policiesClient, k8sClient, openReportStore)
	config.ReportKind = report.ReportKindOpenReport
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanClusterWideResources(t.Context(), runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: oldClusterPolicyReport.GetName()}, oldClusterPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	clusterPolicyReport := openreports.ClusterReport{}

	err = client.Get(t.Context(), types.NamespacedName{Name: string(namespace1.GetUID())}, &clusterPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, clusterPolicyReport.Summary.Pass)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Error)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Skip)
	assert.Len(t, clusterPolicyReport.Results, 2)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(t.Context(), types.NamespacedName{Name: string(namespace2.GetUID())}, &clusterPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 3, clusterPolicyReport.Summary.Pass)
	assert.Len(t, clusterPolicyReport.Results, 3)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}

// TestScanNamespaceWithNoAuditablePoliciesDeletesAllManagedReports covers the
// bulk-delete fast path: when no policy targets any resource in a namespace,
// no report can have been written during the scan, so every kubewarden-managed
// report found for that namespace must be deleted regardless of its
// run-uid label.
func TestScanNamespaceWithNoAuditablePoliciesDeletesAllManagedReports(t *testing.T) {
	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			UID:  "namespace1-uid",
		},
	}

	// A managed report left over from a previous scan, when a policy still
	// targeted this namespace.
	staleReport := testutils.NewPolicyReportFactory().
		Name("stale-report").Namespace("namespace1").WithAppLabel().Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme, namespace1)
	clientset := fake.NewClientset(namespace1)
	client, err := testutils.NewFakeClient(namespace1, staleReport)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", "", logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanNamespace(t.Context(), "namespace1", runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: "stale-report", Namespace: "namespace1"}, &wgpolicy.PolicyReport{})
	require.True(t, apimachineryErrors.IsNotFound(err))
}

// TestScanClusterWideResourcesWithNoAuditablePoliciesDeletesAllManagedReports
// is the cluster-scoped counterpart of
// TestScanNamespaceWithNoAuditablePoliciesDeletesAllManagedReports.
func TestScanClusterWideResourcesWithNoAuditablePoliciesDeletesAllManagedReports(t *testing.T) {
	staleClusterReport := testutils.NewClusterPolicyReportFactory().
		Name("stale-cluster-report").WithAppLabel().Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme)
	clientset := fake.NewClientset()
	client, err := testutils.NewFakeClient(staleClusterReport)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", "", logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanClusterWideResources(t.Context(), runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: "stale-cluster-report"}, &wgpolicy.ClusterPolicyReport{})
	require.True(t, apimachineryErrors.IsNotFound(err))
}

// TestScanNamespaceWithDisableStoreSkipsFastPathDeletion covers --disable-store
// in the bulk-delete fast path (no auditable policies target the namespace):
// a pre-existing managed report must survive the scan, since --disable-store
// must not result in the deletion of any resource in the cluster.
func TestScanNamespaceWithDisableStoreSkipsFastPathDeletion(t *testing.T) {
	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			UID:  "namespace1-uid",
		},
	}

	staleReport := testutils.NewPolicyReportFactory().
		Name("stale-report").Namespace("namespace1").WithAppLabel().Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme, namespace1)
	clientset := fake.NewClientset(namespace1)
	client, err := testutils.NewFakeClient(namespace1, staleReport)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", "", logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	config.DisableStore = true
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanNamespace(t.Context(), "namespace1", runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: "stale-report", Namespace: "namespace1"}, &wgpolicy.PolicyReport{})
	require.NoError(t, err, "--disable-store must not delete existing reports")
}

// TestScanClusterWideResourcesWithDisableStoreSkipsFastPathDeletion is the
// cluster-scoped counterpart of
// TestScanNamespaceWithDisableStoreSkipsFastPathDeletion.
func TestScanClusterWideResourcesWithDisableStoreSkipsFastPathDeletion(t *testing.T) {
	staleClusterReport := testutils.NewClusterPolicyReportFactory().
		Name("stale-cluster-report").WithAppLabel().Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme)
	clientset := fake.NewClientset()
	client, err := testutils.NewFakeClient(staleClusterReport)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", "", logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	config.DisableStore = true
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanClusterWideResources(t.Context(), runUID)
	require.NoError(t, err)

	err = client.Get(t.Context(), types.NamespacedName{Name: "stale-cluster-report"}, &wgpolicy.ClusterPolicyReport{})
	require.NoError(t, err, "--disable-store must not delete existing reports")
}

// TestScanNamespaceWithDisableStoreSkipsDeletionAndCreation covers
// --disable-store on the per-item write-set path (at least one policy is
// auditable in the namespace): a pre-existing stale managed report must
// survive the scan, and no report must be created for the audited resource,
// since --disable-store must not result in the deletion or creation of any
// resource in the cluster.
func TestScanNamespaceWithDisableStoreSkipsDeletionAndCreation(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}
	policyServerService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels:    map[string]string{"app.kubernetes.io/instance": "policy-server-default"},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 443}},
		},
	}

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "namespace1"},
	}
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "namespace1", UID: "pod1-uid"},
	}

	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("admissionPolicy1").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// A managed report left over from a previous scan, unrelated to pod1, so
	// it would be considered stale by the write-set based GC.
	staleReport := testutils.NewPolicyReportFactory().
		Name("stale-report").Namespace("namespace1").WithAppLabel().Build()

	auditScheme, err := auditscheme.NewScheme()
	require.NoError(t, err)
	dynamicClient := dynamicFake.NewSimpleDynamicClient(auditScheme, pod1, namespace1)
	clientset := fake.NewClientset(namespace1)
	client, err := testutils.NewFakeClient(
		namespace1,
		policyServer,
		policyServerService,
		admissionPolicy1,
		staleReport,
	)
	require.NoError(t, err)

	logger := slog.Default()
	k8sClient := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize, logger)
	policiesClient := policies.NewClient(client, "kubewarden", mockPolicyServer.URL, logger)
	policyReportStore := report.NewPolicyReportStore(client, logger)

	config := newTestConfig(policiesClient, k8sClient, policyReportStore)
	config.DisableStore = true
	scanner, err := NewScanner(config)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanNamespace(t.Context(), "namespace1", runUID)
	require.NoError(t, err)

	// the stale report must survive: --disable-store must not delete it
	err = client.Get(t.Context(), types.NamespacedName{Name: "stale-report", Namespace: "namespace1"}, &wgpolicy.PolicyReport{})
	require.NoError(t, err, "--disable-store must not delete existing reports")

	// no report must have been created for pod1: --disable-store must not
	// create new reports either
	err = client.Get(t.Context(), types.NamespacedName{Name: string(pod1.GetUID()), Namespace: "namespace1"}, &wgpolicy.PolicyReport{})
	require.True(t, apimachineryErrors.IsNotFound(err), "--disable-store must not create new reports")
}
