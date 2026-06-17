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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// newTestScheme returns a runtime.Scheme with the PolicyServer types
// registered, which is needed by updateService (SetOwnerReference).
func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = policiesv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}

// newPolicyServer builds a minimal PolicyServer for unit tests.
// It sets the GVK so SetOwnerReference can resolve the owner.
func newPolicyServer(name string, metricsPort *int32) *policiesv1.PolicyServer {
	ps := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  "test-uid",
		},
		Spec: policiesv1.PolicyServerSpec{
			MetricsPort: metricsPort,
		},
	}
	ps.SetGroupVersionKind(policiesv1.GroupVersion.WithKind("PolicyServer"))
	return ps
}

func int32Ptr(v int32) *int32 { return &v }

// findServicePort returns the ServicePort with the given name, or nil.
func findServicePort(ports []corev1.ServicePort, name string) *corev1.ServicePort {
	for i := range ports {
		if ports[i].Name == name {
			return &ports[i]
		}
	}
	return nil
}

// TestUpdateServiceMetricsPortPriorityChain validates the 3-tier priority
// chain for the metrics Service Port:
//
//	CRD field (spec.metricsPort) > --policy-server-metrics-port CLI flag > deprecated env var > constant (8080)
//
// It also verifies that the Service TargetPort is always fixed at the
// controller-wide PolicyServerMetricsPort regardless of any CRD override.
// This is intentional: when the OpenTelemetry sidecar mode is enabled, the
// injected sidecar is a cluster-global singleton that always exports Prometheus
// metrics on the global port — per-PolicyServer pod-side overrides are not
// possible without reconfiguring the sidecar.
//
// It also verifies that when MetricsEnabled is false, no metrics port appears
// on the Service.
func TestUpdateServiceMetricsPortPriorityChain(t *testing.T) {
	tests := []struct {
		name                   string
		metricsEnabled         bool
		policyServerMetricPort int32 // simulates controller-wide CLI flag / env var / constant
		crdMetricsPort         *int32
		expectMetricsPort      bool
		expectedPort           int32 // Service Port
		expectedTargetPort     int32 // Service TargetPort
	}{
		{
			name:                   "CLI flag only (no CRD override)",
			metricsEnabled:         true,
			policyServerMetricPort: 9090,
			crdMetricsPort:         nil,
			expectMetricsPort:      true,
			expectedPort:           9090,
			expectedTargetPort:     9090,
		},
		{
			name:                   "CRD overrides CLI flag",
			metricsEnabled:         true,
			policyServerMetricPort: 9090,
			crdMetricsPort:         int32Ptr(9091),
			expectMetricsPort:      true,
			expectedPort:           9091,
			expectedTargetPort:     9090,
		},
		{
			name:                   "constant default (8080)",
			metricsEnabled:         true,
			policyServerMetricPort: constants.PolicyServerMetricsPort,
			crdMetricsPort:         nil,
			expectMetricsPort:      true,
			expectedPort:           constants.PolicyServerMetricsPort,
			expectedTargetPort:     constants.PolicyServerMetricsPort,
		},
		{
			name:                   "metrics disabled — no metrics port on service",
			metricsEnabled:         false,
			policyServerMetricPort: 9090,
			crdMetricsPort:         nil,
			expectMetricsPort:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newTestScheme()
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			reconciler := &PolicyServerReconciler{
				Client: fakeClient,
				TelemetryConfiguration: TelemetryConfiguration{
					MetricsEnabled: tc.metricsEnabled,
				},
				PolicyServerMetricsPort: tc.policyServerMetricPort,
				DeploymentsNamespace:    "kubewarden",
				Scheme:                  scheme,
			}

			ps := newPolicyServer("test-ps", tc.crdMetricsPort)
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ps.NameWithPrefix(),
					Namespace: "kubewarden",
				},
			}

			err := reconciler.updateService(svc, ps)
			require.NoError(t, err)

			// The "policy-server" port must always be present
			webhookPort := findServicePort(svc.Spec.Ports, "policy-server")
			require.NotNil(t, webhookPort, "policy-server port must always exist")
			assert.Equal(t, int32(constants.PolicyServerServicePort), webhookPort.Port)

			metricsPort := findServicePort(svc.Spec.Ports, "metrics")

			if !tc.expectMetricsPort {
				assert.Nil(t, metricsPort, "metrics port should not be present when metrics are disabled")
				assert.Len(t, svc.Spec.Ports, 1, "only the policy-server port should exist")
				return
			}

			require.NotNil(t, metricsPort, "metrics port must exist when metrics are enabled")
			assert.Equal(t, tc.expectedPort, metricsPort.Port,
				"Service Port should respect CRD > CLI flag > constant priority")
			assert.Equal(t, intstr.FromInt32(tc.expectedTargetPort), metricsPort.TargetPort,
				"Service TargetPort must always equal the global PolicyServerMetricsPort (fixed regardless of spec.metricsPort, to avoid breaking OTel sidecar mode)")
			assert.Equal(t, corev1.ProtocolTCP, metricsPort.Protocol)
			assert.Len(t, svc.Spec.Ports, 2, "both policy-server and metrics ports should exist")
		})
	}
}
