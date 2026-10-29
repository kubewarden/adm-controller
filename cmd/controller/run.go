/*
Copyright 2021.

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

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/fields"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
	"github.com/kubewarden/adm-controller/internal/controller"
	"github.com/kubewarden/adm-controller/internal/featuregates"
	"github.com/kubewarden/adm-controller/internal/metrics"
)

// runManager starts the controller manager and returns the exit code of the process.
//
//nolint:funlen,gocognit,nonamedreturns // The deferred shutdown of the metrics provider sets the exit code.
func runManager(opts Options) (retcode int) {
	// Validate --webhook-server-port range.
	if int64(opts.Manager.WebhookServerPort) < minAllowedPort || int64(opts.Manager.WebhookServerPort) > maxAllowedPort {
		setupLog.Error(
			errors.New("port must be between 1 and 65535"),
			"invalid webhook server port",
			"flag", "--webhook-server-port",
			"value", opts.Manager.WebhookServerPort,
			"min", minAllowedPort,
			"max", maxAllowedPort,
		)
		return 1
	}

	// HostNetwork mode is incompatible with OTel sidecar injection because
	// multiple sidecars on the same node would cause port conflicts.
	if opts.Configuration.HostNetwork && opts.EnableOtelSidecar {
		setupLog.Error(
			errors.New("--host-network and --enable-otel-sidecar are mutually exclusive"),
			"incompatible flags: OpenTelemetry sidecar injection is not supported in host-network mode due to port conflicts; use a remote collector instead",
		)
		return 1
	}

	// Warn when hostNetwork is enabled
	if opts.Configuration.HostNetwork {
		setupLog.Info("WARNING: enabling host-network increases the attack surface by exposing webhook endpoints " +
			"on the host network and giving pods visibility of all node network interfaces. " +
			"Use only when the Kubernetes API server cannot reach pod-network webhook endpoints.")
	}

	// Read the global default metrics port for PolicyServer services from the
	// environment variable, falling back to the hardcoded constant.
	policyServerMetricsPort := int32(constants.PolicyServerMetricsPort)
	if envPort := os.Getenv(constants.PolicyServerMetricsPortEnvVar); envPort != "" {
		parsed, err := strconv.ParseInt(envPort, 10, 32)
		if err != nil {
			setupLog.Error(err, "cannot parse env var as integer port",
				"envVar", constants.PolicyServerMetricsPortEnvVar, "value", envPort)
			return 1
		}
		if parsed < minAllowedPort || parsed > maxAllowedPort {
			setupLog.Error(
				errors.New("port must be between 1 and 65535"),
				"invalid env var port value",
				"envVar", constants.PolicyServerMetricsPortEnvVar,
				"value", envPort,
				"min", minAllowedPort,
				"max", maxAllowedPort,
			)
			return 1
		}
		policyServerMetricsPort = int32(parsed)
	}

	if opts.EnableMetrics {
		shutdown, err := metrics.New()
		if err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			return 1
		}
		setupLog.Info("Metrics initialized")

		// cleanly shutdown and flush telemetry on application exit
		defer func() {
			// Do not make the application hang when it is shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), constants.MetricsShutdownTimeout)
			defer cancel()

			if err := shutdown(ctx); err != nil { //nolint:govet // err is shadowed in purpose
				setupLog.Error(err, "Unable to shutdown telemetry")
				retcode = 1
				return
			}
		}()
	}

	mgr, err := setupManager(opts.Manager)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return 1
	}

	opts.Configuration.FeatureGateAdmissionWebhookMatchConditions, err = featuregates.CheckAdmissionWebhookMatchConditions(ctrl.GetConfigOrDie())
	if err != nil {
		setupLog.Error(err, "unable to check for feature gate AdmissionWebhookMatchConditions")
	}

	otelConfiguration := controller.TelemetryConfiguration{
		MetricsEnabled:              opts.EnableMetrics,
		TracingEnabled:              opts.EnableTracing,
		OtelSidecarEnabled:          opts.EnableOtelSidecar,
		OtelCertificateSecret:       opts.OpenTelemetryCertificateSecret,
		OtelClientCertificateSecret: opts.OpenTelemetryClientCertificateSecret,
	}
	if err = setupReconcilers(mgr,
		opts.Manager.DeploymentsNamespace,
		opts.Configuration,
		otelConfiguration,
		policyServerMetricsPort,
	); err != nil {
		setupLog.Error(err, "unable to create controllers")
		return 1
	}

	if err = setupWebhooks(mgr, opts.Manager.DeploymentsNamespace); err != nil {
		setupLog.Error(err, "unable to create webhooks")
		return 1
	}

	//+kubebuilder:scaffold:builder

	if err = setupProbes(mgr); err != nil {
		setupLog.Error(err, "unable to set up probes")
		return 1
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		return 1
	}

	return 0
}

func setupManager(mgrOpts ManagerOptions) (ctrl.Manager, error) {
	namespaceSelector := cache.ByObject{
		Field: fields.ParseSelectorOrDie("metadata.namespace=" + mgrOpts.DeploymentsNamespace),
	}

	clientCAName := ""
	if mgrOpts.EnableMutualTLS {
		// The WebhookServer shares the same CertDir for both the server
		// certificate and the client CA certificate. We expect the ClientCACert
		// in the "client-ca"  sub-folder from the ConfigMap, since one cannot
		// mount several Secrets/ConfigMaps under the same path.
		clientCAName = filepath.Join("client-ca", constants.ClientCACert)
	}

	mgrOptions := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: mgrOpts.MetricsAddr,
		},
		HealthProbeBindAddress: mgrOpts.ProbeAddr,
		LeaderElection:         mgrOpts.EnableLeaderElection,
		LeaderElectionID:       "a4ddbf36.kubewarden.io",
		// Warning: the manager creates a client, which then uses Watches to monitor
		// certain resources. By default, the client is not going to be namespaced,
		// it will be able to watch resources across the entire cluster. This is of
		// course constrained by the RBAC rules applied to the ServiceAccount that
		// runs the controller.
		// *However*, even when accessing a resource inside a specific Namespace,
		// the default behavior of the cache is to create a Watch that is not namespaced;
		// hence requires the privilege to access all the resources of that type inside
		// of the cluster. That can cause runtime error if the ServiceAccount lacking
		// this privilege.
		// For example, when we access a secret inside the `kubewarden`
		// namespace, the cache will create a Watch against Secrets, that will require
		// privileged to access ALL the secrets of the cluster.
		//
		// To be able to have stricter RBAC rules, we need to instruct the cache to
		// only watch objects inside of the namespace where the controller is running.
		// That applies ONLY to the namespaced resources that we know the controller
		// is going to own inside of a specific namespace.
		// For example, Secret resources are going to be defined by the controller
		// only inside of the `kubewarden` namespace; hence their watch can be namespaced.
		// On the other hand, AdmissionPolicy resources are namespaced, but the controller
		// requires to access them across all the namespaces of the cluster; hence the
		// cache must not be namespaced.
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&appsv1.ReplicaSet{}:                 namespaceSelector,
				&corev1.Secret{}:                     namespaceSelector,
				&corev1.Pod{}:                        namespaceSelector,
				&corev1.Service{}:                    namespaceSelector,
				&k8spoliciesv1.PodDisruptionBudget{}: namespaceSelector,
				&corev1.ConfigMap{}:                  namespaceSelector,
				&appsv1.Deployment{}:                 namespaceSelector,
			},
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			CertDir:      constants.WebhookServerCertDir,
			ClientCAName: clientCAName,
			Port:         mgrOpts.WebhookServerPort,
		}),
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOptions)
	if err != nil {
		return mgr, fmt.Errorf("failed to setup manager: %w", err)
	}
	return mgr, nil
}

func setupProbes(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return errors.Join(errors.New("unable to set up health check"), err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return errors.Join(errors.New("unable to set up ready check"), err)
	}
	return nil
}

func setupReconcilers(mgr ctrl.Manager,
	deploymentsNamespace string,
	config Configuration,
	otelConfiguration controller.TelemetryConfiguration,
	policyServerMetricsPort int32,
) error {
	if err := (&controller.PolicyServerReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("policy-server-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		AlwaysAcceptAdmissionReviewsInDeploymentsNamespace: config.AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		TelemetryConfiguration:                             otelConfiguration,
		ClientCAConfigMapName:                              config.ClientCAConfigMapName,
		ControllerConfigMapName:                            config.ControllerConfigMapName,
		ImagePullSecrets:                                   config.ImagePullSecrets,
		HostNetwork:                                        config.HostNetwork,
		PolicyServerMetricsPort:                            policyServerMetricsPort,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create PolicyServer controller"), err)
	}

	if err := (&controller.AdmissionPolicyReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		Log:                     ctrl.Log.WithName("admission-policy-reconciler"),
		DeploymentsNamespace:    deploymentsNamespace,
		ControllerConfigMapName: config.ControllerConfigMapName,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create AdmissionPolicy controller"), err)
	}

	if err := (&controller.ClusterAdmissionPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("cluster-admission-policy-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicy controller"), err)
	}

	if err := (&controller.CertReconciler{
		Client:               mgr.GetClient(),
		Log:                  ctrl.Log.WithName("cert-recociler"),
		DeploymentsNamespace: deploymentsNamespace,
		WebhookServiceName:   config.WebhookServiceName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create Cert controller"), err)
	}

	if err := (&controller.AdmissionPolicyGroupReconciler{
		Client:                  mgr.GetClient(),
		Scheme:                  mgr.GetScheme(),
		Log:                     ctrl.Log.WithName("admission-policy-group-reconciler"),
		DeploymentsNamespace:    deploymentsNamespace,
		ControllerConfigMapName: config.ControllerConfigMapName,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create AdmissionPolicyGroup controller"), err)
	}

	if err := (&controller.ClusterAdmissionPolicyGroupReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("cluster-admission-policy-group-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
		FeatureGateAdmissionWebhookMatchConditions: config.FeatureGateAdmissionWebhookMatchConditions,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create ClusterAdmissionPolicyGroup controller"), err)
	}

	if err := (&controller.DefaultsApplierReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("defaults-applier"),
		DeploymentsNamespace: deploymentsNamespace,
		ConfigMapName:        config.DefaultsConfigMapName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create DefaultsApplier controller"), err)
	}
	return nil
}

func setupWebhooks(mgr ctrl.Manager, deploymentsNamespace string) error {
	if err := (&policiesv1.PolicyServer{}).SetupWebhookWithManager(mgr, deploymentsNamespace); err != nil {
		return errors.Join(errors.New("unable to create webhook for policy servers"), err)
	}
	if err := (&policiesv1.ClusterAdmissionPolicy{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for cluster admission policies"), err)
	}
	if err := (&policiesv1.AdmissionPolicy{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for admission policies"), err)
	}
	if err := (&policiesv1.AdmissionPolicyGroup{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for admission policies groups"), err)
	}
	if err := (&policiesv1.ClusterAdmissionPolicyGroup{}).SetupWebhookWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create webhook for cluster admission policies groups"), err)
	}
	return nil
}
