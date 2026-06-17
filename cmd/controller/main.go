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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8spoliciesv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/api/policies/v1alpha2"
	"github.com/kubewarden/adm-controller/internal/constants"
	"github.com/kubewarden/adm-controller/internal/controller"
	"github.com/kubewarden/adm-controller/internal/featuregates"
	"github.com/kubewarden/adm-controller/internal/metrics"
	//+kubebuilder:scaffold:imports
)

// Kubewarden controller required permissions
//
//+kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete,namespace="kubewarden"
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete,namespace="kubewarden"
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch,namespace="kubewarden"
//+kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

const (
	minAllowedPort = 1
	maxAllowedPort = 65535
)

//nolint:gochecknoglobals // Following the kubebuilder pattern
var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

type ManagerOptions struct {
	DeploymentsNamespace string
	EnableLeaderElection bool
	EnableMutualTLS      bool
	MetricsAddr          string
	ProbeAddr            string
	WebhookServerPort    int
}

type Configuration struct {
	AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace bool
	ClientCAConfigMapName                              string
	DefaultsConfigMapName                              string
	FeatureGateAdmissionWebhookMatchConditions         bool
	WebhookServiceName                                 string
	ImagePullSecrets                                   []corev1.LocalObjectReference
	// HostNetwork enables host network mode for PolicyServer deployments.
	// WARNING: enabling this increases the attack surface. Use only when
	// the Kubernetes API server cannot reach pod-network webhook endpoints
	// (e.g. clusters using a non-VPC CNI with NAT).
	HostNetwork bool
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
	utilruntime.Must(policiesv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

//nolint:funlen,gocognit // Avoid splitting the main function in multiple functions to avoid changing the retcode logic for metrics shutdown
func main() {
	retcode := 0
	defer func() { os.Exit(retcode) }()

	var mgrOpts ManagerOptions
	var config Configuration
	var enableMetrics bool
	var enableTracing bool
	var enableOtelSidecar bool
	var openTelemetryClientCertificateSecret string
	var openTelemetryCertificateSecret string
	var imagePullSecretsFlag string
	var policyServerMetricsPort int

	flag.StringVar(&mgrOpts.MetricsAddr, "metrics-bind-address", ":8088", "The address the controller-runtime metric endpoint binds to.")
	flag.StringVar(&mgrOpts.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.IntVar(&mgrOpts.WebhookServerPort, "webhook-server-port", 9443, "The port the webhook server listens on.")
	flag.IntVar(&policyServerMetricsPort,
		"policy-server-metrics-port",
		constants.PolicyServerMetricsPort,
		"The default port exposed by every PolicyServer metrics Service. "+
			"Per-PolicyServer overrides (spec.metricsPort) always take priority.")
	flag.BoolVar(&mgrOpts.EnableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableMetrics, "enable-metrics", false,
		"Enable metrics collection for all Policy Servers and the Kubewarden Controller")
	flag.BoolVar(&enableTracing, "enable-tracing", false,
		"Enable tracing collection for all Policy Servers")
	flag.BoolVar(&enableOtelSidecar, "enable-otel-sidecar", false,
		"Enable OpenTelemetry sidecar in Policy Servers")
	flag.StringVar(&openTelemetryClientCertificateSecret, "opentelemetry-client-certificate-secret", "", "")
	flag.StringVar(&openTelemetryCertificateSecret, "opentelemetry-certificate-secret", "", "")
	flag.StringVar(&mgrOpts.DeploymentsNamespace,
		"deployments-namespace",
		"",
		"The namespace where the kubewarden resources will be created.")
	flag.StringVar(&config.WebhookServiceName,
		"webhook-service-name",
		"kubewarden-controller-webhook-service",
		"The name of the service that will be used to expose controller webhooks.")
	flag.BoolVar(&config.AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		"always-accept-admission-reviews-on-deployments-namespace",
		false,
		"Always accept admission reviews targeting the deployments-namespace.")
	flag.StringVar(&config.ClientCAConfigMapName, "client-ca-configmap-name", "", "The name of the ConfigMap containing the client CA certificate. If provided, mTLS will be enabled.")
	flag.StringVar(&config.DefaultsConfigMapName,
		"defaults-configmap-name",
		constants.DefaultDefaultsConfigMapName,
		"Name of the ConfigMap that holds the rendered default Kubewarden resources.")
	flag.StringVar(&imagePullSecretsFlag,
		"image-pull-secrets",
		"",
		"Comma-separated list of Secret names to use as imagePullSecrets on every policy-server Deployment. The secrets must exist in the deployments namespace.")
	flag.BoolVar(&config.HostNetwork,
		"host-network",
		false,
		"Enable host network mode for all PolicyServer deployments. "+
			"WARNING: enabling this increases the attack surface by exposing webhook endpoints "+
			"on the host network and giving pods visibility of all node network interfaces. "+
			"Use only when the Kubernetes API server cannot reach pod-network webhook endpoints.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	policyServerMetricsPortFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "policy-server-metrics-port" {
			policyServerMetricsPortFlagSet = true
		}
	})
	mgrOpts.EnableMutualTLS = config.ClientCAConfigMapName != ""
	config.ImagePullSecrets = parseImagePullSecrets(imagePullSecretsFlag)
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Validate --webhook-server-port range.
	if int64(mgrOpts.WebhookServerPort) < minAllowedPort || int64(mgrOpts.WebhookServerPort) > maxAllowedPort {
		setupLog.Error(
			errors.New("port must be between 1 and 65535"),
			"invalid webhook server port",
			"flag", "--webhook-server-port",
			"value", mgrOpts.WebhookServerPort,
			"min", minAllowedPort,
			"max", maxAllowedPort,
		)
		retcode = 1
		return
	}

	// HostNetwork mode is incompatible with OTel sidecar injection because
	// multiple sidecars on the same node would cause port conflicts.
	if config.HostNetwork && enableOtelSidecar {
		setupLog.Error(
			errors.New("--host-network and --enable-otel-sidecar are mutually exclusive"),
			"incompatible flags: OpenTelemetry sidecar injection is not supported in host-network mode due to port conflicts; use a remote collector instead",
		)
		retcode = 1
		return
	}

	// Warn when hostNetwork is enabled
	if config.HostNetwork {
		setupLog.Info("WARNING: enabling host-network increases the attack surface by exposing webhook endpoints " +
			"on the host network and giving pods visibility of all node network interfaces. " +
			"Use only when the Kubernetes API server cannot reach pod-network webhook endpoints.")
	}

	// Validate --policy-server-metrics-port range.
	if int64(policyServerMetricsPort) < minAllowedPort ||
		int64(policyServerMetricsPort) > maxAllowedPort {
		setupLog.Error(
			errors.New("port must be between 1 and 65535"),
			"invalid policy server metrics port",
			"flag", "--policy-server-metrics-port",
			"value", policyServerMetricsPort,
			"min", minAllowedPort,
			"max", maxAllowedPort,
		)
		retcode = 1
		return
	}
	if envPort := os.Getenv(constants.PolicyServerMetricsPortEnvVar); envPort != "" {
		if policyServerMetricsPortFlagSet {
			setupLog.Info(
				"WARNING: deprecated environment variable ignored because --policy-server-metrics-port was set",
				"envVar", constants.PolicyServerMetricsPortEnvVar,
				"flag", "--policy-server-metrics-port",
			)
		} else {
			envPortParsed, err := strconv.ParseInt(envPort, 10, 32)
			if err != nil {
				setupLog.Error(err, "invalid policy server metrics port environment variable",
					"envVar", constants.PolicyServerMetricsPortEnvVar, "value", envPort)
				retcode = 1
				return
			}
			policyServerMetricsPort = int(envPortParsed)
			setupLog.Info(
				"WARNING: deprecated environment variable used as fallback; use --policy-server-metrics-port instead",
				"envVar", constants.PolicyServerMetricsPortEnvVar,
				"flag", "--policy-server-metrics-port",
			)
		}
	}
	if int64(policyServerMetricsPort) < minAllowedPort ||
		int64(policyServerMetricsPort) > maxAllowedPort {
		setupLog.Error(
			errors.New("port must be between 1 and 65535"),
			"invalid policy server metrics port",
			"value", policyServerMetricsPort,
			"min", minAllowedPort,
			"max", maxAllowedPort,
		)
		retcode = 1
		return
	}

	if enableMetrics {
		shutdown, err := metrics.New()
		if err != nil {
			setupLog.Error(err, "unable to initialize metrics provider")
			retcode = 1
			return
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

	mgr, err := setupManager(mgrOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		retcode = 1
		return
	}

	config.FeatureGateAdmissionWebhookMatchConditions, err = featuregates.CheckAdmissionWebhookMatchConditions(ctrl.GetConfigOrDie())
	if err != nil {
		setupLog.Error(err, "unable to check for feature gate AdmissionWebhookMatchConditions")
	}

	otelConfiguration := controller.TelemetryConfiguration{
		MetricsEnabled:              enableMetrics,
		TracingEnabled:              enableTracing,
		OtelSidecarEnabled:          enableOtelSidecar,
		OtelCertificateSecret:       openTelemetryCertificateSecret,
		OtelClientCertificateSecret: openTelemetryClientCertificateSecret,
	}
	if err = setupReconcilers(mgr,
		mgrOpts.DeploymentsNamespace,
		config,
		otelConfiguration,
		int32(policyServerMetricsPort),
	); err != nil {
		setupLog.Error(err, "unable to create controllers")
		retcode = 1
		return
	}

	if err = setupWebhooks(mgr, mgrOpts.DeploymentsNamespace); err != nil {
		setupLog.Error(err, "unable to create webhooks")
		retcode = 1
		return
	}

	//+kubebuilder:scaffold:builder

	if err = setupProbes(mgr); err != nil {
		setupLog.Error(err, "unable to set up probes")
		retcode = 1
		return
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		retcode = 1
		return
	}
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
		ImagePullSecrets:                                   config.ImagePullSecrets,
		HostNetwork:                                        config.HostNetwork,
		PolicyServerMetricsPort:                            policyServerMetricsPort,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create PolicyServer controller"), err)
	}

	if err := (&controller.AdmissionPolicyReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("admission-policy-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
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
		Client:                      mgr.GetClient(),
		Log:                         ctrl.Log.WithName("cert-recociler"),
		DeploymentsNamespace:        deploymentsNamespace,
		WebhookServiceName:          config.WebhookServiceName,
		CARootSecretName:            constants.CARootSecretName,
		WebhookServerCertSecretName: constants.WebhookServerCertSecretName,
	}).SetupWithManager(mgr); err != nil {
		return errors.Join(errors.New("unable to create Cert controller"), err)
	}

	if err := (&controller.AdmissionPolicyGroupReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Log:                  ctrl.Log.WithName("admission-policy-group-reconciler"),
		DeploymentsNamespace: deploymentsNamespace,
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

// parseImagePullSecrets converts a comma-separated list of secret names into a
// slice of LocalObjectReferences. Empty names are ignored. An empty or blank
// input string returns nil.
func parseImagePullSecrets(s string) []corev1.LocalObjectReference {
	if s == "" {
		return nil
	}
	var refs []corev1.LocalObjectReference
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			refs = append(refs, corev1.LocalObjectReference{Name: name})
		}
	}
	return refs
}
