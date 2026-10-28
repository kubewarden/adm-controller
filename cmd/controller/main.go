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
	"flag"
	"fmt"
	"os"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/api/policies/v1alpha2"
	"github.com/kubewarden/adm-controller/internal/constants"
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

// The modes of the controller binary, selected with the --mode flag.
const (
	// modeRun starts the controller manager. It is the default mode.
	modeRun = "run"
	// modeCleanup removes what the controller created. The pre-delete hook of the Helm chart runs it.
	modeCleanup = "cleanup"
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
	ControllerConfigMapName                            string
	FeatureGateAdmissionWebhookMatchConditions         bool
	WebhookServiceName                                 string
	ImagePullSecrets                                   []corev1.LocalObjectReference
	// HostNetwork enables host network mode for PolicyServer deployments.
	// WARNING: enabling this increases the attack surface. Use only when
	// the Kubernetes API server cannot reach pod-network webhook endpoints
	// (e.g. clusters using a non-VPC CNI with NAT).
	HostNetwork bool
}

// Options holds the values of the command line flags.
type Options struct {
	Mode                                 string
	Manager                              ManagerOptions
	Configuration                        Configuration
	EnableMetrics                        bool
	EnableTracing                        bool
	EnableOtelSidecar                    bool
	OpenTelemetryClientCertificateSecret string
	OpenTelemetryCertificateSecret       string
	ControllerDeploymentName             string
}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha2.AddToScheme(scheme))
	utilruntime.Must(policiesv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	opts := parseFlags()

	switch opts.Mode {
	case modeRun:
		os.Exit(runManager(opts))
	case modeCleanup:
		if err := runCleanup(opts.Manager.DeploymentsNamespace, opts.ControllerDeploymentName); err != nil {
			setupLog.Error(err, "cleanup failed")
			os.Exit(1)
		}
	default:
		setupLog.Error(fmt.Errorf("unknown mode %q", opts.Mode), "invalid flag",
			"flag", "--mode", "accepted", []string{modeRun, modeCleanup})
		os.Exit(1)
	}
}

// parseFlags parses the command line flags and sets up the logger.
func parseFlags() Options {
	var opts Options
	var imagePullSecretsFlag string

	flag.StringVar(&opts.Mode, "mode", modeRun,
		"The mode of the binary: "+
			"\""+modeRun+"\" starts the controller manager, "+
			"\""+modeCleanup+"\" runs the uninstall cleanup of the Helm chart pre-delete hook.")
	flag.StringVar(&opts.Manager.MetricsAddr, "metrics-bind-address", ":8088", "The address the controller-runtime metric endpoint binds to.")
	flag.StringVar(&opts.Manager.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.IntVar(&opts.Manager.WebhookServerPort, "webhook-server-port", 9443, "The port the webhook server listens on.")
	flag.BoolVar(&opts.Manager.EnableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&opts.EnableMetrics, "enable-metrics", false,
		"Enable metrics collection for all Policy Servers and the Kubewarden Controller")
	flag.BoolVar(&opts.EnableTracing, "enable-tracing", false,
		"Enable tracing collection for all Policy Servers")
	flag.BoolVar(&opts.EnableOtelSidecar, "enable-otel-sidecar", false,
		"Enable OpenTelemetry sidecar in Policy Servers")
	flag.StringVar(&opts.OpenTelemetryClientCertificateSecret, "opentelemetry-client-certificate-secret", "", "")
	flag.StringVar(&opts.OpenTelemetryCertificateSecret, "opentelemetry-certificate-secret", "", "")
	flag.StringVar(&opts.Manager.DeploymentsNamespace,
		"deployments-namespace",
		"",
		"The namespace where the kubewarden resources will be created.")
	flag.StringVar(&opts.Configuration.WebhookServiceName,
		"webhook-service-name",
		"kubewarden-controller-webhook-service",
		"The name of the service that will be used to expose controller webhooks.")
	flag.BoolVar(&opts.Configuration.AlwaysAcceptAdmissionReviewsOnDeploymentsNamespace,
		"always-accept-admission-reviews-on-deployments-namespace",
		false,
		"Always accept admission reviews targeting the deployments-namespace.")
	flag.StringVar(&opts.Configuration.ClientCAConfigMapName, "client-ca-configmap-name", "", "The name of the ConfigMap containing the client CA certificate. If provided, mTLS will be enabled.")
	flag.StringVar(&opts.Configuration.DefaultsConfigMapName,
		"defaults-configmap-name",
		constants.DefaultDefaultsConfigMapName,
		"Name of the ConfigMap that holds the rendered default Kubewarden resources.")
	flag.StringVar(&opts.Configuration.ControllerConfigMapName,
		"controller-configmap-name",
		constants.DefaultControllerConfigMapName,
		"Name of the ConfigMap that holds the controller configuration, for example the resources that namespaced policies can target. The ConfigMap must be in the deployments namespace.")
	flag.StringVar(&imagePullSecretsFlag,
		"image-pull-secrets",
		"",
		"Comma-separated list of Secret names to use as imagePullSecrets on every policy-server Deployment. The secrets must exist in the deployments namespace.")
	flag.BoolVar(&opts.Configuration.HostNetwork,
		"host-network",
		false,
		"Enable host network mode for all PolicyServer deployments. "+
			"WARNING: enabling this increases the attack surface by exposing webhook endpoints "+
			"on the host network and giving pods visibility of all node network interfaces. "+
			"Use only when the Kubernetes API server cannot reach pod-network webhook endpoints.")
	flag.StringVar(&opts.ControllerDeploymentName,
		"controller-deployment-name",
		"",
		"The name of the controller Deployment to delete in cleanup mode.")

	zapOpts := zap.Options{}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()
	opts.Manager.EnableMutualTLS = opts.Configuration.ClientCAConfigMapName != ""
	opts.Configuration.ImagePullSecrets = parseImagePullSecrets(imagePullSecretsFlag)
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

	return opts
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
