// Package upgrade tests the upgrade from the last release of the Helm chart to
// the chart of this repository, on its own kind cluster.
package upgrade

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

const (
	namespace      = "kubewarden"
	releaseName    = "kubewarden"
	deploymentName = "kubewarden-admission-controller"
	chartPath      = "../../charts/admission-controller"
	// chartRepository and previousChartVersion select the release that the
	// test upgrades from. Set previousChartVersion to the last release.
	chartRepository      = "https://charts.kubewarden.io"
	previousChartVersion = "6.1.0"

	controllerImage   = "ghcr.io/kubewarden/adm-controller/controller:dev"
	auditScannerImage = "ghcr.io/kubewarden/adm-controller/audit-scanner:dev"
	policyServerImage = "ghcr.io/kubewarden/adm-controller/policy-server:dev"
)

var testenv env.Environment

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testenv = env.NewWithConfig(cfg)
	kindClusterName := envconf.RandomName("kubewarden-e2e-upgrade", 32)

	testenv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
		envfuncs.CreateNamespace(namespace, envfuncs.WithLabels(map[string]string{
			"pod-security.kubernetes.io/enforce":         "restricted",
			"pod-security.kubernetes.io/enforce-version": "latest",
		})),
		envfuncs.LoadImageToCluster(kindClusterName, controllerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, auditScannerImage, "--verbose", "--mode", "direct"),
		envfuncs.LoadImageToCluster(kindClusterName, policyServerImage, "--verbose", "--mode", "direct"),
		func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
			err := helm.New(cfg.KubeconfigFile()).RunInstall(
				helm.WithName(releaseName),
				helm.WithNamespace(namespace),
				helm.WithChart("admission-controller"),
				helm.WithVersion(previousChartVersion),
				helm.WithWait(),
				helm.WithTimeout("10m"),
				helm.WithArgs("--repo", chartRepository),
			)
			if err != nil {
				return ctx, fmt.Errorf("failed to install the chart %s: %w", previousChartVersion, err)
			}
			if err = waitForControllerDeployment(cfg); err != nil {
				return ctx, err
			}
			return ctx, nil
		},
	)

	// Each step is its own Finish action, so that a failed export of the logs
	// does not skip the deletion of the cluster.
	testenv.Finish(envfuncs.ExportClusterLogs(kindClusterName, "./logs"))
	testenv.Finish(envfuncs.DestroyCluster(kindClusterName))

	os.Exit(testenv.Run(m))
}

func TestUpgradeKeepsTheControllerObjects(t *testing.T) {
	feature := features.New("Upgrade from the previous release").
		Assess("keeps the certificate Secrets and the webhook configurations of the controller", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r := cfg.Client().Resources()
			require.NoError(t, policiesv1.AddToScheme(r.GetScheme()))

			before := getControllerObjects(ctx, t, r)
			caBefore := before[0].(*corev1.Secret).Data[constants.CARootCert]
			require.NotEmpty(t, caBefore)

			err := helm.New(cfg.KubeconfigFile()).RunUpgrade(
				helm.WithName(releaseName),
				helm.WithNamespace(namespace),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithTimeout("10m"),
				helm.WithArgs(
					"--set", "image.tag=dev",
					"--set", "auditScanner.image.tag=dev",
					"--set", "policyServer.image.tag=dev",
					"--set", "logLevel=debug",
				),
			)
			require.NoError(t, err, "failed to upgrade to the chart of this repository")
			require.NoError(t, waitForControllerDeployment(cfg))

			after := getControllerObjects(ctx, t, r)
			for i := range before {
				require.Equal(t, before[i].GetUID(), after[i].GetUID(),
					"the upgrade deleted %T %q", after[i], after[i].GetName())
				require.Equal(t, constants.HelmResourcePolicyKeep, after[i].GetAnnotations()[constants.HelmResourcePolicy],
					"%T %q has no keep annotation", after[i], after[i].GetName())
			}
			require.Equal(t, caBefore, after[0].(*corev1.Secret).Data[constants.CARootCert], "the upgrade changed the CA")

			// The API server calls the webhooks of the controller for a dry
			// run too, so this fails if it does not trust their certificate.
			policy := policiesv1.NewClusterAdmissionPolicyFactory().
				WithPolicyServer("default").
				WithoutFinalizers().
				Build()
			require.NoError(t, r.Create(ctx, policy, func(options *metav1.CreateOptions) {
				options.DryRun = []string{metav1.DryRunAll}
			}), "the webhooks of the controller do not work after the upgrade")

			return ctx
		}).Feature()

	testenv.Test(t, feature)
}

// getControllerObjects returns the certificate Secrets and the webhook
// configurations of the controller. The CA root Secret is the first one.
func getControllerObjects(ctx context.Context, t *testing.T, r *resources.Resources) []k8s.Object {
	t.Helper()
	objects := []k8s.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.CARootSecretName}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.WebhookServerCertSecretName}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.AuditScannerClientCertSecretName}},
		&admissionregistrationv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: constants.ControllerValidatingWebhookConfigurationName},
		},
		&admissionregistrationv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: constants.ControllerMutatingWebhookConfigurationName},
		},
	}
	for _, object := range objects {
		require.NoError(t, r.Get(ctx, object.GetName(), object.GetNamespace(), object),
			"failed to get %T %q", object, object.GetName())
	}
	return objects
}

func waitForControllerDeployment(cfg *envconf.Config) error {
	err := wait.For(conditions.New(cfg.Client().Resources()).DeploymentConditionMatch(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: deploymentName, Namespace: namespace}},
		appsv1.DeploymentAvailable,
		corev1.ConditionTrue,
	), wait.WithTimeout(5*time.Minute), wait.WithInterval(time.Second))
	if err != nil {
		return fmt.Errorf("failed to wait for the controller deployment: %w", err)
	}
	return nil
}
