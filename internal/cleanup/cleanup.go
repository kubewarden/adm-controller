// Package cleanup implements the cleanup logic run by the Helm chart
// pre-delete hook when the Kubewarden stack is uninstalled.
//
// The uninstall must leave behind ONLY the Kubewarden CRDs and the
// user-defined PolicyServer/policy CRs, without their Kubewarden
// finalizers, so that:
//   - nothing keeps evaluating admission requests without a controller
//     reconciling it,
//   - a future re-installation of the chart can adopt and reconcile the kept
//     custom resources again,
//   - the kept custom resources (and their CRDs) can be deleted with plain
//     kubectl commands, without a running controller honoring finalizers.
package cleanup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

// The wait tuning is defined as variables so the tests can shorten it.
//
//nolint:gochecknoglobals // overridden by the tests
var (
	// controllerPodsGoneTimeout is the maximum time to wait for the
	// controller pods to be fully terminated after their Deployment is
	// deleted.
	controllerPodsGoneTimeout = 3 * time.Minute
	// controllerPodsGonePollInterval is the poll interval used while waiting
	// for the controller pods to be gone.
	controllerPodsGonePollInterval = 1 * time.Second
)

// Options configures the cleanup run.
type Options struct {
	// DeploymentsNamespace is the namespace where the Kubewarden stack (the
	// controller, policyservers, etc) is deployed.
	DeploymentsNamespace string
	// ControllerDeploymentName is the name of the controller Deployment to
	// delete before cleaning up the resources it manages.
	ControllerDeploymentName string
}

// Run removes what the Kubewarden stack created, in this order: the controller
// Deployment and its pods, every Kubewarden webhook configuration, the
// Kubewarden finalizers of the kept custom resources, the default resources
// of the chart, the resources backing the policy servers, and the certificate
// Secrets of the controller.
func Run(ctx context.Context, c client.Client, log logr.Logger, opts Options) error {
	if opts.DeploymentsNamespace == "" {
		return errors.New("the deployments namespace must be provided")
	}
	if opts.ControllerDeploymentName == "" {
		return errors.New("the controller deployment name must be provided")
	}

	// Delete the controller Deployment and wait for its pods to be gone, so
	// nothing recreates the resources removed by the following steps and
	// nothing re-adds the finalizers stripped below.
	log.Info("deleting the controller deployment", "namespace", opts.DeploymentsNamespace, "name", opts.ControllerDeploymentName)
	if err := deleteControllerDeployment(ctx, c, opts); err != nil {
		return fmt.Errorf("failed to delete the controller deployment: %w", err)
	}

	// Delete every Kubewarden webhook configuration: the policies webhook
	// configurations, so no orphaned webhook keeps intercepting admission
	// requests, and the controller's own webhook configurations, so the
	// following writes to the Kubewarden custom resources are not rejected
	// by webhooks pointing to the deleted controller.
	log.Info("deleting the Kubewarden webhook configurations")
	if err := deleteWebhookConfigurations(ctx, c); err != nil {
		return fmt.Errorf("failed to delete the Kubewarden webhook configurations: %w", err)
	}

	// Strip the Kubewarden finalizers from all the Kubewarden custom
	// resources. The controller is gone, so nothing else would honor them.
	log.Info("stripping the Kubewarden finalizers from the Kubewarden custom resources")
	if err := stripKubewardenFinalizers(ctx, c); err != nil {
		return fmt.Errorf("failed to strip the Kubewarden finalizers: %w", err)
	}

	// Delete the custom resources managed by the chart (the default
	// PolicyServer and the recommended policies). The user-defined custom
	// resources are kept: the controller reconciles them again on
	// re-installation.
	log.Info("deleting the default Kubewarden custom resources managed by the chart")
	if err := deleteDefaultsResources(ctx, c); err != nil {
		return fmt.Errorf("failed to delete the default Kubewarden custom resources: %w", err)
	}

	// Delete the resources backing the policy servers (Deployments,
	// Services, Secrets, ConfigMaps and PodDisruptionBudgets).
	log.Info("deleting the resources backing the policy servers", "namespace", opts.DeploymentsNamespace)
	if err := deletePolicyServerResources(ctx, c, opts.DeploymentsNamespace); err != nil {
		return fmt.Errorf("failed to delete the resources backing the policy servers: %w", err)
	}

	// Delete the certificate Secrets of the controller. They hold the CA, and
	// a new installation must not reuse it. Helm does not delete them when they
	// do not belong to the release, or carry the keep resource policy.
	log.Info("deleting the certificate secrets of the controller", "namespace", opts.DeploymentsNamespace)
	if err := deleteControllerCertificateSecrets(ctx, c, opts.DeploymentsNamespace); err != nil {
		return fmt.Errorf("failed to delete the certificate secrets of the controller: %w", err)
	}

	log.Info("cleanup completed")
	return nil
}

// deleteControllerDeployment deletes the controller Deployment and waits
// until no controller pod is left in the namespace.
func deleteControllerDeployment(ctx context.Context, c client.Client, opts Options) error {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.ControllerDeploymentName,
			Namespace: opts.DeploymentsNamespace,
		},
	}
	if err := c.Delete(ctx, deployment); client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("failed to delete deployment %q: %w", opts.ControllerDeploymentName, err)
	}

	// Waiting on the pods (instead of relying on a delete foreground cascade)
	// guarantees that no controller process can interfere with the next steps.
	err := wait.PollUntilContextTimeout(ctx, controllerPodsGonePollInterval, controllerPodsGoneTimeout, true, func(ctx context.Context) (bool, error) {
		podList := &corev1.PodList{}
		if err := c.List(ctx, podList,
			client.InNamespace(opts.DeploymentsNamespace),
			client.MatchingLabels{constants.ComponentLabelKey: constants.ComponentControllerLabelValue},
		); err != nil {
			return false, fmt.Errorf("failed to list the controller pods: %w", err)
		}
		return len(podList.Items) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("failed to wait for the controller pods to be gone: %w", err)
	}
	return nil
}

// deleteWebhookConfigurations deletes all the ValidatingWebhookConfigurations
// and MutatingWebhookConfigurations labeled as part of Kubewarden. The broad
// "app.kubernetes.io/part-of=kubewarden" selector is intentional: the
// policies webhook configurations carry no other label, and the controller's
// own webhook configurations must be deleted here as well, so the following
// writes to the Kubewarden custom resources are not rejected by fail-closed
// webhooks pointing to the deleted controller.
func deleteWebhookConfigurations(ctx context.Context, c client.Client) error {
	partOfKubewarden := client.MatchingLabels{constants.PartOfLabelKey: constants.PartOfLabelValue}

	for _, list := range []client.ObjectList{
		&admissionregistrationv1.ValidatingWebhookConfigurationList{},
		&admissionregistrationv1.MutatingWebhookConfigurationList{},
	} {
		if err := deleteEachListItem(ctx, c, list, partOfKubewarden); err != nil {
			return err
		}
	}
	return nil
}

// kubewardenResourceLists returns fresh list objects for all the Kubewarden
// custom resource types.
func kubewardenResourceLists() []client.ObjectList {
	return []client.ObjectList{
		&policiesv1.PolicyServerList{},
		&policiesv1.ClusterAdmissionPolicyList{},
		&policiesv1.AdmissionPolicyList{},
		&policiesv1.ClusterAdmissionPolicyGroupList{},
		&policiesv1.AdmissionPolicyGroupList{},
	}
}

// stripKubewardenFinalizers removes the Kubewarden finalizers from all the
// Kubewarden custom resources, in every namespace. Only the Kubewarden
// finalizers are removed: finalizers set by other tooling are left untouched.
func stripKubewardenFinalizers(ctx context.Context, c client.Client) error {
	for _, list := range kubewardenResourceLists() {
		if err := c.List(ctx, list); err != nil {
			return fmt.Errorf("failed to list %T: %w", list, err)
		}

		if err := forEachListItem(list, func(obj client.Object) error {
			return stripObjectKubewardenFinalizers(ctx, c, obj)
		}); err != nil {
			return err
		}
	}
	return nil
}

// stripObjectKubewardenFinalizers removes the Kubewarden finalizers from the
// given object, retrying on conflicts against the latest version.
func stripObjectKubewardenFinalizers(ctx context.Context, c client.Client, obj client.Object) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("failed to get the object: %w", err)
		}

		changed := controllerutil.RemoveFinalizer(obj, constants.KubewardenFinalizer)
		if controllerutil.RemoveFinalizer(obj, constants.KubewardenFinalizerPre114) {
			changed = true
		}
		if !changed {
			return nil
		}

		if err := c.Update(ctx, obj); err != nil {
			// The object can legitimately disappear while being updated: once
			// its finalizers are cleared, a pending deletion completes.
			if apierrors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("failed to update the object: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to strip the Kubewarden finalizers from %T %q: %w",
			obj, client.ObjectKeyFromObject(obj), err)
	}
	return nil
}

// deleteDefaultsResources deletes the Kubewarden custom resources managed by
// the chart (labeled by the defaults applier). Their Kubewarden finalizers
// have already been stripped, so the deletion completes without the
// controller.
func deleteDefaultsResources(ctx context.Context, c client.Client) error {
	managedByDefaults := client.MatchingLabels{constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue}
	for _, list := range kubewardenResourceLists() {
		if err := deleteEachListItem(ctx, c, list, managedByDefaults); err != nil {
			return err
		}
	}
	return nil
}

// deletePolicyServerResources deletes the resources backing the policy
// servers in the deployments namespace. Everything is selected by the
// "app.kubernetes.io/part-of=kubewarden" and
// "app.kubernetes.io/component=policy-server" labels set by the controller
// (the same selection used by the certificate rotation), so the chart-managed
// resources carrying only the part-of label (e.g. the controller Services) are
// left for Helm to delete right after this hook.
func deletePolicyServerResources(ctx context.Context, c client.Client, namespace string) error {
	inNamespace := client.InNamespace(namespace)
	policyServerLabels := client.MatchingLabels{
		constants.PartOfLabelKey:    constants.PartOfLabelValue,
		constants.ComponentLabelKey: constants.ComponentPolicyServerLabelValue,
	}

	for _, list := range []client.ObjectList{
		&appsv1.DeploymentList{},
		&corev1.ServiceList{},
		&corev1.SecretList{},
		&corev1.ConfigMapList{},
		&policyv1.PodDisruptionBudgetList{},
	} {
		if err := deleteEachListItem(ctx, c, list, inNamespace, policyServerLabels); err != nil {
			return err
		}
	}

	// TODO: remove in the future
	// ConfigMaps are additionally selected by the  "kubewarden/policy-server"
	// label, which is the only label set on the ConfigMaps created by
	// controllers v1.36: those ConfigMaps are relabeled on the first
	// reconciliation after an upgrade, but the uninstall must also work when the
	// controller never reconciled after the upgrade (e.g. it is crashlooping).
	// The extra selector can be removed once upgrades from chart versions
	// without the ConfigMap tracking labels are no longer supported
	return deleteEachListItem(ctx, c, &corev1.ConfigMapList{}, inNamespace, client.HasLabels{constants.PolicyServerLabelKey})
}

// deleteControllerCertificateSecrets deletes the CA root Secret, the Secret of
// the webhook server certificate and the Secret of the audit scanner client
// certificate.
func deleteControllerCertificateSecrets(ctx context.Context, c client.Client, namespace string) error {
	for _, name := range []string{
		constants.CARootSecretName,
		constants.WebhookServerCertSecretName,
		constants.AuditScannerClientCertSecretName,
	} {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
		if err := c.Delete(ctx, secret); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to delete secret %q: %w", name, err)
		}
	}
	return nil
}

// deleteEachListItem lists the objects matching the given options and deletes
// them one by one.
// We aren't using a collection deletion because:
//   - The ServiceAccount running the cleanup is not granted the
//     deletecollection verb for security reasons
//   - Errors pinpoint exactly which object fails to delete
//   - Number of objects is small enough
func deleteEachListItem(ctx context.Context, c client.Client, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.List(ctx, list, opts...); err != nil {
		return fmt.Errorf("failed to list %T: %w", list, err)
	}

	return forEachListItem(list, func(obj client.Object) error {
		if err := c.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to delete %T %q: %w",
				obj, client.ObjectKeyFromObject(obj), err)
		}
		return nil
	})
}

// forEachListItem runs the given function on every item of the list.
func forEachListItem(list client.ObjectList, run func(obj client.Object) error) error {
	items, err := apimeta.ExtractList(list)
	if err != nil {
		return fmt.Errorf("failed to extract the items of %T: %w", list, err)
	}

	for _, item := range items {
		obj, ok := item.(client.Object)
		if !ok {
			return fmt.Errorf("unexpected list item type %T", item)
		}
		if runErr := run(obj); runErr != nil {
			return runErr
		}
	}
	return nil
}
