// Package upgrade holds the work of the pre-upgrade hook of the Helm chart.
//
// Older versions of the chart render the certificate Secrets and the webhook
// configurations of the controller. This version does not: the controller
// creates them. On an upgrade, Helm deletes each object that leaves the chart,
// and Argo CD prunes it. Without these objects, the webhooks of the controller
// stop, and the controller creates a new CA, which every webhook must trust
// again.
//
// Helm does not delete an object whose live version has the annotation
// helm.sh/resource-policy: keep. Argo CD does not prune an object whose live
// version has the sync option Prune=false. The pre-upgrade hook adds both to
// the objects, before Helm or Argo CD looks at them. The controller then keeps
// using the objects. The pre-delete hook deletes them on an uninstall.
package upgrade

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/adm-controller/internal/constants"
)

// KeepControllerObjects adds the annotations that make Helm and Argo CD keep
// the certificate Secrets and the webhook configurations of the controller.
// It skips an object that does not exist, and does not change an object that
// has the annotations already.
func KeepControllerObjects(ctx context.Context, c client.Client, log logr.Logger, namespace string) error {
	for _, object := range controllerObjects(namespace) {
		if err := keepObject(ctx, c, log, object); err != nil {
			return err
		}
	}
	return nil
}

// controllerObjects returns the objects that older versions of the chart
// render, and that the controller creates now.
func controllerObjects(namespace string) []client.Object {
	return []client.Object{
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
}

func keepObject(ctx context.Context, c client.Client, log logr.Logger, object client.Object) error {
	key := client.ObjectKeyFromObject(object)
	kind := fmt.Sprintf("%T", object)

	if err := c.Get(ctx, key, object); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("The object does not exist, nothing to keep", "kind", kind, "name", key)
			return nil
		}
		return fmt.Errorf("failed to get %s %q: %w", kind, key, err)
	}

	original, ok := object.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("failed to copy %s %q", kind, key)
	}
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	syncOptions := withNoPrune(annotations[constants.ArgoCDSyncOptions])
	if annotations[constants.HelmResourcePolicy] == constants.HelmResourcePolicyKeep &&
		annotations[constants.ArgoCDSyncOptions] == syncOptions {
		log.Info("The object is kept already", "kind", kind, "name", key)
		return nil
	}
	annotations[constants.HelmResourcePolicy] = constants.HelmResourcePolicyKeep
	annotations[constants.ArgoCDSyncOptions] = syncOptions
	object.SetAnnotations(annotations)

	// A merge patch changes only the annotations, so it cannot undo a
	// concurrent write of the controller to the data of the object.
	if err := c.Patch(ctx, object, client.MergeFrom(original)); err != nil {
		return fmt.Errorf("failed to add the keep annotations to %s %q: %w", kind, key, err)
	}
	log.Info("Added the keep annotations", "kind", kind, "name", key)
	return nil
}

// withNoPrune returns the Argo CD sync options with Prune=false, and without
// any other Prune option. It keeps the other options in their order.
func withNoPrune(syncOptions string) string {
	options := []string{}
	for _, option := range strings.Split(syncOptions, ",") {
		option = strings.TrimSpace(option)
		if option == "" || strings.HasPrefix(option, "Prune=") {
			continue
		}
		options = append(options, option)
	}
	return strings.Join(append(options, constants.ArgoCDSyncOptionNoPrune), ",")
}
