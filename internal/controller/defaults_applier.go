package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	sigsyaml "sigs.k8s.io/yaml"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/kubewarden/adm-controller/internal/constants"
)

// DefaultsApplierReconciler watches a ConfigMap containing default Kubewarden
// resources (PolicyServer, ClusterAdmissionPolicy, etc.) and applies them to
// the cluster. It injects ownership labels and cleans up stale managed resources.

//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch,namespace=kubewarden
//+kubebuilder:rbac:groups=policies.kubewarden.io,resources=policyservers;clusteradmissionpolicies;admissionpolicies;clusteradmissionpolicygroups;admissionpolicygroups,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=list,namespace=kubewarden

// webhookServiceWaitInterval is the time between two checks of the webhook Service, while it has no ready endpoint.
const webhookServiceWaitInterval = 2 * time.Second

type DefaultsApplierReconciler struct {
	client.Client
	// APIReader reads from the API server, with no cache. It reads the EndpointSlices of the webhook Service.
	APIReader            client.Reader
	Scheme               *runtime.Scheme
	Log                  logr.Logger
	DeploymentsNamespace string
	ConfigMapName        string
	// WebhookServiceName is the name of the Service of the controller webhooks. The API server calls the
	// controller webhooks for every resource that this reconciler creates or updates.
	WebhookServiceName string
}

// Reconcile watches the defaults ConfigMap and applies the resources it contains.
func (r *DefaultsApplierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("configmap", req.NamespacedName)

	var cm corev1.ConfigMap
	if err := r.Get(ctx, req.NamespacedName, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ConfigMap not found, cleaning up all managed resources")
			if cleanupErr := r.cleanupAll(ctx); cleanupErr != nil {
				return ctrl.Result{}, fmt.Errorf("failed to cleanup all managed resources: %w", cleanupErr)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get ConfigMap: %w", err)
	}

	// The API server calls the controller webhooks for every resource that this reconciler creates or updates. The
	// Service of the webhooks sends traffic only to ready controller pods. When the controller starts, its own pod is
	// not ready yet, and on a fresh install no other pod is. Every apply would then fail with "connection refused".
	ready, readyErr := r.webhookServiceIsReady(ctx)
	if readyErr != nil {
		return ctrl.Result{}, readyErr
	}
	if !ready {
		log.Info("Waiting for a ready endpoint of the webhook service before applying the defaults", "service", r.WebhookServiceName)
		return ctrl.Result{RequeueAfter: webhookServiceWaitInterval}, nil
	}

	desired := sets.New[resourceKey]()

	for key, yamlData := range cm.Data {
		obj := &unstructured.Unstructured{}
		if err := sigsyaml.Unmarshal([]byte(yamlData), obj); err != nil {
			log.Error(err, "failed to decode resource from ConfigMap", "key", key)
			// Don't fail the whole reconciliation for one bad entry
			continue
		}

		gvk := obj.GroupVersionKind()
		if !isSupportedGVK(gvk) {
			log.Info("Unsupported resource type, skipping", "key", key, "gvk", gvk.String())
			continue
		}

		// Track this resource as desired
		rk := resourceKey{
			gvk:       gvk.String(),
			name:      obj.GetName(),
			namespace: obj.GetNamespace(),
		}
		desired.Insert(rk)

		// Apply the resource with ownership label injected
		if applyErr := r.applyResource(ctx, obj); applyErr != nil {
			return ctrl.Result{}, fmt.Errorf("failed to apply resource %s: %w", rk, applyErr)
		}
	}

	if err := r.cleanupStale(ctx, desired); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to cleanup stale resources: %w", err)
	}

	log.Info("Reconciliation complete", "appliedResources", len(desired))
	return ctrl.Result{}, nil
}

// webhookServiceIsReady returns true if the Service of the controller webhooks has at least one ready endpoint.
func (r *DefaultsApplierReconciler) webhookServiceIsReady(ctx context.Context) (bool, error) {
	endpointSlices := &discoveryv1.EndpointSliceList{}
	if err := r.APIReader.List(ctx, endpointSlices,
		client.InNamespace(r.DeploymentsNamespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: r.WebhookServiceName},
	); err != nil {
		return false, fmt.Errorf("failed to list the endpoint slices of the webhook service %q: %w", r.WebhookServiceName, err)
	}

	for _, endpointSlice := range endpointSlices.Items {
		for _, endpoint := range endpointSlice.Endpoints {
			// A nil value means an unknown state, which consumers must treat as ready.
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				return true, nil
			}
		}
	}
	return false, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *DefaultsApplierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(object client.Object) bool {
			return object.GetName() == r.ConfigMapName &&
				object.GetNamespace() == r.DeploymentsNamespace
		})).
		Complete(r); err != nil {
		return fmt.Errorf("failed to create DefaultsApplier controller: %w", err)
	}
	return nil
}

// applyResource applies the desired resource using Server-Side Apply. Only the fields present
// in the ConfigMap YAML are sent, so the API server applies CRD schema defaults (e.g.
// spec.backgroundAudit=true) for any field the template omits. SSA also manages field ownership:
// keys removed from the YAML are pruned, and re-applying identical content is a no-op.
func (r *DefaultsApplierReconciler) applyResource(ctx context.Context, desired *unstructured.Unstructured) error {
	log := r.Log.WithValues("resource", client.ObjectKeyFromObject(desired), "kind", desired.GetKind())

	// The status subresource cannot be set via an apply to the main resource; drop it so it
	// does not end up in our managed field set.
	unstructured.RemoveNestedField(desired.Object, "status")

	// When adopting a resource that was Helm-managed before the 1.37 chart unification,
	// strip the Helm bookkeeping annotations from the live object. This must happen
	// before the server-side Apply below, while the live object still reports Helm ownership.
	if err := r.stripHelmBookkeeping(ctx, desired); err != nil {
		return err
	}

	// Stamp the ownership label used by cleanupStale to identify managed resources.
	labels := desired.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels[constants.DefaultsManagedByLabelKey] = constants.DefaultsManagedByLabelValue
	desired.SetLabels(labels)

	if err := r.Apply(ctx, client.ApplyConfigurationFromUnstructured(desired),
		client.FieldOwner(constants.DefaultsManagedByLabelValue),
		client.ForceOwnership,
	); err != nil {
		return fmt.Errorf("failed to server-side apply resource: %w", err)
	}

	log.V(1).Info("Resource applied successfully")
	return nil
}

// stripHelmBookkeeping removes Helm bookkeeping annotations from the live resource when it
// was previously Helm-managed and the desired state explicitly claims controller ownership.
//
// This handles the 1.37 migration where the default PolicyServer and recommended policies
// moved from Helm ownership to controller ownership. Requiring both conditions avoids
// stripping annotations from resources that carry managed-by: Helm for unrelated reasons.
//
// The Helm annotations cannot be removed by the server-side apply in applyResource: they are
// owned by Helm's field manager and are absent from our applied configuration,
// so the API server leaves them untouched. A dedicated merge patch is required.
func (r *DefaultsApplierReconciler) stripHelmBookkeeping(ctx context.Context, desired *unstructured.Unstructured) error {
	if desired.GetLabels()[constants.ManagedByKey] != constants.ManagedByKeyLabelValue {
		// exit if we are not taking ownership
		return nil
	}

	live := &unstructured.Unstructured{}
	live.SetGroupVersionKind(desired.GroupVersionKind())
	if err := r.Get(ctx, client.ObjectKeyFromObject(desired), live); err != nil {
		if apierrors.IsNotFound(err) {
			// fresh resource: nothing to strip
			return nil
		}
		return fmt.Errorf("failed to get live resource: %w", err)
	}

	if live.GetLabels()[constants.ManagedByKey] != "Helm" {
		// exit if it wasn't previously owned by Helm
		return nil
	}

	orig := live.DeepCopy()
	annotations := live.GetAnnotations()
	changed := false
	helmBookkeepingAnnotations := []string{
		constants.HelmResourcePolicy,
		constants.HelmMetaReleaseName,
		constants.HelmMetaReleaseNamespace,
	}
	for _, key := range helmBookkeepingAnnotations {
		if _, found := annotations[key]; found {
			delete(annotations, key)
			changed = true
		}
	}
	if !changed {
		// exit if there was no annotations to remove
		return nil
	}
	live.SetAnnotations(annotations)

	if err := r.Patch(ctx, live, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("failed to strip Helm annotations: %w", err)
	}

	r.Log.Info("Stripped Helm bookkeeping annotations from adopted resource",
		"resource", client.ObjectKeyFromObject(live), "kind", live.GetKind())
	return nil
}

// isSupportedGVK returns true if the GroupVersionKind is a known Kubewarden resource type.
func isSupportedGVK(gvk schema.GroupVersionKind) bool {
	if gvk.Group != constants.KubewardenPoliciesGroup {
		return false
	}
	switch gvk.Kind {
	case "PolicyServer",
		"ClusterAdmissionPolicy",
		"AdmissionPolicy",
		"ClusterAdmissionPolicyGroup",
		"AdmissionPolicyGroup":
		return true
	default:
		return false
	}
}

// cleanupStale removes managed resources that are not in the desired set.
func (r *DefaultsApplierReconciler) cleanupStale(ctx context.Context, desired sets.Set[resourceKey]) error {
	managedSelector := client.MatchingLabels{
		constants.DefaultsManagedByLabelKey: constants.DefaultsManagedByLabelValue,
	}

	gvks := []schema.GroupVersionKind{
		{Group: constants.KubewardenPoliciesGroup, Version: "v1", Kind: "PolicyServerList"},
		{Group: constants.KubewardenPoliciesGroup, Version: "v1", Kind: "ClusterAdmissionPolicyList"},
		{Group: constants.KubewardenPoliciesGroup, Version: "v1", Kind: "AdmissionPolicyList"},
		{Group: constants.KubewardenPoliciesGroup, Version: "v1", Kind: "ClusterAdmissionPolicyGroupList"},
		{Group: constants.KubewardenPoliciesGroup, Version: "v1", Kind: "AdmissionPolicyGroupList"},
	}

	for _, gvk := range gvks {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk)

		if err := r.List(ctx, list, managedSelector); err != nil {
			return fmt.Errorf("failed to list managed resources: %w", err)
		}

		for i := range list.Items {
			item := &list.Items[i]
			rk := resourceKey{
				gvk:       item.GetObjectKind().GroupVersionKind().String(),
				name:      item.GetName(),
				namespace: item.GetNamespace(),
			}

			if !desired.Has(rk) {
				r.Log.Info("Deleting stale managed resource", "resource", rk)
				itemUID := item.GetUID()
				deleteErr := r.Delete(ctx, item, client.Preconditions{UID: &itemUID})
				if deleteErr != nil && !apierrors.IsNotFound(deleteErr) && !apierrors.IsConflict(deleteErr) {
					return fmt.Errorf("failed to delete stale resource %s: %w", rk, deleteErr)
				}
			}
		}
	}

	return nil
}

// cleanupAll removes all managed resources (called when ConfigMap is absent).
func (r *DefaultsApplierReconciler) cleanupAll(ctx context.Context) error {
	return r.cleanupStale(ctx, sets.New[resourceKey]())
}

// resourceKey uniquely identifies a Kubernetes resource.
type resourceKey struct {
	gvk       string
	name      string
	namespace string
}

func (rk resourceKey) String() string {
	if rk.namespace == "" {
		return fmt.Sprintf("%s/%s", rk.gvk, rk.name)
	}
	return fmt.Sprintf("%s/%s/%s", rk.gvk, rk.namespace, rk.name)
}
