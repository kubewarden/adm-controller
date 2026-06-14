/*
Copyright 2022.

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
	"encoding/json"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/go-logr/logr"
	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
	"github.com/kubewarden/adm-controller/internal/metrics"
)

type policySubReconciler struct {
	client.Client
	Log                                        logr.Logger
	deploymentsNamespace                       string
	featureGateAdmissionWebhookMatchConditions bool
}

func (r *policySubReconciler) reconcile(ctx context.Context, policy policiesv1.Policy) (ctrl.Result, error) {
	if policy.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, r.removePolicyWebhooksAndFinalizers(ctx, policy)
	}

	// Snapshot the policy before reconciliation so we can (a) skip the API write
	// when the status did not change and (b) compute a merge patch against this
	// base. A policy waiting for its PolicyServer to become ready requeues every
	// couple of seconds; without the guard every requeue would send an identical
	// status update, which is the bulk of the status-update churn reported in
	// issue #743.
	original := policy.DeepCopyObject().(policiesv1.Policy)

	reconcileResult, reconcileErr := r.reconcilePolicy(ctx, policy)

	if err := r.setPolicyModeStatus(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("error setting policy status: %w", err)
	}

	// Use a merge patch rather than an update. The cached client can hand back a
	// momentarily stale policy right after our own previous write; a full update
	// then fails the optimistic-lock check with "the object has been modified",
	// the status update error reported in issue #743. A merge patch carries no
	// resourceVersion precondition, so it applies cleanly from a stale base.
	if !equality.Semantic.DeepEqual(original.GetStatus(), policy.GetStatus()) {
		if err := r.Status().Patch(ctx, policy, client.MergeFrom(original)); err != nil {
			return ctrl.Result{}, fmt.Errorf("update admission policy status error: %w", err)
		}
	}

	// record policy count metric
	if err := metrics.RecordPolicyCount(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to record policy mestrics: %w", err)
	}

	return reconcileResult, reconcileErr
}

func (r *policySubReconciler) reconcilePolicy(ctx context.Context, policy policiesv1.Policy) (ctrl.Result, error) {
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyActive),
			Status:  metav1.ConditionFalse,
			Reason:  "PolicyActive",
			Message: "The policy webhook has not been created",
		},
	)
	if policy.GetPolicyServer() == "" {
		policy.SetStatus(policiesv1.PolicyStatusUnscheduled)
		return ctrl.Result{}, nil
	}

	policyServer, err := r.getPolicyServer(ctx, policy)
	if err != nil {
		if errors.Is(err, errPolicyServerNotAvailable) {
			return r.reconcilePolicyServerUnavailable(ctx, policy)
		}
		return ctrl.Result{}, err
	}

	if policy.GetStatus().PolicyStatus != policiesv1.PolicyStatusActive {
		policy.SetStatus(policiesv1.PolicyStatusPending)
	}

	policyServerDeployment := appsv1.Deployment{}
	if err = r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: policyServerDeploymentName(policy.GetPolicyServer())}, &policyServerDeployment); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, errors.Join(errors.New("could not read policy server Deployment"), err)
	}

	if !r.isPolicyUniquelyReachable(ctx, &policyServerDeployment, policy.GetUniqueName()) {
		apimeta.SetStatusCondition(
			&policy.GetStatus().Conditions,
			metav1.Condition{
				Type:    string(policiesv1.PolicyUniquelyReachable),
				Status:  metav1.ConditionFalse,
				Reason:  "LatestReplicaSetIsNotUniquelyReachable",
				Message: "The latest replica set is not uniquely reachable",
			},
		)
		return ctrl.Result{Requeue: true, RequeueAfter: constants.TimeToRequeuePolicyReconciliation}, nil
	}

	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyUniquelyReachable),
			Status:  metav1.ConditionTrue,
			Reason:  "LatestReplicaSetIsUniquelyReachable",
			Message: "The latest replica set is uniquely reachable",
		},
	)

	secret := corev1.Secret{}
	if err = r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: constants.CARootSecretName}, &secret); err != nil {
		return ctrl.Result{}, errors.Join(errors.New("cannot find policy server secret"), err)
	}

	// Add the controller's finalizer here to avoid webhook orphans
	if !controllerutil.ContainsFinalizer(policy, constants.KubewardenFinalizer) {
		controllerutil.AddFinalizer(policy, constants.KubewardenFinalizer)
		if err = r.Update(ctx, policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot add finalizer to policy: %w", err)
		}
	}

	if err = r.reconcileWebhookConfiguration(ctx, policy, &secret, policyServer.NameWithPrefix()); err != nil {
		return ctrl.Result{}, err
	}
	setPolicyAsActive(policy)

	return ctrl.Result{}, nil
}

// reconcilePolicyServerUnavailable handles the case where the PolicyServer is
// confirmed missing or being deleted.
// It removes the webhook configuration to prevent orphaned webhooks from blocking
// admission requests, then sets the policy status as scheduled.
func (r *policySubReconciler) reconcilePolicyServerUnavailable(ctx context.Context, policy policiesv1.Policy) (ctrl.Result, error) {
	if err := r.removePolicyWebhooksAndFinalizers(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	policy.SetStatus(policiesv1.PolicyStatusScheduled)

	return ctrl.Result{}, nil
}

// reconcileWebhookConfiguration creates or patches the webhook configuration
// for the policy, dispatching to the mutating or validating variant as needed.
func (r *policySubReconciler) reconcileWebhookConfiguration(ctx context.Context, policy policiesv1.Policy, secret *corev1.Secret, policyServerName string) error {
	if policy.IsMutating() {
		if err := r.reconcileMutatingWebhookConfiguration(ctx, policy, secret, policyServerName); err != nil {
			return errors.Join(errors.New("error reconciling mutating webhook"), err)
		}
		return nil
	}
	if err := r.reconcileValidatingWebhookConfiguration(ctx, policy, secret, policyServerName); err != nil {
		return errors.Join(errors.New("error reconciling validating webhook"), err)
	}
	return nil
}

// deleteWebhookConfiguration removes the webhook configuration for the policy,
// dispatching to the mutating or validating variant as needed.
func (r *policySubReconciler) deleteWebhookConfiguration(ctx context.Context, policy policiesv1.Policy) error {
	if policy.IsMutating() {
		return r.reconcileMutatingWebhookConfigurationDeletion(ctx, policy)
	}
	return r.reconcileValidatingWebhookConfigurationDeletion(ctx, policy)
}

// removePolicyWebhooksAndFinalizers removes the webhook configurations, which
// means that the policy can be safely deleted. Therefore, it also removes the
// policy finalizers.
func (r *policySubReconciler) removePolicyWebhooksAndFinalizers(ctx context.Context, policy policiesv1.Policy) error {
	if err := r.deleteWebhookConfiguration(ctx, policy); err != nil {
		return err
	}

	finalizerRemoved := false
	if controllerutil.ContainsFinalizer(policy, constants.KubewardenFinalizer) {
		controllerutil.RemoveFinalizer(policy, constants.KubewardenFinalizer)
		finalizerRemoved = true
	}
	// Remove the old finalizer used to ensure that the policy server created
	// before this controller version is deleted as well.
	// TODO:
	// As the upgrade path supported by the Kubewarden project does not
	// allow jumping versions, we can safely remove this line of code after a few
	// releases.
	if controllerutil.ContainsFinalizer(policy, constants.KubewardenFinalizerPre114) {
		controllerutil.RemoveFinalizer(policy, constants.KubewardenFinalizerPre114)
		finalizerRemoved = true
	}
	if finalizerRemoved {
		if err := r.Update(ctx, policy); err != nil {
			return fmt.Errorf("cannot update policy: %w", err)
		}
	}

	return nil
}

func (r *policySubReconciler) setPolicyModeStatus(ctx context.Context, policy policiesv1.Policy) error {
	policyServerDeployment := appsv1.Deployment{}
	policyServerDeploymentName := policyServerDeploymentName(policy.GetPolicyServer())

	if err := r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: policyServerDeploymentName}, &policyServerDeployment); err != nil {
		if apierrors.IsNotFound(err) {
			// If the policy server deployment is not found, the policy is not scheduled
			return nil
		}

		return errors.Join(errors.New("could not get policy server deployment"), err)
	}

	policyServerConfigMap := corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.deploymentsNamespace, Name: policyServerDeploymentName}, &policyServerConfigMap); err != nil {
		return errors.Join(errors.New("could not get configmap"), err)
	}

	policyMap, err := getPolicyMapFromConfigMap(&policyServerConfigMap)
	if err == nil {
		if policyConfig, ok := policyMap[policy.GetUniqueName()]; ok {
			policy.SetPolicyModeStatus(policiesv1.PolicyModeStatus(policyConfig.PolicyMode))
		} else {
			policy.SetPolicyModeStatus(policiesv1.PolicyModeStatusUnknown)
		}
	} else {
		policy.SetPolicyModeStatus(policiesv1.PolicyModeStatusUnknown)
	}

	policyStatus := policy.GetStatus()
	setPolicyConfigurationCondition(&policyServerConfigMap, &policyServerDeployment, &policyStatus.Conditions)

	return nil
}

// errPolicyServerNotAvailable is returned by getPolicyServer when the
// PolicyServer CR is confirmed to not exist or is being deleted. It is
// distinct from transient API errors so callers can decide whether to clean up
// webhook configurations or simply requeue.
var errPolicyServerNotAvailable = errors.New("policy server not available")

func (r *policySubReconciler) getPolicyServer(ctx context.Context, policy policiesv1.Policy) (*policiesv1.PolicyServer, error) {
	policyServer := policiesv1.PolicyServer{}
	if err := r.Get(ctx, types.NamespacedName{Name: policy.GetPolicyServer()}, &policyServer); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, errPolicyServerNotAvailable
		}
		return nil, errors.Join(errors.New("could not get policy server"), err)
	}
	if policyServer.DeletionTimestamp != nil {
		return nil, errPolicyServerNotAvailable
	}
	return &policyServer, nil
}

func (r *policySubReconciler) isPolicyUniquelyReachable(ctx context.Context, policyServerDeployment *appsv1.Deployment, policyName string) bool {
	configMap := corev1.ConfigMap{}

	err := r.Get(ctx, client.ObjectKey{
		Namespace: policyServerDeployment.Namespace,
		Name:      policyServerDeployment.Name, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return false
	}

	if !isPolicyInConfigMap(configMap, policyName) {
		return false
	}

	replicaSets := appsv1.ReplicaSetList{}
	if err = r.List(ctx, &replicaSets,
		client.InNamespace(policyServerDeployment.Namespace),
		client.MatchingLabels{constants.PolicyServerLabelKey: policyServerDeployment.Labels[constants.PolicyServerLabelKey]}); err != nil {
		return false
	}
	podTemplateHash := ""
	for index := range replicaSets.Items {
		if isLatestReplicaSetFromPolicyServerDeployment(&replicaSets.Items[index], policyServerDeployment, configMap.ResourceVersion) {
			podTemplateHash = replicaSets.Items[index].Labels[appsv1.DefaultDeploymentUniqueLabelKey]
			break
		}
	}
	if podTemplateHash == "" {
		return false
	}
	pods := corev1.PodList{}
	if err = r.List(ctx, &pods,
		client.InNamespace(policyServerDeployment.Namespace),
		client.MatchingLabels{constants.PolicyServerLabelKey: policyServerDeployment.Labels[constants.PolicyServerLabelKey]}); err != nil {
		return false
	}
	if len(pods.Items) == 0 {
		return false
	}
	for _, pod := range pods.Items {
		if pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey] != podTemplateHash || !isPodReady(pod) {
			return false
		}
	}
	return true
}

func isLatestReplicaSetFromPolicyServerDeployment(replicaSet *appsv1.ReplicaSet, policyServerDeployment *appsv1.Deployment, configMapVersion string) bool {
	return replicaSet.Annotations[constants.KubernetesRevisionAnnotation] == policyServerDeployment.Annotations[constants.KubernetesRevisionAnnotation] &&
		replicaSet.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation] == configMapVersion
}

func isPolicyInConfigMap(configMap corev1.ConfigMap, policyName string) bool {
	policies, err := getPolicyMapFromConfigMap(&configMap)
	if err != nil {
		return false
	}
	if _, ok := policies[policyName]; ok {
		return true
	}

	return false
}

func isPodReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == "Ready" {
			return condition.Status == "True"
		}
	}
	return false
}

func findPoliciesForConfigMap(object client.Object) []reconcile.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return []reconcile.Request{}
	}
	if _, isKubewardenConfigmap := configMap.Labels[constants.PolicyServerLabelKey]; !isKubewardenConfigmap {
		return []reconcile.Request{}
	}
	policyMap, err := getPolicyMapFromConfigMap(configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return policyMap.toAdmissionPolicyReconcileRequests()
}

func findClusterPoliciesForConfigMap(object client.Object) []reconcile.Request {
	configMap, ok := object.(*corev1.ConfigMap)
	if !ok {
		return []reconcile.Request{}
	}
	policyMap, err := getPolicyMapFromConfigMap(configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return policyMap.toClusterAdmissionPolicyReconcileRequests()
}

func findPoliciesForPod(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerName, isKubewardenPod := pod.Labels[constants.PolicyServerLabelKey]
	if !isKubewardenPod || pod.DeletionTimestamp != nil {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := policyServerDeploymentName(policyServerName)
	configMap := corev1.ConfigMap{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: pod.ObjectMeta.Namespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return findPoliciesForConfigMap(&configMap)
}

func findClusterPoliciesForPod(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	pod, ok := object.(*corev1.Pod)
	if !ok {
		return []reconcile.Request{}
	}
	policyServerName, ok := pod.Labels[constants.PolicyServerLabelKey]
	if !ok {
		return []reconcile.Request{}
	}
	policyServerDeploymentName := policyServerDeploymentName(policyServerName)
	configMap := corev1.ConfigMap{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Namespace: pod.ObjectMeta.Namespace,
		Name:      policyServerDeploymentName, // As the deployment name matches the name of the ConfigMap
	}, &configMap)
	if err != nil {
		return []reconcile.Request{}
	}
	return findClusterPoliciesForConfigMap(&configMap)
}

// findAdmissionPoliciesForPolicyServer maps a PolicyServer event to reconcile
// requests for AdmissionPolicies that reference it by name.
func findAdmissionPoliciesForPolicyServer(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	policyServer, ok := object.(*policiesv1.PolicyServer)
	if !ok {
		return []reconcile.Request{}
	}

	admissionPolicies := policiesv1.AdmissionPolicyList{}
	if err := k8sClient.List(ctx, &admissionPolicies, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name}); err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(admissionPolicies.Items))
	for _, policy := range admissionPolicies.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: policy.Name, Namespace: policy.Namespace},
		})
	}
	return requests
}

// findAdmissionPolicyGroupsForPolicyServer maps a PolicyServer event to
// reconcile requests for all AdmissionPolicyGroups that reference it by name.
func findAdmissionPolicyGroupsForPolicyServer(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	policyServer, ok := object.(*policiesv1.PolicyServer)
	if !ok {
		return []reconcile.Request{}
	}

	admissionPolicyGroups := policiesv1.AdmissionPolicyGroupList{}
	if err := k8sClient.List(ctx, &admissionPolicyGroups, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name}); err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(admissionPolicyGroups.Items))
	for _, policy := range admissionPolicyGroups.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: policy.Name, Namespace: policy.Namespace},
		})
	}
	return requests
}

// findClusterAdmissionPoliciesForPolicyServer maps a PolicyServer event to reconcile
// requests for all ClusterAdmissionPolicies that reference it by name.
func findClusterAdmissionPoliciesForPolicyServer(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	policyServer, ok := object.(*policiesv1.PolicyServer)
	if !ok {
		return []reconcile.Request{}
	}

	clusterAdmissionPolicies := policiesv1.ClusterAdmissionPolicyList{}
	if err := k8sClient.List(ctx, &clusterAdmissionPolicies, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name}); err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(clusterAdmissionPolicies.Items))
	for _, policy := range clusterAdmissionPolicies.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: policy.Name},
		})
	}
	return requests
}

// findClusterAdmissionPolicyGroupsForPolicyServer maps a PolicyServer event to reconcile
// requests for all ClusterAdmissionPolicyGroups that reference it by name.
func findClusterAdmissionPolicyGroupsForPolicyServer(ctx context.Context, k8sClient client.Client, object client.Object) []reconcile.Request {
	policyServer, ok := object.(*policiesv1.PolicyServer)
	if !ok {
		return []reconcile.Request{}
	}

	clusterAdmissionPolicyGroups := policiesv1.ClusterAdmissionPolicyGroupList{}
	if err := k8sClient.List(ctx, &clusterAdmissionPolicyGroups, client.MatchingFields{constants.PolicyServerIndexKey: policyServer.Name}); err != nil {
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(clusterAdmissionPolicyGroups.Items))
	for _, policy := range clusterAdmissionPolicyGroups.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: policy.Name},
		})
	}
	return requests
}

func hasKubewardenLabel(labels map[string]string) bool {
	// Pre v1.16.0
	kubewardenLabel := labels["kubewarden"]
	// From v1.16.0 on we are using the recommended label "app.kubernetes.io/part-of"
	partOfLabel := labels[constants.PartOfLabelKey]

	return kubewardenLabel == "true" || partOfLabel == constants.PartOfLabelValue //nolint:goconst
}

func getPolicyMapFromConfigMap(configMap *corev1.ConfigMap) (policyConfigEntryMap, error) {
	policyMap := policyConfigEntryMap{}
	if policies, ok := configMap.Data[constants.PolicyServerConfigPoliciesEntry]; ok {
		if err := json.Unmarshal([]byte(policies), &policyMap); err != nil {
			return policyMap, errors.Join(errors.New("failed to unmarshal policy mapping"), err)
		}
	} else {
		return policyMap, nil
	}
	return policyMap, nil
}

func setPolicyAsActive(policy policiesv1.Policy) {
	policy.SetStatus(policiesv1.PolicyStatusActive)
	apimeta.SetStatusCondition(
		&policy.GetStatus().Conditions,
		metav1.Condition{
			Type:    string(policiesv1.PolicyActive),
			Status:  metav1.ConditionTrue,
			Reason:  "PolicyActive",
			Message: "The policy webhook has been created",
		},
	)
}

func setPolicyConfigurationCondition(policyServerConfigMap *corev1.ConfigMap, policyServerDeployment *appsv1.Deployment, conditions *[]metav1.Condition) {
	if configAnnotation, ok := policyServerDeployment.Annotations[constants.PolicyServerDeploymentConfigVersionAnnotation]; ok {
		if configAnnotation == policyServerConfigMap.ResourceVersion {
			apimeta.SetStatusCondition(
				conditions,
				metav1.Condition{
					Type:    string(policiesv1.PolicyServerConfigurationUpToDate),
					Status:  metav1.ConditionTrue,
					Reason:  "ConfigurationVersionMatch",
					Message: "Configuration for this policy is up to date",
				},
			)
		} else {
			apimeta.SetStatusCondition(
				conditions,
				metav1.Condition{
					Type:    string(policiesv1.PolicyServerConfigurationUpToDate),
					Status:  metav1.ConditionFalse,
					Reason:  "ConfigurationVersionMismatch",
					Message: "Configuration for this policy is not up to date",
				},
			)
		}
	} else {
		apimeta.SetStatusCondition(
			conditions,
			metav1.Condition{
				Type:    string(policiesv1.PolicyServerConfigurationUpToDate),
				Status:  metav1.ConditionFalse,
				Reason:  "UnknownConfigurationVersion",
				Message: fmt.Sprintf("Configuration version annotation (%s) in deployment %s is missing", constants.PolicyServerDeploymentConfigVersionAnnotation, policyServerDeployment.GetName()),
			},
		)
	}
}
