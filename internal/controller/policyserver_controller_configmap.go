package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "github.com/kubewarden/adm-controller/api/policies/v1"
	"github.com/kubewarden/adm-controller/internal/constants"
)

type policyGroupMemberWithContext struct {
	Module                string                            `json:"module"`
	Settings              runtime.RawExtension              `json:"settings,omitempty"`
	ContextAwareResources []policiesv1.ContextAwareResource `json:"contextAwareResources,omitempty"`
	TimeoutEvalSeconds    *int32                            `json:"timeoutEvalSeconds,omitempty"`
	HostCapabilities      []string                          `json:"hostCapabilities"`
}

type policyServerConfigEntry struct {
	NamespacedName        types.NamespacedName              `json:"namespacedName"`
	Module                string                            `json:"module,omitempty"`
	PolicyMode            string                            `json:"policyMode"`
	AllowedToMutate       bool                              `json:"allowedToMutate,omitempty"`
	ContextAwareResources []policiesv1.ContextAwareResource `json:"contextAwareResources,omitempty"`
	Settings              runtime.RawExtension              `json:"settings,omitempty"`
	Message               string                            `json:"message,omitempty"`
	TimeoutEvalSeconds    *int32                            `json:"timeoutEvalSeconds,omitempty"`
	HostCapabilities      []string                          `json:"hostCapabilities"`
	// The following fields are used by policy groups only.
	Policies   map[string]policyGroupMemberWithContext `json:"policies,omitempty"`
	Expression string                                  `json:"expression,omitempty"`
}

// The following MarshalJSON and UnmarshalJSON methods are used to serialize
// and deserialize the policyServerConfigEntry struct to and from JSON. This is
// necessary because each policy type has different fields and we need to
// handle them differently. It's not beautiful, but we do not need to change
// other parts of the code to make it work.
func (p *policyServerConfigEntry) UnmarshalJSON(b []byte) error {
	type configEntry *policyServerConfigEntry
	entry := configEntry(p)
	if err := json.Unmarshal(b, entry); err != nil {
		return errors.Join(errors.New("failed to unmarshal policy server config entry"), err)
	}
	if len(p.Policies) == 0 && len(p.Module) == 0 {
		return errors.New("policies JSON should have an URL or a list of policies to be evaluated")
	}
	if len(p.Policies) != 0 && len(p.Module) != 0 {
		return errors.New("policies JSON should not have an URL and a list of policies to be evaluated at the same time")
	}
	return nil
}

func (p policyServerConfigEntry) MarshalJSON() ([]byte, error) {
	if len(p.Policies) > 0 {
		// For policy groups, hostCapabilities is not emitted at the group level.
		// Each group member carries its own hostCapabilities field instead.
		bytes, err := json.Marshal(struct {
			NamespacedName types.NamespacedName                    `json:"namespacedName"`
			PolicyMode     string                                  `json:"policyMode"`
			Policies       map[string]policyGroupMemberWithContext `json:"policies"`
			Expression     string                                  `json:"expression"`
			Message        string                                  `json:"message"`
		}{
			NamespacedName: p.NamespacedName,
			PolicyMode:     p.PolicyMode,
			Policies:       p.Policies,
			Expression:     p.Expression,
			Message:        p.Message,
		})
		if err != nil {
			return nil, errors.New("failed to encode policy server configuration")
		}
		return bytes, nil
	}

	bytes, err := json.Marshal(struct {
		NamespacedName        types.NamespacedName              `json:"namespacedName"`
		Module                string                            `json:"module"`
		PolicyMode            string                            `json:"policyMode"`
		AllowedToMutate       bool                              `json:"allowedToMutate"`
		ContextAwareResources []policiesv1.ContextAwareResource `json:"contextAwareResources,omitempty"`
		Settings              runtime.RawExtension              `json:"settings,omitempty"`
		Message               string                            `json:"message,omitempty"`
		TimeoutEvalSeconds    *int32                            `json:"timeoutEvalSeconds,omitempty"`
		HostCapabilities      []string                          `json:"hostCapabilities"`
	}{
		NamespacedName:        p.NamespacedName,
		Module:                p.Module,
		PolicyMode:            p.PolicyMode,
		AllowedToMutate:       p.AllowedToMutate,
		ContextAwareResources: p.ContextAwareResources,
		Settings:              p.Settings,
		Message:               p.Message,
		TimeoutEvalSeconds:    p.TimeoutEvalSeconds,
		HostCapabilities:      p.HostCapabilities,
	})
	if err != nil {
		return nil, errors.New("failed to encode policy server configuration")
	}
	return bytes, nil
}

type policyServerSourceAuthority struct {
	Type string `json:"type"`
	Data string `json:"data"` // contains a PEM encoded certificate
}

type policyServerSourcesEntry struct {
	InsecureSources   []string                                 `json:"insecure_sources,omitempty"`
	SourceAuthorities map[string][]policyServerSourceAuthority `json:"source_authorities,omitempty"`
}

// Reconciles the ConfigMap that holds the configuration of the Policy Server.
// It returns the ConfigMap resourceVersion as observed after the create/patch,
// so callers can stamp it onto the Deployment without issuing a separate,
// uncached GET against the API server.
func (r *PolicyServerReconciler) reconcilePolicyServerConfigMap(
	ctx context.Context,
	policyServer *policiesv1.PolicyServer,
	policies []policiesv1.Policy,
) (string, error) {
	cfg := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyServer.NameWithPrefix(),
			Namespace: r.DeploymentsNamespace,
			Labels:    policyServer.CommonLabels(),
		},
	}
	_, err := controllerutil.CreateOrPatch(ctx, r.Client, cfg, func() error {
		return r.updateConfigMapData(cfg, policyServer, policies)
	})
	if err != nil {
		return "", fmt.Errorf("cannot create or update PolicyServer ConfigMap: %w", err)
	}
	// CreateOrPatch updates cfg in place with the object returned by the API
	// server, so cfg.ResourceVersion is the authoritative current version.
	return cfg.ResourceVersion, nil
}

// Function used to update the ConfigMap data when creating or updating it.
func (r *PolicyServerReconciler) updateConfigMapData(cfg *corev1.ConfigMap, policyServer *policiesv1.PolicyServer, policies []policiesv1.Policy) error {
	policiesMap := buildPoliciesMap(policies, policyServer)
	policiesYML, err := json.Marshal(policiesMap)
	if err != nil {
		return fmt.Errorf("cannot marshal policies: %w", err)
	}

	sources := buildSourcesMap(policyServer)
	sourcesYML, err := json.Marshal(sources)
	if err != nil {
		return fmt.Errorf("cannot marshal insecureSources: %w", err)
	}

	data := map[string]string{
		constants.PolicyServerConfigPoliciesEntry: string(policiesYML),
		constants.PolicyServerConfigSourcesEntry:  string(sourcesYML),
	}

	cfg.Data = data
	cfg.ObjectMeta.Labels = map[string]string{
		constants.PolicyServerLabelKey: policyServer.ObjectMeta.Name,
	}
	if err = controllerutil.SetOwnerReference(policyServer, cfg, r.Client.Scheme()); err != nil {
		return errors.Join(errors.New("failed to set policy server configmap owner reference"), err)
	}
	return nil
}

func buildPolicyGroupMembersWithContext(policies policiesv1.PolicyGroupMembersWithContext, hostCaps []string) map[string]policyGroupMemberWithContext {
	policyGroupMembers := map[string]policyGroupMemberWithContext{}
	for name, policy := range policies {
		policyGroupMembers[name] = policyGroupMemberWithContext{
			Module:                policy.Module,
			Settings:              policy.Settings,
			ContextAwareResources: policy.ContextAwareResources,
			TimeoutEvalSeconds:    policy.TimeoutEvalSeconds,
			HostCapabilities:      hostCaps,
		}
	}
	return policyGroupMembers
}

// hostCapabilitiesForPolicy returns the host capabilities for a policy based on
// whether it is namespaced or cluster-wide.
// Cluster-wide policies always get all host capabilities ("*").
// Namespaced policies get the capabilities configured on the PolicyServer. If it
// is not configured on the PolicyServer, they get all host capabilities ("*").
func hostCapabilitiesForPolicy(admissionPolicy policiesv1.Policy, policyServer *policiesv1.PolicyServer) []string {
	if admissionPolicy.GetNamespace() == "" {
		// Cluster-wide policy: grant all host capabilities
		return []string{"*"}
	}

	// Namespaced policy: use the PolicyServer's configured capabilities
	if policyServer.Spec.NamespacedPoliciesCapabilities != nil {
		return policyServer.Spec.NamespacedPoliciesCapabilities
	}

	// Namespaced policy and no PolicyServer.spec.NamespacedPoliciesCapabilities,
	// default to grant all host capabilities
	return []string{"*"}
}

func buildPoliciesMap(admissionPolicies []policiesv1.Policy, policyServer *policiesv1.PolicyServer) policyConfigEntryMap {
	policies := policyConfigEntryMap{}
	for _, admissionPolicy := range admissionPolicies {
		hostCaps := hostCapabilitiesForPolicy(admissionPolicy, policyServer)

		configEntry := policyServerConfigEntry{
			NamespacedName: types.NamespacedName{
				Namespace: admissionPolicy.GetNamespace(),
				Name:      admissionPolicy.GetName(),
			},
			Module:                admissionPolicy.GetModule(),
			PolicyMode:            string(admissionPolicy.GetPolicyMode()),
			AllowedToMutate:       admissionPolicy.IsMutating(),
			Settings:              admissionPolicy.GetSettings(),
			ContextAwareResources: admissionPolicy.GetContextAwareResources(),
			Message:               admissionPolicy.GetMessage(),
			TimeoutEvalSeconds:    admissionPolicy.GetTimeoutEvalSeconds(),
			HostCapabilities:      hostCaps,
		}

		if policyGroup, ok := admissionPolicy.(policiesv1.PolicyGroup); ok {
			configEntry.Policies = buildPolicyGroupMembersWithContext(policyGroup.GetPolicyGroupMembersWithContext(), hostCaps)
			configEntry.Expression = policyGroup.GetExpression()
		}

		policies[admissionPolicy.GetUniqueName()] = configEntry
	}
	return policies
}

func buildSourcesMap(policyServer *policiesv1.PolicyServer) policyServerSourcesEntry {
	sourcesEntry := policyServerSourcesEntry{}
	sourcesEntry.InsecureSources = policyServer.Spec.InsecureSources
	if sourcesEntry.InsecureSources == nil {
		sourcesEntry.InsecureSources = make([]string, 0)
	}

	sourcesEntry.SourceAuthorities = make(map[string][]policyServerSourceAuthority)
	// build sources.yml with data keys for Policy-server
	for uri, certs := range policyServer.Spec.SourceAuthorities {
		sourcesEntry.SourceAuthorities[uri] = make([]policyServerSourceAuthority, 0)
		for _, cert := range certs {
			sourcesEntry.SourceAuthorities[uri] = append(sourcesEntry.SourceAuthorities[uri],
				policyServerSourceAuthority{
					Type: "Data", //nolint: goconst
					Data: cert,
				})
		}
	}
	return sourcesEntry
}

type policyConfigEntryMap map[string]policyServerConfigEntry

func (e policyConfigEntryMap) toAdmissionPolicyReconcileRequests() []reconcile.Request {
	res := []reconcile.Request{}
	for _, policy := range e {
		if policy.NamespacedName.Namespace == "" {
			continue
		}
		res = append(res, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: policy.NamespacedName.Namespace,
				Name:      policy.NamespacedName.Name,
			},
		})
	}
	return res
}

func (e policyConfigEntryMap) toClusterAdmissionPolicyReconcileRequests() []reconcile.Request {
	res := []reconcile.Request{}
	for _, policy := range e {
		if policy.NamespacedName.Namespace != "" {
			continue
		}
		res = append(res, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: policy.NamespacedName.Name,
			},
		})
	}
	return res
}
