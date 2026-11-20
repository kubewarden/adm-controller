/*
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

package v1

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/kubewarden/adm-controller/internal/constants"
)

func TestValidateRulesField(t *testing.T) {
	tests := []struct {
		name                  string
		policy                Policy
		expectedErrorMessages []string // use nil when no error is expected
	}{
		{
			"with valid APIVersion and resources. But with empty APIGroup",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}).
				WithPolicyServer("default").Build(),
			nil,
		},
		{
			"with valid APIVersion, Resources and APIGroup",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{"deployments"},
						},
					},
				}).
				WithPolicyServer("default").Build(),
			nil,
		},
		{
			"with no operations and API groups and resources",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules: Required value: a value must be specified"},
		},
		{
			"with empty objects",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].operations: Required value: a value must be specified"},
		},
		{
			"with no operations",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].operations: Required value: a value must be specified"},
		},
		{
			"with null operations",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: nil,
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{"*/*"},
					},
				}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].operations: Required value: a value must be specified"},
		},
		{
			"with empty operations string",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{""},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{"*/*"},
					},
				}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].operations[0]: Required value: must be non-empty"},
		},
		{
			"with no apiVersion",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{},
						Resources:   []string{"*/*"},
					},
				}}).
				WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].apiVersions: Required value: a value must be specified"},
		},
		{
			"with no resources",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].resources: Required value: a value must be specified"},
		},
		{
			"with empty apiVersion string",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{""},
						Resources:   []string{"*/*"},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].apiVersions[0]: Required value: must be non-empty"},
		},
		{
			"with empty resources string",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{"*"},
						APIVersions: []string{"*"},
						Resources:   []string{""},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].resources[0]: Required value: must be non-empty"},
		},
		{
			"with some of the resources are empty strings",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{{
					Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
					Rule: admissionregistrationv1.Rule{
						APIGroups:   []string{""},
						APIVersions: []string{"v1"},
						Resources:   []string{"", "pods"},
					},
				}}).WithPolicyServer("default").Build(),
			[]string{"spec.rules[0].resources[0]: Required value: must be non-empty"},
		},
		{
			"with two rules. Only the second one has an empty resource",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"v1"},
							Resources:   []string{""},
						},
					},
				}).WithPolicyServer("default").Build(),
			[]string{"spec.rules[1].resources[0]: Required value: must be non-empty"},
		},
		{
			"with all operations and API groups and resources",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"with wildcard usage. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*/*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules[0].apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules[0].resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"with wildcard usage. But an AdmissionPolicyGroup",
			NewAdmissionPolicyGroupFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"*"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules[0].apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules[0].resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"targeting a PolicyReport. But a ClusterAdmissionPolicy",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"wgpolicyk8s.io"},
							APIVersions: []string{"v1alpha2"},
							Resources:   []string{"policyreports"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"targeting a PolicyReport. But an AdmissionPolicy. The controller checks the allow list at reconcile time",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"wgpolicyk8s.io"},
							APIVersions: []string{"v1alpha2"},
							Resources:   []string{"policyreports"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"targeting all wgpolicyk8s.io resources. But an AdmissionPolicyGroup. A wildcard on resources alone is permitted",
			NewAdmissionPolicyGroupFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"wgpolicyk8s.io"},
							APIVersions: []string{"v1alpha2"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"targeting an openreports.io Report. But a ClusterAdmissionPolicy",
			NewClusterAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"openreports.io"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"reports"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"targeting an openreports.io Report. But an AdmissionPolicy. The controller checks the allow list at reconcile time",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"openreports.io"},
							APIVersions: []string{"v1alpha1"},
							Resources:   []string{"reports"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"with apiGroups wildcard and a matching apiVersion. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"v1"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules[0].apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules[0].resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"with apiGroups wildcard and a double wildcard resource. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"v1"},
							Resources:   []string{"*/*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules[0].apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules[0].resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"with apiGroups wildcard and a matching apiVersion. But an AdmissionPolicyGroup",
			NewAdmissionPolicyGroupFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"v1"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			[]string{
				"spec.rules[0].apiGroups[0]: Forbidden: apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
				"spec.rules[0].resources[0]: Forbidden: resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup",
			},
		},
		{
			"with a named apiGroup and a wildcard apiVersion and resource. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"apps"},
							APIVersions: []string{"*"},
							Resources:   []string{"*"},
						},
					},
				}).Build(),
			nil,
		},
		{
			"with an apiGroups wildcard and a named resource. But an AdmissionPolicy",
			NewAdmissionPolicyFactory().
				WithRules([]admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"*"},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
					},
				}).Build(),
			nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allErrors := validateRulesField(test.policy)

			if len(test.expectedErrorMessages) != 0 {
				err := prepareInvalidAPIError(test.policy, allErrors)
				for _, expectedErrorMessage := range test.expectedErrorMessages {
					require.ErrorContains(t, err, expectedErrorMessage)
				}
			} else {
				require.Empty(t, allErrors)
			}
		})
	}
}

func TestValidateMatchConditionsField(t *testing.T) {
	defaultRules := []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
			Rule:       admissionregistrationv1.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments"}},
		},
	}
	tests := []struct {
		name                 string
		policy               Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"with empty MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				Build(),
			"",
		},
		{
			"with valid MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions([]admissionregistrationv1.MatchCondition{
					{
						Name:       "foo",
						Expression: "true",
					},
				}).
				WithPolicyServer("default").
				Build(),
			"",
		},
		{
			"with non-boolean MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions([]admissionregistrationv1.MatchCondition{
					{
						Name:       "foo",
						Expression: "1 + 1",
					},
				}).
				WithPolicyServer("default").
				Build(),
			"Invalid value: \"1 + 1\": must evaluate to bool",
		},
		{
			"with invalid expression in MatchConditions",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions([]admissionregistrationv1.MatchCondition{
					{
						Name:       "foo",
						Expression: "invalid expression",
					},
				}).
				WithPolicyServer("default").
				Build(),
			"Syntax error: extraneous input 'expression'",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allErrors := validateMatchConditions(test.policy.GetMatchConditions(), field.NewPath("spec").Child("matchConditions"))

			if test.expectedErrorMessage != "" {
				err := prepareInvalidAPIError(test.policy, allErrors)
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Empty(t, allErrors)
			}
		})
	}
}

func TestValidatePolicyServerField(t *testing.T) {
	defaultRules := []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		},
	}}
	tests := []struct {
		name                 string
		oldPolicy            Policy
		newPolicy            Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"policy server unchanged",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("old-policy-server").
				WithMode("monitor").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("old-policy-server").
				WithMode("monitor").
				Build(),
			"",
		},
		{
			"policy server changed",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("old-policy-server").
				WithMode("monitor").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("new-policy-server").
				WithMode("monitor").
				Build(),
			"spec.policyServer: Forbidden: the field is immutable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyServerField(test.oldPolicy, test.newPolicy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidatePolicyModeField(t *testing.T) {
	defaultRules := []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		},
	}}
	tests := []struct {
		name                 string
		oldPolicy            Policy
		newPolicy            Policy
		expectedErrorMessage string // use empty string when no error is expected
	}{
		{
			"policy mode unchanged",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			"",
		},
		{
			"policy mode changed from monitor to protect",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("monitor").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			"",
		},
		{
			"policy mode changed from protect to monitor",
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("protect").
				Build(),
			NewClusterAdmissionPolicyFactory().
				WithRules(defaultRules).
				WithMatchConditions(nil).
				WithPolicyServer("default").
				WithMode("monitor").
				Build(),
			"spec.mode: Forbidden: field cannot transition from protect to monitor. Recreate instead.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyModeField(test.oldPolicy, test.newPolicy)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidateTimeoutSeconds(t *testing.T) {
	maxTimeout := int32(30)
	underTimeout := int32(10)

	type testCase struct {
		name               string
		timeoutSeconds     *int32
		timeoutEvalSeconds *int32
		expectedErrors     []string
	}

	tests := []testCase{
		{
			name:               "both nil",
			timeoutSeconds:     nil,
			timeoutEvalSeconds: nil,
			expectedErrors:     nil,
		},
		{
			name:               "timeoutEvalSeconds > timeoutSeconds",
			timeoutSeconds:     &underTimeout,
			timeoutEvalSeconds: &maxTimeout,
			expectedErrors:     []string{"timeoutEvalSeconds cannot be greater than timeoutSeconds"},
		},
		{
			name:               "valid values",
			timeoutSeconds:     &maxTimeout,
			timeoutEvalSeconds: &underTimeout,
			expectedErrors:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := NewClusterAdmissionPolicyFactory().
				WithTimeoutSeconds(tc.timeoutSeconds).
				WithTimeoutEvalSeconds(tc.timeoutEvalSeconds).
				Build()
			errs := validateTimeoutSeconds(policy)
			if tc.expectedErrors == nil {
				require.Empty(t, errs)
			} else {
				for _, expected := range tc.expectedErrors {
					found := false
					for _, err := range errs {
						if strings.Contains(err.Error(), expected) {
							found = true
							break
						}
					}
					require.True(t, found, "expected error containing %q, got %v", expected, errs)
				}
			}
		})
	}
}

// TestValidateUniqueNameLength verifies that a policy whose unique name,
// combined with the webhook entry name suffix, would exceed the Kubernetes
// DNS1123 subdomain length limit is rejected, for all four policy kinds.
// A policy at exactly the maximum allowed length must be accepted.
func TestValidateUniqueNameLength(t *testing.T) {
	tests := []struct {
		name        string
		buildPolicy func(policyName string) Policy
	}{
		{
			name: "AdmissionPolicy",
			buildPolicy: func(policyName string) Policy {
				return NewAdmissionPolicyFactory().WithName(policyName).WithNamespace("team").Build()
			},
		},
		{
			name: "AdmissionPolicyGroup",
			buildPolicy: func(policyName string) Policy {
				return NewAdmissionPolicyGroupFactory().WithName(policyName).WithNamespace("team").Build()
			},
		},
		{
			name: "ClusterAdmissionPolicy",
			buildPolicy: func(policyName string) Policy {
				return NewClusterAdmissionPolicyFactory().WithName(policyName).Build()
			},
		},
		{
			name: "ClusterAdmissionPolicyGroup",
			buildPolicy: func(policyName string) Policy {
				return NewClusterAdmissionPolicyGroupFactory().WithName(policyName).Build()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The unique name is built as some fixed overhead (kind token,
			// optional namespace, dots) plus the policy name verbatim. Probe
			// that overhead with a throwaway 1-character name, then derive
			// the exact name length at which the webhook entry name reaches
			// the DNS1123 subdomain length limit.
			probe := tc.buildPolicy("x")
			overhead := len(probe.GetUniqueName()) - len(probe.GetName())
			maxNameLength := validation.DNS1123SubdomainMaxLength - len(constants.WebhookNameSuffix) - overhead
			require.Positive(t, maxNameLength, "test setup error: computed a non-positive max name length")

			atLimit := tc.buildPolicy(strings.Repeat("a", maxNameLength))
			require.Nil(t, validateUniqueNameLength(atLimit),
				"a policy name at the maximum allowed length should be accepted")

			overLimit := tc.buildPolicy(strings.Repeat("a", maxNameLength+1))
			err := validateUniqueNameLength(overLimit)
			require.NotNil(t, err, "a policy name one character over the limit should be rejected")
			require.Contains(t, err.Error(), fmt.Sprintf("at most %d characters long", maxNameLength))
		})
	}
}

func TestValidatePolicyModule(t *testing.T) {
	badModule := "https://example.com/policy.wasm?id=1"
	goodModule := "https://example.com/policy.wasm"
	modulePath := "spec.module"
	message := "the module URL is not valid. An http or https module URL must have only " +
		"the host, an optional port, and the full path to the file."

	t.Run("create rejects a bad module", func(t *testing.T) {
		policy := NewClusterAdmissionPolicyFactory().Build()
		policy.Spec.Module = badModule

		errs := validatePolicyCreate(policy)
		require.Len(t, errs, 1)
		require.Equal(t, modulePath, errs[0].Field)
		require.Equal(t, message, errs[0].Detail)
	})

	t.Run("create accepts a good module", func(t *testing.T) {
		policy := NewClusterAdmissionPolicyFactory().Build()
		policy.Spec.Module = goodModule

		require.Empty(t, validatePolicyCreate(policy))
	})

	t.Run("update rejects a bad module", func(t *testing.T) {
		oldPolicy := NewClusterAdmissionPolicyFactory().Build()
		oldPolicy.Spec.Module = badModule
		newPolicy := oldPolicy.DeepCopy()

		errs := validatePolicyUpdate(oldPolicy, newPolicy)
		require.Len(t, errs, 1)
		require.Equal(t, modulePath, errs[0].Field)
		require.Equal(t, message, errs[0].Detail)
	})

	t.Run("namespaced policy rejects a bad module", func(t *testing.T) {
		policy := NewAdmissionPolicyFactory().Build()
		policy.Spec.Module = badModule

		errs := validatePolicyCreate(policy)
		require.Len(t, errs, 1)
		require.Equal(t, modulePath, errs[0].Field)
		require.Equal(t, message, errs[0].Detail)

		errs = validatePolicyUpdate(policy, policy.DeepCopy())
		require.Len(t, errs, 1)
		require.Equal(t, modulePath, errs[0].Field)
		require.Equal(t, message, errs[0].Detail)
	})
}
