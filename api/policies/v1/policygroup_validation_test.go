package v1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidatePolicyGroupExpressionField(t *testing.T) {
	tests := []struct {
		name                 string
		policyGroup          PolicyGroup
		expectedErrorMessage string
	}{
		{
			"with valid expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "policy1() && policy2()",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			"",
		},
		{
			"with empty expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			`spec.expression: Required value: must be non-empty`,
		},
		{
			"with non-boolean expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "123",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			`spec.expression: Invalid value: "123": must evaluate to bool`,
		},
		{
			"with invalid expression",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "2 > 1",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			`spec.expression: Invalid value: "2 > 1": compilation failed`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePolicyGroupExpressionField(test.policyGroup)

			if test.expectedErrorMessage != "" {
				require.ErrorContains(t, err, test.expectedErrorMessage)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidatePolicyGroupMembers(t *testing.T) {
	tests := []struct {
		name                 string
		policyGroup          PolicyGroup
		expectedErrorMessage string
	}{
		{
			"with valid policy members",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						GroupSpec: GroupSpec{
							Expression: "policy1() && policy2()",
							Message:    "This is a test policy",
						},
						Policies: PolicyGroupMembersWithContext{
							"policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			"",
		},
		{
			"with no policy members",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: map[string]PolicyGroupMemberWithContext{},
					},
				},
			},
			`spec.policies: Required value: policy groups must have at least one policy member`,
		},
		{
			"policy member with empty name",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "": policy group member name is invalid`,
		},
		{
			"policy member with reserved keyword",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"in": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "in": policy group member name is invalid`,
		},
		{
			"policy member name cannot start with digits",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"0policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "0policy1": policy group member name is invalid`,
		},
		{
			"policy member name cannot have special chars",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"p!ol.ic?y1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
						},
					},
				},
			},
			`spec.policies: Invalid value: "p!ol.ic?y1": policy group member name is invalid`,
		},
		{
			"policy member names allow underscores",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"_policy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"pol_icy2": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			"",
		},
		{
			"policy member names allow digits in the middle",
			&ClusterAdmissionPolicyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "testing-cluster-policy-group",
				},
				Spec: ClusterAdmissionPolicyGroupSpec{
					ClusterPolicyGroupSpec: ClusterPolicyGroupSpec{
						Policies: PolicyGroupMembersWithContext{
							"po0licy1": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/user-group-psp:v0.4.9",
								},
							},
							"policy21": {
								PolicyGroupMember: PolicyGroupMember{
									Module: "ghcr.io/kubewarden/tests/safe-labels:v1.0.0",
								},
							},
						},
					},
				},
			},
			"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			errors := validatePolicyGroupMembers(test.policyGroup)

			if test.expectedErrorMessage != "" {
				errors = errors.Filter(func(e error) bool {
					return !strings.Contains(e.Error(), test.expectedErrorMessage)
				})
				require.NotEmpty(t, errors)
			} else {
				require.Empty(t, errors)
			}
		})
	}
}

func TestValidatePolicyGroupTimeoutSeconds(t *testing.T) {
	maxTimeout := int32(30)
	underTimeout := int32(10)
	overMinusUnderTimeout := int32(21)

	type testCase struct {
		name                string
		timeoutSeconds      *int32
		timeoutEvalSeconds  *int32
		timeoutEvalSeconds2 *int32
		expectedErrors      []string
	}

	tests := []testCase{
		{
			name:                "both nil",
			timeoutSeconds:      nil,
			timeoutEvalSeconds:  nil,
			timeoutEvalSeconds2: nil,
			expectedErrors:      nil,
		},
		{
			name:                "timeoutEvalSeconds > timeoutSeconds",
			timeoutSeconds:      &underTimeout,
			timeoutEvalSeconds:  &maxTimeout,
			timeoutEvalSeconds2: nil,
			expectedErrors:      []string{"timeoutEvalSeconds cannot be greater than group timeoutSeconds"},
		},
		{
			name:                "the sum of all members' timeoutEvalSeconds > timeoutSeconds",
			timeoutSeconds:      &underTimeout,
			timeoutEvalSeconds:  &underTimeout,
			timeoutEvalSeconds2: &underTimeout,
			expectedErrors:      []string{"the sum of all members' timeoutEvalSeconds cannot be greater than group timeoutSeconds (10)"},
		},
		{
			name:                "the sum of all members' timeoutEvalSeconds > maxTimeoutSeconds",
			timeoutSeconds:      nil,
			timeoutEvalSeconds:  &underTimeout,
			timeoutEvalSeconds2: &overMinusUnderTimeout,
			expectedErrors:      []string{"the sum of all members' timeoutEvalSeconds cannot be greater than 30 (Kubernetes webhook max timeout)"},
		},
		{
			name:                "valid values",
			timeoutSeconds:      &maxTimeout,
			timeoutEvalSeconds:  &underTimeout,
			timeoutEvalSeconds2: nil,
			expectedErrors:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			group := NewClusterAdmissionPolicyGroupFactory().
				WithTimeoutSeconds(tc.timeoutSeconds).
				WithMembers(PolicyGroupMembersWithContext{
					"pod_privileged": {
						PolicyGroupMember: PolicyGroupMember{
							Module:             "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
							TimeoutEvalSeconds: tc.timeoutEvalSeconds,
						},
					},
					"pod_privileged2": {
						PolicyGroupMember: PolicyGroupMember{
							Module:             "registry://ghcr.io/kubewarden/tests/pod-privileged:v0.2.5",
							TimeoutEvalSeconds: tc.timeoutEvalSeconds2,
						},
					},
				},
				).
				Build()
			errs := validatePolicyGroupMembersTimeouts(group)
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

func TestValidatePolicyGroupMembersModule(t *testing.T) {
	message := "the module URL is not valid. An http or https module URL must have only " +
		"the host, an optional port, and the full path to the file."
	members := PolicyGroupMembersWithContext{
		"good": {
			PolicyGroupMember: PolicyGroupMember{Module: "https://example.com/good.wasm"},
		},
		"bad": {
			PolicyGroupMember: PolicyGroupMember{Module: "https://example.com/bad.wasm#a"},
		},
	}
	policyGroup := NewClusterAdmissionPolicyGroupFactory().WithMembers(members).Build()
	policyGroup.Spec.Expression = "good() && bad()"

	t.Run("create reports only the bad member", func(t *testing.T) {
		errs := validatePolicyGroupCreate(policyGroup)
		require.Len(t, errs, 1)
		require.Equal(t, "spec.policies[bad].module", errs[0].Field)
		require.Equal(t, message, errs[0].Detail)
	})

	t.Run("update reports only the bad member", func(t *testing.T) {
		errs := validatePolicyGroupUpdate(policyGroup, policyGroup.DeepCopy())
		require.Len(t, errs, 1)
		require.Equal(t, "spec.policies[bad].module", errs[0].Field)
		require.Equal(t, message, errs[0].Detail)
	})

	t.Run("namespaced group reports only the bad member", func(t *testing.T) {
		namespacedGroup := NewAdmissionPolicyGroupFactory().Build()
		namespacedGroup.Spec.Expression = "good() && bad()"
		namespacedGroup.Spec.Policies = PolicyGroupMembers{
			"good": {Module: "https://example.com/good.wasm"},
			"bad":  {Module: "https://example.com/bad.wasm#a"},
		}

		errs := validatePolicyGroupCreate(namespacedGroup)
		require.Len(t, errs, 1)
		require.Equal(t, "spec.policies[bad].module", errs[0].Field)
		require.Equal(t, message, errs[0].Detail)

		errs = validatePolicyGroupUpdate(namespacedGroup, namespacedGroup.DeepCopy())
		require.Len(t, errs, 1)
		require.Equal(t, "spec.policies[bad].module", errs[0].Field)
		require.Equal(t, message, errs[0].Detail)
	})
}
