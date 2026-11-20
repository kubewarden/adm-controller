package v1

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/stdlib"
	"github.com/google/cel-go/common/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Regex to validate the policy members names.
// For more information about the CEL grammar, see
// https://github.com/google/cel-spec/blob/master/doc/langdef.md#syntax
var idenRegex = regexp.MustCompile(`^[_a-zA-Z][_a-zA-Z0-9]*$`)

// Reserved symbols in CEL that cannot be used as policy member names.
//
//nolint:gochecknoglobals // Using a global variable to avoid recreating it every evaluation
var celReservedSymbols = sets.NewString(
	"true", "false", "null", "in",
	"as", "break", "const", "continue", "else",
	"for", "function", "if", "import", "let",
	"loop", "package", "namespace", "return",
	"var", "void", "while",
)

func validatePolicyGroupCreate(policyGroup PolicyGroup) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validatePolicyCreate(policyGroup)...)
	allErrors = append(allErrors, validatePolicyGroupMembers(policyGroup)...)
	allErrors = append(allErrors, validatePolicyGroupMembersTimeouts(policyGroup)...)
	allErrors = append(allErrors, validatePolicyGroupMembersModule(policyGroup, nil)...)
	if err := validatePolicyGroupExpressionField(policyGroup); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validatePolicyGroupMessageField(policyGroup); err != nil {
		allErrors = append(allErrors, err)
	}

	return allErrors
}

func validatePolicyGroupUpdate(oldPolicyGroup, newPolicyGroup PolicyGroup) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validatePolicyUpdate(oldPolicyGroup, newPolicyGroup)...)
	allErrors = append(allErrors, validatePolicyGroupMembers(newPolicyGroup)...)
	allErrors = append(allErrors, validatePolicyGroupMembersTimeouts(newPolicyGroup)...)
	allErrors = append(allErrors, validatePolicyGroupMembersModule(newPolicyGroup, oldPolicyGroup)...)
	if err := validatePolicyGroupExpressionField(newPolicyGroup); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validatePolicyGroupMessageField(newPolicyGroup); err != nil {
		allErrors = append(allErrors, err)
	}

	return allErrors
}

func validatePolicyGroupMessageField(policyGroup PolicyGroup) *field.Error {
	messageField := field.NewPath("spec").Child("message")

	if len(policyGroup.GetMessage()) == 0 {
		return field.Required(messageField, "must be non-empty")
	}
	return nil
}

// validatePolicyGroupMembers validates that a policy group has at least one policy member.
func validatePolicyGroupMembers(policyGroup PolicyGroup) field.ErrorList {
	var allErrors field.ErrorList
	if len(policyGroup.GetPolicyGroupMembersWithContext()) == 0 {
		allErrors = append(allErrors, field.Required(field.NewPath("spec").Child("policies"), "policy groups must have at least one policy member"))
	}
	for memberName := range policyGroup.GetPolicyGroupMembersWithContext() {
		_, matchReservedSymbol := celReservedSymbols[memberName]
		if len(memberName) == 0 || matchReservedSymbol || !idenRegex.MatchString(memberName) {
			allErrors = append(allErrors, field.Invalid(field.NewPath("spec").Child("policies"), memberName, "policy group member name is invalid"))
		}
	}

	return allErrors
}

// validatePolicyGroupExpressionField validates that the expression is a valid CEL expression that evaluates to a boolean.
// Only the following operators are allowed: equals, not equals, logical or, logical and, and logical not.
// Policy members are imported as custom functions that take no arguments and return a boolean.
func validatePolicyGroupExpressionField(policyGroup PolicyGroup) *field.Error {
	expressionField := field.NewPath("spec").Child("expression")

	if policyGroup.GetExpression() == "" {
		return field.Required(expressionField, "must be non-empty")
	}

	// Create a CEL environment with custom functions for each policy member
	var opts []cel.EnvOption
	for policyName := range policyGroup.GetPolicyGroupMembersWithContext() {
		fn := cel.Function(policyName, cel.Overload(policyName, []*cel.Type{}, types.BoolType))
		opts = append(opts, fn)
	}

	// Import only equals, not equals, logical or, logical and, and logical not operators
	// from the standard library
	allowedOperators := map[string]bool{
		operators.Equals:     true,
		operators.NotEquals:  true,
		operators.LogicalOr:  true,
		operators.LogicalAnd: true,
		operators.LogicalNot: true,
	}
	for _, fn := range stdlib.Functions() {
		if !allowedOperators[fn.Name()] {
			continue
		}

		opts = append(opts, cel.Function(fn.Name(),
			func(*decls.FunctionDecl) (*decls.FunctionDecl, error) {
				return fn, nil
			}))
	}

	env, err := cel.NewCustomEnv(
		opts...,
	)
	if err != nil {
		return field.InternalError(expressionField, fmt.Errorf("error creating CEL environment: %w", err))
	}

	ast, issues := env.Compile(policyGroup.GetExpression())
	if issues != nil && issues.Err() != nil {
		return field.Invalid(expressionField, policyGroup.GetExpression(), fmt.Sprintf("compilation failed: %v", issues.Err()))
	}
	if ast.OutputType() != types.BoolType {
		return field.Invalid(expressionField, policyGroup.GetExpression(), "must evaluate to bool")
	}

	return nil
}

// validatePolicyGroupMembersTimeouts checks the timeouts so that:
//   - each member's timeoutEvalSeconds is not greater than the group's
//     timeoutSeconds
//   - the sum of each members' timeoutEvalSeconds is not greater than the group's
//     timeoutSeconds nor the Kubernetes webhook max timeout (30s)
func validatePolicyGroupMembersTimeouts(policyGroup PolicyGroup) field.ErrorList {
	var allErrors field.ErrorList
	groupTimeout := policyGroup.GetTimeoutSeconds()
	fldMembers := field.NewPath("spec").Child("policies")

	sumMemberTimeoutEval := int32(0)
	for memberName, member := range policyGroup.GetPolicyGroupMembersWithContext() {
		memberTimeoutEval := member.TimeoutEvalSeconds
		if memberTimeoutEval == nil {
			continue
		}
		sumMemberTimeoutEval += *memberTimeoutEval

		if *memberTimeoutEval > maxWebhookTimeoutSeconds {
			allErrors = append(allErrors, field.Invalid(
				fldMembers.Key(memberName).Child("timeoutEvalSeconds"),
				*memberTimeoutEval,
				fmt.Sprintf("timeoutEvalSeconds cannot be greater than %d (Kubernetes webhook max timeout)", maxWebhookTimeoutSeconds),
			))
		}
		if groupTimeout != nil && *memberTimeoutEval > *groupTimeout {
			allErrors = append(allErrors, field.Invalid(
				fldMembers.Key(memberName).Child("timeoutEvalSeconds"),
				*memberTimeoutEval,
				fmt.Sprintf("timeoutEvalSeconds cannot be greater than group timeoutSeconds (%d)", *groupTimeout),
			))
		}
	}

	if groupTimeout != nil && sumMemberTimeoutEval > *groupTimeout {
		allErrors = append(allErrors, field.Invalid(
			fldMembers,
			sumMemberTimeoutEval,
			fmt.Sprintf("the sum of all members' timeoutEvalSeconds cannot be greater than group timeoutSeconds (%d)", *groupTimeout),
		))
	}

	if sumMemberTimeoutEval > maxWebhookTimeoutSeconds {
		allErrors = append(allErrors, field.Invalid(
			fldMembers,
			sumMemberTimeoutEval,
			fmt.Sprintf("the sum of all members' timeoutEvalSeconds cannot be greater than %d (Kubernetes webhook max timeout)", maxWebhookTimeoutSeconds),
		))
	}

	return allErrors
}

// validatePolicyGroupMembersModule checks the module of each member. If
// oldPolicyGroup is not nil, it skips the members whose module did not change.
// A member with a new name is checked, even if its module did not change.
func validatePolicyGroupMembersModule(policyGroup, oldPolicyGroup PolicyGroup) field.ErrorList {
	var allErrors field.ErrorList
	fldMembers := field.NewPath("spec").Child("policies")

	members := policyGroup.GetPolicyGroupMembersWithContext()
	var oldMembers PolicyGroupMembersWithContext
	if oldPolicyGroup != nil {
		oldMembers = oldPolicyGroup.GetPolicyGroupMembersWithContext()
	}
	for _, memberName := range slices.Sorted(maps.Keys(members)) {
		member := members[memberName]
		if oldMember, found := oldMembers[memberName]; found && oldMember.Module == member.Module {
			continue
		}
		if err := validateModuleURL(member.Module, fldMembers.Key(memberName).Child("module")); err != nil {
			allErrors = append(allErrors, err)
		}
	}
	return allErrors
}
