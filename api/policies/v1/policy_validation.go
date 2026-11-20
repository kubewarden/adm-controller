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

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kubewarden/adm-controller/internal/constants"
)

// nonStrictStatelessCELCompiler is a cel Compiler that does not enforce strict cost enforcement.
//
//nolint:gochecknoglobals // lets keep the compiler available for the how module
var (
	nonStrictStatelessCELCompiler = plugincel.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
)

const (
	maxMatchConditionsCount = 64
	wildcardAllResources    = "*/*"
	protectMode             = "protect"
)

func validatePolicyCreate(policy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validateRulesField(policy)...)
	allErrors = append(allErrors, validateMatchConditions(policy.GetMatchConditions(), field.NewPath("spec").Child("matchConditions"))...)
	allErrors = append(allErrors, validateTimeoutSeconds(policy)...)
	if err := validateModuleURL(policy.GetModule(), field.NewPath("spec").Child("module")); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validateUniqueNameLength(policy); err != nil {
		allErrors = append(allErrors, err)
	}
	return allErrors
}

func validatePolicyUpdate(oldPolicy, newPolicy Policy) field.ErrorList {
	var allErrors field.ErrorList

	allErrors = append(allErrors, validateRulesField(newPolicy)...)
	allErrors = append(allErrors, validateMatchConditions(newPolicy.GetMatchConditions(), field.NewPath("spec").Child("matchConditions"))...)
	allErrors = append(allErrors, validateTimeoutSeconds(newPolicy)...)
	// Check the module only when it changes. A policy that was created before
	// this check can have a module that the check now rejects. Updates to such
	// a policy, for example to remove its finalizer, must pass.
	if newPolicy.GetModule() != oldPolicy.GetModule() {
		if err := validateModuleURL(newPolicy.GetModule(), field.NewPath("spec").Child("module")); err != nil {
			allErrors = append(allErrors, err)
		}
	}
	if err := validatePolicyServerField(oldPolicy, newPolicy); err != nil {
		allErrors = append(allErrors, err)
	}
	if err := validatePolicyModeField(oldPolicy, newPolicy); err != nil {
		allErrors = append(allErrors, err)
	}

	return allErrors
}

// validateUniqueNameLength ensures that the policy's derived unique name,
// once combined with the suffix used to build the corresponding webhook
// entry name, does not exceed the Kubernetes DNS1123 subdomain length limit.
// Name and namespace are immutable, so this is only checked on creation:
// checking it on update as well would make an already-persisted, overlong
// policy impossible to modify without providing any additional protection.
func validateUniqueNameLength(policy Policy) *field.Error {
	webhookName := policy.GetUniqueName() + constants.WebhookNameSuffix
	if len(webhookName) <= validation.DNS1123SubdomainMaxLength {
		return nil
	}

	maxNameLength := validation.DNS1123SubdomainMaxLength - len(constants.WebhookNameSuffix) - len(policy.GetUniqueName()) + len(policy.GetName())

	return field.Invalid(
		field.NewPath("metadata").Child("name"),
		policy.GetName(),
		fmt.Sprintf(
			"the policy name combined with its namespace and kind produces an identity that is too long (%d characters, max %d); "+
				"the name must be at most %d characters long",
			len(webhookName), validation.DNS1123SubdomainMaxLength, maxNameLength,
		),
	)
}

// Validates the spec.Rules field for non-empty, webhook-valid rules.
func validateRulesField(policy Policy) field.ErrorList {
	var allErrors field.ErrorList
	rulesField := field.NewPath("spec", "rules")

	if len(policy.GetRules()) == 0 {
		allErrors = append(allErrors, field.Required(rulesField, "a value must be specified"))

		return allErrors
	}

	_, isAdmissionPolicy := policy.(*AdmissionPolicy)
	_, isAdmissionPolicyGroup := policy.(*AdmissionPolicyGroup)

	for i, rule := range policy.GetRules() {
		ruleField := rulesField.Index(i)
		switch {
		case len(rule.Operations) == 0:
			allErrors = append(allErrors, field.Required(ruleField.Child("operations"), "a value must be specified"))
		case len(rule.Rule.APIVersions) == 0 || len(rule.Rule.Resources) == 0:
			if len(rule.Rule.APIVersions) == 0 {
				allErrors = append(allErrors, field.Required(ruleField.Child("apiVersions"), "a value must be specified"))
			}
			if len(rule.Rule.Resources) == 0 {
				allErrors = append(allErrors, field.Required(ruleField.Child("resources"), "a value must be specified"))
			}
		default:
			allErrors = append(allErrors, checkOperationsArrayForEmptyString(rule.Operations, ruleField)...)
			allErrors = append(allErrors, checkRulesArrayForEmptyString(rule.Rule.APIVersions, ruleField.Child("apiVersions"))...)
			allErrors = append(allErrors, checkRulesArrayForEmptyString(rule.Rule.Resources, ruleField.Child("resources"))...)

			if isAdmissionPolicy || isAdmissionPolicyGroup {
				allErrors = append(allErrors, checkRulesArrayForWildcardUsage(rule.Rule, ruleField)...)
			}
		}
	}

	return allErrors
}

// checkOperationsArrayForEmptyString returns one error for each empty
// string in the operations list.
func checkOperationsArrayForEmptyString(operationsArray []admissionregistrationv1.OperationType, ruleField *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	for i, operation := range operationsArray {
		if operation == "" {
			allErrors = append(allErrors, field.Required(ruleField.Child("operations").Index(i), "must be non-empty"))
		}
	}

	return allErrors
}

// checkRulesArrayForEmptyString returns one error for each empty string in
// the list.
func checkRulesArrayForEmptyString(rulesArray []string, ruleField *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	for i, apiVersion := range rulesArray {
		if apiVersion == "" {
			allErrors = append(allErrors, field.Required(ruleField.Index(i), "must be non-empty"))
		}
	}

	return allErrors
}

// checkRulesArrayForWildcardUsage returns an error when apiGroups and
// resources both contain a wildcard.
func checkRulesArrayForWildcardUsage(rule admissionregistrationv1.Rule, ruleField *field.Path) field.ErrorList {
	var allErrors field.ErrorList

	apiGroupHasWildcard := false
	apiGroupWildcardIndex := -1

	resourceHasWildcard := false
	resourceWildcardIndex := -1

	for i, apiGroup := range rule.APIGroups {
		if apiGroup == "*" {
			apiGroupHasWildcard = true
			apiGroupWildcardIndex = i
			break
		}
	}

	for i, resource := range rule.Resources {
		if resource == "*" || resource == wildcardAllResources {
			resourceHasWildcard = true
			resourceWildcardIndex = i
			break
		}
	}

	if apiGroupHasWildcard && resourceHasWildcard {
		allErrors = append(allErrors, field.Forbidden(ruleField.Child("apiGroups").Index(apiGroupWildcardIndex), "apiGroups cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup"))
		allErrors = append(allErrors, field.Forbidden(ruleField.Child("resources").Index(resourceWildcardIndex), "resources cannot use wildcards when using AdmissionPolicy or AdmissionPolicyGroup"))
	}

	return allErrors
}

func validatePolicyServerField(oldPolicy, newPolicy Policy) *field.Error {
	if oldPolicy.GetPolicyServer() != newPolicy.GetPolicyServer() {
		return field.Forbidden(field.NewPath("spec").Child("policyServer"), "the field is immutable")
	}

	return nil
}

func validatePolicyModeField(oldPolicy, newPolicy Policy) *field.Error {
	if oldPolicy.GetPolicyMode() == protectMode && newPolicy.GetPolicyMode() == "monitor" {
		return field.Forbidden(field.NewPath("spec").Child("mode"), "field cannot transition from protect to monitor. Recreate instead.")
	}

	return nil
}

// prepareInvalidAPIError is a shorthand for generating an invalid apierrors.StatusError with data from an object.
func prepareInvalidAPIError(obj client.Object, errorList field.ErrorList) *apierrors.StatusError {
	return apierrors.NewInvalid(
		obj.GetObjectKind().GroupVersionKind().GroupKind(),
		obj.GetName(),
		errorList,
	)
}

func validateMatchConditions(m []admissionregistrationv1.MatchCondition, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	conditionNames := sets.NewString()
	if len(m) > maxMatchConditionsCount {
		allErrors = append(allErrors, field.TooMany(fldPath, len(m), maxMatchConditionsCount))
	}
	for i, matchCondition := range m {
		allErrors = append(allErrors, validateMatchCondition(&matchCondition, fldPath.Index(i))...)
		if len(matchCondition.Name) > 0 {
			if conditionNames.Has(matchCondition.Name) {
				allErrors = append(allErrors, field.Duplicate(fldPath.Index(i).Child("name"), matchCondition.Name))
			} else {
				conditionNames.Insert(matchCondition.Name)
			}
		}
	}
	return allErrors
}

func validateMatchCondition(v *admissionregistrationv1.MatchCondition, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	trimmedExpression := strings.TrimSpace(v.Expression)
	if len(trimmedExpression) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("expression"), ""))
	} else {
		allErrors = append(allErrors, validateMatchConditionsExpression(trimmedExpression, fldPath.Child("expression"))...)
	}
	if len(v.Name) == 0 {
		allErrors = append(allErrors, field.Required(fldPath.Child("name"), ""))
	} else {
		for _, msg := range validation.IsQualifiedName(v.Name) {
			allErrors = append(allErrors, field.Invalid(fldPath, v.Name, msg))
		}
	}
	return allErrors
}

func convertCELErrorToValidationError(fldPath *field.Path, expression plugincel.ExpressionAccessor, err error) *field.Error {
	//nolint:errorlint // The code is not only checking the type. It is also using the errors fields.
	if celErr, ok := err.(*cel.Error); ok {
		switch celErr.Type {
		case cel.ErrorTypeRequired:
			return field.Required(fldPath, celErr.Detail)
		case cel.ErrorTypeInvalid:
			return field.Invalid(fldPath, expression.GetExpression(), celErr.Detail)
		case cel.ErrorTypeInternal:
			return field.InternalError(fldPath, celErr)
		}
	}
	return field.InternalError(fldPath, fmt.Errorf("unsupported error type: %w", err))
}

func validateMatchConditionsExpression(expressionStr string, fldPath *field.Path) field.ErrorList {
	var allErrors field.ErrorList
	expression := &matchconditions.MatchCondition{
		Expression: expressionStr,
	}
	result := nonStrictStatelessCELCompiler.CompileCELExpression(expression, plugincel.OptionalVariableDeclarations{
		HasParams:     false,
		HasAuthorizer: true,
	}, environment.NewExpressions)
	if result.Error != nil {
		allErrors = append(allErrors, convertCELErrorToValidationError(fldPath, expression, result.Error))
	}
	return allErrors
}

// validateTimeoutSeconds checks the timeouts so that:
//   - the policy's timeoutEvalSeconds is not greater than the policy's timeoutSeconds.
func validateTimeoutSeconds(policy Policy) field.ErrorList {
	var allErrors field.ErrorList
	timeoutSeconds := policy.GetTimeoutSeconds()
	timeoutEvalSeconds := policy.GetTimeoutEvalSeconds()
	fldTimeoutEvalSeconds := field.NewPath("spec").Child("timeoutEvalSeconds")

	if timeoutSeconds != nil && timeoutEvalSeconds != nil {
		if *timeoutEvalSeconds > *timeoutSeconds {
			allErrors = append(allErrors, field.Invalid(
				fldTimeoutEvalSeconds,
				*timeoutEvalSeconds,
				"timeoutEvalSeconds cannot be greater than timeoutSeconds",
			))
		}
	}
	return allErrors
}
