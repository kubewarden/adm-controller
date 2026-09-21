use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kubewarden_policy_sdk::{
    response::ValidationResponse as PolicyValidationResponse, settings::SettingsValidationResponse,
};
use serde_json::{Value, json};
use tracing::{error, warn};

use crate::{
    admission_response::AdmissionResponse,
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicySettings, ValidateRequest},
    runtimes::ferricel::{
        errors::{FerricelRuntimeError, format_cel_error},
        stack::Stack,
    },
};

pub(crate) struct Runtime<'a>(pub(crate) &'a Stack);

impl Runtime<'_> {
    pub fn validate(
        &self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
        // The settings passed `validate_settings` at load time, so an
        // invalid value here is a bug in the caller. Fall back to `Fail`,
        // the safe choice, instead of a panic.
        let failure_policy = FailurePolicy::from_settings(settings).unwrap_or_else(|e| {
            error!(
                error = e.as_str(),
                "invalid failurePolicy in settings, using Fail"
            );
            FailurePolicy::Fail
        });

        let bindings = match self.build_bindings(settings, request) {
            Ok(b) => b,
            Err(response) => return *response,
        };

        let bindings_str = match serde_json::to_string(&bindings) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize ferricel bindings"
                );
                return AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    e.to_string(),
                );
            }
        };

        match self.0.eval(Some(&bindings_str)) {
            Ok(result_str) => match serde_json::from_str::<PolicyValidationResponse>(&result_str) {
                Ok(pvr) => {
                    let req_json_value = serde_json::to_value(request)
                        .expect("cannot convert request to json value");
                    let req_obj = req_json_value.get("object");

                    AdmissionResponse::from_policy_validation_response(
                        request.uid().to_string(),
                        req_obj,
                        &pvr,
                    )
                    .unwrap_or_else(|e| {
                        AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            format!("Cannot convert policy validation response: {e}"),
                        )
                    })
                }
                Err(e) => AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    format!("Cannot deserialize ferricel response: {e}"),
                ),
            },
            Err(FerricelRuntimeError::ExecutionDeadlineExceeded) => {
                error!(policy_id = %self.0.eval_ctx().policy_id, "policy execution time exceeded");
                AdmissionResponse::reject(
                    request.uid().to_string(),
                    "Policy execution interrupted because it exceeded the allowed execution time"
                        .to_owned(),
                    500,
                )
            }
            Err(FerricelRuntimeError::CelRuntimeError(cel_err)) => {
                self.handle_cel_runtime_error(request, &cel_err, failure_policy)
            }
            Err(e) => AdmissionResponse::reject_internal_server_error(
                request.uid().to_string(),
                e.to_string(),
            ),
        }
    }

    /// Apply the VAP `failurePolicy` to a CEL runtime error.
    ///
    /// This mirrors what the Kubernetes API server does with a
    /// `ValidatingAdmissionPolicy` whose expression cannot be evaluated:
    ///   - `Fail`: reject the request. The message names the error.
    ///   - `Ignore`: skip the policy and admit the request. The response
    ///     carries a warning, so the client and the audit results show that
    ///     the policy did not run.
    ///
    /// Only a CEL runtime error reaches this function. A deadline, a Wasm
    /// trap, or a host bug always rejects the request, whatever the
    /// `failurePolicy` says.
    fn handle_cel_runtime_error(
        &self,
        request: &ValidateRequest,
        cel_err: &ferricel_core::CelRuntimeError,
        failure_policy: FailurePolicy,
    ) -> AdmissionResponse {
        let policy_id = &self.0.eval_ctx().policy_id;
        let message = format_cel_error(cel_err);

        match failure_policy {
            FailurePolicy::Fail => {
                error!(
                    policy_id = %policy_id,
                    error = %message,
                    "CEL runtime error, request rejected because failurePolicy is Fail"
                );
                AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    format!("CEL runtime error: {message}"),
                )
            }
            FailurePolicy::Ignore => {
                warn!(
                    policy_id = %policy_id,
                    error = %message,
                    "CEL runtime error, policy skipped because failurePolicy is Ignore"
                );
                AdmissionResponse {
                    uid: request.uid().to_string(),
                    allowed: true,
                    warnings: Some(vec![format!(
                        "policy {policy_id} skipped (failurePolicy is Ignore): CEL runtime error: {message}"
                    )]),
                    ..Default::default()
                }
            }
        }
    }

    /// Build the JSON bindings object passed to the compiled VAP module.
    ///
    /// Bindings provided:
    ///   - `object`     The resource being admitted.
    ///   - `oldObject`  The previous version of the resource (UPDATE/DELETE) or null.
    ///   - `request`    The full AdmissionRequest map (operation, userInfo, etc.).
    ///   - `paramRef`   Forwarded from `settings["paramRef"]` when present. The
    ///     compiled wasm reads `name`/`namespace` or `selector`, plus
    ///     `parameterNotFoundAction`, and fetches the param resources itself via
    ///     the `kw.k8s.get`/`kw.k8s.list` extensions (registered in
    ///     `StackPre::rehydrate`). When `paramRef.namespace` is empty the wasm
    ///     falls back to `request.namespace`, so `request` must always be bound.
    ///
    /// Since ferricel 0.11, the compiled wasm resolves `namespaceObject` on
    /// its own, the same way it resolves `paramRef`: it reads
    /// `request.namespace` and calls `kw.k8s.get` for the Namespace. The
    /// host does not build or bind `namespaceObject` any more.
    ///
    /// Returns `Err(AdmissionResponse)` on failure so that `validate` can return the
    /// error response immediately.
    fn build_bindings(
        &self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> Result<Value, Box<AdmissionResponse>> {
        match request {
            ValidateRequest::AdmissionRequest(admission_request) => {
                let object = admission_request.object.as_ref().map(|o| &o.0);
                let old_object = admission_request.old_object.as_ref().map(|o| &o.0);

                let request_map =
                    serde_json::to_value(admission_request.as_ref()).map_err(|e| {
                        error!(
                            error = e.to_string().as_str(),
                            "cannot serialize AdmissionRequest"
                        );
                        Box::new(AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            e.to_string(),
                        ))
                    })?;

                let param_ref = settings.0.get("paramRef").cloned().unwrap_or(Value::Null);

                Ok(json!({
                    "object":    object,
                    "oldObject": old_object,
                    "request":   request_map,
                    "paramRef":  param_ref,
                }))
            }
            ValidateRequest::Raw(_raw) => {
                error!("ferricel runtime does not support raw validation requests");
                Err(Box::new(AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    "ferricel runtime does not support raw validation requests".to_string(),
                )))
            }
        }
    }

    /// Ferricel/VAP policies do not have runtime settings validation for the
    /// bulk of their behavior: all validation logic is compiled into the
    /// Wasm module. This function only validates the settings that the
    /// runtime itself consumes, not the compiled wasm: the value of
    /// `failurePolicy` and the shape of `paramKind`/`paramRef`. The latter
    /// is consumed by the compiled wasm, but a malformed value would only
    /// surface on the first request; validating it here fails fast at load
    /// time instead. On top of that, it warns -- without failing validation
    /// -- when a `paramKind` grant, or a `namespaceObject` grant, is missing.
    pub fn validate_settings(&self, settings: String) -> SettingsValidationResponse {
        let references_namespace_object = self.0.references_vap_variable("namespaceObject");
        match validate_settings_json(&settings, self.0.eval_ctx(), references_namespace_object) {
            Ok(()) => SettingsValidationResponse {
                valid: true,
                message: None,
            },
            Err(message) => SettingsValidationResponse {
                valid: false,
                message: Some(message),
            },
        }
    }
}

/// Parses `settings` as JSON and validates the `failurePolicy` and
/// `paramKind`/`paramRef` fields.
///
/// Kept as a free function (rather than a `Runtime` method) so it only
/// depends on `&EvaluationContext`, making it unit-testable without a real
/// `Stack` (which requires a compiled wasm module).
///
/// `references_namespace_object` tells whether the compiled policy may read
/// `namespaceObject` (from the `ferricel.vap-variables` Wasm custom
/// section, see `Stack::references_vap_variable`). When it does, and
/// `v1/Namespace` is not in `eval_ctx`'s allow list, this only warns: the
/// compiled module fetches the Namespace itself via `kw.k8s.get`, and that
/// call will be denied at evaluation time (see
/// `EvaluationContext::can_access_kubernetes_resource`), but the
/// administrator may withhold the grant on purpose.
fn validate_settings_json(
    settings: &str,
    eval_ctx: &EvaluationContext,
    references_namespace_object: bool,
) -> Result<(), String> {
    let settings_json: Value = serde_json::from_str(settings)
        .map_err(|e| format!("cannot parse policy settings as JSON: {e}"))?;

    FailurePolicy::from_value(settings_json.get("failurePolicy"))?;

    if references_namespace_object && !eval_ctx.can_access_kubernetes_resource("v1", "Namespace") {
        warn!(
            "policy may reference namespaceObject, but v1/Namespace is not listed in spec.contextAwareResources; \
             fetching the Namespace via kw.k8s.get will be denied at evaluation time"
        );
    }

    validate_params(&settings_json, eval_ctx)
}

/// What the runtime does when a CEL expression of the policy evaluates to
/// an error. This is the `spec.failurePolicy` of the source
/// `ValidatingAdmissionPolicy`.
///
/// The value comes from `settings.failurePolicy`, not from the compiled Wasm
/// module. As a result, the Kubewarden administrator can change it in the
/// `ClusterAdmissionPolicy` without a new build of the policy. The
/// `kwctl scaffold vap --compile-to-wasm` command copies the value of the
/// VAP into the generated settings.
///
/// Do not confuse it with `spec.failurePolicy` of the Kubewarden policy
/// CRDs. That field goes to the webhook configuration, and the API server
/// applies it only when the call to the policy server fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum FailurePolicy {
    /// Reject the request. This is the default, as in Kubernetes.
    #[default]
    Fail,
    /// Skip the policy and admit the request.
    Ignore,
}

impl FailurePolicy {
    const INVALID_VALUE_MESSAGE: &str = "failurePolicy must be either 'Fail' or 'Ignore'";

    /// Read the policy from `settings["failurePolicy"]`. A missing or `null`
    /// value means `Fail`.
    pub(crate) fn from_settings(settings: &PolicySettings) -> Result<Self, String> {
        Self::from_value(settings.0.get("failurePolicy"))
    }

    fn from_value(value: Option<&Value>) -> Result<Self, String> {
        match value {
            None | Some(Value::Null) => Ok(Self::Fail),
            Some(Value::String(s)) if s == "Fail" => Ok(Self::Fail),
            Some(Value::String(s)) if s == "Ignore" => Ok(Self::Ignore),
            Some(_) => Err(Self::INVALID_VALUE_MESSAGE.to_string()),
        }
    }
}

/// Reads `obj[key]` and requires it to be a JSON string if present.
///
/// Returns:
///   - `Ok(None)`      if `key` is absent (or explicitly `null`)
///   - `Ok(Some(str))` if `key` is present and is a string
///   - `Err(..)`       if `key` is present with a non-string, non-null value
fn optional_str_field<'a>(
    obj: &'a serde_json::Map<String, Value>,
    path: &str,
    key: &str,
) -> Result<Option<&'a str>, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(format!("{path}.{key} must be a string")),
    }
}

/// Validates the shape of `settings["paramKind"]`, returning the named
/// resource (apiVersion, kind) on success.
fn validate_param_kind(value: &Value) -> Result<(String, String), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "paramKind must be an object".to_string())?;

    let api_version = optional_str_field(obj, "paramKind", "apiVersion")?.filter(|s| !s.is_empty());
    let kind = optional_str_field(obj, "paramKind", "kind")?.filter(|s| !s.is_empty());

    match (api_version, kind) {
        (Some(api_version), Some(kind)) => Ok((api_version.to_string(), kind.to_string())),
        _ => Err("paramKind must have both apiVersion and kind specified".to_string()),
    }
}

/// Validates the shape of `settings["paramRef"]`.
fn validate_param_ref(value: &Value) -> Result<(), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "paramRef must be an object".to_string())?;

    let name = optional_str_field(obj, "paramRef", "name")?.filter(|s| !s.is_empty());
    let selector = match obj.get("selector") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => Some(v),
        Some(_) => return Err("paramRef.selector must be an object".to_string()),
    };

    match (name, selector) {
        (None, None) => {
            return Err("paramRef must have either name or selector specified".to_string());
        }
        (Some(_), Some(_)) => {
            return Err("paramRef cannot have both name and selector specified".to_string());
        }
        (None, Some(selector)) => validate_label_selector(selector)?,
        (Some(_), None) => {}
    }

    match optional_str_field(obj, "paramRef", "parameterNotFoundAction")? {
        Some("Allow") | Some("Deny") => Ok(()),
        _ => Err(
            "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified"
                .to_string(),
        ),
    }
}

/// Validates a Kubernetes `LabelSelector` found in `paramRef.selector`.
///
/// The compiled module turns the selector into a label selector string at
/// evaluation time (see `format_label_selector` in the ferricel guest
/// runtime). A malformed selector would trap there, on the first request
/// that reaches the policy, and the request would be rejected or the policy
/// skipped depending on `failurePolicy`. This check moves that failure to
/// load time.
///
/// The type shape (`matchLabels` is a string map, `matchExpressions` items
/// have a string `key`, `operator` and an optional string list `values`)
/// comes from deserializing into the `k8s_openapi` `LabelSelector` type. The
/// operator check comes from `kube::core::Selector::try_from`, which knows
/// `In`, `NotIn`, `Exists` and `DoesNotExist`. On top of that, this function
/// applies two rules from `ValidateLabelSelectorRequirement` in
/// `k8s.io/apimachinery` that neither crate enforces: `key` must not be
/// empty (`k8s_openapi` defaults a missing key to `""`), and `values` must
/// be non-empty for `In`/`NotIn` and empty for `Exists`/`DoesNotExist`.
fn validate_label_selector(selector: &Value) -> Result<(), String> {
    const PATH: &str = "paramRef.selector";

    let selector: LabelSelector = serde_json::from_value(selector.clone())
        .map_err(|e| format!("{PATH} is not a valid LabelSelector: {e}"))?;

    for (i, requirement) in selector
        .match_expressions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        if requirement.key.is_empty() {
            return Err(format!(
                "{PATH}.matchExpressions[{i}].key must be a non-empty string"
            ));
        }

        let has_values = requirement.values.as_ref().is_some_and(|v| !v.is_empty());
        let operator = requirement.operator.as_str();
        match operator {
            "In" | "NotIn" if !has_values => {
                return Err(format!(
                    "{PATH}.matchExpressions[{i}].values must be non-empty when operator is {operator}"
                ));
            }
            "Exists" | "DoesNotExist" if has_values => {
                return Err(format!(
                    "{PATH}.matchExpressions[{i}].values must be empty when operator is {operator}"
                ));
            }
            _ => {}
        }
    }

    kube::core::Selector::try_from(selector)
        .map(|_| ())
        .map_err(|e| format!("{PATH} is not a valid LabelSelector: {e}"))
}

/// Validates the `paramKind`/`paramRef` settings.
///
/// The two fields must be present together, or both absent. The compiled
/// module reads `paramRef` from the bindings on every request when the VAP
/// was compiled with `paramKind`; without it, every evaluation fails. A
/// `paramRef` without `paramKind` is inert, but it is a sign of a broken
/// scaffold, so it is rejected too. `kwctl scaffold vap` applies the same
/// rule.
///
/// `paramKind` must fully specify `apiVersion` and `kind` (this is required
/// regardless of grants: the wasm module has this resource baked in at
/// compile time via `compile_vap_from_policy`, so an incomplete `paramKind`
/// here can never be legitimate). `paramRef` must specify exactly one of
/// `name`/`selector`, a well-formed selector when `selector` is used, and a
/// valid `parameterNotFoundAction`.
///
/// Separately, if `paramKind` is complete but its resource is not listed in
/// `eval_ctx`'s `ctx_aware_resources_allow_list` (populated from
/// `spec.contextAwareResources` on the CRD), this only warns rather than
/// failing validation: fetching the param resource via `kw.k8s.get`/`list`
/// at evaluation time will be denied by the authorization gate (see
/// `EvaluationContext::can_access_kubernetes_resource`), causing the policy
/// to fail on every request that reaches it, but the Kubewarden
/// administrator may intentionally withhold the grant (e.g. because a
/// policy's declared `paramKind` looks suspicious), and settings validation
/// must not block loading the policy in that case.
fn validate_params(settings: &Value, eval_ctx: &EvaluationContext) -> Result<(), String> {
    let param_kind = settings.get("paramKind").filter(|v| !v.is_null());
    let param_ref = settings.get("paramRef").filter(|v| !v.is_null());

    let (param_kind, param_ref) = match (param_kind, param_ref) {
        (None, None) => return Ok(()),
        (Some(param_kind), Some(param_ref)) => (param_kind, param_ref),
        _ => {
            return Err(
                "Both paramKind and paramRef must be present together, or both absent".to_string(),
            );
        }
    };

    let (api_version, kind) = validate_param_kind(param_kind)?;
    validate_param_ref(param_ref)?;

    if !eval_ctx.can_access_kubernetes_resource(&api_version, &kind) {
        warn!(
            %api_version,
            %kind,
            "policy declares paramKind {api_version}/{kind}, but this resource is not listed in spec.contextAwareResources; \
             fetching the param resource via paramRef will be denied at evaluation time"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::policy_metadata::ContextAwareResource;

    fn eval_ctx_with_allow_list(
        ctx_aware_resources_allow_list: BTreeSet<ContextAwareResource>,
    ) -> EvaluationContext {
        EvaluationContext {
            ctx_aware_resources_allow_list,
            ..Default::default()
        }
    }

    #[rstest]
    #[case::absent(json!({}), FailurePolicy::Fail)]
    #[case::null(json!({"failurePolicy": null}), FailurePolicy::Fail)]
    #[case::fail(json!({"failurePolicy": "Fail"}), FailurePolicy::Fail)]
    #[case::ignore(json!({"failurePolicy": "Ignore"}), FailurePolicy::Ignore)]
    fn failure_policy_from_settings(
        #[case] settings: serde_json::Value,
        #[case] expected: FailurePolicy,
    ) {
        let settings = PolicySettings(settings.as_object().unwrap().clone());
        assert_eq!(FailurePolicy::from_settings(&settings).unwrap(), expected);
    }

    #[rstest]
    #[case::wrong_case(json!({"failurePolicy": "ignore"}))]
    #[case::unknown_value(json!({"failurePolicy": "Sometimes"}))]
    #[case::wrong_type(json!({"failurePolicy": true}))]
    fn failure_policy_rejects_invalid_values(#[case] settings: serde_json::Value) {
        let err =
            validate_settings_json(&settings.to_string(), &EvaluationContext::default(), false)
                .expect_err("expected an error for an invalid failurePolicy");
        assert_eq!(err, "failurePolicy must be either 'Fail' or 'Ignore'");
    }

    #[test]
    fn validate_settings_json_invalid_json_is_rejected() {
        let err = validate_settings_json("not json", &EvaluationContext::default(), false)
            .expect_err("expected an error for invalid JSON");
        assert!(
            err.contains("cannot parse policy settings as JSON"),
            "unexpected error: {err}"
        );
    }

    /// A complete `paramKind`, used to pair with the `paramRef` under test.
    fn config_map_param_kind() -> serde_json::Value {
        json!({"apiVersion": "v1", "kind": "ConfigMap"})
    }

    /// A complete `paramRef`, used to pair with the `paramKind` under test.
    fn named_param_ref() -> serde_json::Value {
        json!({"name": "replica-limit", "parameterNotFoundAction": "Deny"})
    }

    /// The resource `namespaceObject` fetches via `kw.k8s.get`.
    fn namespace_resource() -> ContextAwareResource {
        ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
        }
    }

    #[rstest]
    #[case::no_params(json!({}))]
    #[case::unrelated_settings(json!({"validations": []}))]
    #[case::both_null(json!({"paramKind": null, "paramRef": null}))]
    fn validate_params_without_param_kind_or_ref_is_ok(#[case] settings: serde_json::Value) {
        validate_params(&settings, &EvaluationContext::default())
            .expect("settings without paramKind/paramRef should be valid");
    }

    #[rstest]
    #[case::param_kind_only(json!({"paramKind": config_map_param_kind()}))]
    #[case::param_kind_with_null_ref(json!({"paramKind": config_map_param_kind(), "paramRef": null}))]
    #[case::param_ref_only(json!({"paramRef": named_param_ref()}))]
    #[case::param_ref_with_null_kind(json!({"paramKind": null, "paramRef": named_param_ref()}))]
    fn validate_params_requires_param_kind_and_param_ref_together(
        #[case] settings: serde_json::Value,
    ) {
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("paramKind and paramRef must be present together");
        assert_eq!(
            "Both paramKind and paramRef must be present together, or both absent",
            err
        );
    }

    #[rstest]
    #[case::not_an_object(json!("v1/ConfigMap"), "paramKind must be an object")]
    #[case::missing_kind(
        json!({"apiVersion": "v1"}),
        "paramKind must have both apiVersion and kind specified"
    )]
    #[case::missing_api_version(
        json!({"kind": "ConfigMap"}),
        "paramKind must have both apiVersion and kind specified"
    )]
    #[case::empty_strings(
        json!({"apiVersion": "", "kind": ""}),
        "paramKind must have both apiVersion and kind specified"
    )]
    #[case::api_version_wrong_type(
        json!({"apiVersion": 1, "kind": "ConfigMap"}),
        "paramKind.apiVersion must be a string"
    )]
    #[case::kind_wrong_type(
        json!({"apiVersion": "v1", "kind": []}),
        "paramKind.kind must be a string"
    )]
    fn validate_params_rejects_malformed_param_kind(
        #[case] param_kind: serde_json::Value,
        #[case] expected_message: &str,
    ) {
        let settings = json!({"paramKind": param_kind, "paramRef": named_param_ref()});
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("expected an error for malformed paramKind");
        assert_eq!(expected_message, err);
    }

    #[rstest]
    #[case::not_an_object(json!("replica-limit"), "paramRef must be an object")]
    #[case::missing_name_and_selector(
        json!({"parameterNotFoundAction": "Deny"}),
        "paramRef must have either name or selector specified"
    )]
    #[case::both_name_and_selector(
        json!({
            "name": "replica-limit",
            "selector": {"matchLabels": {"app": "demo"}},
            "parameterNotFoundAction": "Deny"
        }),
        "paramRef cannot have both name and selector specified"
    )]
    #[case::name_wrong_type(
        json!({"name": 1, "parameterNotFoundAction": "Deny"}),
        "paramRef.name must be a string"
    )]
    #[case::selector_wrong_type(
        json!({"selector": "app=demo", "parameterNotFoundAction": "Deny"}),
        "paramRef.selector must be an object"
    )]
    #[case::missing_parameter_not_found_action(
        json!({"name": "replica-limit"}),
        "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified"
    )]
    #[case::invalid_parameter_not_found_action(
        json!({"name": "replica-limit", "parameterNotFoundAction": "Maybe"}),
        "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified"
    )]
    #[case::parameter_not_found_action_wrong_type(
        json!({"name": "replica-limit", "parameterNotFoundAction": 1}),
        "paramRef.parameterNotFoundAction must be a string"
    )]
    fn validate_params_rejects_malformed_param_ref(
        #[case] param_ref: serde_json::Value,
        #[case] expected_message: &str,
    ) {
        let settings = json!({"paramKind": config_map_param_kind(), "paramRef": param_ref});
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("expected an error for malformed paramRef");
        assert_eq!(expected_message, err);
    }

    /// Type-shape errors come from deserializing into the `k8s_openapi`
    /// `LabelSelector`, operator errors from `kube::core::Selector`. Their
    /// exact wording belongs to those crates, so only the prefix is
    /// asserted here.
    #[rstest]
    #[case::match_labels_not_an_object(json!({"matchLabels": "app=demo"}))]
    #[case::match_labels_value_not_a_string(json!({"matchLabels": {"app": 1}}))]
    #[case::match_expressions_not_an_array(json!({"matchExpressions": {"key": "tier"}}))]
    #[case::expression_not_an_object(json!({"matchExpressions": ["tier in (web)"]}))]
    #[case::expression_missing_operator(json!({"matchExpressions": [{"key": "tier"}]}))]
    #[case::expression_unknown_operator(
        json!({"matchExpressions": [{"key": "tier", "operator": "Like", "values": ["web"]}]})
    )]
    #[case::expression_lowercase_operator(
        json!({"matchExpressions": [{"key": "tier", "operator": "in", "values": ["web"]}]})
    )]
    #[case::expression_values_not_an_array(
        json!({"matchExpressions": [{"key": "tier", "operator": "In", "values": "web"}]})
    )]
    #[case::expression_values_not_strings(
        json!({"matchExpressions": [{"key": "tier", "operator": "In", "values": [1]}]})
    )]
    fn validate_params_rejects_malformed_selector(#[case] selector: serde_json::Value) {
        let settings = json!({
            "paramKind": config_map_param_kind(),
            "paramRef": {"selector": selector, "parameterNotFoundAction": "Deny"}
        });
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("expected an error for malformed selector");
        assert!(
            err.starts_with("paramRef.selector is not a valid LabelSelector: "),
            "unexpected error: {err}"
        );
    }

    /// The `key` and `values` rules are not enforced by `k8s_openapi` or
    /// `kube`, so they are checked here and the messages are ours.
    #[rstest]
    #[case::missing_key(
        json!({"matchExpressions": [{"operator": "Exists"}]}),
        "paramRef.selector.matchExpressions[0].key must be a non-empty string"
    )]
    #[case::empty_key(
        json!({"matchExpressions": [{"key": "", "operator": "Exists"}]}),
        "paramRef.selector.matchExpressions[0].key must be a non-empty string"
    )]
    #[case::in_without_values(
        json!({"matchExpressions": [{"key": "tier", "operator": "In"}]}),
        "paramRef.selector.matchExpressions[0].values must be non-empty when operator is In"
    )]
    #[case::in_with_null_values(
        json!({"matchExpressions": [{"key": "tier", "operator": "In", "values": null}]}),
        "paramRef.selector.matchExpressions[0].values must be non-empty when operator is In"
    )]
    #[case::not_in_with_empty_values(
        json!({"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": []}]}),
        "paramRef.selector.matchExpressions[0].values must be non-empty when operator is NotIn"
    )]
    #[case::exists_with_values(
        json!({"matchExpressions": [{"key": "tier", "operator": "Exists", "values": ["web"]}]}),
        "paramRef.selector.matchExpressions[0].values must be empty when operator is Exists"
    )]
    #[case::does_not_exist_with_values(
        json!({"matchExpressions": [{"key": "tier", "operator": "DoesNotExist", "values": ["web"]}]}),
        "paramRef.selector.matchExpressions[0].values must be empty when operator is DoesNotExist"
    )]
    #[case::second_expression_is_reported_by_index(
        json!({"matchExpressions": [
            {"key": "tier", "operator": "Exists"},
            {"key": "env", "operator": "In"}
        ]}),
        "paramRef.selector.matchExpressions[1].values must be non-empty when operator is In"
    )]
    fn validate_params_rejects_selector_with_wrong_key_or_values(
        #[case] selector: serde_json::Value,
        #[case] expected_message: &str,
    ) {
        let settings = json!({
            "paramKind": config_map_param_kind(),
            "paramRef": {"selector": selector, "parameterNotFoundAction": "Deny"}
        });
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("expected an error for a selector with a wrong key or values");
        assert_eq!(expected_message, err);
    }

    #[rstest]
    #[case::name_with_allow(json!({"name": "replica-limit", "parameterNotFoundAction": "Allow"}))]
    #[case::name_with_deny(json!({"name": "replica-limit", "parameterNotFoundAction": "Deny"}))]
    #[case::name_with_namespace(json!({
        "name": "replica-limit",
        "namespace": "team-a",
        "parameterNotFoundAction": "Deny"
    }))]
    #[case::selector_with_deny(json!({
        "selector": {"matchLabels": {"app": "demo"}},
        "parameterNotFoundAction": "Deny"
    }))]
    #[case::selector_with_allow(json!({
        "selector": {"matchLabels": {"app": "demo"}},
        "parameterNotFoundAction": "Allow"
    }))]
    #[case::empty_selector_matches_everything(json!({
        "selector": {},
        "parameterNotFoundAction": "Deny"
    }))]
    #[case::selector_with_null_fields(json!({
        "selector": {"matchLabels": null, "matchExpressions": null},
        "parameterNotFoundAction": "Deny"
    }))]
    #[case::selector_with_every_operator(json!({
        "selector": {
            "matchLabels": {"app": "demo"},
            "matchExpressions": [
                {"key": "tier", "operator": "In", "values": ["web", "api"]},
                {"key": "env", "operator": "NotIn", "values": ["dev"]},
                {"key": "owner", "operator": "Exists"},
                {"key": "legacy", "operator": "DoesNotExist", "values": []},
                {"key": "deprecated", "operator": "DoesNotExist", "values": null}
            ]
        },
        "parameterNotFoundAction": "Deny"
    }))]
    fn validate_params_accepts_well_formed_param_ref(#[case] param_ref: serde_json::Value) {
        let settings = json!({"paramKind": config_map_param_kind(), "paramRef": param_ref});
        validate_params(&settings, &EvaluationContext::default())
            .expect("well-formed paramRef should be valid");
    }

    #[test]
    fn validate_params_ok_when_param_kind_resource_is_granted() {
        let settings = json!({"paramKind": config_map_param_kind(), "paramRef": named_param_ref()});
        let eval_ctx = eval_ctx_with_allow_list(BTreeSet::from([ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
        }]));

        validate_params(&settings, &eval_ctx)
            .expect("paramKind resource is granted, settings should be valid");
    }

    #[test]
    fn validate_params_ok_but_warns_when_param_kind_resource_is_not_granted() {
        // A missing grant must not fail settings validation: the Kubewarden
        // administrator may deliberately withhold it (see module docs on
        // `validate_params`). It only produces a `tracing::warn!`, which
        // this test can't assert on directly, but the important contract
        // -- that validation still succeeds -- is what's checked here.
        let settings = json!({"paramKind": config_map_param_kind(), "paramRef": named_param_ref()});

        validate_params(&settings, &EvaluationContext::default())
            .expect("a missing grant should only warn, not fail settings validation");
    }

    /// The `namespaceObject` grant follows the same contract as the
    /// `paramKind` grant above: a compiled policy that may read
    /// `namespaceObject` but has no `v1/Namespace` grant must still load.
    /// The compiled module fetches the Namespace itself via `kw.k8s.get`,
    /// and that call will be denied at evaluation time, but only a
    /// `tracing::warn!` reports it here, which this test can't assert on
    /// directly. What it pins is that validation succeeds regardless of
    /// whether the policy references `namespaceObject` and whether the
    /// grant is present.
    #[rstest]
    #[case::referenced_and_not_granted(true, BTreeSet::new())]
    #[case::referenced_and_granted(true, BTreeSet::from([namespace_resource()]))]
    #[case::not_referenced_and_not_granted(false, BTreeSet::new())]
    fn validate_settings_json_is_ok_regardless_of_the_namespace_object_grant(
        #[case] references_namespace_object: bool,
        #[case] allow_list: BTreeSet<ContextAwareResource>,
    ) {
        validate_settings_json(
            "{}",
            &eval_ctx_with_allow_list(allow_list),
            references_namespace_object,
        )
        .expect("a missing v1/Namespace grant should only warn, not fail settings validation");
    }
}
