use kubewarden_policy_sdk::{
    response::ValidationResponse as PolicyValidationResponse, settings::SettingsValidationResponse,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tracing::{error, warn};

use crate::{
    admission_response::AdmissionResponse,
    callback_requests::{CallbackRequest, CallbackRequestType},
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicySettings, ValidateRequest},
    runtimes::ferricel::{errors::FerricelRuntimeError, stack::Stack},
};

pub(crate) struct Runtime<'a>(pub(crate) &'a Stack);

impl Runtime<'_> {
    pub fn validate(
        &self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
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
            Err(e) => AdmissionResponse::reject_internal_server_error(
                request.uid().to_string(),
                e.to_string(),
            ),
        }
    }

    /// Build the JSON bindings object passed to the compiled VAP module.
    ///
    /// Bindings provided:
    ///   - `object`          The resource being admitted.
    ///   - `oldObject`       The previous version of the resource (UPDATE/DELETE) or null.
    ///   - `request`         The full AdmissionRequest map (operation, userInfo, etc.).
    ///   - `namespaceObject` The Namespace resource for `request.namespace`, fetched from
    ///     the cluster via the callback channel. null for cluster-scoped resources, and
    ///     also null (without fetching) when the compiled policy's `ferricel.vap-variables`
    ///     Wasm custom section proves that `namespaceObject` is never referenced (see
    ///     `StackPre::references_vap_variable`). Error if the request is namespace-scoped,
    ///     the policy may reference `namespaceObject`, but no callback channel is available.
    ///     Derived from `AdmissionRequest.namespace` rather than `object.metadata.namespace`
    ///     because `object` is null for DELETE requests, even though the request is
    ///     still namespace-scoped.
    ///   - `paramRef`        Forwarded from `settings["paramRef"]` when present, so that
    ///     the compiled wasm can use it to fetch the param resource via the
    ///     `kw.k8s.get` extension (registered in StackPre::rehydrate).
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

                let namespace_object = if self.0.references_vap_variable("namespaceObject") {
                    fetch_namespace_object(
                        admission_request.namespace.as_deref(),
                        self.0.eval_ctx(),
                    )
                    .map_err(|e| {
                        error!(error = e.as_str(), "failed to fetch namespace object");
                        Box::new(AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            e,
                        ))
                    })?
                } else {
                    // The compiled policy's `ferricel.vap-variables` Wasm
                    // custom section (see `StackPre::references_vap_variable`)
                    // proves that `namespaceObject` is never referenced by
                    // this policy's CEL: skip the fetch entirely, avoiding an
                    // unnecessary Kubernetes API call and (more importantly)
                    // a hard failure when no Kubernetes client/callback
                    // channel is available (e.g. `kwctl run` without cluster
                    // access), which would otherwise reject every namespaced
                    // request even though the policy never needs this value.
                    Value::Null
                };

                let param_ref = settings.0.get("paramRef").cloned().unwrap_or(Value::Null);

                Ok(json!({
                    "object":          object,
                    "oldObject":       old_object,
                    "request":         request_map,
                    "namespaceObject": namespace_object,
                    "paramRef":        param_ref,
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
    /// Wasm module. This function only validates the shape of the
    /// `paramKind`/`paramRef` settings (which are consumed by the runtime
    /// itself, not by the compiled wasm's own logic) and, on top of that,
    /// warns -- without failing validation -- when a `paramKind` grant is
    /// missing.
    pub fn validate_settings(&self, settings: String) -> SettingsValidationResponse {
        match validate_settings_json(&settings, self.0.eval_ctx()) {
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

/// Parses `settings` as JSON and validates the `paramKind`/`paramRef` fields.
///
/// Kept as a free function (rather than a `Runtime` method) so it only
/// depends on `&EvaluationContext`, making it unit-testable without a real
/// `Stack` (which requires a compiled wasm module).
fn validate_settings_json(settings: &str, eval_ctx: &EvaluationContext) -> Result<(), String> {
    let settings_json: Value = serde_json::from_str(settings)
        .map_err(|e| format!("cannot parse policy settings as JSON: {e}"))?;

    validate_params(&settings_json, eval_ctx)
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
        Some(Value::Object(o)) => Some(o),
        Some(_) => return Err("paramRef.selector must be an object".to_string()),
    };

    match (name, selector) {
        (None, None) => {
            return Err("paramRef must have either name or selector specified".to_string());
        }
        (Some(_), Some(_)) => {
            return Err("paramRef cannot have both name and selector specified".to_string());
        }
        _ => {}
    }

    match optional_str_field(obj, "paramRef", "parameterNotFoundAction")? {
        Some("Allow") | Some("Deny") => Ok(()),
        _ => Err(
            "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified"
                .to_string(),
        ),
    }
}

/// Validates the `paramKind`/`paramRef` settings, when present.
///
/// If `paramKind` is present, it must fully specify `apiVersion` and `kind`
/// (this is required regardless of grants: the wasm module has this
/// resource baked in at compile time via `compile_vap_from_policy`, so an
/// incomplete `paramKind` here can never be legitimate). If `paramRef` is
/// present, it must specify exactly one of `name`/`selector`, and a valid
/// `parameterNotFoundAction`.
///
/// Separately, if `paramKind` is complete but its resource is not listed in
/// `eval_ctx`'s `ctx_aware_resources_allow_list` (populated from
/// `spec.contextAwareResources` on the CRD), this only warns rather than
/// failing validation: fetching the param resource via `paramRef`/
/// `kw.k8s.get` at evaluation time will be denied by the authorization gate
/// (see `EvaluationContext::can_access_kubernetes_resource`), causing the
/// policy to fail on every request that reaches it, but the Kubewarden
/// administrator may intentionally withhold the grant (e.g. because a
/// policy's declared `paramKind` looks suspicious), and settings validation
/// must not block loading the policy in that case.
fn validate_params(settings: &Value, eval_ctx: &EvaluationContext) -> Result<(), String> {
    let param_kind_resource = match settings.get("paramKind") {
        Some(param_kind) => Some(validate_param_kind(param_kind)?),
        None => None,
    };

    if let Some(param_ref) = settings.get("paramRef") {
        validate_param_ref(param_ref)?;
    }

    if let Some((api_version, kind)) = param_kind_resource
        && !eval_ctx.can_access_kubernetes_resource(&api_version, &kind)
    {
        warn!(
            %api_version,
            %kind,
            "policy declares paramKind {api_version}/{kind}, but this resource is not listed in spec.contextAwareResources; \
             fetching the param resource via paramRef will be denied at evaluation time"
        );
    }

    Ok(())
}

fn fetch_namespace_object(
    namespace: Option<&str>,
    eval_ctx: &EvaluationContext,
) -> Result<Value, String> {
    let namespace = namespace.unwrap_or("");

    if namespace.is_empty() {
        return Ok(Value::Null);
    }

    // Intentionally bypasses the `kubernetes/get_resource` host-capability and
    // Kubernetes-resource authorization gate (see
    // `runtimes::callback::host_callback_typed`): this fetch implements VAP's
    // built-in `namespaceObject` CEL binding, which is runtime infrastructure
    // rather than a policy-invoked capability. Gating it would force every
    // ferricel policy evaluating a namespaced resource to be explicitly
    // granted access to `v1/Namespace`, even though the policy itself never
    // calls `kw.k8s.get`/`list`.
    let channel = match &eval_ctx.callback_channel {
        Some(ch) => ch,
        None => {
            return Err(
                "cannot fetch namespaceObject: callback channel is not available".to_string(),
            );
        }
    };

    let (tx, rx) = oneshot::channel::<anyhow::Result<crate::callback_requests::CallbackResponse>>();
    let req = CallbackRequest {
        request: CallbackRequestType::KubernetesGetResource {
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
            name: namespace.to_string(),
            namespace: None,
            disable_cache: false,
            field_masks: None,
        },
        response_channel: tx,
    };

    channel
        .try_send(req)
        .map_err(|e| format!("failed to send namespace fetch request: {e}"))?;

    match rx.blocking_recv() {
        Ok(Ok(response)) => serde_json::from_slice(&response.payload)
            .map_err(|e| format!("failed to deserialize namespace object: {e}")),
        Ok(Err(e)) => Err(format!("failed to fetch namespace object: {e}")),
        Err(e) => Err(format!("namespace fetch channel closed: {e}")),
    }
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

    #[test]
    fn validate_settings_json_invalid_json_is_rejected() {
        let err = validate_settings_json("not json", &EvaluationContext::default())
            .expect_err("expected an error for invalid JSON");
        assert!(
            err.contains("cannot parse policy settings as JSON"),
            "unexpected error: {err}"
        );
    }

    #[rstest]
    #[case::no_params(json!({}))]
    #[case::unrelated_settings(json!({"validations": []}))]
    fn validate_params_without_param_kind_or_ref_is_ok(#[case] settings: serde_json::Value) {
        validate_params(&settings, &EvaluationContext::default())
            .expect("settings without paramKind/paramRef should be valid");
    }

    #[rstest]
    #[case::not_an_object(json!({"paramKind": "v1/ConfigMap"}), "paramKind must be an object")]
    #[case::missing_kind(
        json!({"paramKind": {"apiVersion": "v1"}}),
        "paramKind must have both apiVersion and kind specified"
    )]
    #[case::missing_api_version(
        json!({"paramKind": {"kind": "ConfigMap"}}),
        "paramKind must have both apiVersion and kind specified"
    )]
    #[case::empty_strings(
        json!({"paramKind": {"apiVersion": "", "kind": ""}}),
        "paramKind must have both apiVersion and kind specified"
    )]
    #[case::api_version_wrong_type(
        json!({"paramKind": {"apiVersion": 1, "kind": "ConfigMap"}}),
        "paramKind.apiVersion must be a string"
    )]
    #[case::kind_wrong_type(
        json!({"paramKind": {"apiVersion": "v1", "kind": []}}),
        "paramKind.kind must be a string"
    )]
    fn validate_params_rejects_malformed_param_kind(
        #[case] settings: serde_json::Value,
        #[case] expected_message: &str,
    ) {
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("expected an error for malformed paramKind");
        assert_eq!(expected_message, err);
    }

    #[rstest]
    #[case::not_an_object(json!({"paramRef": "replica-limit"}), "paramRef must be an object")]
    #[case::missing_name_and_selector(
        json!({"paramRef": {"parameterNotFoundAction": "Deny"}}),
        "paramRef must have either name or selector specified"
    )]
    #[case::both_name_and_selector(
        json!({"paramRef": {
            "name": "replica-limit",
            "selector": {"matchLabels": {"app": "demo"}},
            "parameterNotFoundAction": "Deny"
        }}),
        "paramRef cannot have both name and selector specified"
    )]
    #[case::name_wrong_type(
        json!({"paramRef": {"name": 1, "parameterNotFoundAction": "Deny"}}),
        "paramRef.name must be a string"
    )]
    #[case::selector_wrong_type(
        json!({"paramRef": {"selector": "app=demo", "parameterNotFoundAction": "Deny"}}),
        "paramRef.selector must be an object"
    )]
    #[case::missing_parameter_not_found_action(
        json!({"paramRef": {"name": "replica-limit"}}),
        "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified"
    )]
    #[case::invalid_parameter_not_found_action(
        json!({"paramRef": {"name": "replica-limit", "parameterNotFoundAction": "Maybe"}}),
        "parameterNotFoundAction must be 'Deny' or 'Allow' if paramRef is specified"
    )]
    #[case::parameter_not_found_action_wrong_type(
        json!({"paramRef": {"name": "replica-limit", "parameterNotFoundAction": 1}}),
        "paramRef.parameterNotFoundAction must be a string"
    )]
    fn validate_params_rejects_malformed_param_ref(
        #[case] settings: serde_json::Value,
        #[case] expected_message: &str,
    ) {
        let err = validate_params(&settings, &EvaluationContext::default())
            .expect_err("expected an error for malformed paramRef");
        assert_eq!(expected_message, err);
    }

    #[rstest]
    #[case::name_with_allow(json!({"paramRef": {"name": "replica-limit", "parameterNotFoundAction": "Allow"}}))]
    #[case::name_with_deny(json!({"paramRef": {"name": "replica-limit", "parameterNotFoundAction": "Deny"}}))]
    #[case::selector_with_deny(json!({"paramRef": {
        "selector": {"matchLabels": {"app": "demo"}},
        "parameterNotFoundAction": "Deny"
    }}))]
    fn validate_params_accepts_well_formed_param_ref(#[case] settings: serde_json::Value) {
        validate_params(&settings, &EvaluationContext::default())
            .expect("well-formed paramRef should be valid");
    }

    #[test]
    fn validate_params_ok_when_param_kind_resource_is_granted() {
        let settings = json!({"paramKind": {"apiVersion": "v1", "kind": "ConfigMap"}});
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
        let settings = json!({"paramKind": {"apiVersion": "v1", "kind": "ConfigMap"}});

        validate_params(&settings, &EvaluationContext::default())
            .expect("a missing grant should only warn, not fail settings validation");
    }
}
