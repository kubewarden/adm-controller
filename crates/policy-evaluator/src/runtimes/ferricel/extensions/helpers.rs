use std::sync::Arc;

use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType, evaluation_context::EvaluationContext,
    runtimes::callback::host_callback_typed,
};

// ─── Handler helpers ──────────────────────────────────────────────────────────

/// Extract a required string field from a builder map.
pub(crate) fn str_field(map: &Value, key: &str) -> Result<String, String> {
    map[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or non-string field '{key}' in builder map"))
}

/// Extract an optional field mask array from a builder map.
pub(crate) fn parse_field_masks(map: &Value) -> Option<std::collections::BTreeSet<String>> {
    map["fieldMasks"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    })
}

/// Extract the optional `namespace` of a `kw.k8s` builder map.
///
/// An absent key and an empty string both mean "no namespace". A `kw.k8s`
/// chain written in CEL sets the key only when the policy calls
/// `.namespace(...)`. The `params` lookup that a compiled VAP module runs on
/// its own always sets the key, and uses `""` when neither
/// `paramRef.namespace` nor `request.namespace` is set (for example, a
/// cluster-scoped param resource). Treating `""` as a real namespace would
/// build a broken API path, or reject a cluster-scoped resource with
/// "cannot search for it inside of a namespace".
pub(crate) fn optional_namespace(map: &Value) -> Option<String> {
    map["namespace"]
        .as_str()
        .filter(|ns| !ns.is_empty())
        .map(str::to_owned)
}

/// Authorize and dispatch a `CallbackRequestType` built from a ferricel
/// extension handler, synchronously waiting for the response.
///
/// This routes through [`host_callback_typed`] -- the single authorization
/// gate (host-capability + Kubernetes-resource checks) for the callback
/// channel, which waPC/Wasi policies also reach via their `host_callback`
/// adapter -- so no gating logic lives in the ferricel handlers themselves.
///
/// Returns an error if the callback channel is not set; the channel handling
/// is part of the shared dispatch path, so the error is the very same one
/// waPC/Wasi guests get when no callback channel is available.
pub(crate) fn call_host(
    eval_ctx: &Arc<EvaluationContext>,
    namespace: &str,
    operation: &str,
    request_type: CallbackRequestType,
) -> Result<Value, String> {
    let payload = host_callback_typed(namespace, operation, request_type, eval_ctx)
        .map_err(|e| e.to_string())?;

    serde_json::from_slice(&payload).map_err(|e| format!("failed to deserialize response: {e}"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    #[rstest]
    #[case::absent(json!({"kind": "ConfigMap"}), None)]
    #[case::null(json!({"namespace": null}), None)]
    #[case::empty(json!({"namespace": ""}), None)]
    #[case::not_a_string(json!({"namespace": 1}), None)]
    #[case::set(json!({"namespace": "team-a"}), Some("team-a".to_string()))]
    fn optional_namespace_treats_empty_as_absent(
        #[case] map: Value,
        #[case] expected: Option<String>,
    ) {
        assert_eq!(optional_namespace(&map), expected);
    }
}
