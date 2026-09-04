use std::sync::Arc;

use anyhow::{Result, anyhow};
use kubewarden_policy_sdk::host_capabilities::{
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
    crypto_v1::CertificateVerificationRequest,
    kubernetes::{
        CanIRequest, GetResourceRequest, ListAllResourcesRequest, ListResourcesByNamespaceRequest,
    },
};
use tokio::sync::{mpsc, oneshot, oneshot::Receiver};
use tracing::{debug, error};

use crate::{
    callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse},
    evaluation_context::EvaluationContext,
};

fn unknown_operation(
    namespace: &str,
    operation: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    error!(namespace, operation, "unknown operation");
    Err(format!("unknown operation: {}", operation).into())
}

fn unknown_namespace(namespace: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    error!(namespace, "unknown namespace");
    Err(format!("unknown namespace: {}", namespace).into())
}

fn host_capability_denied(
    policy_id: &str,
    capability_path: &str,
    eval_ctx: &EvaluationContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    error!(
        policy = policy_id,
        capability = capability_path,
        allowed_capabilities = %eval_ctx.host_capabilities,
        "Policy tried to use a host capability it doesn't have access to"
    );
    Err(format!(
        "Policy has not been granted access to the '{capability_path}' host capability. The violation has been reported."
    )
    .into())
}

fn kubernetes_resource_denied(
    policy_id: &str,
    api_version: &str,
    kind: &str,
    eval_ctx: &EvaluationContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    error!(
        policy = policy_id,
        resource_requested = format!("{api_version}/{kind}"),
        resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
        "Policy tried to access a Kubernetes resource it doesn't have access to"
    );
    Err(format!(
        "Policy has not been granted access to Kubernetes {api_version}/{kind} resources. The violation has been reported."
    )
    .into())
}

/// Checks that `eval_ctx` grants access to the host capability identified by
/// `{namespace}/{operation}`, and -- for the Kubernetes read operations that
/// carry a resource type -- that it also grants access to that specific
/// `apiVersion`/`kind`.
///
/// This is the single authorization gate shared by every caller of the
/// callback channel.
fn check_authorization(
    eval_ctx: &EvaluationContext,
    namespace: &str,
    operation: &str,
    req: &CallbackRequestType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // "tracing" is not gated by host capabilities.
    if namespace != "tracing" {
        let capability_path = format!("{namespace}/{operation}");
        if !eval_ctx.can_access_host_capability(&capability_path) {
            host_capability_denied(&eval_ctx.policy_id, &capability_path, eval_ctx)?;
        }
    }

    let resource = match req {
        CallbackRequestType::KubernetesListResourceNamespace {
            api_version, kind, ..
        }
        | CallbackRequestType::KubernetesListResourceAll {
            api_version, kind, ..
        }
        | CallbackRequestType::KubernetesGetResource {
            api_version, kind, ..
        } => Some((api_version.as_str(), kind.as_str())),
        _ => None,
    };

    if let Some((api_version, kind)) = resource
        && !eval_ctx.can_access_kubernetes_resource(api_version, kind)
    {
        kubernetes_resource_denied(&eval_ctx.policy_id, api_version, kind, eval_ctx)?;
    }

    Ok(())
}

/// Authorize and dispatch an already-constructed [`CallbackRequestType`] over
/// the callback channel, synchronously waiting for the response.
///
/// This is the typed entry point used by the ferricel runtime, which builds
/// `CallbackRequestType` values directly in Rust code (no wasm guest payload
/// to deserialize). [`host_callback`] (used by waPC/Wasi) is a thin adapter
/// on top of this function.
pub(crate) fn host_callback_typed(
    namespace: &str,
    operation: &str,
    req: CallbackRequestType,
    eval_ctx: &Arc<EvaluationContext>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    check_authorization(eval_ctx, namespace, operation, &req)?;

    let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
    let callback_request = CallbackRequest {
        request: req,
        response_channel: tx,
    };
    send_request_and_wait_for_response(operation, callback_request, rx, eval_ctx)
}

/// The callback function used by waPC and Wasi policies to use host capabilities
pub(crate) fn host_callback(
    binding: &str,
    namespace: &str,
    operation: &str,
    payload: &[u8],
    eval_ctx: &Arc<EvaluationContext>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if binding != "kubewarden" {
        error!(binding, "unknown binding");
        return Err(format!("unknown binding: {binding}").into());
    }

    // "tracing" never goes through the callback channel (it's not gated by
    // host capabilities either), so it's handled inline rather than being
    // folded into the `CallbackRequestType` match below.
    if namespace == "tracing" {
        return match operation {
            "log" => {
                if let Err(e) = eval_ctx.log(payload) {
                    error!(
                        payload = String::from_utf8_lossy(payload).to_string(),
                        error = e.to_string(),
                        "Cannot log event"
                    );
                }
                Ok(Vec::new())
            }
            _ => unknown_operation(namespace, operation),
        };
    }

    let req: CallbackRequestType = match (namespace, operation) {
        ("oci", "v1/verify") => {
            serde_json::from_slice::<SigstoreVerificationInputV1>(payload)?.into()
        }
        ("oci", "v2/verify") => {
            serde_json::from_slice::<SigstoreVerificationInputV2>(payload)?.into()
        }
        ("oci", "v1/manifest_digest") => CallbackRequestType::OciManifestDigest {
            image: serde_json::from_slice(payload)?,
        },
        ("oci", "v1/oci_manifest") => CallbackRequestType::OciManifest {
            image: serde_json::from_slice(payload)?,
        },
        ("oci", "v1/oci_manifest_config") => CallbackRequestType::OciManifestAndConfig {
            image: serde_json::from_slice(payload)?,
        },
        ("net", "v1/dns_lookup_host") => CallbackRequestType::DNSLookupHost {
            host: serde_json::from_slice(payload)?,
        },
        ("crypto", "v1/is_certificate_trusted") => {
            serde_json::from_slice::<CertificateVerificationRequest>(payload)?.into()
        }
        ("kubernetes", "list_resources_by_namespace") => {
            serde_json::from_slice::<ListResourcesByNamespaceRequest>(payload)?.into()
        }
        ("kubernetes", "list_resources_all") => {
            serde_json::from_slice::<ListAllResourcesRequest>(payload)?.into()
        }
        ("kubernetes", "get_resource") => {
            serde_json::from_slice::<GetResourceRequest>(payload)?.into()
        }
        ("kubernetes", "can_i") => serde_json::from_slice::<CanIRequest>(payload)?.into(),
        ("oci" | "net" | "crypto" | "kubernetes", _) => {
            return unknown_operation(namespace, operation);
        }
        _ => return unknown_namespace(namespace),
    };

    host_callback_typed(namespace, operation, req, eval_ctx)
}

fn send_request_and_wait_for_response(
    operation: &str,
    req: CallbackRequest,
    rx: Receiver<Result<CallbackResponse>>,
    eval_ctx: &EvaluationContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let policy_id = eval_ctx.policy_id.as_str();

    let cb_channel: mpsc::Sender<CallbackRequest> =
        if let Some(c) = eval_ctx.callback_channel.clone() {
            Ok(c)
        } else {
            error!(
                policy_id,
                operation, "Cannot process Wasm guest request: callback channel not provided"
            );
            Err(anyhow!(
                "Cannot process Wasm guest request: callback channel not provided"
            ))
        }?;

    debug!(
        policy_id,
        operation,
        request = ?req.request,
        "Sending request via callback channel"
    );

    let send_result = cb_channel.try_send(req);
    if let Err(e) = send_result {
        return Err(format!("Error sending request over callback channel: {e:?}").into());
    }

    // wait for the response
    match rx.blocking_recv() {
        Ok(msg) => match msg {
            Ok(resp) => Ok(resp.payload),
            Err(e) => {
                error!(
                    policy_id,
                    operation,
                    error = ?e,
                    "callback evaluation failed"
                );
                Err(format!("Callback evaluation failure: {e:?}").into())
            }
        },
        Err(e) => {
            error!(
                policy_id,
                operation,
                error = ?e,
                "Cannot process Wasm guest request: error obtaining response over callback channel"
            );
            Err("Error obtaining response over callback channel".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use rstest::rstest;

    use super::{host_callback, host_callback_typed};
    use crate::{
        callback_requests::CallbackRequestType, evaluation_context::EvaluationContext,
        host_capabilities::HostCapabilities, policy_metadata::ContextAwareResource,
    };

    /// Build an `EvaluationContext` for exercising the authorization gate.
    ///
    /// `callback_channel` is always `None`, so a request that passes
    /// authorization fails fast at the channel send instead of silently
    /// succeeding, letting tests assert "not a denial" without a real channel.
    fn test_ctx(
        host_capabilities: HostCapabilities,
        ctx_aware_resources_allow_list: BTreeSet<ContextAwareResource>,
    ) -> Arc<EvaluationContext> {
        Arc::new(EvaluationContext {
            policy_id: "test-policy".to_owned(),
            callback_channel: None,
            ctx_aware_resources_allow_list,
            epoch_deadline: None,
            host_capabilities,
        })
    }

    /// A minimal, valid payload for each `(namespace, operation)` pair handled
    /// by [`host_callback`], used by both the denial and allowed tests below
    /// so the capability gate -- checked after payload deserialization -- is
    /// what's actually being exercised, rather than a payload-parsing failure.
    fn valid_payload_for(namespace: &str, operation: &str) -> &'static [u8] {
        match (namespace, operation) {
            // oci: v1/verify uses externally-tagged SigstoreVerificationInputV1
            ("oci", "v1/verify") => {
                br#"{"SigstorePubKeyVerify":{"image":"ghcr.io/example/image:latest","pub_keys":[],"annotations":null}}"#
            }
            // oci: v2/verify uses internally-tagged SigstoreVerificationInputV2
            ("oci", "v2/verify") => {
                br#"{"type":"SigstorePubKeyVerify","image":"ghcr.io/example/image:latest","pub_keys":[],"annotations":null}"#
            }
            // oci: remaining operations take a JSON-encoded image reference string
            ("oci", "v1/manifest_digest" | "v1/oci_manifest" | "v1/oci_manifest_config") => {
                br#""ghcr.io/example/image:latest""#
            }
            // net: payload is a JSON-encoded hostname string
            ("net", "v1/dns_lookup_host") => br#""example.com""#,
            // crypto: minimal CertificateVerificationRequest
            ("crypto", "v1/is_certificate_trusted") => {
                br#"{"cert":{"encoding":"Pem","data":[]},"cert_chain":null,"not_after":null}"#
            }
            ("kubernetes", "list_resources_by_namespace") => {
                br#"{"api_version":"v1","kind":"Pod","namespace":"default","label_selector":null,"field_selector":null,"field_masks":null}"#
            }
            ("kubernetes", "list_resources_all") => {
                br#"{"api_version":"v1","kind":"Pod","label_selector":null,"field_selector":null,"field_masks":null}"#
            }
            ("kubernetes", "get_resource") => {
                br#"{"api_version":"v1","kind":"Pod","name":"test","namespace":"default","disable_cache":false}"#
            }
            ("kubernetes", "can_i") => {
                br#"{"subject_access_review":{"groups":null,"resource_attributes":{"group":null,"name":null,"namespace":null,"resource":"pods","subresource":null,"verb":"get","version":null},"user":"test"},"disable_cache":false}"#
            }
            _ => panic!("no valid payload defined for {namespace}/{operation}"),
        }
    }

    #[rstest]
    #[case("oci", "v1/verify")]
    #[case("oci", "v2/verify")]
    #[case("oci", "v1/manifest_digest")]
    #[case("oci", "v1/oci_manifest")]
    #[case("oci", "v1/oci_manifest_config")]
    #[case("net", "v1/dns_lookup_host")]
    #[case("crypto", "v1/is_certificate_trusted")]
    #[case("kubernetes", "list_resources_by_namespace")]
    #[case("kubernetes", "list_resources_all")]
    #[case("kubernetes", "get_resource")]
    #[case("kubernetes", "can_i")]
    fn host_capability_denied_returns_denial_error(
        #[case] namespace: &str,
        #[case] operation: &str,
    ) {
        let ctx = test_ctx(HostCapabilities::DenyAll, BTreeSet::new());
        let payload = valid_payload_for(namespace, operation);

        // The capability gate (inside `check_authorization`) fires right after
        // payload deserialization, before any Kubernetes-resource check or
        // channel send, so a denied policy is rejected even with a fully valid
        // payload.
        let result = host_callback("kubewarden", namespace, operation, payload, &ctx);

        let err = result.expect_err("expected Err for denied capability");
        assert!(
            err.to_string().contains("has not been granted access"),
            "namespace={namespace}, operation={operation}: unexpected error: {err}"
        );
    }

    #[rstest]
    #[case("oci", "v1/verify")]
    #[case("oci", "v2/verify")]
    #[case("oci", "v1/manifest_digest")]
    #[case("oci", "v1/oci_manifest")]
    #[case("oci", "v1/oci_manifest_config")]
    #[case("net", "v1/dns_lookup_host")]
    #[case("crypto", "v1/is_certificate_trusted")]
    // kubernetes: list/get operations also have a ctx_aware_resources check after
    // the capability gate; with an empty allow-list the function returns a
    // *kubernetes* resource denial rather than a host-capability denial,
    // confirming the capability gate was cleared.
    #[case("kubernetes", "list_resources_by_namespace")]
    #[case("kubernetes", "list_resources_all")]
    #[case("kubernetes", "get_resource")]
    // kubernetes/can_i: no ctx_aware_resources check; proceeds straight to channel send
    #[case("kubernetes", "can_i")]
    fn host_capability_allowed_proceeds_past_capability_check(
        #[case] namespace: &str,
        #[case] operation: &str,
    ) {
        let ctx = test_ctx(HostCapabilities::AllowAll, BTreeSet::new());
        let payload = valid_payload_for(namespace, operation);
        let result = host_callback("kubewarden", namespace, operation, payload, &ctx);

        // The capability check passes; the function then fails for a different reason
        // (channel send, or kubernetes resource check). Either way the error must NOT
        // be a host-capability denial.
        let err = result.expect_err("expected Err because callback channel is None");
        let msg = err.to_string();
        assert!(
            !msg.contains("host capability"),
            "namespace={namespace}, operation={operation}: should not be a host-capability denial, got: {msg}"
        );
    }

    // ── host_callback_typed: the single authorization gate ───────────────────
    //
    // All authorization (host-capability + Kubernetes-resource checks) lives in
    // `host_callback_typed`, via `check_authorization`. Ferricel calls this entry
    // point directly, building a `CallbackRequestType` in Rust with no wasm guest
    // payload to deserialize; waPC/Wasi reach it through `host_callback`, which
    // is just a payload-decoding adapter that delegates here.
    //
    // These tests exercise `host_callback_typed` on its own, independently of
    // `host_callback`: if a future refactor ever stopped `host_callback` from
    // delegating to it, the bytes-based tests above would still pass while the
    // ferricel path silently lost its authorization gate -- these tests pin the
    // contract of the entry point ferricel actually calls, so that regression
    // would be caught here.

    #[rstest]
    #[case("oci", "v1/oci_manifest", CallbackRequestType::OciManifest { image: "ghcr.io/example/image:latest".to_string() })]
    #[case("net", "v1/dns_lookup_host", CallbackRequestType::DNSLookupHost { host: "example.com".to_string() })]
    #[case("kubernetes", "get_resource", CallbackRequestType::KubernetesGetResource {
        api_version: "v1".to_string(),
        kind: "Pod".to_string(),
        name: "test".to_string(),
        namespace: Some("default".to_string()),
        disable_cache: false,
        field_masks: None,
    })]
    fn typed_host_capability_denied_returns_denial_error(
        #[case] namespace: &str,
        #[case] operation: &str,
        #[case] req: CallbackRequestType,
    ) {
        let ctx = test_ctx(HostCapabilities::DenyAll, BTreeSet::new());
        let result = host_callback_typed(namespace, operation, req, &ctx);

        let err = result.expect_err("expected Err for denied capability");
        assert!(
            err.to_string().contains("has not been granted access"),
            "namespace={namespace}, operation={operation}: unexpected error: {err}"
        );
    }

    #[test]
    fn typed_kubernetes_resource_denied_when_not_in_allow_list() {
        // Host capability is allowed, but the ctx_aware_resources_allow_list is
        // empty, so the Kubernetes-resource gate (not the capability gate) must
        // reject the request.
        let ctx = test_ctx(HostCapabilities::AllowAll, BTreeSet::new());
        let result = host_callback_typed(
            "kubernetes",
            "get_resource",
            CallbackRequestType::KubernetesGetResource {
                api_version: "v1".to_string(),
                kind: "Secret".to_string(),
                name: "test".to_string(),
                namespace: Some("default".to_string()),
                disable_cache: false,
                field_masks: None,
            },
            &ctx,
        );

        let err = result.expect_err("expected Err for denied Kubernetes resource");
        let msg = err.to_string();
        assert!(
            msg.contains("has not been granted access to Kubernetes"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn typed_kubernetes_resource_allowed_when_in_allow_list() {
        // Host capability and Kubernetes resource are both allowed, so the
        // function proceeds past both gates and only fails because the
        // callback channel is None (fast-fail at channel send).
        let ctx = test_ctx(
            HostCapabilities::AllowAll,
            BTreeSet::from([ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Secret".to_string(),
            }]),
        );

        let result = host_callback_typed(
            "kubernetes",
            "get_resource",
            CallbackRequestType::KubernetesGetResource {
                api_version: "v1".to_string(),
                kind: "Secret".to_string(),
                name: "test".to_string(),
                namespace: Some("default".to_string()),
                disable_cache: false,
                field_masks: None,
            },
            &ctx,
        );

        let err = result.expect_err("expected Err because callback channel is None");
        let msg = err.to_string();
        assert!(
            !msg.contains("host capability") && !msg.contains("Kubernetes"),
            "should have passed both gates, got: {msg}"
        );
    }
}
