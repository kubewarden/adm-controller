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

    // "tracing" is not gated by host capabilities; all other namespaces are.
    // Check if host capability is allowed.
    if namespace != "tracing" {
        let capability_path = format!("{namespace}/{operation}");
        if !eval_ctx.can_access_host_capability(&capability_path) {
            return host_capability_denied(&eval_ctx.policy_id, &capability_path, eval_ctx);
        }
    }

    match namespace {
        "tracing" => match operation {
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
        },
        "oci" => match operation {
            "v1/verify" => {
                let req: SigstoreVerificationInputV1 = serde_json::from_slice(payload)?;
                let req_type: CallbackRequestType = req.into();
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req_type,
                    response_channel: tx,
                };

                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "v2/verify" => {
                let req: SigstoreVerificationInputV2 = serde_json::from_slice(payload)?;
                let req_type: CallbackRequestType = req.into();
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: req_type,
                    response_channel: tx,
                };

                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "v1/manifest_digest" => {
                let image: String = serde_json::from_slice(payload)?;
                debug!(
                    eval_ctx.policy_id,
                    binding, operation, image, "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::OciManifestDigest { image },
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "v1/oci_manifest" => {
                let image: String = serde_json::from_slice(payload)?;
                debug!(
                    eval_ctx.policy_id,
                    binding, operation, image, "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::OciManifest { image },
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "v1/oci_manifest_config" => {
                let image: String = serde_json::from_slice(payload)?;
                debug!(
                    eval_ctx.policy_id,
                    binding, operation, image, "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::OciManifestAndConfig { image },
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            _ => unknown_operation(namespace, operation),
        },
        "net" => match operation {
            "v1/dns_lookup_host" => {
                let host: String = serde_json::from_slice(payload)?;
                debug!(
                    eval_ctx.policy_id,
                    binding, operation, host, "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::DNSLookupHost { host },
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            _ => unknown_operation(namespace, operation),
        },
        "crypto" => match operation {
            "v1/is_certificate_trusted" => {
                let req: CertificateVerificationRequest = serde_json::from_slice(payload)?;

                debug!(
                    eval_ctx.policy_id,
                    binding,
                    operation,
                    ?req,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::from(req),
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            _ => unknown_operation(namespace, operation),
        },
        "kubernetes" => match operation {
            "list_resources_by_namespace" => {
                let req: ListResourcesByNamespaceRequest = serde_json::from_slice(payload)?;

                if !eval_ctx.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                    error!(
                        policy = eval_ctx.policy_id,
                        resource_requested = format!("{}/{}", req.api_version, req.kind),
                        resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
                        "Policy tried to access a Kubernetes resource it doesn't have access to");
                    return Err(format!(
                            "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                            req.api_version,
                            req.kind).into());
                }

                debug!(
                    eval_ctx.policy_id,
                    binding,
                    operation,
                    ?req,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::from(req),
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "list_resources_all" => {
                let req: ListAllResourcesRequest = serde_json::from_slice(payload)?;
                if !eval_ctx.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                    error!(
                        policy = eval_ctx.policy_id,
                        resource_requested = format!("{}/{}", req.api_version, req.kind),
                        resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
                        "Policy tried to access a Kubernetes resource it doesn't have access to");
                    return Err(format!(
                            "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                            req.api_version,
                            req.kind).into());
                }

                debug!(
                    eval_ctx.policy_id,
                    binding,
                    operation,
                    ?req,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::from(req),
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "get_resource" => {
                let req: GetResourceRequest = serde_json::from_slice(payload)?;
                if !eval_ctx.can_access_kubernetes_resource(&req.api_version, &req.kind) {
                    error!(
                        policy = eval_ctx.policy_id,
                        resource_requested = format!("{}/{}", req.api_version, req.kind),
                        resources_allowed = ?eval_ctx.ctx_aware_resources_allow_list,
                        "Policy tried to access a Kubernetes resource it doesn't have access to");
                    return Err(format!(
                            "Policy has not been granted access to Kubernetes {}/{} resources. The violation has been reported.",
                            req.api_version,
                            req.kind).into());
                }

                debug!(
                    eval_ctx.policy_id,
                    binding,
                    operation,
                    ?req,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::from(req),
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "can_i" => {
                let req: CanIRequest = serde_json::from_slice(payload)?;

                debug!(
                    eval_ctx.policy_id,
                    binding,
                    namespace,
                    operation,
                    ?req,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::from(req),
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            _ => unknown_operation(namespace, operation),
        },
        "cache" => match operation {
            "set" => {
                let req: crate::callback_handler::cache::CacheSetRequest =
                    serde_json::from_slice(payload)?;
                debug!(
                    eval_ctx.policy_id,
                    binding,
                    namespace,
                    operation,
                    key = req.key,
                    ttl = req.ttl,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::CacheSet {
                        key: req.key,
                        value: req.value,
                        ttl: req.ttl,
                    },
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            "get" => {
                let req: crate::callback_handler::cache::CacheGetRequest =
                    serde_json::from_slice(payload)?;
                debug!(
                    eval_ctx.policy_id,
                    binding,
                    namespace,
                    operation,
                    key = req.key,
                    "Sending request via callback channel"
                );
                let (tx, rx) = oneshot::channel::<Result<CallbackResponse>>();
                let req = CallbackRequest {
                    request: CallbackRequestType::CacheGet { key: req.key },
                    response_channel: tx,
                };
                send_request_and_wait_for_response(
                    &eval_ctx.policy_id,
                    binding,
                    operation,
                    req,
                    rx,
                    eval_ctx,
                )
            }
            _ => unknown_operation(namespace, operation),
        },
        _ => unknown_namespace(namespace),
    }
}

fn send_request_and_wait_for_response(
    policy_id: &str,
    binding: &str,
    operation: &str,
    req: CallbackRequest,
    rx: Receiver<Result<CallbackResponse>>,
    eval_ctx: &EvaluationContext,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cb_channel: mpsc::Sender<CallbackRequest> = if let Some(c) =
        eval_ctx.callback_channel.clone()
    {
        Ok(c)
    } else {
        error!(
            policy_id,
            binding, operation, "Cannot process Wasm guest request: callback channel not provided"
        );
        Err(anyhow!(
            "Cannot process Wasm guest request: callback channel not provided"
        ))
    }?;

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
                    binding,
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
                binding,
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
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use rstest::rstest;

    use crate::evaluation_context::EvaluationContext;
    use crate::host_capabilities::HostCapabilities;

    use super::host_callback;

    fn deny_all_ctx() -> Arc<EvaluationContext> {
        Arc::new(EvaluationContext {
            policy_id: "test-policy".to_owned(),
            callback_channel: None,
            ctx_aware_resources_allow_list: BTreeSet::new(),
            epoch_deadline: None,
            host_capabilities: HostCapabilities::DenyAll,
        })
    }

    fn allow_all_ctx() -> Arc<EvaluationContext> {
        Arc::new(EvaluationContext {
            policy_id: "test-policy".to_owned(),
            callback_channel: None, // None so allowed calls fail fast at channel send, not capability check
            ctx_aware_resources_allow_list: BTreeSet::new(),
            epoch_deadline: None,
            host_capabilities: HostCapabilities::AllowAll,
        })
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
        let ctx = deny_all_ctx();

        // The capability check fires before payload deserialisation, so an empty
        // payload is valid for all cases here.
        let result = host_callback("kubewarden", namespace, operation, b"", &ctx);

        let err = result.expect_err("expected Err for denied capability");
        assert!(
            err.to_string().contains("has not been granted access"),
            "namespace={namespace}, operation={operation}: unexpected error: {err}"
        );
    }

    #[rstest]
    // oci: v1/verify uses externally-tagged SigstoreVerificationInputV1
    #[case(
        "oci",
        "v1/verify",
        br#"{"SigstorePubKeyVerify":{"image":"ghcr.io/example/image:latest","pub_keys":[],"annotations":null}}"#.as_slice()
    )]
    // oci: v2/verify uses internally-tagged SigstoreVerificationInputV2
    #[case(
        "oci",
        "v2/verify",
        br#"{"type":"SigstorePubKeyVerify","image":"ghcr.io/example/image:latest","pub_keys":[],"annotations":null}"#.as_slice()
    )]
    // oci: remaining operations take a JSON-encoded image reference string
    #[case("oci", "v1/manifest_digest",     br#""ghcr.io/example/image:latest""#.as_slice())]
    #[case("oci", "v1/oci_manifest",        br#""ghcr.io/example/image:latest""#.as_slice())]
    #[case("oci", "v1/oci_manifest_config", br#""ghcr.io/example/image:latest""#.as_slice())]
    // net: payload is a JSON-encoded hostname string
    #[case("net", "v1/dns_lookup_host", br#""example.com""#.as_slice())]
    // crypto: minimal CertificateVerificationRequest
    #[case(
        "crypto",
        "v1/is_certificate_trusted",
        br#"{"cert":{"encoding":"Pem","data":[]},"cert_chain":null,"not_after":null}"#.as_slice()
    )]
    // kubernetes: list/get operations also have a ctx_aware_resources check after the
    // capability gate; with an empty allow-list the function returns a *kubernetes*
    // resource denial rather than a host-capability denial, confirming the capability
    // gate was cleared.
    #[case(
        "kubernetes",
        "list_resources_by_namespace",
        br#"{"api_version":"v1","kind":"Pod","namespace":"default","label_selector":null,"field_selector":null,"field_masks":null}"#.as_slice()
    )]
    #[case(
        "kubernetes",
        "list_resources_all",
        br#"{"api_version":"v1","kind":"Pod","label_selector":null,"field_selector":null,"field_masks":null}"#.as_slice()
    )]
    #[case(
        "kubernetes",
        "get_resource",
        br#"{"api_version":"v1","kind":"Pod","name":"test","namespace":"default","disable_cache":false}"#.as_slice()
    )]
    // kubernetes/can_i: no ctx_aware_resources check; proceeds straight to channel send
    #[case(
        "kubernetes",
        "can_i",
        br#"{"subject_access_review":{"groups":null,"resource_attributes":{"group":null,"name":null,"namespace":null,"resource":"pods","subresource":null,"verb":"get","version":null},"user":"test"},"disable_cache":false}"#.as_slice()
    )]
    fn host_capability_allowed_proceeds_past_capability_check(
        #[case] namespace: &str,
        #[case] operation: &str,
        #[case] payload: &[u8],
    ) {
        let ctx = allow_all_ctx();
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
}
