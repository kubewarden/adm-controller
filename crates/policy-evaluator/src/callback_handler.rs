use std::sync::Arc;

use anyhow::anyhow;
use kubewarden_policy_sdk::host_capabilities::net::LookupResponse;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::callback_handler::kubernetes::field_mask;
use crate::callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse};

mod builder;
mod crypto;
mod kubernetes;
mod oci;
mod sigstore_verification;

pub use builder::CallbackHandlerBuilder;

use sigstore_verification::{
    get_sigstore_certificate_verification_cached, get_sigstore_github_actions_verification_cached,
    get_sigstore_keyless_prefix_verification_cached, get_sigstore_keyless_verification_cached,
    get_sigstore_pub_key_verification_cached,
};

/// Struct that computes request coming from a Wasm guest.
/// This should be used only to handle the requests that need some async
/// code in order to be fulfilled.
pub struct CallbackHandler {
    oci_client: Arc<oci::Client>,
    sigstore_client: sigstore_verification::Client,
    kubernetes_client: Option<kubernetes::Client>,
    rx: mpsc::Receiver<CallbackRequest>,
    tx: mpsc::Sender<CallbackRequest>,
    shutdown_channel: oneshot::Receiver<()>,
}

macro_rules! handle_callback {
    ($req:expr, $log_value: expr, $log_msg: expr, $code:block) => {{
        let response = { $code }
            .await
            .map(|response| {
                debug!(
                    value = ?$log_value,
                    cached = response.was_cached,
                    $log_msg,
                );
                let payload = serde_json::to_vec(&response.value)
                    .map_err(|e| anyhow!("error serializing payload: {e:?}"))?;
                Ok(CallbackResponse { payload })
            })
            .and_then(|r| r);

        if let Err(e) = $req.response_channel.send(response) {
            warn!("callback handler: cannot send response back: {:?}", e);
        }
    }};
}

impl CallbackHandler {
    /// Returns the sender side of the channel that can be used by the sync code
    /// (like the `host_callback` function of PolicyEvaluator)
    /// to request the computation of async code.
    ///
    /// Can be invoked as many times as wanted.
    pub fn sender_channel(&self) -> mpsc::Sender<CallbackRequest> {
        self.tx.clone()
    }

    /// Enter an endless loop that:
    ///    1. Waits for requests to be evaluated
    ///    2. Evaluate the request
    ///    3. Send back the result of the evaluation
    ///
    /// The loop is interrupted only when a message is sent over the
    /// `shutdown_channel`.
    pub async fn loop_eval(&mut self) {
        loop {
            tokio::select! {
                // place the shutdown check before the message evaluation,
                // as recommended by tokio's documentation about select!
                _ = &mut self.shutdown_channel => {
                    return;
                },
                req = self.rx.recv() => {
                    if let Some(req) = req {
                        self.handle_request(req).await;
                   }
                }
            }
        }
    }

    async fn handle_request(&mut self, req: CallbackRequest) {
        let oci_client = self.oci_client.clone();
        let mut sigstore_client = self.sigstore_client.clone();
        let mut kubernetes_client = self.kubernetes_client.clone();

        tokio::spawn(async move {
            match req.request {
                CallbackRequestType::OciManifestDigest { image } => {
                    handle_callback!(req, image, "Image digest computed", {
                        oci::get_oci_digest_cached(&oci_client, &image)
                    });
                }
                CallbackRequestType::OciManifest { image } => {
                    handle_callback!(req, image, "Image manifest computed", {
                        oci::get_oci_manifest_cached(&oci_client, &image)
                    });
                }
                CallbackRequestType::OciManifestAndConfig { image } => {
                    handle_callback!(req, image, "Image manifest computed", {
                        oci::get_oci_manifest_and_config_cached(&oci_client, &image)
                    });
                }
                CallbackRequestType::SigstorePubKeyVerify {
                    image,
                    pub_keys,
                    annotations,
                } => {
                    handle_callback!(req, image, "Sigstore pub key verification done", {
                        get_sigstore_pub_key_verification_cached(
                            &mut sigstore_client,
                            image.clone(),
                            pub_keys,
                            annotations,
                        )
                    });
                }
                CallbackRequestType::SigstoreKeylessVerify {
                    image,
                    keyless,
                    annotations,
                } => {
                    handle_callback!(req, image, "Sigstore keyless verification done", {
                        get_sigstore_keyless_verification_cached(
                            &mut sigstore_client,
                            image.clone(),
                            keyless,
                            annotations,
                        )
                    });
                }
                CallbackRequestType::SigstoreKeylessPrefixVerify {
                    image,
                    keyless_prefix,
                    annotations,
                } => {
                    handle_callback!(req, image, "Sigstore keyless prefix verification done", {
                        get_sigstore_keyless_prefix_verification_cached(
                            &mut sigstore_client,
                            image.clone(),
                            keyless_prefix,
                            annotations,
                        )
                    });
                }
                CallbackRequestType::SigstoreGithubActionsVerify {
                    image,
                    owner,
                    repo,
                    annotations,
                } => {
                    handle_callback!(req, image, "Sigstore GitHub Action verification done", {
                        get_sigstore_github_actions_verification_cached(
                            &mut sigstore_client,
                            image.clone(),
                            owner,
                            repo,
                            annotations,
                        )
                    });
                }
                CallbackRequestType::SigstoreCertificateVerify {
                    image,
                    certificate,
                    certificate_chain,
                    require_rekor_bundle,
                    annotations,
                } => {
                    handle_callback!(req, image, "Sigstore GitHub Action verification done", {
                        get_sigstore_certificate_verification_cached(
                            &mut sigstore_client,
                            &image,
                            &certificate,
                            certificate_chain.as_deref(),
                            require_rekor_bundle,
                            annotations,
                        )
                    })
                }
                CallbackRequestType::DNSLookupHost { host } => {
                    let response = dns_lookup::lookup_host(&host)
                        .map(|ip_addresses| {
                            let res = LookupResponse {
                                ips: ip_addresses.map(|ip| ip.to_string()).collect(),
                            };
                            CallbackResponse {
                                payload: serde_json::to_vec(&res).unwrap(),
                            }
                        })
                        .map_err(anyhow::Error::new);

                    if let Err(e) = req.response_channel.send(response) {
                        warn!("callback handler: cannot send response back: {:?}", e);
                    }
                }
                CallbackRequestType::KubernetesListResourceNamespace {
                    api_version,
                    kind,
                    namespace,
                    label_selector,
                    field_selector,
                    disable_cache,
                    field_masks,
                } => {
                    if disable_cache {
                        handle_callback!(
                            req,
                            format!("[{namespace}] {api_version}/{kind}"),
                            "List namespaced Kubernetes resource - no cache",
                            {
                                kubernetes::list_resources_by_namespace_direct(
                                    kubernetes_client.as_mut(),
                                    &api_version,
                                    &kind,
                                    &namespace,
                                    label_selector,
                                    field_selector,
                                    field_masks,
                                )
                            }
                        )
                    } else {
                        handle_callback!(
                            req,
                            format!("[{namespace}] {api_version}/{kind}"),
                            "List namespaced Kubernetes resource",
                            {
                                kubernetes::list_resources_by_namespace(
                                    kubernetes_client.as_mut(),
                                    &api_version,
                                    &kind,
                                    &namespace,
                                    label_selector,
                                    field_selector,
                                    field_masks,
                                )
                            }
                        )
                    }
                }
                CallbackRequestType::KubernetesListResourceAll {
                    api_version,
                    kind,
                    label_selector,
                    field_selector,
                    disable_cache,
                    field_masks,
                } => {
                    if disable_cache {
                        handle_callback!(
                            req,
                            format!("{api_version}/{kind}"),
                            "List Kubernetes resource - no cache",
                            {
                                kubernetes::list_resources_all_direct(
                                    kubernetes_client.as_mut(),
                                    &api_version,
                                    &kind,
                                    label_selector,
                                    field_selector,
                                    field_masks,
                                )
                            }
                        )
                    } else {
                        handle_callback!(
                            req,
                            format!("{api_version}/{kind}"),
                            "List Kubernetes resource",
                            {
                                kubernetes::list_resources_all(
                                    kubernetes_client.as_mut(),
                                    &api_version,
                                    &kind,
                                    label_selector,
                                    field_selector,
                                    field_masks,
                                )
                            }
                        )
                    }
                }
                CallbackRequestType::KubernetesGetResource {
                    api_version,
                    kind,
                    name,
                    namespace,
                    disable_cache,
                    field_masks,
                } => {
                    if disable_cache {
                        handle_callback!(
                            req,
                            format!("{api_version}/{kind}"),
                            "Get Kubernetes resource - no cache",
                            {
                                let res = kubernetes::get_resource(
                                    kubernetes_client.as_mut(),
                                    &api_version,
                                    &kind,
                                    &name,
                                    namespace.as_deref(),
                                )
                                .await
                                .map(|mut obj| {
                                    if let Some(field_masks) = field_masks {
                                        let field_masker =
                                            field_mask::FieldMaskNode::new(field_masks.into_iter());
                                        field_mask::prune_in_place(&mut obj.data, &field_masker);
                                    }
                                    obj
                                });
                                async { res }
                            }
                        )
                    } else {
                        handle_callback!(
                            req,
                            format!("{api_version}/{kind}"),
                            "Get Kubernetes resource",
                            {
                                let res = kubernetes::get_resource_cached(
                                    kubernetes_client.as_mut(),
                                    &api_version,
                                    &kind,
                                    &name,
                                    namespace.as_deref(),
                                )
                                .await
                                .map(|mut obj| {
                                    if let Some(field_masks) = field_masks {
                                        let field_masker =
                                            field_mask::FieldMaskNode::new(field_masks.into_iter());
                                        field_mask::prune_in_place(&mut obj.data, &field_masker);
                                    }
                                    obj
                                });

                                async { res }
                            }
                        )
                    }
                }
                CallbackRequestType::KubernetesGetResourcePluralName { api_version, kind } => {
                    handle_callback!(
                        req,
                        format!("{api_version}/{kind}"),
                        "Get Kubernetes resource plural name",
                        {
                            kubernetes::get_resource_plural_name(
                                kubernetes_client.as_mut(),
                                &api_version,
                                &kind,
                            )
                        }
                    )
                }
                CallbackRequestType::HasKubernetesListResourceAllResultChangedSinceInstant {
                    api_version,
                    kind,
                    label_selector,
                    field_selector,
                    field_masks,
                    since,
                } => {
                    handle_callback!(
                        req,
                        format!("{api_version}/{kind}"),
                        "Has the result of 'Kubernetes list all resources' changed since a given instant",
                        {
                            kubernetes::has_list_resources_all_result_changed_since_instant(
                                kubernetes_client.as_mut(),
                                &api_version,
                                &kind,
                                label_selector,
                                field_selector,
                                field_masks,
                                since,
                            )
                        }
                    )
                }
                CallbackRequestType::KubernetesCanI {
                    request,
                    disable_cache,
                } => {
                    if disable_cache {
                        handle_callback!(
                            req,
                            "can_i".to_owned(),
                            "Check if user or service account has permission to perform operation",
                            { kubernetes::can_i(kubernetes_client.as_mut(), request) }
                        )
                    } else {
                        handle_callback!(
                            req,
                            "can_i".to_owned(),
                            "Check if user or service account has permission to perform operation",
                            { kubernetes::can_i_cached(kubernetes_client.as_mut(), request) }
                        )
                    }
                }
                CallbackRequestType::CryptoIsCertificateTrusted { request } => {
                    let cert_description = request.cert.to_string();
                    handle_callback!(req, cert_description, "Certificate verification done", {
                        async { crypto::verify_certificate(request) }
                    })
                }
            }
        });
    }
}
