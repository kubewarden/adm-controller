use std::{collections::BTreeSet, path::Path, sync::Arc};

use anyhow::{Result, anyhow};
use policy_evaluator::{
    admission_request::AdmissionRequest,
    admission_response::AdmissionResponse,
    evaluation_context::EvaluationContext,
    host_capabilities::HostCapabilities,
    kube,
    kubewarden_policy_sdk::settings::SettingsValidationResponse,
    policy_evaluator::{PolicyEvaluator, PolicyExecutionMode, PolicySettings, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_group_evaluator::evaluator::PolicyGroupEvaluator,
    policy_metadata::{ContextAwareResource, Metadata, PolicyType},
};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::{
    backend::BackendDetector,
    callback_handler::{CallbackHandler, ProxyMode},
    command::run::{local_data::LocalData, policy_execution_mode::determine_execution_mode},
    config::{
        HostCapabilitiesMode,
        policy_definition::{
            ContextAwareConfiguration, PolicyDefinition, PolicyExecutionConfiguration,
        },
        pull_and_run::PullAndRunSettings,
    },
};

fn has_raw_policy_type(metadata: Option<&Metadata>) -> bool {
    if let Some(metadata) = metadata {
        metadata.policy_type == PolicyType::Raw
    } else {
        false
    }
}

async fn build_callback_handler(
    kube_client_needed: bool,
    cfg: &PullAndRunSettings,
    shutdown_channel_rx: oneshot::Receiver<()>,
) -> Result<CallbackHandler> {
    let kube_client = if !kube_client_needed {
        None
    } else {
        match &cfg.host_capabilities_mode {
            HostCapabilitiesMode::Proxy(ProxyMode::Replay { source: _ }) => None,
            _ => Some(build_kube_client().await?),
        }
    };
    CallbackHandler::new(cfg, kube_client, shutdown_channel_rx).await
}

/// Whether a compiled ferricel policy may reference the well-known VAP
/// `namespaceObject` variable, i.e. whether evaluating it against a
/// namespace-scoped request requires a Kubernetes client to be available (see
/// `runtimes::ferricel::runtime::Runtime::build_bindings` in
/// `policy-evaluator`).
///
/// Inspects the `ferricel.vap-variables` Wasm custom section (see
/// [`ferricel_core::vap_variables_used`]). Returns `true` conservatively if
/// the section is absent (e.g. a module compiled by an older ferricel
/// version), so that the caller defaults to always provisioning a client.
///
/// Only meaningful for [`PolicyExecutionMode::Ferricel`] policies; callers
/// must check the execution mode themselves.
fn ferricel_policy_may_reference_namespace_object(wasm_path: &Path) -> Result<bool> {
    let wasm_bytes = std::fs::read(wasm_path)
        .map_err(|e| anyhow!("cannot read wasm module at {}: {e}", wasm_path.display()))?;
    match ferricel_core::vap_variables_used(&wasm_bytes) {
        Ok(vap_variables) => Ok(vap_variables.iter().any(|v| v == "namespaceObject")),
        Err(e) => {
            warn!(
                error = e.to_string().as_str(),
                "cannot read VAP variables from compiled ferricel module; assuming namespaceObject may be referenced"
            );
            Ok(true)
        }
    }
}

/// Whether evaluating `execution_mode` against `wasm_path` requires a
/// Kubernetes client to be provisioned for reasons other than the
/// `contextAwareResources` allow list, e.g. ferricel's `namespaceObject`
/// VAP binding (see `fetch_namespace_object` in `policy-evaluator`, which
/// intentionally bypasses the ctx-aware authorization gate).
fn requires_kube_client_beyond_ctx_aware_grants(
    execution_mode: PolicyExecutionMode,
    wasm_path: &Path,
) -> Result<bool> {
    match execution_mode {
        PolicyExecutionMode::Ferricel => ferricel_policy_may_reference_namespace_object(wasm_path),
        _ => Ok(false),
    }
}

pub(crate) enum Evaluator {
    Policy {
        // This enum uses the `Box` type to avoid the need for a large enum size causing memory layout
        // problems. https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant
        policy_evaluator: Box<PolicyEvaluator>,
        settings: PolicySettings,
        request: ValidateRequest,
    },
    GroupPolicy {
        // Contrary to PolicyEvaluator, PolicyGroupEvaluator is shared across closures in
        // rhai_eval_env.clone(), which requires +Send+Sync
        policy_group_evaluator: Arc<PolicyGroupEvaluator>,
        request: ValidateRequest,
    },
}

impl Evaluator {
    pub(crate) async fn new(
        policy: &PolicyDefinition,
        cfg: &PullAndRunSettings,
        local_data: &LocalData,
    ) -> Result<(Self, CallbackHandler, oneshot::Sender<()>)> {
        let (shutdown_channel_tx, shutdown_channel_rx) = oneshot::channel();

        match policy {
            PolicyDefinition::Policy {
                uri,
                user_execution_cfg,
                raw,
                settings,
                ctx_aware_cfg,
                allowed_host_capabilities,
                ..
            } => {
                let metadata = local_data.metadata(uri);

                let execution_mode = match user_execution_cfg {
                    PolicyExecutionConfiguration::UserDefined(mode) => mode.to_owned(),
                    PolicyExecutionConfiguration::PolicyDefined => {
                        let wasm_path = local_data.local_path(uri)?;
                        determine_execution_mode(
                            metadata,
                            None,
                            BackendDetector::default(),
                            wasm_path,
                        )?
                    }
                };

                let context_aware_allowed_resources =
                    build_context_aware_allowed_resources(metadata, ctx_aware_cfg);

                let request =
                    build_validate_request(&cfg.request, *raw || has_raw_policy_type(metadata))?;

                let wasm_path = local_data.local_path(uri)?;
                let kube_client_needed = !context_aware_allowed_resources.is_empty()
                    || requires_kube_client_beyond_ctx_aware_grants(execution_mode, wasm_path)?;

                let callback_handler =
                    build_callback_handler(kube_client_needed, cfg, shutdown_channel_rx).await?;

                let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new()
                    .policy_file(local_data.local_path(uri)?)?
                    .execution_mode(execution_mode);
                if cfg.enable_wasmtime_cache {
                    policy_evaluator_builder = policy_evaluator_builder.enable_wasmtime_cache();
                }
                let eval_ctx = EvaluationContext {
                    policy_id: uri.to_owned(),
                    callback_channel: Some(callback_handler.sender_channel()),
                    ctx_aware_resources_allow_list: context_aware_allowed_resources.clone(),
                    epoch_deadline: None,
                    host_capabilities: HostCapabilities::new(allowed_host_capabilities)
                        .map_err(|e| anyhow::anyhow!("Invalid host capabilities pattern: {e}"))?,
                };
                let policy_evaluator =
                    policy_evaluator_builder.build_pre()?.rehydrate(&eval_ctx)?;

                Ok((
                    Self::Policy {
                        policy_evaluator: policy_evaluator.into(),
                        request,
                        settings: settings.clone(),
                    },
                    callback_handler,
                    shutdown_channel_tx,
                ))
            }
            PolicyDefinition::PolicyGroup {
                id,
                policy_members,
                expression,
                message,
                ..
            } => {
                let is_context_aware = policy_members
                    .iter()
                    .any(|(_, pm)| !pm.settings.ctx_aware_resources_allow_list.is_empty());

                // Pre-scan every member's execution mode (and, for ferricel
                // members, whether they may reference `namespaceObject`)
                // *before* building the callback handler, since that
                // decides whether a Kubernetes client needs to be
                // provisioned. Collected eagerly (rather than iterating
                // `policy_members` a second time later) to avoid relying on
                // `HashMap` iteration order being stable across two
                // separate `.iter()` calls.
                let mut kube_client_needed = is_context_aware;
                let mut members_with_execution_mode = Vec::with_capacity(policy_members.len());
                for (member_id, member) in policy_members {
                    let metadata = local_data.metadata(&member.uri);
                    let wasm_path = local_data.local_path(&member.uri)?;
                    let execution_mode = determine_execution_mode(
                        metadata,
                        None,
                        BackendDetector::default(),
                        wasm_path,
                    )?;
                    kube_client_needed = kube_client_needed
                        || requires_kube_client_beyond_ctx_aware_grants(execution_mode, wasm_path)?;
                    members_with_execution_mode.push((member_id, member, execution_mode));
                }

                let callback_handler =
                    build_callback_handler(kube_client_needed, cfg, shutdown_channel_rx).await?;

                // group policies cannot be raw right now
                let request = build_validate_request(&cfg.request, false)?;

                let mut policy_group_evaluator = PolicyGroupEvaluator::new(
                    id,
                    message,
                    expression,
                    Some(callback_handler.sender_channel()),
                );

                for (member_id, member, execution_mode) in members_with_execution_mode {
                    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new()
                        .policy_file(local_data.local_path(&member.uri)?)?
                        .execution_mode(execution_mode);

                    if cfg.enable_wasmtime_cache {
                        policy_evaluator_builder = policy_evaluator_builder.enable_wasmtime_cache();
                    }

                    let policy_evaluator_pre = Arc::new(policy_evaluator_builder.build_pre()?);

                    policy_group_evaluator.add_policy_member(
                        member_id,
                        policy_evaluator_pre,
                        member.settings.clone(),
                    );
                }

                Ok((
                    Self::GroupPolicy {
                        policy_group_evaluator: policy_group_evaluator.into(),
                        request,
                    },
                    callback_handler,
                    shutdown_channel_tx,
                ))
            }
        }
    }

    /// Evaluates the policy against the request and settings.
    /// Note well: this does **not** validate the settings, it assumes that the settings
    /// are already validated.
    pub(crate) fn evaluate(&mut self) -> AdmissionResponse {
        match self {
            Self::Policy {
                policy_evaluator,
                settings,
                request,
            } => policy_evaluator.validate(request.clone(), settings),
            Self::GroupPolicy {
                policy_group_evaluator,
                request,
            } => policy_group_evaluator.clone().validate(request),
        }
    }

    /// Validates the settings given by the user.
    pub(crate) fn validate_settings(&mut self) -> SettingsValidationResponse {
        match self {
            Self::Policy {
                policy_evaluator,
                settings,
                ..
            } => {
                // validate the settings given by the user
                policy_evaluator.validate_settings(settings)
            }
            Self::GroupPolicy {
                policy_group_evaluator,
                ..
            } => policy_group_evaluator.validate_settings(),
        }
    }
}

fn build_validate_request(
    request: &serde_json::Value,
    raw_request: bool,
) -> Result<ValidateRequest> {
    if raw_request {
        return Ok(ValidateRequest::Raw(request.to_owned()));
    }

    let object = request.as_object();
    if object.is_none() {
        return Err(anyhow!("Invalid request object"));
    }
    let object = object.unwrap();

    let req_obj =
        if object.get("kind").and_then(serde_json::Value::as_str) == Some("AdmissionReview") {
            object
                .get("request")
                .cloned()
                .ok_or_else(|| anyhow!("invalid AdmissionReview object"))
        } else {
            Ok(request.to_owned())
        }?;

    let adm_req: AdmissionRequest = serde_json::from_value(req_obj)
        .map_err(|e| anyhow!("cannot build AdmissionRequest object from given input: {e}"))?;
    Ok(ValidateRequest::AdmissionRequest(Box::new(adm_req)))
}

fn build_context_aware_allowed_resources(
    metadata: Option<&Metadata>,
    ctx_aware_cfg: &ContextAwareConfiguration,
) -> BTreeSet<ContextAwareResource> {
    match ctx_aware_cfg {
        ContextAwareConfiguration::NoAccess => {
            if let Some(metadata) = metadata
                && !metadata.context_aware_resources.is_empty()
            {
                warn!(
                    "Policy requires access to Kubernetes resources at evaluation time. During this execution the access to Kubernetes resources is denied. This can cause the policy to not behave properly"
                );
                warn!(
                    "Carefully review which types of Kubernetes resources the policy needs via the `inspect` command, then run the policy using the `--allow-context-aware` flag."
                );
            }
            BTreeSet::new()
        }
        ContextAwareConfiguration::AllowList(allowed) => allowed.to_owned(),
        ContextAwareConfiguration::TrustPolicyMetadata => match metadata {
            Some(metadata) => metadata.context_aware_resources.to_owned(),
            None => {
                info!("Policy is not annotated, access to Kubernetes resources is not allowed");
                BTreeSet::new()
            }
        },
    }
}

/// kwctl is built using rustls enabled. Unfortunately rustls does not support validating IP addresses
/// yet (see https://github.com/kube-rs/kube/issues/1003).
///
/// This function provides a workaround to this limitation.
async fn build_kube_client() -> Result<kube::Client> {
    // This is the usual way of obtaining a kubeconfig
    let mut kube_config = kube::Config::infer().await.map_err(anyhow::Error::new)?;

    // Does the cluster_url have an host? This is probably true 99.999% of the times
    if let Some(host) = kube_config.cluster_url.host() {
        // is the host an IP or a hostname?
        let is_an_ip = host.parse::<std::net::Ipv4Addr>().is_ok()
            || host.parse::<std::net::Ipv6Addr>().is_ok();

        // if the host is an IP and no `tls_server_name` is set, then
        // set `tls_server_name` to `kubernetes.default.svc`. This is a FQDN
        // that is always associated to the certificate used by the API server.
        // This will make kwctl work against minikube and k3d, to name a few...
        if is_an_ip && kube_config.tls_server_name.is_none() {
            warn!(
                host,
                "The loaded kubeconfig connects to a server using an IP address instead of a FQDN. This is usually done by minikube, k3d and other local development solutions"
            );
            warn!(
                "Due to a limitation of rustls, certificate validation cannot be performed against IP addresses, the certificate validation will be made against `kubernetes.default.svc`"
            );
            kube_config.tls_server_name = Some("kubernetes.default.svc".to_string());
        }
    }

    kube::Client::try_from(kube_config).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn access_to_pod_and_service() -> BTreeSet<ContextAwareResource> {
        BTreeSet::from([
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
        ])
    }

    fn meta_access_to_pod_and_service() -> Option<Metadata> {
        let metadata = Metadata {
            context_aware_resources: access_to_pod_and_service(),
            ..Default::default()
        };
        Some(metadata)
    }

    fn access_to_deployments() -> BTreeSet<ContextAwareResource> {
        BTreeSet::from([ContextAwareResource {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
        }])
    }

    fn ctx_cfg_access_to_deployments() -> ContextAwareConfiguration {
        ContextAwareConfiguration::AllowList(access_to_deployments())
    }

    #[rstest]
    #[case::ctx_cfg_no_access_overrides_meta(
        meta_access_to_pod_and_service(),
        ContextAwareConfiguration::NoAccess,
        BTreeSet::new()
    )]
    #[case::ctx_cfg_no_access_and_no_meta(
        None,
        ContextAwareConfiguration::NoAccess,
        BTreeSet::new()
    )]
    #[case::ctx_cfg_allow_list_overrides_meta(
        meta_access_to_pod_and_service(),
        ctx_cfg_access_to_deployments(),
        access_to_deployments()
    )]
    #[case::ctx_cfg_allow_list_overrides_no_meta(
        None,
        ctx_cfg_access_to_deployments(),
        access_to_deployments()
    )]
    #[case::ctx_cfg_trust_meta_with_meta(
        meta_access_to_pod_and_service(),
        ContextAwareConfiguration::TrustPolicyMetadata,
        access_to_pod_and_service()
    )]
    #[case::ctx_cfg_trust_meta_with_no_meta(
        None,
        ContextAwareConfiguration::TrustPolicyMetadata,
        BTreeSet::new()
    )]
    fn determine_context_aware_allowed_resources(
        #[case] metadata: Option<Metadata>,
        #[case] ctx_cfg: ContextAwareConfiguration,
        #[case] expected_allowed: BTreeSet<ContextAwareResource>,
    ) {
        let actual = build_context_aware_allowed_resources(metadata.as_ref(), &ctx_cfg);
        assert_eq!(actual, expected_allowed);
    }
}
