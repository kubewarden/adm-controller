use std::{
    collections::{BTreeSet, HashMap},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
    sync::Once,
};

use axum::Router;
use policy_evaluator::{
    admission_response_handler::policy_mode::PolicyMode, policy_evaluator::PolicySettings,
    policy_metadata::ContextAwareResource,
};
use policy_server::{
    PolicyServer,
    config::{Config, PolicyGroupMember, PolicyOrPolicyGroup},
};
use serde_json::json;
use tempfile::tempdir;

static START: Once = Once::new();

/// Common setup for tests. This function should be called at the beginning of each test.
pub(crate) fn setup() {
    START.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub(crate) fn default_test_config() -> Config {
    let policies = HashMap::from([
        (
            "pod-privileged".to_owned(),
            PolicyOrPolicyGroup::Policy {
                module: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: None,
                settings: None,
                context_aware_resources: BTreeSet::new(),
                message: None,
                timeout_eval_seconds: None,
                host_capabilities: vec![],
            },
        ),
        (
            "raw-mutation".to_owned(),
            PolicyOrPolicyGroup::Policy {
                module: "ghcr.io/kubewarden/tests/raw-mutation-policy:v0.1.0".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: Some(true),
                settings: Some(
                    PolicySettings::try_from(&json!({
                        "forbiddenResources": ["banana", "carrot"],
                        "defaultResource": "hay"
                    }))
                    .unwrap(),
                ),
                context_aware_resources: BTreeSet::new(),
                message: None,
                timeout_eval_seconds: None,
                host_capabilities: vec![],
            },
        ),
        (
            "sleep".to_owned(),
            PolicyOrPolicyGroup::Policy {
                module: "ghcr.io/kubewarden/tests/sleeping-policy:v0.1.0".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: None,
                timeout_eval_seconds: None,
                host_capabilities: vec![],
                settings: Some(
                    PolicySettings::try_from(&json!({
                        "sleepMilliseconds": 2
                    }))
                    .unwrap(),
                ),
                context_aware_resources: BTreeSet::new(),
                message: None,
            },
        ),
        (
            "group-policy-just-pod-privileged".to_owned(),
            PolicyOrPolicyGroup::PolicyGroup {
                expression: "pod_privileged() && true".to_string(),
                message: "The group policy rejected your request".to_string(),
                policy_mode: PolicyMode::Protect,
                policies: HashMap::from([(
                    "pod_privileged".to_string(),
                    PolicyGroupMember {
                        module: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
                        settings: None,
                        context_aware_resources: BTreeSet::new(),
                        timeout_eval_seconds: None,
                        host_capabilities: vec![],
                    },
                )]),
            },
        ),
        (
            "group-policy-just-raw-mutation".to_owned(),
            PolicyOrPolicyGroup::PolicyGroup {
                expression: "raw_mutation() && true".to_string(),
                message: "The group policy rejected your request".to_string(),
                policy_mode: PolicyMode::Protect,
                policies: HashMap::from([(
                    "raw_mutation".to_string(),
                    PolicyGroupMember {
                        module: "ghcr.io/kubewarden/tests/raw-mutation-policy:v0.1.0".to_owned(),
                        settings: Some(
                            PolicySettings::try_from(&json!({
                                "forbiddenResources": ["banana", "carrot"],
                                "defaultResource": "hay"
                            }))
                            .unwrap(),
                        ),
                        context_aware_resources: BTreeSet::new(),
                        timeout_eval_seconds: None,
                        host_capabilities: vec![],
                    },
                )]),
            },
        ),
        (
            "sleep-1s-timeout".to_owned(),
            PolicyOrPolicyGroup::Policy {
                module: "ghcr.io/kubewarden/tests/sleeping-policy:v0.1.0".to_owned(),
                policy_mode: PolicyMode::Protect,
                allowed_to_mutate: None,
                timeout_eval_seconds: Some(1),
                host_capabilities: vec![],
                settings: Some(
                    PolicySettings::try_from(&json!({
                        "sleepMilliseconds": 2
                    }))
                    .unwrap(),
                ),
                context_aware_resources: BTreeSet::new(),
                message: None,
            },
        ),
    ]);

    let mut config = default_config();
    config.policies.extend(policies);
    config
}

pub(crate) fn pod_privileged_test_config() -> Config {
    let policies = HashMap::from([(
        "pod-privileged".to_owned(),
        PolicyOrPolicyGroup::Policy {
            module: "ghcr.io/kubewarden/tests/pod-privileged:v0.2.1".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources: BTreeSet::new(),
            message: None,
            timeout_eval_seconds: None,
            host_capabilities: vec![],
        },
    )]);

    let mut config = default_config();
    config.policies.extend(policies);
    config
}

/// Returns a Config with the context-aware test policy registered under
/// the given `policy_id`, using the provided `host_capabilities` and
/// `context_aware_resources`.
pub(crate) fn context_aware_policy_test_config(
    policy_id: &str,
    host_capabilities: Vec<String>,
    context_aware_resources: BTreeSet<ContextAwareResource>,
) -> Config {
    let policies = HashMap::from([(
        policy_id.to_owned(),
        PolicyOrPolicyGroup::Policy {
            module: "ghcr.io/kubewarden/tests/context-aware-test-policy:latest".to_owned(),
            policy_mode: PolicyMode::Protect,
            allowed_to_mutate: None,
            settings: None,
            context_aware_resources,
            message: None,
            timeout_eval_seconds: None,
            host_capabilities,
        },
    )]);

    let mut config = default_config();
    config.policies.extend(policies);
    config
}

/// Returns a Config with the context-aware test policy registered as a group policy
/// under the given `policy_id`. The single group member uses the provided
/// `host_capabilities` and `context_aware_resources`.
pub(crate) fn context_aware_policy_group_test_config(
    policy_id: &str,
    host_capabilities: Vec<String>,
    context_aware_resources: BTreeSet<ContextAwareResource>,
) -> Config {
    let policies = HashMap::from([(
        policy_id.to_owned(),
        PolicyOrPolicyGroup::PolicyGroup {
            expression: "ctx_aware_policy() && true".to_string(),
            message: "group policy rejected".to_string(),
            policy_mode: PolicyMode::Protect,
            policies: HashMap::from([(
                "ctx_aware_policy".to_string(),
                PolicyGroupMember {
                    module: "ghcr.io/kubewarden/tests/context-aware-test-policy:latest".to_owned(),
                    settings: None,
                    context_aware_resources,
                    timeout_eval_seconds: None,
                    host_capabilities,
                },
            )]),
        },
    )]);

    let mut config = default_config();
    config.policies.extend(policies);
    config
}

fn default_config() -> Config {
    Config {
        addr: get_available_address_with_port(),
        readiness_probe_addr: get_available_address_with_port(),
        sources: None,
        policies: HashMap::new(),
        policies_download_dir: tempdir().unwrap().keep(),
        ignore_kubernetes_connection_failure: true,
        always_accept_admission_reviews_on_namespace: None,
        policy_evaluation_limit_seconds: Some(2),
        policy_memory_limit_bytes: Some(256 * 1024 * 1024),
        tls_config: None,
        pool_size: 2,
        metrics_enabled: false,
        sigstore_cache_dir: tempdir().unwrap().keep(),
        sigstore_trust_config_path: None,
        verification_config: None,
        log_level: "info".to_owned(),
        log_fmt: "json".to_owned(),
        log_no_color: false,
        daemon: false,
        daemon_pid_file: "policy_server.pid".to_owned(),
        daemon_stdout_file: None,
        daemon_stderr_file: None,
        enable_pprof: false,
        continue_on_errors: false,
        enable_http_policies: false,
    }
}

/// Returns a random address with an available port to use with policy server. Therefore, we can
/// have multiple policy server running at the same time in async tests
fn get_available_address_with_port() -> SocketAddr {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("failed to bind to available port")
        .local_addr()
        .expect("failed to get local address")
}

pub(crate) async fn app(config: Config) -> Router {
    let server = PolicyServer::new_from_config(config).await.unwrap();

    server.router()
}
