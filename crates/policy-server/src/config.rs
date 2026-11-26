use std::{
    collections::{BTreeSet, HashMap},
    env,
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use lazy_static::lazy_static;
use opentelemetry_otlp::tonic_types::transport::{Certificate, ClientTlsConfig, Identity};
use policy_evaluator::{
    admission_response_handler::policy_mode::PolicyMode,
    policy_evaluator::PolicySettings,
    policy_fetcher::{
        proxy::ProxyConfig,
        sources::{Sources, read_sources_file},
        verify::config::{LatestVerificationConfig, VerificationConfigV1, read_verification_file},
    },
    policy_metadata::ContextAwareResource,
};
use serde::Deserialize;

pub static SERVICE_NAME: &str = "kubewarden-policy-server";
const DOCKER_CONFIG_ENV_VAR: &str = "DOCKER_CONFIG";
const BYTES_PER_MIB: usize = 1024 * 1024;

lazy_static! {
    pub(crate) static ref HOSTNAME: String =
        std::env::var("HOSTNAME").unwrap_or_else(|_| String::from("unknown"));
}

pub struct Config {
    pub addr: SocketAddr,
    pub readiness_probe_addr: SocketAddr,
    pub sources: Option<Sources>,
    pub policies: HashMap<String, PolicyOrPolicyGroup>,
    pub policies_download_dir: PathBuf,
    pub ignore_kubernetes_connection_failure: bool,
    pub always_accept_admission_reviews_on_namespace: Option<String>,
    // This is the global timeout for each policy evaluation.
    pub policy_evaluation_limit_seconds: Option<u64>,
    // This is the global limit, expressed in bytes, applied to the linear memory of
    // each policy.
    pub policy_memory_limit_bytes: Option<usize>,
    pub tls_config: Option<TlsConfig>,
    pub pool_size: usize,
    pub metrics_enabled: bool,
    pub sigstore_cache_dir: PathBuf,
    pub sigstore_trust_config_path: Option<PathBuf>,
    pub verification_config: Option<VerificationConfigV1>,
    pub log_level: String,
    pub log_fmt: String,
    pub log_no_color: bool,
    pub daemon: bool,
    pub enable_pprof: bool,
    pub daemon_pid_file: String,
    pub daemon_stdout_file: Option<String>,
    pub daemon_stderr_file: Option<String>,
    pub continue_on_errors: bool,
    pub enable_http_policies: bool,
}

pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: Vec<PathBuf>,
}

impl Config {
    pub fn from_args(matches: &ArgMatches) -> Result<Self> {
        // init some variables based on the cli parameters
        let addr = api_bind_address(matches)?;
        let readiness_probe_addr = readiness_probe_bind_address(matches)?;

        let policies = policies(matches)?;
        let policies_download_dir = matches
            .get_one::<String>("policies-download-dir")
            .map(PathBuf::from)
            .expect("This should not happen, there's a default value for policies-download-dir");
        let policy_evaluation_limit_seconds = if *matches
            .get_one::<bool>("disable-timeout-protection")
            .expect("clap should have set a default value")
        {
            None
        } else {
            Some(
                matches
                    .get_one::<String>("policy-timeout")
                    .expect("policy-timeout should always be set")
                    .parse::<u64>()?,
            )
        };
        let policy_memory_limit_bytes = if *matches
            .get_one::<bool>("disable-memory-limit")
            .expect("clap should have set a default value")
        {
            None
        } else {
            let policy_memory_limit_mib = matches
                .get_one::<String>("policy-memory-limit")
                .expect("policy-memory-limit should always be set")
                .parse::<usize>()?;
            if policy_memory_limit_mib == 0 {
                return Err(anyhow!(
                    "policy-memory-limit must be greater than 0, or the limit must be disabled \
                     via --disable-memory-limit"
                ));
            }
            Some(policy_memory_limit_mib * BYTES_PER_MIB)
        };
        let sources = remote_server_options(matches)?;
        let pool_size = matches
            .get_one::<String>("workers")
            .map_or_else(num_cpus::get, |v| {
                v.parse::<usize>()
                    .expect("error parsing the number of workers")
            });
        let always_accept_admission_reviews_on_namespace = matches
            .get_one::<String>("always-accept-admission-reviews-on-namespace")
            .map(|s| s.to_owned());

        let metrics_enabled = matches
            .get_one::<bool>("enable-metrics")
            .expect("clap should have set a default value")
            .to_owned();
        let ignore_kubernetes_connection_failure = matches
            .get_one::<bool>("ignore-kubernetes-connection-failure")
            .expect("clap should have set a default value")
            .to_owned();
        let verification_config = verification_config(matches)?;
        let sigstore_cache_dir = matches
            .get_one::<String>("sigstore-cache-dir")
            .map(PathBuf::from)
            .expect("This should not happen, there's a default value for sigstore-cache-dir");
        let sigstore_trust_config_path =
            matches.get_one::<PathBuf>("sigstore-trust-config").cloned();

        let daemon = matches
            .get_one::<bool>("daemon")
            .expect("clap should have set a default value")
            .to_owned();
        let daemon_pid_file = matches
            .get_one::<String>("daemon-pid-file")
            .expect("This should not happen, there's a default value for daemon-pid-file")
            .to_owned();
        let daemon_stdout_file = matches.get_one::<String>("daemon-stdout-file").cloned();
        let daemon_stderr_file = matches.get_one::<String>("daemon-stderr-file").cloned();

        let log_level = matches
            .get_one::<String>("log-level")
            .expect("This should not happen, there's a default value for log-level")
            .to_owned();
        let log_fmt = matches
            .get_one::<String>("log-fmt")
            .expect("This should not happen, there's a default value for log-fmt")
            .to_owned();
        let log_no_color = matches
            .get_one::<bool>("log-no-color")
            .expect("clap should have assigned a default value")
            .to_owned();

        let tls_config = build_tls_config(matches)?;

        let enable_pprof = matches
            .get_one::<bool>("enable-pprof")
            .expect("clap should have assigned a default value")
            .to_owned();

        let continue_on_errors = matches
            .get_one::<bool>("continue-on-errors")
            .expect("clap should have assigned a default value")
            .to_owned();

        let enable_http_policies = matches
            .get_one::<bool>("enable-http-policies")
            .expect("clap should have assigned a default value")
            .to_owned();

        Ok(Self {
            addr,
            readiness_probe_addr,
            sources,
            policies,
            policies_download_dir,
            ignore_kubernetes_connection_failure,
            tls_config,
            always_accept_admission_reviews_on_namespace,
            policy_evaluation_limit_seconds,
            policy_memory_limit_bytes,
            pool_size,
            metrics_enabled,
            sigstore_cache_dir,
            sigstore_trust_config_path,
            verification_config,
            log_level,
            log_fmt,
            log_no_color,
            daemon,
            daemon_pid_file,
            daemon_stdout_file,
            daemon_stderr_file,
            enable_pprof,
            continue_on_errors,
            enable_http_policies,
        })
    }
}

fn api_bind_address(matches: &clap::ArgMatches) -> Result<SocketAddr> {
    format!(
        "{}:{}",
        matches.get_one::<String>("address").unwrap(),
        matches.get_one::<String>("port").unwrap()
    )
    .parse()
    .map_err(|e| anyhow!("error parsing arguments: {}", e))
}

fn readiness_probe_bind_address(matches: &clap::ArgMatches) -> Result<SocketAddr> {
    format!(
        "{}:{}",
        matches.get_one::<String>("address").unwrap(),
        matches.get_one::<String>("readiness-probe-port").unwrap()
    )
    .parse()
    .map_err(|e| anyhow!("error parsing arguments: {}", e))
}

fn build_tls_config(matches: &clap::ArgMatches) -> Result<Option<TlsConfig>> {
    let cert_file = matches.get_one::<PathBuf>("cert-file").cloned();
    let key_file = matches.get_one::<PathBuf>("key-file").cloned();
    let client_ca_file = matches.get_many::<PathBuf>("client-ca-file");

    match (cert_file, key_file, &client_ca_file) {
        (Some(cert_file), Some(key_file), _) => Ok(Some(TlsConfig {
            cert_file,
            key_file,
            client_ca_file: client_ca_file
                .unwrap_or_default()
                .map(|p| p.to_owned())
                .collect::<Vec<PathBuf>>(),
        })),
        // No TLS configuration provided
        (None, None, None) => Ok(None),
        // Client CA certificate provided without server certificate and key
        (None, None, Some(_)) => Err(anyhow!(
            "client CA certificate requires server certificate and key to be specified"
        )),
        // Server certificate or key provided without the other
        (Some(_), None, _) | (None, Some(_), _) => Err(anyhow!(
            "both certificate and key must be provided together"
        )),
    }
}

fn policies(matches: &clap::ArgMatches) -> Result<HashMap<String, PolicyOrPolicyGroup>> {
    let policies_file = Path::new(matches.get_one::<String>("policies").unwrap());
    let policies = read_policies_file(policies_file).map_err(|e| {
        anyhow!(
            "error while loading policies from {:?}: {}",
            policies_file,
            e
        )
    })?;

    validate_policies(&policies)?;

    Ok(policies)
}

// Validate the policies and policy groups:
//  - ensure policy names do not contain a '/' character
//  - ensure names of policy group's policies do not contain a '/' character
fn validate_policies(policies: &HashMap<String, PolicyOrPolicyGroup>) -> Result<()> {
    for (name, policy) in policies.iter() {
        if name.contains('/') {
            return Err(anyhow!("policy name '{}' contains a '/' character", name));
        }
        if let PolicyOrPolicyGroup::PolicyGroup { policies, .. } = policy {
            let policies_with_invalid_name: Vec<String> = policies
                .keys()
                .filter(|id| id.contains('/'))
                .cloned()
                .collect();
            if !policies_with_invalid_name.is_empty() {
                return Err(anyhow!(
                    "policy group '{}' contains policies with invalid names: {:?}",
                    name,
                    policies_with_invalid_name
                ));
            }
        }
    }
    Ok(())
}

fn verification_config(matches: &clap::ArgMatches) -> Result<Option<LatestVerificationConfig>> {
    match matches.get_one::<String>("verification-path") {
        None => Ok(None),
        Some(path) => {
            let verification_file = Path::new(path);
            Ok(Some(read_verification_file(verification_file)?))
        }
    }
}

fn remote_server_options(matches: &clap::ArgMatches) -> Result<Option<Sources>> {
    let sources = match matches.get_one::<String>("sources-path") {
        Some(sources_file) => Some(
            read_sources_file(Path::new(sources_file))
                .map_err(|e| anyhow!("error while loading sources from {}: {}", sources_file, e))?,
        ),
        None => None,
    };

    // Inject proxy settings read from the environment so every HTTP client
    // inside policy-fetcher honours them without needing system-proxy feature.
    let sources = sources.map(|mut s| {
        s.proxies = Some(ProxyConfig::from_env());
        s
    });

    if let Some(docker_config_json_path) = matches.get_one::<String>("docker-config-json-path") {
        // docker_credential crate expects the config path in the $DOCKER_CONFIG. Keep docker-config-json-path parameter for backwards compatibility
        unsafe {
            env::set_var(DOCKER_CONFIG_ENV_VAR, docker_config_json_path);
        }
    }

    Ok(sources)
}

#[derive(Debug, Clone)]
pub enum PolicyOrPolicyGroupSettings {
    Policy(PolicySettings),
    PolicyGroup {
        expression: String,
        message: String,
        policies: Vec<String>,
    },
}

/// `PolicyGroupMember` represents a single policy that is part of a policy group.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyGroupMember {
    /// The URL where the policy is located
    pub module: String,
    /// The settings for the policy
    pub settings: Option<PolicySettings>,
    /// The list of Kubernetes resources the policy is allowed to access
    #[serde(default)]
    pub context_aware_resources: BTreeSet<ContextAwareResource>,
    /// Timeout for the evaluation of the policy. Overrides the server-wide
    /// `policy_evaluation_limit_seconds` for this policy. Only takes effect
    /// when timeout protection is enabled (i.e. `--disable-timeout-protection`
    /// is not set); it is ignored otherwise.
    pub timeout_eval_seconds: Option<u64>,
    /// List of host capabilities granted to this policy
    #[serde(default)]
    pub host_capabilities: Vec<String>,
}

impl PolicyGroupMember {
    pub fn settings(&self) -> Result<PolicyOrPolicyGroupSettings> {
        Ok(PolicyOrPolicyGroupSettings::Policy(
            self.settings.clone().unwrap_or_default(),
        ))
    }
}

/// Describes a policy that can be either an individual policy or a group policy.
#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum PolicyOrPolicyGroup {
    /// An individual policy
    #[serde(rename_all = "camelCase")]
    Policy {
        /// The URL where the policy is located
        module: String,
        #[serde(default)]
        /// The mode of the policy
        policy_mode: PolicyMode,
        /// Whether the policy is allowed to mutate the request
        allowed_to_mutate: Option<bool>,
        /// The settings for the policy, as provided by the user
        settings: Option<PolicySettings>,
        #[serde(default)]
        /// The list of Kubernetes resources the policy is allowed to access
        context_aware_resources: BTreeSet<ContextAwareResource>,
        /// The message that is returned when the policy evaluates to false
        message: Option<String>,
        /// Timeout for the evaluation of the policy. Overrides the server-wide
        /// `policy_evaluation_limit_seconds` for this policy. Only takes effect
        /// when timeout protection is enabled (i.e. `--disable-timeout-protection`
        /// is not set); it is ignored otherwise.
        timeout_eval_seconds: Option<u64>,
        /// The list of host capabilities granted to this policy
        #[serde(default)]
        host_capabilities: Vec<String>,
    },
    /// A group of policies that are evaluated together using a given expression
    #[serde(rename_all = "camelCase")]
    PolicyGroup {
        /// The mode of the policy
        #[serde(default)]
        policy_mode: PolicyMode,
        /// The policies that make up for this group
        /// Key is a unique identifier
        policies: HashMap<String, PolicyGroupMember>,
        /// The expression that is used to evaluate the group of policies
        expression: String,
        /// The message that is returned when the group of policies evaluates to false
        message: String,
    },
}

impl PolicyOrPolicyGroup {
    pub fn settings(&self) -> Result<PolicyOrPolicyGroupSettings> {
        match self {
            PolicyOrPolicyGroup::Policy { settings, .. } => Ok(
                PolicyOrPolicyGroupSettings::Policy(settings.clone().unwrap_or_default()),
            ),
            PolicyOrPolicyGroup::PolicyGroup {
                expression,
                message,
                policies,
                ..
            } => Ok(PolicyOrPolicyGroupSettings::PolicyGroup {
                expression: expression.clone(),
                message: message.clone(),
                policies: policies.keys().cloned().collect(),
            }),
        }
    }
}

/// Returns `true` when at least one policy, or policy-group member, defines
/// `timeoutEvalSeconds`.
///
/// `timeoutEvalSeconds` only takes effect as an override of the server-wide
/// `policy_evaluation_limit_seconds`; when the global timeout protection is
/// disabled (e.g. `--disable-timeout-protection`), per-policy timeouts are
/// ignored. This helper is used to warn the operator when that combination
/// is detected at startup.
pub(crate) fn any_policy_has_timeout(policies: &HashMap<String, PolicyOrPolicyGroup>) -> bool {
    policies.values().any(|policy| match policy {
        PolicyOrPolicyGroup::Policy {
            timeout_eval_seconds,
            ..
        } => timeout_eval_seconds.is_some(),
        PolicyOrPolicyGroup::PolicyGroup { policies, .. } => policies
            .values()
            .any(|member| member.timeout_eval_seconds.is_some()),
    })
}

/// Reads the policies configuration file, returns a HashMap with String as value
/// and Policy as values. The key is the name of the policy as provided by the user
/// inside of the configuration file. This name is used to build the API path
/// exposing the policy.
fn read_policies_file(path: &Path) -> Result<HashMap<String, PolicyOrPolicyGroup>> {
    let settings_file = File::open(path)?;
    let ps: HashMap<String, PolicyOrPolicyGroup> = serde_yaml::from_reader(&settings_file)?;
    Ok(ps)
}

/// Creates a `ClientTlsConfig` used by OTLP exporters based on the environment variables.
/// TODO: this function will be removed once this issue is resolved upstream:
/// https://github.com/open-telemetry/opentelemetry-rust/issues/984
pub fn build_client_tls_config_from_env(prefix: &str) -> Result<ClientTlsConfig> {
    let mut client_tls_config = ClientTlsConfig::new();

    let ca_env = format!("OTEL_EXPORTER_OTLP_{}CERTIFICATE", prefix);
    let fallback_ca_env = "OTEL_EXPORTER_OTLP_CERTIFICATE";

    let ca_file = env::var(&ca_env)
        .or_else(|_| env::var(fallback_ca_env))
        .ok();

    if let Some(ca_path) = ca_file {
        let ca_cert = std::fs::read(ca_path)?;
        client_tls_config = client_tls_config.ca_certificate(Certificate::from_pem(ca_cert));
    }

    let client_cert_env = format!("OTEL_EXPORTER_OTLP_{}CLIENT_CERTIFICATE", prefix);
    let fallback_client_cert_env = "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE";

    let client_cert_file = std::env::var(&client_cert_env)
        .or_else(|_| std::env::var(fallback_client_cert_env))
        .ok();

    let client_key_env = format!("OTEL_EXPORTER_OTLP_{}CLIENT_KEY", prefix);
    let fallback_client_key_env = "OTEL_EXPORTER_OTLP_CLIENT_KEY";

    let client_key_file = std::env::var(&client_key_env)
        .or_else(|_| std::env::var(fallback_client_key_env))
        .ok();

    if let (Some(cert_path), Some(key_path)) = (client_cert_file, client_key_file) {
        let cert = fs::read(cert_path)?;
        let key = fs::read(key_path)?;

        let identity = Identity::from_pem(cert, key);
        client_tls_config = client_tls_config.identity(identity);
    }

    Ok(client_tls_config)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rstest::*;
    use serde_json::json;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::cli;

    #[test]
    fn read_policies_file_test() {
        let policies_yaml = r#"
---
example:
    module: ghcr.io/kubewarden/policies/context-aware-policy:0.1.0
    settings: {}
    allowedToMutate: true
    message: "my custom error message"
    contextAwareResources:
        - apiVersion: v1
          kind: Namespace
        - apiVersion: v1
          kind: Pod
    hostCapabilities:
      - kubernetes/*
group_policy:
    policyMode: monitor
    expression: "true"
    message: "group policy message"
    policies:
        policy1:
            module: ghcr.io/kubewarden/policies/policy1:0.1.0
            settings: {}
        policy2:
            module: ghcr.io/kubewarden/policies/policy2:0.1.0
            settings: {}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(policies_yaml.as_bytes()).unwrap();
        let file_path = temp_file.into_temp_path();

        let policies = read_policies_file(file_path.as_ref()).unwrap();

        let expected_policies = HashMap::from([
            (
                "example".to_owned(),
                PolicyOrPolicyGroup::Policy {
                    module: "ghcr.io/kubewarden/policies/context-aware-policy:0.1.0".to_owned(),
                    policy_mode: PolicyMode::Protect,
                    allowed_to_mutate: Some(true),
                    settings: Some(PolicySettings::default()),
                    context_aware_resources: BTreeSet::from([
                        ContextAwareResource {
                            api_version: "v1".to_owned(),
                            kind: "Namespace".to_owned(),
                        },
                        ContextAwareResource {
                            api_version: "v1".to_owned(),
                            kind: "Pod".to_owned(),
                        },
                    ]),
                    message: Some("my custom error message".to_owned()),
                    timeout_eval_seconds: None,
                    host_capabilities: vec!["kubernetes/*".to_owned()],
                },
            ),
            (
                "group_policy".to_owned(),
                PolicyOrPolicyGroup::PolicyGroup {
                    policy_mode: PolicyMode::Monitor,
                    expression: "true".to_owned(),
                    message: "group policy message".to_owned(),
                    policies: HashMap::from([
                        (
                            "policy1".to_owned(),
                            PolicyGroupMember {
                                module: "ghcr.io/kubewarden/policies/policy1:0.1.0".to_owned(),
                                settings: Some(PolicySettings::default()),
                                context_aware_resources: BTreeSet::new(),
                                timeout_eval_seconds: None,
                                host_capabilities: vec![],
                            },
                        ),
                        (
                            "policy2".to_string(),
                            PolicyGroupMember {
                                module: "ghcr.io/kubewarden/policies/policy2:0.1.0".to_owned(),
                                settings: Some(PolicySettings::default()),
                                context_aware_resources: BTreeSet::new(),
                                timeout_eval_seconds: None,
                                host_capabilities: vec![],
                            },
                        ),
                    ]),
                },
            ),
        ]);

        assert_eq!(expected_policies, policies);
    }

    #[rstest]
    #[case::settings_empty(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#, json!({})
    )]
    #[case::settings_missing(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
"#, json!({})
    )]
    #[case::settings_null(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: null
"#, json!({})
    )]
    #[case::settings_provided(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings:
    "counter": 1
    "items": ["a", "b"]
    "nested": {"key": "value"}
"#, json!({"counter": 1, "items": ["a", "b"], "nested": {"key": "value"}})
    )]
    fn handle_settings_conversion(#[case] input: &str, #[case] expected: serde_json::Value) {
        let policies: HashMap<String, PolicyOrPolicyGroup> = serde_yaml::from_str(input).unwrap();
        assert!(!policies.is_empty());

        let policy = policies.get("example").unwrap();
        let settings = policy.settings().unwrap();
        match settings {
            PolicyOrPolicyGroupSettings::Policy(settings) => {
                assert_eq!(serde_json::Value::Object(settings.0), expected);
            }
            _ => panic!("Expected an Individual policy"),
        }
    }

    #[test]
    fn boolean_flags() {
        let policies_yaml = r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(policies_yaml.as_bytes()).unwrap();
        let file_path = temp_file.into_temp_path();
        let policies_flag = format!("--policies={}", file_path.to_str().unwrap());

        let boolean_flags = [
            "--enable-pprof",
            "--log-no-color",
            "--daemon",
            "--enable-metrics",
            "--enable-http-policies",
        ];

        for provide_flag in [true, false] {
            let cli = cli::build_cli();

            let mut flags = vec!["policy-server", &policies_flag];
            if provide_flag {
                flags.extend(boolean_flags);
            }

            let matches = cli.clone().try_get_matches_from(flags).unwrap();
            let config = Config::from_args(&matches).unwrap();
            assert_eq!(provide_flag, config.enable_pprof);
            assert_eq!(provide_flag, config.log_no_color);
            assert_eq!(provide_flag, config.daemon);
            assert_eq!(provide_flag, config.metrics_enabled);
            assert_eq!(provide_flag, config.enable_http_policies);
        }
    }

    #[test]
    fn http_policies_env() {
        let cli = cli::build_cli();
        let arg = cli
            .get_arguments()
            .find(|arg| arg.get_id() == "enable-http-policies")
            .expect("the enable-http-policies flag must exist");

        assert_eq!(
            arg.get_env(),
            Some(std::ffi::OsStr::new("KUBEWARDEN_ENABLE_HTTP_POLICIES"))
        );
    }

    fn config_with_policies_and_args(extra_args: &[&str]) -> Result<Config> {
        let policies_yaml = r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(policies_yaml.as_bytes()).unwrap();
        let file_path = temp_file.into_temp_path();
        let policies_flag = format!("--policies={}", file_path.to_str().unwrap());

        let mut args = vec!["policy-server", &policies_flag];
        args.extend_from_slice(extra_args);

        let matches = cli::build_cli().try_get_matches_from(args)?;
        Config::from_args(&matches)
    }

    #[rstest]
    #[case::default(&[], Some(256 * 1024 * 1024))]
    #[case::custom_value(&["--policy-memory-limit=64"], Some(64 * 1024 * 1024))]
    #[case::disabled(&["--disable-memory-limit"], None)]
    fn policy_memory_limit_bytes(#[case] extra_args: &[&str], #[case] expected: Option<usize>) {
        let config = config_with_policies_and_args(extra_args).unwrap();
        assert_eq!(config.policy_memory_limit_bytes, expected);
    }

    #[test]
    fn policy_memory_limit_rejects_zero() {
        assert!(config_with_policies_and_args(&["--policy-memory-limit=0"]).is_err());
    }

    #[rstest]
    #[case::all_good(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
group_policy:
  expression: "true"
  message: "group policy message"
  policies:
    policy1:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
    policy2:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
"#,
        true
    )]
    #[case::policy_with_invalid_name(
        r#"
---
example/invalid:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
"#,
        false
    )]
    #[case::policy_group_member_with_invalid_name(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
group_policy:
  expression: "true"
  message: "group policy message"
  policies:
    policy1/a:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
    policy2:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
"#,
        false
    )]
    fn policy_validation(#[case] policies_yaml: &str, #[case] is_valid: bool) {
        let policies: HashMap<String, PolicyOrPolicyGroup> =
            serde_yaml::from_str(policies_yaml).unwrap();

        let validation_result = validate_policies(&policies);
        assert_eq!(is_valid, validation_result.is_ok());
    }

    #[test]
    fn any_policy_has_timeout_empty() {
        let policies: HashMap<String, PolicyOrPolicyGroup> = HashMap::new();
        assert!(!any_policy_has_timeout(&policies));
    }

    #[rstest]
    #[case::no_timeouts(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
group_policy:
  expression: "true"
  message: "group policy message"
  policies:
    policy1:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
"#,
        false
    )]
    #[case::policy_with_timeout(
        r#"
---
example:
  module: file:///tmp/namespace-validate-policy.wasm
  settings: {}
  timeoutEvalSeconds: 5
"#,
        true
    )]
    #[case::group_member_with_timeout(
        r#"
---
group_policy:
  expression: "true"
  message: "group policy message"
  policies:
    policy1:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
    policy2:
      module: file:///tmp/namespace-validate-policy.wasm
      settings: {}
      timeoutEvalSeconds: 3
"#,
        true
    )]
    fn any_policy_has_timeout_detection(#[case] policies_yaml: &str, #[case] expected: bool) {
        let policies: HashMap<String, PolicyOrPolicyGroup> =
            serde_yaml::from_str(policies_yaml).unwrap();

        assert_eq!(expected, any_policy_has_timeout(&policies));
    }
}
