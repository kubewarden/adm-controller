use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use policy_evaluator::policy_fetcher::{
    sigstore::trust::sigstore::SigstoreTrustRoot, sources::Sources, store::Store,
    verify::config::LatestVerificationConfig,
};
use tracing::{info, warn};

use crate::{
    callback_handler,
    config::{
        HostCapabilitiesMode,
        policy_definition::PolicyDefinition,
        sources::remote_server_options,
        verification::{build_sigstore_trust_root, build_verification_options},
    },
    verify,
};

const BYTES_PER_MIB: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct PullAndRunSettings {
    pub sources: Option<Sources>,
    pub request: serde_json::Value,
    /// When verification is enabled, the map is populated with:
    /// - key: the policy URI
    /// - value: the digest of the verified manifest
    pub verified_manifest_digests: Option<HashMap<String, String>>,
    pub sigstore_trust_root: Option<Arc<SigstoreTrustRoot>>,
    pub enable_wasmtime_cache: bool,
    /// Maximum amount of linear memory, in bytes, a policy is allowed to use.
    /// `None` means the memory limit is disabled.
    pub policy_memory_limit_bytes: Option<usize>,
    pub host_capabilities_mode: HostCapabilitiesMode,
    pub enable_http_policies: bool,
}

pub(crate) fn parse_policy_definitions(
    matches: &ArgMatches,
    store: &Store,
) -> Result<Vec<PolicyDefinition>> {
    let uri = matches
        .get_one::<String>("uri_or_sha_prefix_or_yaml_file")
        .expect("uri_or_sha_prefix is guaranteed to be Some here");

    if uri.ends_with(".yaml") || uri.ends_with(".yml") {
        let raw = matches.get_one::<bool>("raw").unwrap_or(&false);
        if *raw {
            return Err(anyhow!(
                "The --raw option cannot be used with a YAML file: {}",
                uri
            ));
        }
        if matches.contains_id("settings-json") || matches.contains_id("settings-path") {
            info!(
                "The --settings-json and --settings-path options are ignored when using a YAML file"
            );
        }

        let allowed_host_capabilities: Vec<String> = matches
            .get_many::<String>("allowed-host-capabilities")
            .unwrap_or_default()
            .cloned()
            .collect();
        // If the URI is a YAML file, parse it as a policy definition
        return PolicyDefinition::from_yaml_file(uri, &allowed_host_capabilities);
    }

    Ok(vec![PolicyDefinition::from_cli(matches, store)?])
}

pub(crate) async fn parse_pull_and_run_settings(
    matches: &ArgMatches,
    policy_definitions: &[PolicyDefinition],
    enable_http_policies: bool,
) -> Result<PullAndRunSettings> {
    let request_raw = match matches
        .get_one::<String>("request-path")
        .map(|s| s.as_str())
        .unwrap()
    {
        "-" => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| anyhow!("Error reading request from stdin: {}", e))?;
            buffer
        }
        request_path => fs::read_to_string(request_path).map_err(|e| {
            anyhow!(
                "Error opening request file {}; {}",
                matches.get_one::<String>("request-path").unwrap(),
                e
            )
        })?,
    };
    let request = serde_json::from_str::<serde_json::Value>(&request_raw)?;

    let sources = remote_server_options(matches)
        .map_err(|e| anyhow!("Error getting remote server options: {}", e))?;

    let verification_options = build_verification_options(matches)?;

    let sigstore_trust_root = match build_sigstore_trust_root(
        matches.get_one::<PathBuf>("sigstore-trust-config"),
    )
    .await
    {
        Ok(trust_root) => trust_root,
        Err(e) => {
            if verification_options.is_some() {
                return Err(anyhow!(
                    "Error building Sigstore trust root: {}. \
                    Note that verification options were provided, \
                    so a Sigstore trust root is required.",
                    e
                ));
            } else {
                warn!(
                    error=?e, "Cannot create Sigstore trust root, verification relying on Rekor and Fulcio will fail"
                );
                None
            }
        }
    };

    let verified_manifest_digests = if let Some(verification_options) = verification_options {
        Some(
            build_verified_manifest_digests(
                policy_definitions,
                &verification_options,
                &sources,
                sigstore_trust_root.clone(),
            )
            .await?,
        )
    } else {
        None
    };

    let enable_wasmtime_cache = !matches
        .get_one::<bool>("disable-wasmtime-cache")
        .unwrap_or(&false)
        .to_owned();

    let policy_memory_limit_bytes = parse_policy_memory_limit_bytes(matches)?;

    let mut host_capabilities_mode = HostCapabilitiesMode::Direct;
    if matches.contains_id("record-host-capabilities-interactions") {
        let destination = matches
            .get_one::<String>("record-host-capabilities-interactions")
            .map(|destination| PathBuf::from_str(destination).unwrap())
            .ok_or_else(|| anyhow!("Cannot parse 'record-host-capabilities-interactions' file"))?;

        info!(session_file = ?destination, "host capabilities proxy enabled with record mode");
        host_capabilities_mode =
            HostCapabilitiesMode::Proxy(callback_handler::ProxyMode::Record { destination });
    }
    if matches.contains_id("replay-host-capabilities-interactions") {
        let source = matches
            .get_one::<String>("replay-host-capabilities-interactions")
            .map(|source| PathBuf::from_str(source).unwrap())
            .ok_or_else(|| anyhow!("Cannot parse 'replay-host-capabilities-interaction' file"))?;

        info!(session_file = ?source, "host capabilities proxy enabled with replay mode");
        host_capabilities_mode =
            HostCapabilitiesMode::Proxy(callback_handler::ProxyMode::Replay { source });
    }

    Ok(PullAndRunSettings {
        sources,
        request,
        verified_manifest_digests,
        sigstore_trust_root,
        enable_wasmtime_cache,
        policy_memory_limit_bytes,
        host_capabilities_mode,
        enable_http_policies,
    })
}

/// Parses the `--policy-memory-limit`/`--disable-memory-limit` flags into the
/// maximum amount of linear memory, in bytes, a policy is allowed to use.
/// Returns `None` when the memory limit is disabled.
fn parse_policy_memory_limit_bytes(matches: &ArgMatches) -> Result<Option<usize>> {
    if *matches
        .get_one::<bool>("disable-memory-limit")
        .unwrap_or(&false)
    {
        return Ok(None);
    }

    let policy_memory_limit_mib = matches
        .get_one::<String>("policy-memory-limit")
        .expect("policy-memory-limit should always be set")
        .parse::<usize>()
        .map_err(|e| anyhow!("Cannot parse 'policy-memory-limit' as a number: {}", e))?;

    if policy_memory_limit_mib == 0 {
        return Err(anyhow!(
            "policy-memory-limit must be greater than 0, or the limit must be disabled via \
             --disable-memory-limit"
        ));
    }

    Ok(Some(policy_memory_limit_mib * BYTES_PER_MIB))
}

async fn build_verified_manifest_digests(
    policy_definitions: &[PolicyDefinition],
    verification_options: &LatestVerificationConfig,
    sources: &Option<Sources>,
    sigstore_trust_root: Option<Arc<SigstoreTrustRoot>>,
) -> Result<HashMap<String, String>> {
    let mut uris: HashSet<String> = HashSet::new();
    for policy_definition in policy_definitions {
        uris = uris.union(&policy_definition.uris()).cloned().collect();
    }

    let mut verified_manifest_digests = HashMap::new();

    for uri in &uris {
        // verify policy prior to pulling if keys listed, and keep the
        // verified manifest digest:
        let verified_manifest_digest = verify::verify(
            uri.as_str(),
            sources.as_ref(),
            verification_options,
            sigstore_trust_root.clone(),
        )
        .await
        .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?;
        verified_manifest_digests.insert(uri.clone(), verified_manifest_digest);
    }

    Ok(verified_manifest_digests)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn run_matches(extra_args: &[&str]) -> ArgMatches {
        let mut args = vec!["kwctl", "run", "--request-path", "/dev/null"];
        args.extend_from_slice(extra_args);
        args.push("file:///tmp/policy.wasm");

        let matches = crate::cli::build_cli()
            .try_get_matches_from(args)
            .expect("cannot parse CLI arguments");
        matches
            .subcommand_matches("run")
            .expect("run subcommand should be present")
            .to_owned()
    }

    #[rstest]
    #[case::default(&[], Some(256 * 1024 * 1024))]
    #[case::custom_value(&["--policy-memory-limit", "64"], Some(64 * 1024 * 1024))]
    #[case::disabled(&["--disable-memory-limit"], None)]
    fn policy_memory_limit_bytes(#[case] extra_args: &[&str], #[case] expected: Option<usize>) {
        let matches = run_matches(extra_args);
        assert_eq!(parse_policy_memory_limit_bytes(&matches).unwrap(), expected);
    }

    #[test]
    fn policy_memory_limit_rejects_zero() {
        let matches = run_matches(&["--policy-memory-limit", "0"]);
        assert!(parse_policy_memory_limit_bytes(&matches).is_err());
    }
}
