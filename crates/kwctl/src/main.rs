use std::{
    collections::HashMap, convert::TryFrom, env, fs, io::prelude::*, path::PathBuf, str::FromStr,
};

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use itertools::Itertools;
use lazy_static::lazy_static;
use policy_evaluator::policy_fetcher::{PullDestination, registry::Registry, store::DEFAULT_ROOT};
use rustls::crypto::aws_lc_rs::default_provider;
use tracing::{debug, info};
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    prelude::*,
};

use crate::{
    config::{
        sources::remote_server_options,
        verification::{build_sigstore_trust_root, build_verification_options},
    },
    load::load,
    save::save,
    utils::{LookupError, find_file_matching_file, normalize_uri},
};

mod annotate;
mod backend;
mod callback_handler;
mod cli;
mod command;
mod completions;
mod config;
mod info;
mod inspect;
mod load;
mod policies;
mod pull;
mod push;
mod rm;
mod save;
mod scaffold;
mod utils;
mod verify;
mod wasm_scanner;

pub(crate) const KWCTL_VERIFICATION_CONFIG: &str = "verification-config.yml";

lazy_static! {
    pub(crate) static ref KWCTL_DEFAULT_VERIFICATION_CONFIG_PATH: String = {
        DEFAULT_ROOT
            .config_dir()
            .join(KWCTL_VERIFICATION_CONFIG)
            .display()
            .to_string()
    };
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    let mut term_color_support = "dumb".to_string();

    if let Ok(val) = env::var("TERM") {
        term_color_support = val
    }

    let no_color = matches
        .get_one::<bool>("no-color")
        .unwrap_or(&false)
        .to_owned();

    // Need to set this env variable to have prettytable
    // adapt the output. This can later be removed if
    // prettytable provides methods to disable color globally
    if no_color {
        unsafe {
            env::set_var("TERM", "dumb");
        }
    } else {
        unsafe {
            env::set_var("TERM", term_color_support);
        }
    }

    // setup logging
    let verbose = matches
        .get_one::<bool>("verbose")
        .unwrap_or(&false)
        .to_owned();
    let level_filter = if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let filter_layer = EnvFilter::from_default_env()
        .add_directive(level_filter.into())
        .add_directive("cranelift_codegen=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("cranelift_wasm=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("hyper=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("regalloc=off".parse().unwrap()) // this crate generates lots of tracing events we don't care about
        .add_directive("wasmtime_cache=off".parse().unwrap()) // wasmtime_cache messages are not critical and just confuse users
        .add_directive("walrus=warn".parse().unwrap()); // walrus: ignore warning messages
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(!no_color),
        )
        .init();

    if let Err(e) = default_provider().install_default() {
        tracing::warn!("Failed to install rustls crypto provider: {:?}", e);
    }

    match matches.subcommand_name() {
        Some("policies") => policies::list(),
        Some("info") => info::info(),
        Some("pull") => {
            if let Some(matches) = matches.subcommand_matches("pull") {
                let uri = normalize_uri(matches.get_one::<String>("uri").unwrap());
                let uri = &uri;
                let destination = matches
                    .get_one::<String>("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                let destination = match destination {
                    Some(destination) => PullDestination::LocalFile(destination),
                    None => PullDestination::MainStore,
                };
                pull_command(uri, destination, matches).await?
            };
            Ok(())
        }
        Some("verify") => {
            if let Some(matches) = matches.subcommand_matches("verify") {
                let uri = normalize_uri(matches.get_one::<String>("uri").unwrap());
                let uri = uri.as_str();
                let sources = remote_server_options(matches)?;
                let verification_options = build_verification_options(matches)?
                    .ok_or_else(|| anyhow!("could not retrieve sigstore options"))?;
                let sigstore_trust_root =
                    build_sigstore_trust_root(matches.get_one::<PathBuf>("sigstore-trust-config"))
                        .await?;
                verify::verify(
                    uri,
                    sources.as_ref(),
                    &verification_options,
                    sigstore_trust_root.clone(),
                )
                .await
                .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?;
            };
            Ok(())
        }
        Some("push") => {
            if let Some(matches) = matches.subcommand_matches("push") {
                let sources = remote_server_options(matches)?;
                let wasm_uri =
                    crate::utils::map_path_to_uri(matches.get_one::<String>("policy").unwrap())?;
                let wasm_path = crate::utils::wasm_path(wasm_uri.as_str())?;
                let uri = matches
                    .get_one::<String>("uri")
                    .map(|u| {
                        if u.starts_with("registry://") {
                            u.clone()
                        } else {
                            format!("registry://{u}")
                        }
                    })
                    .unwrap();

                debug!(
                    policy = wasm_path.to_string_lossy().to_string().as_str(),
                    destination = uri.as_str(),
                    "policy push"
                );

                let force = matches.contains_id("force");

                let immutable_ref = push::push(wasm_path, &uri, sources.as_ref(), force).await?;

                match matches.get_one::<String>("output").map(|s| s.as_str()) {
                    Some("json") => {
                        let mut response: HashMap<&str, String> = HashMap::new();
                        response.insert("immutable_ref", immutable_ref);
                        serde_json::to_writer(std::io::stdout(), &response)?
                    }
                    _ => {
                        println!("Policy successfully pushed: {immutable_ref}");
                    }
                }
            };
            Ok(())
        }
        Some("rm") => {
            if let Some(matches) = matches.subcommand_matches("rm") {
                let uri_or_sha_prefix =
                    normalize_uri(matches.get_one::<String>("uri_or_sha_prefix").unwrap());
                rm::rm(&uri_or_sha_prefix)?;
            }
            Ok(())
        }
        Some("run") => {
            let run_arg = matches
                .subcommand_matches("run")
                .expect("run subcommand not found");
            cli::run::exec(run_arg).await
        }
        Some("bench") => {
            let bench_arg = matches
                .subcommand_matches("bench")
                .expect("bench subcommand not found");
            cli::bench::exec(bench_arg).await
        }
        Some("annotate") => {
            if let Some(matches) = matches.subcommand_matches("annotate") {
                let wasm_path = matches
                    .get_one::<String>("wasm-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let metadata_file = matches
                    .get_one::<String>("metadata-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let destination = matches
                    .get_one::<String>("output-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .unwrap();
                let usage_file = matches
                    .get_one::<String>("usage-path")
                    .map(|output| PathBuf::from_str(output).unwrap());
                annotate::write_annotation(wasm_path, metadata_file, destination, usage_file)?;
            }
            Ok(())
        }
        Some("inspect") => {
            if let Some(matches) = matches.subcommand_matches("inspect") {
                let uri_or_sha_prefix =
                    normalize_uri(matches.get_one::<String>("uri_or_sha_prefix").unwrap());
                let output = inspect::OutputType::try_from(
                    matches.get_one::<String>("output").map(|s| s.as_str()),
                )?;
                let sources = remote_server_options(matches)?;
                let no_signatures = !matches
                    .get_one::<bool>("show-signatures")
                    .unwrap_or(&false)
                    .to_owned();
                inspect::inspect(&uri_or_sha_prefix, output, sources, no_color, no_signatures)
                    .await?;
            };
            Ok(())
        }
        Some("scaffold") => {
            if let Some(matches) = matches.subcommand_matches("scaffold")
                && let Some(_matches) = matches.subcommand_matches("verification-config")
            {
                println!("{}", scaffold::verification_config()?);
            }
            if let Some(matches) = matches.subcommand_matches("scaffold")
                && let Some(artifacthub_matches) = matches.subcommand_matches("artifacthub")
            {
                let metadata_file = artifacthub_matches
                    .get_one::<String>("metadata-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .or_else(|| find_file_matching_file(&["metadata.yml", "metadata.yaml"]))
                    .ok_or_else(|| {
                        anyhow!("path to metadata file not provided, plus 'metadata.yml' not found")
                    })?;

                if artifacthub_matches.get_one::<String>("version").is_some() {
                    tracing::warn!(
                        "The 'version' flag is deprecated and will be removed in a future release. The value of the `io.kubewarden.policy.version` field in the policy metadata file is used instead."
                    );
                }
                let questions_file = artifacthub_matches
                    .get_one::<String>("questions-path")
                    .map(|output| PathBuf::from_str(output).unwrap())
                    .or_else(|| {
                        find_file_matching_file(&[
                            "questions-ui.yml",
                            "questions-ui.yaml",
                            "questions.yml",
                            "questions.yaml",
                        ])
                    });
                let content = scaffold::artifacthub(metadata_file, questions_file)?;
                if let Some(output) = artifacthub_matches.get_one::<String>("output") {
                    let output_path = PathBuf::from_str(output)?;
                    fs::write(output_path, content)?;
                } else {
                    println!("{}", content);
                }
            }
            if let Some(matches) = matches.subcommand_matches("scaffold")
                && let Some(matches) = matches.subcommand_matches("manifest")
            {
                scaffold_manifest_command(matches).await?;
            };
            if let Some(matches) = matches.subcommand_matches("scaffold")
                && let Some(matches) = matches.subcommand_matches("vap")
            {
                let cel_policy_uri = matches.get_one::<String>("cel-policy").unwrap();
                let vap_file: PathBuf = matches.get_one::<String>("policy").unwrap().into();
                let vap_binding_file: PathBuf =
                    matches.get_one::<String>("binding").unwrap().into();

                scaffold::vap(
                    cel_policy_uri.as_str(),
                    vap_file.as_path(),
                    vap_binding_file.as_path(),
                )?;
            };
            if let Some(matches) = matches.subcommand_matches("scaffold")
                && let Some(matches) = matches.subcommand_matches("admission-request")
            {
                let operation: scaffold::AdmissionRequestOperation = matches
                    .get_one::<String>("operation")
                    .unwrap()
                    .parse::<scaffold::AdmissionRequestOperation>()
                    .map_err(|e| anyhow!("Error parsing operation: {}", e))?;
                let object_path: Option<PathBuf> = if matches.contains_id("object") {
                    Some(matches.get_one::<String>("object").unwrap().into())
                } else {
                    None
                };
                let old_object_path: Option<PathBuf> = if matches.contains_id("old-object") {
                    Some(matches.get_one::<String>("old-object").unwrap().into())
                } else {
                    None
                };

                scaffold::admission_request(operation, object_path, old_object_path).await?;
            };

            Ok(())
        }
        Some("completions") => {
            if let Some(matches) = matches.subcommand_matches("completions") {
                completions::completions(matches.get_one::<String>("shell").unwrap())?;
            }
            Ok(())
        }
        Some("digest") => {
            if let Some(matches) = matches.subcommand_matches("digest") {
                let uri = matches.get_one::<String>("uri").unwrap();
                let sources = remote_server_options(matches)?;
                let registry = Registry::new();
                let digest = registry.manifest_digest(uri, sources.as_ref()).await?;
                println!("{uri}@{digest}");
            }
            Ok(())
        }
        Some("save") => {
            if let Some(matches) = matches.subcommand_matches("save") {
                let policies = matches.get_many::<String>("policies").unwrap();
                let output = matches.get_one::<String>("output").unwrap();

                save(policies.collect_vec(), output)?;
            }
            Ok(())
        }
        Some("load") => {
            if let Some(matches) = matches.subcommand_matches("load") {
                let input = matches.get_one::<String>("input").unwrap();
                load(input)?;
            }
            Ok(())
        }
        Some("docs") => {
            if let Some(matches) = matches.subcommand_matches("docs") {
                let output = matches.get_one::<String>("output").unwrap();
                let mut file = std::fs::File::create(output)
                    .map_err(|e| anyhow!("cannot create file {}: {}", output, e))?;
                let docs_content = if output.ends_with(".md") {
                    clap_documentation::help_markdown_command(&cli::build_cli())
                } else {
                    clap_documentation::help_asciidoc_command(&cli::build_cli())
                };
                file.write_all(docs_content.as_bytes())
                    .map_err(|e| anyhow!("cannot write to file {}: {}", output, e))?;
            }
            Ok(())
        }
        Some(command) => Err(anyhow!("unknown subcommand: {}", command)),
        None => {
            // NOTE: this should not happen due to
            // SubcommandRequiredElseHelp setting
            unreachable!();
        }
    }
}

// Check if the policy is already present in the local store, and if not, pull it from the remote server.
async fn pull_if_needed(uri_or_sha_prefix: &str, matches: &ArgMatches) -> Result<()> {
    match crate::utils::get_wasm_path(uri_or_sha_prefix) {
        Err(LookupError::PolicyMissing(uri)) => {
            info!(
                "cannot find policy with uri: {}, trying to pull it from remote registry",
                uri
            );
            pull_command(&uri, PullDestination::MainStore, matches).await
        }
        Err(e) => Err(anyhow!("{}", e)),
        Ok(_path) => Ok(()),
    }
}

// Pulls a policy from a remote server and verifies it if verification options are provided.
async fn pull_command(
    uri: &String,
    destination: PullDestination,
    matches: &ArgMatches,
) -> Result<()> {
    let sources = remote_server_options(matches)?;

    let verification_options = build_verification_options(matches)?;
    let mut verified_manifest_digest: Option<String> = None;
    if let Some(ref verification_config) = verification_options {
        let sigstore_trust_root =
            build_sigstore_trust_root(matches.get_one::<PathBuf>("sigstore-trust-config")).await?;
        // verify policy prior to pulling if keys listed, and keep the
        // verified manifest digest:
        verified_manifest_digest = Some(
            verify::verify(
                uri,
                sources.as_ref(),
                verification_config,
                sigstore_trust_root.clone(),
            )
            .await
            .map_err(|e| anyhow!("Policy {} cannot be validated\n{:?}", uri, e))?,
        );
    }

    let policy = pull::pull(uri, sources.as_ref(), destination).await?;

    if verification_options.is_some() {
        let sigstore_trust_root =
            build_sigstore_trust_root(matches.get_one::<PathBuf>("sigstore-trust-config")).await?;
        return verify::verify_local_checksum(
            &policy,
            sources.as_ref(),
            &verified_manifest_digest.unwrap(),
            sigstore_trust_root.clone(),
        )
        .await;
    }
    Ok(())
}

/*
 * Scaffold a manifest from a policy.
 * This function will pull the policy if it is not already present in the local store.
 */
async fn scaffold_manifest_command(matches: &ArgMatches) -> Result<()> {
    let uri_or_sha_prefix = normalize_uri(matches.get_one::<String>("uri_or_sha_prefix").unwrap());
    let uri_or_sha_prefix = uri_or_sha_prefix.as_str();

    pull_if_needed(uri_or_sha_prefix, matches).await?;

    let resource_type = matches.get_one::<String>("type").unwrap();
    if matches.contains_id("settings-path") && matches.contains_id("settings-json") {
        return Err(anyhow!(
            "'settings-path' and 'settings-json' cannot be used at the same time"
        ));
    }
    let settings = if matches.contains_id("settings-path") {
        matches
            .get_one::<String>("settings-path")
            .map(|settings| -> Result<String> {
                fs::read_to_string(settings)
                    .map_err(|e| anyhow!("Error reading settings from {}: {}", settings, e))
            })
            .transpose()?
    } else if matches.contains_id("settings-json") {
        Some(matches.get_one::<String>("settings-json").unwrap().clone())
    } else {
        None
    };
    let policy_title = matches.get_one::<String>("title").cloned();

    let allow_context_aware_resources = matches
        .get_one::<bool>("allow-context-aware")
        .unwrap_or(&false)
        .to_owned();

    scaffold::manifest(
        uri_or_sha_prefix,
        resource_type.parse()?,
        settings.as_deref(),
        policy_title.as_deref(),
        allow_context_aware_resources,
    )
}
