use std::{collections::HashMap, path::PathBuf};

use anyhow::{Result, anyhow};
use policy_evaluator::{policy_fetcher::PullDestination, policy_metadata::Metadata};

use crate::{
    backend::has_minimum_kubewarden_version,
    config::{policy_definition::PolicyDefinition, pull_and_run::PullAndRunSettings},
    pull, verify,
};

pub(crate) struct LocalData {
    // Map of URIs to local paths where the policies are stored.
    local_paths: HashMap<String, PathBuf>,
    // Map of URIs to their metadata.
    modules_metadata: HashMap<String, Metadata>,
}

impl LocalData {
    pub async fn new(
        policy_definitions: &[PolicyDefinition],
        cfg: &PullAndRunSettings,
    ) -> Result<Self> {
        let local_paths = pull_all(policy_definitions, cfg).await?;
        let modules_metadata = build_metadata(&local_paths)?;

        Ok(Self {
            local_paths,
            modules_metadata,
        })
    }

    pub fn metadata(&self, uri: &str) -> Option<&Metadata> {
        self.modules_metadata.get(uri)
    }

    pub fn local_path(&self, uri: &str) -> Result<&PathBuf> {
        self.local_paths
            .get(uri)
            .ok_or_else(|| anyhow!("No local path found for {}", uri))
    }
}

// Pulls all policy definitions and returns a map of URIs to local paths.
async fn pull_all(
    policy_definitions: &[PolicyDefinition],
    cfg: &PullAndRunSettings,
) -> Result<HashMap<String, PathBuf>> {
    let sources = cfg.sources.as_ref();

    let mut local_paths = HashMap::new();

    for policy_definition in policy_definitions {
        for uri in policy_definition.uris() {
            if local_paths.contains_key(&uri) {
                continue;
            }
            let policy = pull::pull(
                &uri,
                sources,
                PullDestination::MainStore,
                cfg.enable_http_policies,
            )
            .await?;

            if let Some(digests) = cfg.verified_manifest_digests.as_ref() {
                let digest = digests
                    .get(&uri)
                    .ok_or_else(|| anyhow!("No digest found for {}", uri))?;

                verify::verify_local_checksum(
                    &policy,
                    sources,
                    digest,
                    cfg.sigstore_trust_root.clone(),
                )
                .await?
            }

            local_paths.insert(uri, policy.local_path);
        }
    }
    Ok(local_paths)
}

fn build_metadata(local_paths: &HashMap<String, PathBuf>) -> Result<HashMap<String, Metadata>> {
    let mut modules_metadata = HashMap::new();

    for (uri, local_path) in local_paths {
        let metadata = Metadata::from_path(local_path)?;
        if metadata.is_none() {
            continue;
        }
        has_minimum_kubewarden_version(metadata.as_ref())?;
        modules_metadata.insert(uri.to_owned(), metadata.unwrap());
    }

    Ok(modules_metadata)
}
