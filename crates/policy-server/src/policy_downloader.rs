use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use policy_evaluator::{
    policy_fetcher,
    policy_fetcher::{
        sigstore,
        sources::Sources,
        verify::{Verifier, config::LatestVerificationConfig},
    },
    policy_metadata::Metadata,
};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use tracing::{debug, error, info};

use crate::config::PolicyOrPolicyGroup;

/// A Map with the `policy.url` as key,
/// and a `PathBuf` as value. The `PathBuf` points to the location where
/// the WebAssembly module has been downloaded.
pub(crate) type FetchedPolicies = HashMap<String, Result<PathBuf>>;

/// Handles download and verification of policies
pub(crate) struct Downloader {
    verifier: Option<Verifier>,
    sources: Option<Sources>,
    enable_http_policies: bool,
}

impl Downloader {
    /// Create a new instance of Downloader
    ///
    /// **Warning:** this needs network connectivity because the constructor
    /// fetches Fulcio and Rekor data from the official TUF repository of
    /// sigstore.
    pub async fn new(
        sources: Option<Sources>,
        manual_root: Option<Arc<SigstoreTrustRoot>>,
        enable_http_policies: bool,
    ) -> Result<Self> {
        let verifier = if let Some(manual_root) = manual_root {
            info!("Fetching sigstore data from remote TUF repository");
            Some(create_verifier(sources.clone(), manual_root).await?)
        } else {
            None
        };

        Ok(Downloader {
            verifier,
            sources,
            enable_http_policies,
        })
    }

    /// Download all the policies to the given destination
    pub async fn download_policies(
        &mut self,
        policies: &HashMap<String, PolicyOrPolicyGroup>,
        destination: impl AsRef<Path>,
        verification_config: Option<&LatestVerificationConfig>,
    ) -> FetchedPolicies {
        let policies = policies_to_download(policies);
        let policies_total = policies.len();
        info!(
            download_dir = destination
                .as_ref()
                .to_str()
                .expect("cannot convert path to string"),
            policies_count = policies_total,
            status = "init",
            "policies download",
        );

        let verification_config = verification_config.unwrap_or(&LatestVerificationConfig {
            all_of: None,
            any_of: None,
        });

        // The same WebAssembly module can be referenced by multiple policies,
        // there's no need to keep downloading and verifying it

        // List of policies that we have already tried to download & verify.
        // Note: this Set includes both successful downloads and ones that
        // failed.
        let mut processed_policies: HashSet<&str> = HashSet::new();

        // List of policies that have been successfully fetched.
        // This can be a subset of `processed_policies`
        let mut fetched_policies: FetchedPolicies = HashMap::new();

        for (name, policy_url) in policies.iter() {
            debug!(policy = name.as_str(), "download");
            if !processed_policies.insert(policy_url) {
                debug!(
                    policy = name.as_str(),
                    "skipping, wasm module already processed"
                );

                continue;
            }

            let mut verified_manifest_digest: Option<String> = None;

            if let Some(ver) = self.verifier.as_ref() {
                info!(
                    policy = name.as_str(),
                    "verifying policy authenticity and integrity using sigstore"
                );
                verified_manifest_digest = match ver.verify(policy_url, verification_config).await {
                    Ok(d) => Some(d),
                    Err(e) => {
                        error!(policy = name.as_str(), error =?e, "policy cannot be verified");
                        fetched_policies.insert(
                            policy_url.to_owned(),
                            Err(anyhow!("Policy '{}' cannot be verified: {}", name, e)),
                        );

                        continue;
                    }
                };
                info!(
                    name = name.as_str(),
                    sha256sum = verified_manifest_digest
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                        .as_str(),
                    status = "verified-signatures",
                    "policy download",
                );
            }

            let fetched_policy = match policy_fetcher::fetch_policy(
                policy_url,
                policy_fetcher::PullDestination::Store(destination.as_ref().to_path_buf()),
                self.sources.as_ref(),
                self.enable_http_policies,
            )
            .await
            {
                Ok(fetched_policy) => fetched_policy,
                Err(e) => {
                    error!(
                        policy = name.as_str(),
                        error =? e,
                        "policy download failed"
                    );
                    fetched_policies.insert(
                        policy_url.to_owned(),
                        Err(anyhow!(
                            "Error while downloading policy '{}' from {}: {}",
                            name,
                            policy_url,
                            e
                        )),
                    );

                    continue;
                }
            };

            if let Some(ver) = self.verifier.as_ref() {
                if let Err(e) = ver
                    .verify_local_file_checksum(
                        &fetched_policy,
                        verified_manifest_digest.as_ref().unwrap(),
                    )
                    .await
                {
                    error!(
                        policy = name.as_str(),
                        error =? e,
                        "verification failed"
                    );

                    fetched_policies.insert(
                        policy_url.to_owned(),
                        Err(anyhow!("Verification of policy {} failed: {}", name, e)),
                    );
                    continue;
                }

                info!(
                    name = name.as_str(),
                    sha256sum = verified_manifest_digest
                        .as_ref()
                        .unwrap_or(&"unknown".to_string())
                        .as_str(),
                    status = "verified-local-checksum",
                    "policy download",
                );
            }

            if let Ok(Some(policy_metadata)) = Metadata::from_path(&fetched_policy.local_path) {
                info!(
                    name = name.as_str(),
                    path = fetched_policy.local_path.clone().into_os_string().to_str(),
                    sha256sum = fetched_policy
                        .digest()
                        .unwrap_or_else(|_| "unknown".to_string())
                        .as_str(),
                    mutating = policy_metadata.mutating,
                    "policy download",
                );
            } else {
                info!(
                    name = name.as_str(),
                    path = fetched_policy.local_path.clone().into_os_string().to_str(),
                    sha256sum = fetched_policy
                        .digest()
                        .unwrap_or_else(|_| "unknown".to_string())
                        .as_str(),
                    "policy download",
                );
            }

            fetched_policies.insert(policy_url.to_owned(), Ok(fetched_policy.local_path));
        }

        fetched_policies
    }
}

/// Creates a new Verifier that fetches Fulcio and Rekor data from the official
/// TUF repository of the sigstore project
async fn create_verifier(
    sources: Option<Sources>,
    trust_root: Arc<SigstoreTrustRoot>,
) -> Result<Verifier> {
    let verifier = Verifier::new(sources, Some(trust_root)).await?;

    Ok(verifier)
}

/// Group policies need to be flattened into a single list of policies to download
///
/// Return a map with the name of the policy as key, and the its download url as value.
/// Sub-policies are named as `group_name/sub_policy_name`
fn policies_to_download(
    policies: &HashMap<String, PolicyOrPolicyGroup>,
) -> HashMap<String, String> {
    let mut flattened_policies: HashMap<String, String> = HashMap::new();

    for (name, policy) in policies {
        match policy {
            PolicyOrPolicyGroup::Policy { module: url, .. } => {
                flattened_policies.insert(name.to_owned(), url.to_owned());
            }
            PolicyOrPolicyGroup::PolicyGroup { policies, .. } => {
                for (sub_policy_name, sub_policy) in policies {
                    flattened_policies.insert(
                        format!("{name}/#{sub_policy_name}"),
                        sub_policy.module.to_owned(),
                    );
                }
            }
        }
    }

    flattened_policies
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn verify_success() {
        let verification_cfg_yml = r#"---
    allOf:
      - kind: pubKey
        owner: pubkey1.pub
        key: |
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQiTy5S+2JFvVlhUwWPLziM7iTM2j
              byLgh2IjpNQN0Uio/9pZOTP/CsJmXoUNshfpTUHd3OxgHgz/6adtf2nBwQ==
              -----END PUBLIC KEY-----
        annotations:
          env: prod
          stable: "true"
      - kind: pubKey
        owner: pubkey2.pub
        key: |
              -----BEGIN PUBLIC KEY-----
              MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx0HuqSss8DUIIUg3I006b1EQjj3Q
              igsTrvZ/Q3+h+81DkNJg4LzID1rz0UJFUcdzI5NqlFLSTDIQw0gVKOiK7g==
              -----END PUBLIC KEY-----
        annotations:
          env: prod
        "#;
        let verification_config =
            serde_yaml::from_str::<LatestVerificationConfig>(verification_cfg_yml)
                .expect("Cannot convert verification config");

        let policies_cfg = r#"
    pod-privileged:
      module: registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    another-pod-privileged:
      module: registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    "#;

        let policies: HashMap<String, PolicyOrPolicyGroup> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");

        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");

        let mut downloader = Downloader::new(None, None, false).await.unwrap();

        let fetched_policies = downloader
            .download_policies(
                &policies,
                policy_download_dir.path().to_str().unwrap(),
                Some(&verification_config),
            )
            .await;

        // There are 2 policies defined, but they both reference the same
        // WebAssembly module. Hence, just one `.wasm` file is going to be
        // be downloaded
        assert_eq!(fetched_policies.len(), 1);

        assert!(
            fetched_policies
                .get("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9")
                .unwrap()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn http_policies_disabled() {
        let policies_cfg = r#"
    http-policy:
      module: https://127.0.0.1:1/policy.wasm
    "#;
        let policies: HashMap<String, PolicyOrPolicyGroup> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");
        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");
        let mut downloader = Downloader::new(None, None, false)
            .await
            .expect("Cannot create the downloader");

        let fetched_policies = downloader
            .download_policies(&policies, policy_download_dir.path(), None)
            .await;

        assert!(matches!(
            fetched_policies.get("https://127.0.0.1:1/policy.wasm"),
            Some(Err(error)) if error.to_string().contains("'http-policy'")
                && error.to_string().contains("--enable-http-policies")
        ));
    }

    #[tokio::test]
    async fn verify_error() {
        let verification_cfg_yml = r#"---
    allOf:
      - kind: githubAction
        owner: kubewarden
       "#;
        let verification_config =
            serde_yaml::from_str::<LatestVerificationConfig>(verification_cfg_yml)
                .expect("Cannot convert verification config");

        let policies_cfg = r#"
    pod-privileged:
      module: registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9
    "#;

        let policies: HashMap<String, PolicyOrPolicyGroup> =
            serde_yaml::from_str(policies_cfg).expect("Cannot parse policy cfg");

        let policy_download_dir = TempDir::new().expect("Cannot create temp dir");
        let trust_root = sigstore::trust::sigstore::SigstoreTrustRoot::new(None)
            .await
            .unwrap();

        let mut downloader = Downloader::new(None, Some(Arc::new(trust_root)), false)
            .await
            .unwrap();

        let fetched_policies = downloader
            .download_policies(
                &policies,
                policy_download_dir.path().to_str().unwrap(),
                Some(&verification_config),
            )
            .await;

        // There are 2 policies defined, but they both reference the same
        // WebAssembly module. Hence, just one `.wasm` file is going to be
        // be downloaded
        assert_eq!(fetched_policies.len(), 1);

        assert!(matches!(
            fetched_policies
                .get("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9")
                .unwrap(),
            Err(error) if error.to_string().contains("Policy 'pod-privileged' cannot be verified: Image verification failed: missing signatures")
        ));
    }
}
