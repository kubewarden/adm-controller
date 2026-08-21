use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use itertools::Itertools;
use kubewarden_policy_sdk::host_capabilities::verification::{
    KeylessInfo, KeylessPrefixInfo, VerificationResponse,
};
use policy_fetcher::{
    sigstore::{self, trust::sigstore::SigstoreTrustRoot},
    sources::Sources,
    verify::{
        Verifier,
        config::{LatestVerificationConfig, Signature, Subject},
        fetch_sigstore_remote_data,
    },
};
use sha2::{Digest, Sha256};
use sigstore::{
    cosign::verification_constraint::{
        AnnotationVerifier, CertificateVerifier, VerificationConstraintVec,
    },
    registry::{Certificate, CertificateEncoding},
};
use tokio::sync::Mutex;
use tracing::warn;

use super::cache;

/// Sigstore verifications are expensive, so the results are kept in the shared
/// cache for this long.
const SIGSTORE_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(crate) struct Client {
    cosign_client: Arc<Mutex<sigstore::cosign::Client>>,
    verifier: Verifier,
}

impl Client {
    pub async fn new(
        sources: Option<Sources>,
        trust_root: Option<Arc<SigstoreTrustRoot>>,
    ) -> Result<Self> {
        let cosign_client = Arc::new(Mutex::new(
            Self::build_cosign_client(sources.clone(), trust_root).await?,
        ));
        let verifier = Verifier::new_from_cosign_client(cosign_client.clone(), sources);

        Ok(Client {
            cosign_client,
            verifier,
        })
    }

    async fn build_cosign_client(
        sources: Option<Sources>,
        trust_root: Option<Arc<SigstoreTrustRoot>>,
    ) -> Result<sigstore::cosign::Client> {
        let client_config: sigstore::registry::ClientConfig = sources.unwrap_or_default().into();

        let mut cosign_client_builder = sigstore::cosign::ClientBuilder::default()
            .with_oci_client_config(client_config)
            .enable_registry_caching();
        let cosign_client = match trust_root {
            Some(trust_root) => {
                cosign_client_builder =
                    cosign_client_builder.with_trust_repository(trust_root.as_ref())?;
                cosign_client_builder.build()?
            }
            None => {
                warn!(
                    "Sigstore Verifier created without Fulcio data: keyless signatures are going to be discarded because they cannot be verified"
                );
                warn!(
                    "Sigstore Verifier created without Rekor data: transparency log data won't be used"
                );
                warn!("Sigstore capabilities are going to be limited");

                cosign_client_builder.build()?
            }
        };
        Ok(cosign_client)
    }

    pub async fn verify_public_key(
        &mut self,
        image: String,
        pub_keys: Vec<String>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if pub_keys.is_empty() {
            return Err(anyhow!("Must provide at least one pub key"));
        }
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in pub_keys.iter() {
            let signature = Signature::PubKey {
                owner: None,
                key: k.clone(),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self.verifier.verify(&image, &verification_config).await;
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn verify_keyless(
        &mut self,
        image: String,
        keyless: Vec<KeylessInfo>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if keyless.is_empty() {
            return Err(anyhow!("Must provide keyless info"));
        }
        // Build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in keyless.iter() {
            let signature = Signature::GenericIssuer {
                issuer: k.issuer.clone(),
                subject: Subject::Equal(k.subject.clone()),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self.verifier.verify(&image, &verification_config).await;
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn verify_keyless_prefix(
        &mut self,
        image: String,
        keyless_prefix: Vec<KeylessPrefixInfo>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if keyless_prefix.is_empty() {
            return Err(anyhow!("Must provide keyless info"));
        }
        // Build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        for k in keyless_prefix.iter() {
            let prefix = url::Url::parse(&k.url_prefix).expect("Cannot build url prefix");
            let signature = Signature::GenericIssuer {
                issuer: k.issuer.clone(),
                subject: Subject::UrlPrefix(prefix),
                annotations: annotations.clone(),
            };
            signatures_all_of.push(signature);
        }
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self.verifier.verify(&image, &verification_config).await;
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn verify_github_actions(
        &mut self,
        image: String,
        owner: String,
        repo: Option<String>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<VerificationResponse> {
        if owner.is_empty() {
            return Err(anyhow!("Must provide owner info"));
        }
        // Build interim VerificationConfig:
        //
        let mut signatures_all_of: Vec<Signature> = Vec::new();
        let signature = Signature::GithubAction {
            owner: owner.clone(),
            repo: repo.clone(),
            annotations: annotations.clone(),
        };
        signatures_all_of.push(signature);
        let verification_config = LatestVerificationConfig {
            all_of: Some(signatures_all_of),
            any_of: None,
        };

        let result = self.verifier.verify(&image, &verification_config).await;
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn verify_certificate(
        &mut self,
        image: &str,
        certificate: &[u8],
        certificate_chain: Option<&[Vec<u8>]>,
        require_rekor_bundle: bool,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<VerificationResponse> {
        let (source_image_digest, trusted_layers) =
            fetch_sigstore_remote_data(&self.cosign_client, image).await?;
        let chain: Option<Vec<Certificate>> = certificate_chain.map(|certs| {
            certs
                .iter()
                .map(|cert_data| Certificate {
                    data: cert_data.to_owned(),
                    encoding: CertificateEncoding::Pem,
                })
                .collect()
        });

        let cert_verifier =
            CertificateVerifier::from_pem(certificate, require_rekor_bundle, chain.as_deref())?;

        let mut verification_constraints: VerificationConstraintVec = vec![Box::new(cert_verifier)];
        if let Some(a) = annotations {
            let annotations_verifier = AnnotationVerifier { annotations: a };
            verification_constraints.push(Box::new(annotations_verifier));
        }

        let result =
            sigstore::cosign::verify_constraints(&trusted_layers, verification_constraints.iter())
                .map(|_| source_image_digest)
                .map_err(|e| anyhow!("verification failed: {}", e));
        match result {
            Ok(digest) => Ok(VerificationResponse {
                digest,
                is_trusted: true,
            }),
            Err(e) => Err(e),
        }
    }
}

// Sigstore verifications are time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
pub(crate) async fn get_sigstore_pub_key_verification_cached(
    cache: &dyn cache::Cache,
    client: &mut Client,
    image: String,
    pub_keys: Vec<String>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<cached::Return<VerificationResponse>> {
    let sub_key = format!("sigstore_pubkey:{image}{pub_keys:?}{annotations:?}");
    cache::internal_cached(cache, &sub_key, SIGSTORE_CACHE_TTL, || async move {
        client.verify_public_key(image, pub_keys, annotations).await
    })
    .await
}

// Sigstore verifications are time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
pub(crate) async fn get_sigstore_keyless_verification_cached(
    cache: &dyn cache::Cache,
    client: &mut Client,
    image: String,
    keyless: Vec<KeylessInfo>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<cached::Return<VerificationResponse>> {
    let sub_key = format!("sigstore_keyless:{image}{keyless:?}{annotations:?}");
    cache::internal_cached(cache, &sub_key, SIGSTORE_CACHE_TTL, || async move {
        client.verify_keyless(image, keyless, annotations).await
    })
    .await
}

// Sigstore verifications are time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
pub(crate) async fn get_sigstore_keyless_prefix_verification_cached(
    cache: &dyn cache::Cache,
    client: &mut Client,
    image: String,
    keyless_prefix: Vec<KeylessPrefixInfo>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<cached::Return<VerificationResponse>> {
    let sub_key = format!("sigstore_keyless_prefix:{image}{keyless_prefix:?}{annotations:?}");
    cache::internal_cached(cache, &sub_key, SIGSTORE_CACHE_TTL, || async move {
        client
            .verify_keyless_prefix(image, keyless_prefix, annotations)
            .await
    })
    .await
}

// Sigstore verifications are time expensive, this can cause a massive slow down
// of policy evaluations, especially inside of PolicyServer.
// Because of that we will keep a cache of the digests results.
//
// Details about this cache:
//   * the cache is time bound: cached values are purged after 60 seconds
//   * only successful results are cached
pub(crate) async fn get_sigstore_github_actions_verification_cached(
    cache: &dyn cache::Cache,
    client: &mut Client,
    image: String,
    owner: String,
    repo: Option<String>,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<cached::Return<VerificationResponse>> {
    let sub_key = format!("sigstore_github_actions:{image}{owner}{repo:?}{annotations:?}");
    cache::internal_cached(cache, &sub_key, SIGSTORE_CACHE_TTL, || async move {
        client
            .verify_github_actions(image, owner, repo, annotations)
            .await
    })
    .await
}

fn get_sigstore_certificate_verification_cache_key(
    image: &str,
    certificate: &[u8],
    certificate_chain: Option<&[Vec<u8>]>,
    require_rekor_bundle: bool,
    annotations: Option<&BTreeMap<String, String>>,
) -> String {
    let mut hasher = Sha256::new();

    hasher.update(image);
    hasher.update(certificate);

    if let Some(certs) = certificate_chain {
        for c in certs {
            hasher.update(c);
        }
    };

    if require_rekor_bundle {
        hasher.update(b"1");
    } else {
        hasher.update(b"0");
    };

    if let Some(a) = annotations {
        for key in a.keys().sorted() {
            hasher.update(key);
            hasher.update(b"\n");
            hasher.update(a.get(key).expect("key not found"));
        }
    };

    hex::encode(hasher.finalize())
}

pub(crate) async fn get_sigstore_certificate_verification_cached(
    cache: &dyn cache::Cache,
    client: &mut Client,
    image: &str,
    certificate: &[u8],
    certificate_chain: Option<&[Vec<u8>]>,
    require_rekor_bundle: bool,
    annotations: Option<BTreeMap<String, String>>,
) -> Result<cached::Return<VerificationResponse>> {
    let sub_key = format!(
        "sigstore_certificate:{}",
        get_sigstore_certificate_verification_cache_key(
            image,
            certificate,
            certificate_chain,
            require_rekor_bundle,
            annotations.as_ref(),
        )
    );
    cache::internal_cached(cache, &sub_key, SIGSTORE_CACHE_TTL, || async move {
        client
            .verify_certificate(
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            )
            .await
    })
    .await
}
