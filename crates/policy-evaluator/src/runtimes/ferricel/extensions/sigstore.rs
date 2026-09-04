use std::{collections::BTreeMap, sync::Arc};

use ferricel_types::extensions::{BuilderChainDecl, BuilderStep, ExtensionDecl};
use kubewarden_policy_sdk::host_capabilities::verification::{KeylessInfo, KeylessPrefixInfo};
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType, evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::call_host,
};

/// `BuilderChainDecl` for the `kw.sigstore` library.
///
/// ```text
/// kw.sigstore.image(<string>)                          → kw.sigstore.VerifierBuilder
///   .annotation(<string>, <string>)                    → kw.sigstore.VerifierBuilder  (map-entry)
///   .pubKey(<string>)                                  → kw.sigstore.PubKeysVerifier  (accumulate)
///     .pubKey(<string>)                                → kw.sigstore.PubKeysVerifier  (accumulate)
///     .verify()                                        → dyn  (host call: kw.sigstore/pubKeyVerify)
///   .keyless(<string>, <string>)                       → kw.sigstore.KeylessVerifier  (accumulate)
///     .keyless(<string>, <string>)                     → kw.sigstore.KeylessVerifier  (accumulate)
///     .verify()                                        → dyn  (host call: kw.sigstore/keylessVerify)
///   .keylessPrefix(<string>, <string>)                 → kw.sigstore.KeylessPrefixVerifier  (accumulate)
///     .keylessPrefix(<string>, <string>)               → kw.sigstore.KeylessPrefixVerifier  (accumulate)
///     .verify()                                        → dyn  (host call: kw.sigstore/keylessPrefixVerify)
///   .githubAction(<string>)                            → kw.sigstore.GitHubActionVerifier
///   .githubAction(<string>, <string>)                  → kw.sigstore.GitHubActionVerifier
///     .verify()                                        → dyn  (host call: kw.sigstore/githubActionsVerify)
///   .certificate(<string>)                             → kw.sigstore.CertificateVerifier
///     .certificateChain(<string>)                      → kw.sigstore.CertificateVerifier  (accumulate)
///     .requireRekorBundle(<bool>)                      → kw.sigstore.CertificateVerifier
///     .verify()                                        → dyn  (host call: kw.sigstore/certificateVerify)
/// ```
pub fn chain() -> BuilderChainDecl {
    BuilderChainDecl {
        steps: vec![
            // ── Entry ─────────────────────────────────────────────────────────
            BuilderStep::Entry {
                function: "kw.sigstore.image".to_string(),
                state_keys: vec!["image".to_string()],
                output_type: "kw.sigstore.VerifierBuilder".to_string(),
            },
            // ── annotation (map-entry) ────────────────────────────────────────
            // .annotation(key, value) accumulates into a nested "annotations" map.
            BuilderStep::MapEntry {
                function: "annotation".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_key: "annotations".to_string(),
                output_type: "kw.sigstore.VerifierBuilder".to_string(),
            },
            // ── pubKey (transition + accumulate) ─────────────────────────────
            // First .pubKey() transitions VerifierBuilder → PubKeysVerifier.
            BuilderStep::Chain {
                function: "pubKey".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["pubKeys".to_string()],
                output_type: "kw.sigstore.PubKeysVerifier".to_string(),
                accumulate: true,
            },
            // Subsequent .pubKey() calls accumulate on PubKeysVerifier.
            BuilderStep::Chain {
                function: "pubKey".to_string(),
                input_type: "kw.sigstore.PubKeysVerifier".to_string(),
                state_keys: vec!["pubKeys".to_string()],
                output_type: "kw.sigstore.PubKeysVerifier".to_string(),
                accumulate: true,
            },
            // Terminal for PubKeysVerifier.
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.PubKeysVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "pubKeyVerify".to_string(),
            },
            // ── keyless (transition + accumulate) ────────────────────────────
            // First .keyless(issuer, subject) transitions VerifierBuilder → KeylessVerifier.
            BuilderStep::Chain {
                function: "keyless".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["keylessIssuers".to_string(), "keylessSubjects".to_string()],
                output_type: "kw.sigstore.KeylessVerifier".to_string(),
                accumulate: true,
            },
            // Subsequent .keyless() calls accumulate on KeylessVerifier.
            BuilderStep::Chain {
                function: "keyless".to_string(),
                input_type: "kw.sigstore.KeylessVerifier".to_string(),
                state_keys: vec!["keylessIssuers".to_string(), "keylessSubjects".to_string()],
                output_type: "kw.sigstore.KeylessVerifier".to_string(),
                accumulate: true,
            },
            // Terminal for KeylessVerifier.
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.KeylessVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "keylessVerify".to_string(),
            },
            // ── keylessPrefix (transition + accumulate) ───────────────────────
            BuilderStep::Chain {
                function: "keylessPrefix".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec![
                    "keylessPrefixIssuers".to_string(),
                    "keylessPrefixUrls".to_string(),
                ],
                output_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Chain {
                function: "keylessPrefix".to_string(),
                input_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                state_keys: vec![
                    "keylessPrefixIssuers".to_string(),
                    "keylessPrefixUrls".to_string(),
                ],
                output_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "keylessPrefixVerify".to_string(),
            },
            // ── githubAction (1-arg: owner only) ─────────────────────────────
            BuilderStep::Chain {
                function: "githubAction".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["owner".to_string()],
                output_type: "kw.sigstore.GitHubActionVerifier".to_string(),
                accumulate: false,
            },
            // ── githubAction (2-arg: owner + repo) ───────────────────────────
            BuilderStep::Chain {
                function: "githubAction".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["owner".to_string(), "repo".to_string()],
                output_type: "kw.sigstore.GitHubActionVerifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.GitHubActionVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "githubActionsVerify".to_string(),
            },
            // ── certificate chain ─────────────────────────────────────────────
            BuilderStep::Chain {
                function: "certificate".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["certificate".to_string()],
                output_type: "kw.sigstore.CertificateVerifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Chain {
                function: "certificateChain".to_string(),
                input_type: "kw.sigstore.CertificateVerifier".to_string(),
                state_keys: vec!["certificateChain".to_string()],
                output_type: "kw.sigstore.CertificateVerifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Chain {
                function: "requireRekorBundle".to_string(),
                input_type: "kw.sigstore.CertificateVerifier".to_string(),
                state_keys: vec!["requireRekorBundle".to_string()],
                output_type: "kw.sigstore.CertificateVerifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.CertificateVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "certificateVerify".to_string(),
            },
        ],
    }
}

// ─── Runtime extension declarations ──────────────────────────────────────────

pub fn pub_key_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "pubKeyVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn keyless_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "keylessVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn keyless_prefix_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "keylessPrefixVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn github_actions_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "githubActionsVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn certificate_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "certificateVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

/// `.digest()` -- receiver-style accessor that reads `digest` from the
/// `VerificationResponse` returned by any sigstore verify call. No host call.
pub fn digest_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: None,
        function: "digest".to_string(),
        global_style: false,
        receiver_style: true,
        num_args: 1,
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────
//
// All five verify variants are dispatched under the "oci"/"v2/verify" host
// capability (see `host_capabilities()` in `extensions.rs`), matching how the
// waPC/Wasi `host_callback` handles the internally-tagged
// `SigstoreVerificationInputV2` payload for the same operation.

pub(crate) fn pub_key_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = builder_map["image"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.pubKeyVerify: missing 'image'".to_string())?
        .to_owned();

    let pub_keys: Vec<String> = builder_map["pubKeys"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let annotations = parse_annotations(builder_map);

    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        CallbackRequestType::SigstorePubKeyVerify {
            image,
            pub_keys,
            annotations,
        },
    )
    .map_err(|e| format!("kw.sigstore.pubKeyVerify: {e}"))
}

pub(crate) fn keyless_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = builder_map["image"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.keylessVerify: missing 'image'".to_string())?
        .to_owned();

    // issuers and subjects are stored as parallel arrays; zip them into KeylessInfo pairs.
    let keyless = zip_keyless(builder_map, "keylessIssuers", "keylessSubjects")
        .map_err(|e| format!("kw.sigstore.keylessVerify: {e}"))?;

    let annotations = parse_annotations(builder_map);

    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        CallbackRequestType::SigstoreKeylessVerify {
            image,
            keyless,
            annotations,
        },
    )
    .map_err(|e| format!("kw.sigstore.keylessVerify: {e}"))
}

pub(crate) fn keyless_prefix_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = builder_map["image"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.keylessPrefixVerify: missing 'image'".to_string())?
        .to_owned();

    let issuers = str_array(builder_map, "keylessPrefixIssuers")
        .map_err(|e| format!("kw.sigstore.keylessPrefixVerify: {e}"))?;
    let urls = str_array(builder_map, "keylessPrefixUrls")
        .map_err(|e| format!("kw.sigstore.keylessPrefixVerify: {e}"))?;

    if issuers.len() != urls.len() {
        return Err(format!(
            "kw.sigstore.keylessPrefixVerify: issuer/urlPrefix arrays have different lengths ({} vs {})",
            issuers.len(),
            urls.len()
        ));
    }

    let keyless_prefix: Vec<KeylessPrefixInfo> = issuers
        .into_iter()
        .zip(urls)
        .map(|(issuer, url_prefix)| KeylessPrefixInfo { issuer, url_prefix })
        .collect();

    let annotations = parse_annotations(builder_map);

    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        CallbackRequestType::SigstoreKeylessPrefixVerify {
            image,
            keyless_prefix,
            annotations,
        },
    )
    .map_err(|e| format!("kw.sigstore.keylessPrefixVerify: {e}"))
}

pub(crate) fn github_actions_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = builder_map["image"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.githubActionsVerify: missing 'image'".to_string())?
        .to_owned();

    let owner = builder_map["owner"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.githubActionsVerify: missing 'owner'".to_string())?
        .to_owned();

    // `repo` is optional — only set by the 2-arg githubAction overload.
    let repo = builder_map["repo"].as_str().map(str::to_owned);

    let annotations = parse_annotations(builder_map);

    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        CallbackRequestType::SigstoreGithubActionsVerify {
            image,
            owner,
            repo,
            annotations,
        },
    )
    .map_err(|e| format!("kw.sigstore.githubActionsVerify: {e}"))
}

pub(crate) fn certificate_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = builder_map["image"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.certificateVerify: missing 'image'".to_string())?
        .to_owned();

    let cert_pem = builder_map["certificate"]
        .as_str()
        .ok_or_else(|| "kw.sigstore.certificateVerify: missing 'certificate'".to_string())?;
    let certificate: Vec<u8> = cert_pem.as_bytes().to_vec();

    let certificate_chain: Option<Vec<Vec<u8>>> =
        builder_map["certificateChain"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|pem| pem.as_bytes().to_vec())
                .collect()
        });
    let certificate_chain = certificate_chain.filter(|v| !v.is_empty());

    let require_rekor_bundle = builder_map["requireRekorBundle"].as_bool().unwrap_or(false);

    let annotations = parse_annotations(builder_map);

    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        CallbackRequestType::SigstoreCertificateVerify {
            image,
            certificate,
            certificate_chain,
            require_rekor_bundle,
            annotations,
        },
    )
    .map_err(|e| format!("kw.sigstore.certificateVerify: {e}"))
}

/// `.digest()` -- no host call. Returns the `digest` field from the
/// `VerificationResponse` map (`{"is_trusted": bool, "digest": string}`).
pub(crate) fn digest_handler(args: &[Value]) -> Result<Value, String> {
    args.first()
        .and_then(|v| v.get("digest"))
        .cloned()
        .ok_or_else(|| "digest: expected a response map with a 'digest' field".to_string())
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Parse the optional `annotations` nested map from the builder state.
fn parse_annotations(builder_map: &Value) -> Option<BTreeMap<String, String>> {
    builder_map["annotations"].as_object().map(|obj| {
        obj.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect()
    })
}

/// Extract a string array from a builder map field. Returns an empty Vec if
/// the field is absent; errors if present but not an array of strings.
fn str_array(map: &Value, key: &str) -> Result<Vec<String>, String> {
    match &map[key] {
        Value::Null => Ok(vec![]),
        Value::Array(arr) => Ok(arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()),
        other => Err(format!("field '{key}' is not an array (got {other})")),
    }
}

/// Zip parallel `issuers` and `subjects` arrays into `Vec<KeylessInfo>`.
fn zip_keyless(
    map: &Value,
    issuers_key: &str,
    subjects_key: &str,
) -> Result<Vec<KeylessInfo>, String> {
    let issuers = str_array(map, issuers_key)?;
    let subjects = str_array(map, subjects_key)?;

    if issuers.len() != subjects.len() {
        return Err(format!(
            "issuer/subject arrays have different lengths ({} vs {})",
            issuers.len(),
            subjects.len()
        ));
    }

    Ok(issuers
        .into_iter()
        .zip(subjects)
        .map(|(issuer, subject)| KeylessInfo { issuer, subject })
        .collect())
}
