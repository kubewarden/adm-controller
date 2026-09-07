use std::sync::Arc;

use ferricel_types::extensions::{BuilderChainDecl, BuilderStep, ExtensionDecl};
use kubewarden_policy_sdk::host_capabilities::{
    crypto::{Certificate, CertificateEncoding},
    crypto_v1::CertificateVerificationRequest,
};
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType, evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::call_host,
};

/// `BuilderChainDecl` for the `kw.crypto` library.
///
/// ```text
/// kw.crypto.certificate(<string>)          → kw.crypto.Verifier
///   .certificateChain(<string>)            → kw.crypto.Verifier  (accumulates)
///   .notAfter(<google.protobuf.Timestamp>) → kw.crypto.Verifier  (RFC-3339 string)
///   .verify()                              → dyn  (host call: kw.crypto.verify)
/// ```
pub fn chain() -> BuilderChainDecl {
    BuilderChainDecl {
        steps: vec![
            BuilderStep::Entry {
                function: "kw.crypto.certificate".to_string(),
                state_keys: vec!["cert".to_string()],
                output_type: "kw.crypto.Verifier".to_string(),
            },
            BuilderStep::Chain {
                function: "certificateChain".to_string(),
                input_type: "kw.crypto.Verifier".to_string(),
                state_keys: vec!["certChain".to_string()],
                output_type: "kw.crypto.Verifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Chain {
                function: "notAfter".to_string(),
                input_type: "kw.crypto.Verifier".to_string(),
                state_keys: vec!["notAfter".to_string()],
                output_type: "kw.crypto.Verifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.crypto.Verifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.crypto".to_string(),
                host_function: "verify".to_string(),
            },
        ],
    }
}

// ─── Runtime extension declarations ──────────────────────────────────────────

pub fn verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.crypto".to_string()),
        function: "verify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

/// `.isTrusted()` -- receiver-style accessor that reads `trusted` from the
/// response map returned by `kw.crypto.verify`. No host call is made.
pub fn is_trusted_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: None,
        function: "isTrusted".to_string(),
        global_style: false,
        receiver_style: true,
        num_args: 1,
    }
}

/// `.reason()` -- receiver-style accessor that reads `reason` from the
/// response map returned by `kw.crypto.verify`. No host call is made.
pub fn reason_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: None,
        function: "reason".to_string(),
        global_style: false,
        receiver_style: true,
        num_args: 1,
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub(crate) fn verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let cert_pem = builder_map["cert"]
        .as_str()
        .ok_or_else(|| "kw.crypto.verify: missing 'cert' field in builder map".to_string())?;
    let cert = Certificate {
        encoding: CertificateEncoding::Pem,
        data: cert_pem.as_bytes().to_vec(),
    };

    let cert_chain: Option<Vec<Certificate>> = builder_map["certChain"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str())
            .map(|pem| Certificate {
                encoding: CertificateEncoding::Pem,
                data: pem.as_bytes().to_vec(),
            })
            .collect()
    });
    // Treat an empty chain array the same as no chain.
    let cert_chain = cert_chain.filter(|v| !v.is_empty());

    // `notAfter` is an RFC-3339 string serialized by ferricel from a CEL timestamp.
    let not_after = builder_map["notAfter"].as_str().map(str::to_owned);

    let request = CertificateVerificationRequest {
        cert,
        cert_chain,
        not_after,
    };

    call_host(
        eval_ctx,
        "crypto",
        "v1/is_certificate_trusted",
        CallbackRequestType::CryptoIsCertificateTrusted { request },
    )
    .map_err(|e| format!("kw.crypto.verify: {e}"))
}

/// Handler for `.isTrusted()` -- no host call. Returns the boolean trust field
/// from a verify response map. Accepts either:
/// - `{"trusted": bool, ...}` (kw.crypto response), or
/// - `{"is_trusted": bool, ...}` (kw.sigstore VerificationResponse).
pub(crate) fn is_trusted_handler(args: &[Value]) -> Result<Value, String> {
    let map = args
        .first()
        .ok_or_else(|| "isTrusted: expected at least one argument".to_string())?;
    // Try the crypto key first, then the sigstore key.
    map.get("trusted")
        .or_else(|| map.get("is_trusted"))
        .cloned()
        .ok_or_else(|| {
            "isTrusted: expected a response map with a 'trusted' or 'is_trusted' field".to_string()
        })
}

/// Handler for `.reason()` -- no host call. Returns the `reason` field from
/// the verify response map as a JSON string.
pub(crate) fn reason_handler(args: &[Value]) -> Result<Value, String> {
    args.first()
        .and_then(|v| v.get("reason"))
        .cloned()
        .ok_or_else(|| "reason: expected a response map with a 'reason' field".to_string())
}
