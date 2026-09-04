use std::sync::Arc;

use ferricel_types::extensions::{BuilderChainDecl, BuilderStep, ExtensionDecl};
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{call_host, str_field},
};

/// `BuilderChainDecl` for the `kw.oci` library.
///
/// ```text
/// kw.oci.image(<string>)   → kw.oci.Client
///   .manifest()            → dyn  (host call: kw.oci.manifest)
///   .manifestDigest()      → dyn  (host call: kw.oci.manifestDigest)
///   .manifestConfig()      → dyn  (host call: kw.oci.manifestConfig)
/// ```
pub fn chain() -> BuilderChainDecl {
    BuilderChainDecl {
        steps: vec![
            BuilderStep::Entry {
                function: "kw.oci.image".to_string(),
                state_keys: vec!["image".to_string()],
                output_type: "kw.oci.Client".to_string(),
            },
            BuilderStep::Terminal {
                function: "manifest".to_string(),
                input_type: "kw.oci.Client".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.oci".to_string(),
                host_function: "manifest".to_string(),
            },
            BuilderStep::Terminal {
                function: "manifestDigest".to_string(),
                input_type: "kw.oci.Client".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.oci".to_string(),
                host_function: "manifestDigest".to_string(),
            },
            BuilderStep::Terminal {
                function: "manifestConfig".to_string(),
                input_type: "kw.oci.Client".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.oci".to_string(),
                host_function: "manifestConfig".to_string(),
            },
        ],
    }
}

// ─── Runtime extension declarations ──────────────────────────────────────────

pub fn manifest_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.oci".to_string()),
        function: "manifest".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn manifest_digest_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.oci".to_string()),
        function: "manifestDigest".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn manifest_config_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.oci".to_string()),
        function: "manifestConfig".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub(crate) fn manifest_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = str_field(builder_map, "image").map_err(|e| format!("kw.oci.manifest: {e}"))?;
    call_host(
        eval_ctx,
        "oci",
        "v1/oci_manifest",
        CallbackRequestType::OciManifest { image },
    )
    .map_err(|e| format!("kw.oci.manifest: {e}"))
}

pub(crate) fn manifest_digest_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image =
        str_field(builder_map, "image").map_err(|e| format!("kw.oci.manifestDigest: {e}"))?;
    call_host(
        eval_ctx,
        "oci",
        "v1/manifest_digest",
        CallbackRequestType::OciManifestDigest { image },
    )
    .map_err(|e| format!("kw.oci.manifestDigest: {e}"))
}

pub(crate) fn manifest_config_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image =
        str_field(builder_map, "image").map_err(|e| format!("kw.oci.manifestConfig: {e}"))?;
    call_host(
        eval_ctx,
        "oci",
        "v1/oci_manifest_config",
        CallbackRequestType::OciManifestAndConfig { image },
    )
    .map_err(|e| format!("kw.oci.manifestConfig: {e}"))
}
