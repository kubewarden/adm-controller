use thiserror::Error;

#[derive(Error, Debug)]
pub enum FerricelRuntimeError {
    #[error("failed to build ferricel engine: {0}")]
    EngineBuild(#[source] anyhow::Error),

    /// The CEL expression of the policy evaluated to an error. Examples: a
    /// division by zero, a field that does not exist, or a `kw.*` call that
    /// the host denied. The `origin` field of the inner error names the host
    /// extension that produced the error, when there is one.
    ///
    /// This is the only failure that the VAP `failurePolicy` applies to.
    /// The runtime decides what to do with it. See
    /// `runtimes::ferricel::runtime::Runtime::validate`.
    #[error("CEL runtime error: {}", format_cel_error(.0))]
    CelRuntimeError(ferricel_core::CelRuntimeError),

    /// The `{0:#}` (alternate) format flattens the cause chain of
    /// `anyhow::Error` into the message. The top-level `Display` of a wasmtime
    /// trap is a generic "error while executing at wasm backtrace: ..."
    /// message. The useful text is in the cause chain. Plain `{0}` would
    /// discard it from every rejection message this error flows into.
    #[error("ferricel evaluation failed: {0:#}")]
    EvalFailed(#[source] anyhow::Error),

    #[error("policy execution interrupted: execution deadline exceeded")]
    ExecutionDeadlineExceeded,

    #[error("cannot serialize ferricel bindings: {0}")]
    BindingsSerialization(#[source] serde_json::Error),

    #[error("cannot deserialize ferricel response: {0}")]
    ResponseDeserialization(#[source] serde_json::Error),

    #[error("cannot read the ferricel ABI version of the module: {0}")]
    ReadAbiVersion(#[source] anyhow::Error),

    /// The module was built by a ferricel compiler with a different ABI
    /// (the contract between the Wasm module and the host runtime).
    #[error(
        "the ferricel module uses ABI version {}. This runtime supports ABI version {expected}. \
         Compile the policy again with a newer kwctl",
        found.map_or_else(|| "unknown".to_string(), |v| v.to_string())
    )]
    AbiVersionMismatch { found: Option<u32>, expected: u32 },
}

/// Format a [`ferricel_core::CelRuntimeError`] as `<origin>: <message>`, or
/// as `<message>` when the error did not come from a host extension.
pub(crate) fn format_cel_error(err: &ferricel_core::CelRuntimeError) -> String {
    match &err.origin {
        Some(origin) => format!("{origin}: {}", err.message),
        None => err.message.clone(),
    }
}

/// Make sure that `wasm` was built for the ferricel ABI version that this
/// runtime supports.
///
/// The ferricel runtime does this check on its own only when it receives
/// the raw Wasm bytes. Kubewarden gives it a compiled [`wasmtime::Module`],
/// which has no custom sections, so the check must run here. Without it, an
/// old module loads without an error and then fails on every evaluation
/// with a message that does not name the real cause.
///
/// [`wasmtime::Module`]: wasmtime_provider::wasmtime::Module
pub fn check_abi_version(wasm: &[u8]) -> Result<(), FerricelRuntimeError> {
    let found = ferricel_core::abi_version(wasm).map_err(FerricelRuntimeError::ReadAbiVersion)?;
    match found {
        Some(v) if v == ferricel_core::ABI_VERSION => Ok(()),
        _ => Err(FerricelRuntimeError::AbiVersionMismatch {
            found,
            expected: ferricel_core::ABI_VERSION,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_abi_version_rejects_module_without_section() {
        // A minimal valid Wasm module: magic + version, no sections.
        let wasm = b"\0asm\x01\0\0\0";
        let err = check_abi_version(wasm).expect_err("module without ABI section must be rejected");
        assert!(
            matches!(
                err,
                FerricelRuntimeError::AbiVersionMismatch {
                    found: None,
                    expected
                } if expected == ferricel_core::ABI_VERSION
            ),
            "unexpected error: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("unknown"),
            "message must name the missing version: {msg}"
        );
        assert!(
            msg.contains("newer kwctl"),
            "message must tell the user what to do: {msg}"
        );
    }

    #[test]
    fn format_cel_error_includes_origin_when_present() {
        let err = ferricel_core::CelRuntimeError::new("divide by zero");
        assert_eq!(format_cel_error(&err), "divide by zero");

        let err = ferricel_core::CelRuntimeError::from_extension(
            "Policy has not been granted access",
            Some("kw.k8s"),
            "get",
        );
        assert_eq!(
            format_cel_error(&err),
            "kw.k8s.get: Policy has not been granted access"
        );
    }
}
