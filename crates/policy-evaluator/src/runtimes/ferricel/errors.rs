use thiserror::Error;

#[derive(Error, Debug)]
pub enum FerricelRuntimeError {
    #[error("failed to build ferricel engine: {0}")]
    EngineBuild(#[source] anyhow::Error),

    /// The `{0:#}` (alternate) format flattens `anyhow::Error`'s cause chain
    /// into the message. This matters here specifically: a CEL runtime error
    /// (e.g. a denied `kw.*` extension call, or a compiled VAP validation
    /// that failed to evaluate) surfaces to the host as a wasmtime trap
    /// whose top-level `Display` is a generic
    /// "error while executing at wasm backtrace: ..." message; the actual CEL
    /// error text (e.g. "kw.k8s.get: Policy has not been granted access to
    /// ...") only appears in the trap's cause chain. Using plain `{0}` here
    /// would silently discard it from every rejection message this error
    /// flows into.
    #[error("ferricel evaluation failed: {0:#}")]
    EvalFailed(#[source] anyhow::Error),

    #[error("policy execution interrupted: execution deadline exceeded")]
    ExecutionDeadlineExceeded,

    #[error("cannot serialize ferricel bindings: {0}")]
    BindingsSerialization(#[source] serde_json::Error),

    #[error("cannot deserialize ferricel response: {0}")]
    ResponseDeserialization(#[source] serde_json::Error),
}
