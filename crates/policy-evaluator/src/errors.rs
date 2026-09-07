use thiserror::Error;

use crate::policy_evaluator::errors::InvalidUserInputError;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ArtifactHubError {
    #[error("no annotations in policy metadata. policy metadata must specify annotations")]
    NoAnnotations,

    #[error("policy version must be in semver: {0}")]
    NoSemverVersion(String),

    #[error("questions-ui content cannot be empty")]
    EmptyQuestionsUI,

    #[error("policy metadata must specify \"{0}\" in annotations")]
    MissingAnnotation(String),

    #[error("annotation \"{annot:?}\" in policy metadata must be a well formed URL: {error:?}")]
    MalformedURL { annot: String, error: String },

    #[error("annotation \"{0}\" in policy metadata is malformed, must be csv values")]
    MalformedCSV(String),

    #[error(
        "annotation \"{0}\" in policy metadata is malformed, must be csv values of \"name <email>\""
    )]
    MalformedCSVEmail(String),

    #[error("annotation \"{annot:?}\" in policy metadata must be a well formed email: {error:?}")]
    MalformedEmail { annot: String, error: String },

    #[error(
        "annotation \"{0}\" in policy metadata is malformed, must be a string \"true\" or \"false\""
    )]
    MalformedBoolString(String),
}

#[derive(Error, Debug)]
pub enum PolicyEvaluatorError {
    #[error("protocol_version is only applicable to a Kubewarden policy")]
    InvalidProtocolVersion(),

    #[error("protocol_version is only applicable to a Kubewarden policy")]
    InvokeWapcProtocolVersion(#[source] crate::runtimes::wapc::errors::WapcRuntimeError),
}

#[derive(Error, Debug)]
pub enum PolicyEvaluatorBuilderError {
    #[error("cannot convert given path to String")]
    ConvertPath,

    #[error("execution mode not convertible to a Rego based execution mode")]
    ExecutionModeNotRegoCompatible,

    #[error("execution mode '{0}' is not supported for direct evaluation")]
    UnsupportedExecutionMode(crate::policy_evaluator::PolicyExecutionMode),

    #[error("protocol_version is only applicable to a Kubewarden policy")]
    InvokeWapcProtocolVersion(#[source] crate::runtimes::wapc::errors::WapcRuntimeError),

    #[error(transparent)]
    InvalidUserInput(#[from] InvalidUserInputError),

    #[error("error when creating wasmtime engine: {0}")]
    WasmtimeEngineBuild(#[source] wasmtime::Error),

    #[error("error when building wasm module: {0}")]
    WasmModuleBuild(#[source] wasmtime::Error),

    #[error("error when building wapc precompiled stack: {0}")]
    NewWapcStackPre(#[source] crate::runtimes::wapc::errors::WapcRuntimeError),

    #[error("error when building wasi precompiled stack: {0}")]
    NewWasiStackPre(#[source] crate::runtimes::wasi_cli::errors::WasiRuntimeError),

    #[error("error when building rego precompiled stack")]
    NewRegoStackPre(#[source] wasmtime::Error),

    #[error("error when building ferricel precompiled stack: {0}")]
    NewFerricelStackPre(#[source] crate::runtimes::ferricel::errors::FerricelRuntimeError),

    #[error("cannot read policy file to inspect ferricel VAP variables: {0}")]
    ReadPolicyFileForVapVariables(#[source] std::io::Error),

    #[error("cannot read VAP variables referenced by the compiled ferricel module: {0}")]
    ReadVapVariables(#[source] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum PolicyEvaluatorPreError {
    #[error("unable to rehydrate wapc module: {0}")]
    RehydrateWapc(#[source] crate::runtimes::wapc::errors::WapcRuntimeError),

    #[error("unable to rehydrate rego module: {0}")]
    RehydrateRego(#[source] crate::runtimes::rego::errors::RegoRuntimeError),
}

#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("cannot read metadata from path: {0}")]
    Path(#[source] std::io::Error),

    #[error("cannot parse custom section of wasm module: {0}")]
    WasmPayload(#[source] wasmparser::BinaryReaderError),

    #[error("cannot deserialize custom section `{section}` of wasm module: {error}")]
    Deserialize {
        section: String,
        #[source]
        error: serde_json::Error,
    },
}

#[derive(Error, Debug)]
pub enum ResponseError {
    #[error("cannot deserialize JSONPatch: {0}")]
    Deserialize(#[source] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostCapabilitiesPatternError {
    #[error(
        "invalid pattern {pattern:?}: wildcard '*' must be the entire last path segment (e.g. 'oci/*'), not a partial match"
    )]
    InvalidWildcard { pattern: String },
    #[error("invalid pattern: pattern must not be empty")]
    Empty,
    #[error(
        "invalid pattern {pattern:?}: unknown segment {segment:?}, valid options at this level are: {valid_options}"
    )]
    UnknownSegment {
        pattern: String,
        segment: String,
        valid_options: String,
    },
    #[error(
        "invalid pattern {pattern:?}: not a complete capability path; use {suggestion:?} to allow all capabilities under it"
    )]
    IncompleteCapabilityPath { pattern: String, suggestion: String },
}
