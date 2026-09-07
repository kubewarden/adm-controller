pub extern crate burrego;

pub mod admission_request;
pub mod admission_response;
pub mod admission_response_handler;
pub mod callback_handler;
pub mod callback_requests;
pub mod constants;
pub mod errors;
pub mod evaluation_context;
pub mod host_capabilities;
pub mod policy_artifacthub;
pub mod policy_evaluator;
pub mod policy_group_evaluator;
pub mod policy_metadata;
mod policy_tracing;
pub mod runtimes;

// API's that expose other crate types (such as Kubewarden Policy SDK
// or `policy_fetcher`) can either implement their own exposed types,
// and means to convert those types internally to their dependencies
// types, or depending on the specific case, re-export dependencies
// API's directly.
//
// Re-exporting specific crates that belong to us is easier for common
// consumers of these libraries along with the `policy-evaluator`, so
// they can access these crates through the `policy-evaluator` itself,
// streamlining their dependencies as well.
pub use kube;
pub use kubewarden_policy_sdk::{self, metadata::ProtocolVersion};
pub use policy_evaluator::policy_evaluator_builder;
pub use policy_fetcher;
/// Chain and extension declarations for the ferricel compiler.
///
/// Use these when compiling a Kubewarden VAP policy with ferricel so that
/// the compiler knows about all Kubewarden host-capability extensions the
/// policy may call at evaluation time.
pub use runtimes::ferricel::extensions::{
    compiler_builder_chains as ferricel_compiler_builder_chains,
    compiler_extension_decls as ferricel_compiler_extension_decls,
    host_capabilities as ferricel_host_capabilities,
};
pub use validator;
pub use wasmparser;
pub use wasmtime_provider::wasmtime;
