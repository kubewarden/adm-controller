use std::fmt::Display;

use crate::policy_evaluator::RegoPolicyExecutionMode;

pub(crate) mod callback;
pub mod ferricel;
pub(crate) mod rego;
pub(crate) mod wapc;
pub(crate) mod wasi_cli;

pub(crate) enum Runtime {
    // This enum uses the `Box` type to avoid the need for a large enum size causing memory layout
    // problems. https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant
    Wapc(Box<wapc::WapcStack>),
    Rego(Box<rego::Stack>),
    Cli(wasi_cli::Stack),
    Ferricel(ferricel::Stack),
}

impl Display for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Runtime::Cli(_) => write!(f, "wasi"),
            Runtime::Wapc(_) => write!(f, "wapc"),
            Runtime::Ferricel(_) => write!(f, "ferricel"),
            Runtime::Rego(stack) => match stack.policy_execution_mode {
                RegoPolicyExecutionMode::Opa => {
                    write!(f, "OPA")
                }
                RegoPolicyExecutionMode::Gatekeeper => {
                    write!(f, "Gatekeeper")
                }
            },
        }
    }
}
