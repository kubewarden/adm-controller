use std::result::Result;

use crate::{
    errors::PolicyEvaluatorPreError,
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicyEvaluator, stack_pre::StackPre},
    runtimes::{Runtime, ferricel, rego, wapc, wasi_cli},
};

/// This struct provides a way to quickly allocate a `PolicyEvaluator`
/// object.
///
/// See the [`rehydrate`](PolicyEvaluatorPre::rehydrate) method.
#[derive(Clone)]
pub struct PolicyEvaluatorPre {
    stack_pre: StackPre,
}

impl PolicyEvaluatorPre {
    pub(crate) fn new(stack_pre: StackPre) -> Self {
        PolicyEvaluatorPre { stack_pre }
    }

    /// Create a `PolicyEvaluator` instance. The creation of the instance is achieved by
    /// using wasmtime low level primitives (like `wasmtime::InstancePre`) to make the operation
    /// as fast as possible.
    ///
    /// Warning: the Rego stack cannot make use of these low level primitives, but its
    /// instantiation times are negligible. More details inside of the
    /// documentation of [`rego::StackPre`](crate::runtimes::rego::StackPre).
    pub fn rehydrate(
        &self,
        eval_ctx: &EvaluationContext,
    ) -> Result<PolicyEvaluator, PolicyEvaluatorPreError> {
        let runtime = match &self.stack_pre {
            StackPre::Wapc(stack_pre) => {
                let wapc_stack = wapc::WapcStack::new_from_pre(stack_pre, eval_ctx)
                    .map_err(PolicyEvaluatorPreError::RehydrateWapc)?;
                Runtime::Wapc(Box::new(wapc_stack))
            }
            StackPre::Wasi(stack_pre) => {
                let wasi_stack = wasi_cli::Stack::new_from_pre(stack_pre, eval_ctx);
                Runtime::Cli(wasi_stack)
            }
            StackPre::Rego(stack_pre) => {
                let rego_stack = rego::Stack::new_from_pre(stack_pre, eval_ctx)
                    .map_err(PolicyEvaluatorPreError::RehydrateRego)?;
                Runtime::Rego(Box::new(rego_stack))
            }
            StackPre::Ferricel(stack_pre) => {
                let ferricel_stack = ferricel::Stack::new_from_pre(stack_pre, eval_ctx);
                Runtime::Ferricel(ferricel_stack)
            }
        };

        Ok(PolicyEvaluator::new(runtime, eval_ctx))
    }
}
