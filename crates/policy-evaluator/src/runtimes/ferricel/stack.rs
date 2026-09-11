use std::{collections::BTreeSet, sync::Arc};

use wasmtime_provider::wasmtime;

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::ferricel::{errors::FerricelRuntimeError, stack_pre::StackPre},
};

/// Per-evaluation state for the ferricel runtime.
pub(crate) struct Stack {
    engine: Arc<ferricel_core::runtime::Engine>,
    eval_ctx: Arc<EvaluationContext>,

    /// See [`StackPre`]'s `vap_variables` field docs for `None` semantics.
    vap_variables: Option<Arc<BTreeSet<String>>>,
}

impl Stack {
    pub fn new_from_pre(stack_pre: &StackPre, eval_ctx: &EvaluationContext) -> Self {
        Self {
            engine: Arc::new(stack_pre.rehydrate(eval_ctx)),
            eval_ctx: Arc::new(eval_ctx.clone()),
            vap_variables: stack_pre.vap_variables(),
        }
    }

    pub(crate) fn eval_ctx(&self) -> &EvaluationContext {
        &self.eval_ctx
    }

    /// Whether the compiled policy may reference the well-known VAP variable
    /// `name` (e.g. `"namespaceObject"`).
    ///
    /// Returns `true` conservatively when this information isn't available
    /// (see [`StackPre`]'s `vap_variables` field docs), so that callers
    /// default to their historical, always-provide behavior in that case.
    pub(crate) fn references_vap_variable(&self, name: &str) -> bool {
        self.vap_variables
            .as_deref()
            .is_none_or(|vars| vars.contains(name))
    }

    /// Evaluate the compiled Wasm module with the given JSON-encoded bindings.
    ///
    /// The error tells the caller what went wrong:
    ///   - [`FerricelRuntimeError::ExecutionDeadlineExceeded`] when the
    ///     evaluation ran past the epoch deadline configured with
    ///     [`EvaluationContext::epoch_deadline`].
    ///   - [`FerricelRuntimeError::CelRuntimeError`] when the CEL expression
    ///     of the policy evaluated to an error. Only this error is subject to
    ///     the VAP `failurePolicy`.
    ///   - [`FerricelRuntimeError::EvalFailed`] for every other failure: a
    ///     Wasm trap, a memory limit, a missing export, or a bug in the host.
    pub fn eval(&self, bindings_json: Option<&str>) -> Result<String, FerricelRuntimeError> {
        self.engine.eval(bindings_json).map_err(|e| {
            if matches!(
                e.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::Interrupt)
            ) {
                return FerricelRuntimeError::ExecutionDeadlineExceeded;
            }
            if let Some(cel_err) = e.downcast_ref::<ferricel_core::CelRuntimeError>() {
                return FerricelRuntimeError::CelRuntimeError(cel_err.clone());
            }
            FerricelRuntimeError::EvalFailed(e)
        })
    }
}
