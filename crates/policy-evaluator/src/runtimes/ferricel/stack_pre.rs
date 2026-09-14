use std::{collections::BTreeSet, sync::Arc};

use ferricel_core::EnginePre;
use ferricel_types::LogLevel;
use wasmtime_provider::wasmtime;

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::ferricel::{errors::FerricelRuntimeError, extensions, logging},
};

/// Pre-initialized ferricel engine.
///
/// Stores a [`ferricel_core::EnginePre`] -- the pre-compiled, pre-linked
/// [`wasmtime::InstancePre`] without any extension function implementations.
/// Extension functions are injected at rehydration time in
/// [`rehydrate`](StackPre::rehydrate), where the per-evaluation
/// [`EvaluationContext`] (including the callback channel) is available.
///
/// [`Clone`] is cheap: [`EnginePre`] is internally `Arc`-backed, and
/// `vap_variables` is `Arc`-wrapped for the same reason -- `StackPre` is
/// rehydrated into a new [`super::stack::Stack`] on every evaluation (see
/// `new_from_pre`), so cloning it must not deep-copy this set on every
/// request.
#[derive(Clone)]
pub(crate) struct StackPre {
    engine_pre: EnginePre,

    /// The well-known VAP variables (see ferricel's `ferricel.vap-variables`
    /// Wasm custom section) referenced by the compiled policy, when known.
    ///
    /// `None` when the raw Wasm bytes were not available at build time (e.g.
    /// the `PolicyEvaluatorBuilder::policy_module` path, used by
    /// `policy-server`, which only has a pre-compiled `wasmtime::Module`) or
    /// the module predates ferricel's `vap-variables` section. Consumers must
    /// treat `None` conservatively, i.e. as if every variable may be
    /// referenced.
    ///
    /// Only consumed by [`super::stack::Stack`] (via
    /// [`Self::vap_variables`]); `StackPre` itself never reads it.
    vap_variables: Option<Arc<BTreeSet<String>>>,
}

impl StackPre {
    /// Create a new `StackPre` from the already-compiled `wasmtime::Module`.
    ///
    /// The `engine` must be the same engine used to compile the module.
    /// This runs the linker setup and `instantiate_pre` once; per-request
    /// cost is then limited to [`rehydrate`](Self::rehydrate).
    ///
    /// `vap_variables` should be the set of well-known VAP variables (from
    /// ferricel's `ferricel.vap-variables` Wasm custom section, see
    /// [`ferricel_core::vap_variables_used`]) referenced by the compiled
    /// policy, or `None` if that information is not available (see the
    /// `vap_variables` field docs).
    pub fn new(
        wasm_engine: wasmtime::Engine,
        module: wasmtime::Module,
        vap_variables: Option<BTreeSet<String>>,
    ) -> Result<Self, FerricelRuntimeError> {
        let engine_pre = ferricel_core::runtime::Builder::new()
            .with_engine(wasm_engine)
            .with_module(module)
            // Forward all guest log levels to the host tracing subscriber;
            // the subscriber's own filter decides what is actually recorded.
            .with_log_level(LogLevel::Debug)
            .build_pre()
            .map_err(FerricelRuntimeError::EngineBuild)?;
        Ok(Self {
            engine_pre,
            vap_variables: vap_variables.map(Arc::new),
        })
    }

    /// The well-known VAP variables referenced by the compiled policy, or
    /// `None` if that information isn't available. Cloning the returned
    /// `Arc` is cheap; used by [`super::stack::Stack::new_from_pre`] to hand
    /// each `Stack` its own reference without deep-copying the set.
    pub(crate) fn vap_variables(&self) -> Option<Arc<BTreeSet<String>>> {
        self.vap_variables.clone()
    }

    /// Create a ready-to-use [`ferricel_core::runtime::Engine`] by injecting
    /// all Kubewarden host-capability extension functions and a per-evaluation
    /// logger that routes guest `cel_log` events to the `policy_log` tracing
    /// target with `policy_id` attached.
    ///
    /// Every extension is always registered. Extensions that require a callback
    /// channel return a clear error if `eval_ctx.callback_channel` is `None`.
    ///
    /// `eval_ctx.epoch_deadline`, when set, is forwarded to
    /// [`ferricel_core::runtime::EnginePre::rehydrate`] and applied to the
    /// [`wasmtime::Store`] created for every evaluation. This requires the
    /// shared [`wasmtime::Engine`] used to build this `StackPre` to have been
    /// created with `epoch_interruption` enabled (see
    /// `PolicyEvaluatorBuilder::enable_epoch_interruptions`); otherwise the
    /// deadline has no effect. Conversely, if epoch interruption is enabled on
    /// the engine but no deadline is set here, evaluation traps immediately.
    pub(crate) fn rehydrate(&self, eval_ctx: &EvaluationContext) -> ferricel_core::runtime::Engine {
        self.engine_pre.rehydrate(
            extensions::build_extensions(eval_ctx),
            logging::policy_logger(eval_ctx.policy_id.clone()),
            eval_ctx.epoch_deadline,
        )
    }
}
