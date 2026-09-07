use std::{borrow::Cow, collections::BTreeSet, path::Path, result::Result};

use wasmtime_provider::wasmtime;

use crate::{
    errors::PolicyEvaluatorBuilderError,
    policy_evaluator::{
        PolicyEvaluatorPre, PolicyExecutionMode, errors::InvalidUserInputError, stack_pre::StackPre,
    },
    runtimes::{ferricel, rego, wapc, wasi_cli},
};

/// Configure behavior of wasmtime [epoch-based interruptions](https://docs.rs/wasmtime/latest/wasmtime/struct.Config.html#method.epoch_interruption)
///
/// There are two kind of deadlines that apply to waPC modules:
///
/// * waPC initialization code: this is the code defined by the module inside
///   of the `wapc_init` or the `_start` functions
/// * user function: the actual waPC guest function written by an user
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct EpochDeadlines {
    /// Deadline for waPC initialization code. Expressed in number of epoch ticks
    pub wapc_init: u64,

    /// Deadline for user-defined waPC function computation. Expressed in number of epoch ticks
    pub wapc_func: u64,
}

/// Helper Struct that creates a `PolicyEvaluator` object
#[derive(Default)]
pub struct PolicyEvaluatorBuilder {
    engine: Option<wasmtime::Engine>,
    policy_file: Option<String>,
    policy_contents: Option<Vec<u8>>,
    policy_module: Option<wasmtime::Module>,
    execution_mode: Option<PolicyExecutionMode>,
    wasmtime_cache: bool,
    epoch_deadlines: Option<EpochDeadlines>,
}

impl PolicyEvaluatorBuilder {
    /// Create a new PolicyEvaluatorBuilder object.
    pub fn new() -> PolicyEvaluatorBuilder {
        PolicyEvaluatorBuilder::default()
    }

    /// [`wasmtime::Engine`] instance to be used when creating the
    /// policy evaluator
    ///
    /// **Warning:** when used, all the [`wasmtime::Engine`] specific settings
    /// must be set by the caller when creating the engine.
    /// This includes options like: cache, epoch counter
    #[must_use]
    pub fn engine(mut self, engine: wasmtime::Engine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Build the policy by reading the Wasm file from disk.
    /// Cannot be used at the same time as `policy_contents`
    pub fn policy_file(
        mut self,
        path: &Path,
    ) -> Result<PolicyEvaluatorBuilder, PolicyEvaluatorBuilderError> {
        let filename = path
            .to_str()
            .map(|s| s.to_string())
            .ok_or_else(|| PolicyEvaluatorBuilderError::ConvertPath)?;
        self.policy_file = Some(filename);
        Ok(self)
    }

    /// Build the policy by using the Wasm object given via the `data` array.
    /// Cannot be used at the same time as `policy_file`
    #[must_use]
    pub fn policy_contents(mut self, data: &[u8]) -> PolicyEvaluatorBuilder {
        self.policy_contents = Some(data.to_owned());
        self
    }

    /// Use a pre-built [`wasmtime::Module`] instance.
    /// **Warning:** you must provide also the [`wasmtime::Engine`] used
    /// to allocate the `Module`, otherwise the code will panic at runtime
    #[must_use]
    pub fn policy_module(mut self, module: wasmtime::Module) -> Self {
        self.policy_module = Some(module);
        self
    }

    /// Sets the policy execution mode
    #[must_use]
    pub fn execution_mode(mut self, mode: PolicyExecutionMode) -> PolicyEvaluatorBuilder {
        self.execution_mode = Some(mode);
        self
    }

    /// Enable Wasmtime cache feature
    #[must_use]
    pub fn enable_wasmtime_cache(mut self) -> PolicyEvaluatorBuilder {
        self.wasmtime_cache = true;
        self
    }

    /// Enable Wasmtime [epoch-based interruptions](wasmtime::Config::epoch_interruption) and set
    /// the deadlines to be enforced
    ///
    /// Two kind of deadlines have to be set:
    ///
    /// * `wapc_init_deadline`: the number of ticks the waPC initialization code can take before the
    ///   code is interrupted. This is the code usually defined inside of the `wapc_init`/`_start`
    ///   functions
    /// * `wapc_func_deadline`: the number of ticks any regular waPC guest function can run before
    ///   its terminated by the host
    ///
    /// Both these limits are expressed using the number of ticks that are allowed before the
    /// WebAssembly execution is interrupted.
    /// It's up to the embedder of waPC to define how much time a single tick is granted. This could
    /// be 1 second, 10 nanoseconds, or whatever the user prefers.
    ///
    /// **Warning:** when providing an instance of `wasmtime::Engine` via the
    /// `WasmtimeEngineProvider::engine` helper, ensure the `wasmtime::Engine`
    /// has been created with the `epoch_interruption` feature enabled
    #[must_use]
    pub fn enable_epoch_interruptions(
        mut self,
        wapc_init_deadline: u64,
        wapc_func_deadline: u64,
    ) -> Self {
        self.epoch_deadlines = Some(EpochDeadlines {
            wapc_init: wapc_init_deadline,
            wapc_func: wapc_func_deadline,
        });
        self
    }

    /// Ensure the configuration provided to the build is correct
    fn validate_user_input(&self) -> Result<(), InvalidUserInputError> {
        if self.policy_file.is_some() && self.policy_contents.is_some() {
            return Err(InvalidUserInputError::FileAndContents);
        }
        if self.policy_file.is_some() && self.policy_module.is_some() {
            return Err(InvalidUserInputError::FileAndModule);
        }
        if self.policy_contents.is_some() && self.policy_module.is_some() {
            return Err(InvalidUserInputError::ContentsAndModule);
        }

        if self.policy_file.is_none()
            && self.policy_contents.is_none()
            && self.policy_module.is_none()
        {
            return Err(InvalidUserInputError::OneOfFileContentsModule);
        }

        if self.engine.is_none() && self.policy_module.is_some() {
            return Err(InvalidUserInputError::EngineForModule);
        }

        Ok(())
    }

    /// Create the instance of `PolicyEvaluatorPre` to be used
    pub fn build_pre(&self) -> Result<PolicyEvaluatorPre, PolicyEvaluatorBuilderError> {
        self.validate_user_input()
            .map_err(PolicyEvaluatorBuilderError::InvalidUserInput)?;

        let engine = self.build_engine()?;
        let module = self.build_module(&engine)?;

        let execution_mode = self.execution_mode.unwrap_or_default();

        let stack_pre = match execution_mode {
            PolicyExecutionMode::KubewardenWapc => {
                let wapc_stack_pre = wapc::StackPre::new(engine, module)
                    .map_err(PolicyEvaluatorBuilderError::NewWapcStackPre)?;
                StackPre::from(wapc_stack_pre)
            }
            PolicyExecutionMode::Wasi => {
                let wasi_stack_pre = wasi_cli::StackPre::new(engine, module)
                    .map_err(PolicyEvaluatorBuilderError::NewWasiStackPre)?;
                StackPre::from(wasi_stack_pre)
            }
            PolicyExecutionMode::Opa | PolicyExecutionMode::OpaGatekeeper => {
                let rego_stack_pre = rego::StackPre::new(
                    engine,
                    module,
                    0, // currently the entrypoint is hard coded to this value
                    execution_mode.try_into()?,
                );
                StackPre::from(rego_stack_pre)
            }
            PolicyExecutionMode::Ferricel => {
                let vap_variables = self.ferricel_vap_variables()?;
                let ferricel_stack_pre = ferricel::StackPre::new(engine, module, vap_variables)
                    .map_err(PolicyEvaluatorBuilderError::NewFerricelStackPre)?;
                StackPre::from(ferricel_stack_pre)
            }
        };

        Ok(PolicyEvaluatorPre::new(stack_pre))
    }

    fn build_engine(&self) -> Result<wasmtime::Engine, PolicyEvaluatorBuilderError> {
        self.engine
            .as_ref()
            .map_or_else(
                || {
                    let mut wasmtime_config = wasmtime::Config::new();
                    if self.wasmtime_cache {
                        let cache = wasmtime::Cache::new(wasmtime::CacheConfig::new())?;
                        wasmtime_config.cache(Some(cache));
                    }
                    if self.epoch_deadlines.is_some() {
                        wasmtime_config.epoch_interruption(true);
                    }
                    // required by policies built by the official go compiler >= 1.26.0
                    wasmtime_config.wasm_function_references(true);

                    wasmtime::Engine::new(&wasmtime_config)
                },
                |e| Ok(e.clone()),
            )
            .map_err(PolicyEvaluatorBuilderError::WasmtimeEngineBuild)
    }

    fn build_module(
        &self,
        engine: &wasmtime::Engine,
    ) -> Result<wasmtime::Module, PolicyEvaluatorBuilderError> {
        if let Some(m) = &self.policy_module {
            // it's fine to clone a Module, this is a cheap operation that just
            // copies its internal reference. See wasmtime docs
            Ok(m.clone())
        } else {
            match &self.policy_file {
                Some(file) => wasmtime::Module::from_file(engine, file)
                    .map_err(PolicyEvaluatorBuilderError::WasmModuleBuild),
                None => wasmtime::Module::new(engine, self.policy_contents.as_ref().unwrap())
                    .map_err(PolicyEvaluatorBuilderError::WasmModuleBuild),
            }
        }
    }

    /// Determine the well-known VAP variables (e.g. `namespaceObject`)
    /// referenced by the compiled ferricel policy, by inspecting the
    /// `ferricel.vap-variables` Wasm custom section (see
    /// [`ferricel_core::vap_variables_used`]).
    ///
    /// Returns `None` -- meaning "unknown, assume every variable may be
    /// referenced" -- when the raw Wasm bytes aren't available, i.e. the
    /// `policy_module` builder input was used (this is how `policy-server`
    /// builds its evaluators, from a pre-compiled/deserialized
    /// `wasmtime::Module`, which does not retain the original Wasm bytes or
    /// their custom sections).
    fn ferricel_vap_variables(
        &self,
    ) -> Result<Option<BTreeSet<String>>, PolicyEvaluatorBuilderError> {
        let wasm_bytes: Cow<'_, [u8]> = match (&self.policy_contents, &self.policy_file) {
            (Some(contents), _) => Cow::Borrowed(contents.as_slice()),
            (None, Some(file)) => Cow::Owned(
                std::fs::read(file)
                    .map_err(PolicyEvaluatorBuilderError::ReadPolicyFileForVapVariables)?,
            ),
            (None, None) => return Ok(None),
        };

        let vap_variables = ferricel_core::vap_variables_used(&wasm_bytes)
            .map_err(PolicyEvaluatorBuilderError::ReadVapVariables)?;
        Ok(Some(vap_variables.into_iter().collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_policy_evaluator_pre() {
        let engine = wasmtime::Engine::default();
        let wat = include_bytes!("../../tests/data/endless_wasm/wapc_endless_loop.wat");
        let module = wasmtime::Module::new(&engine, wat).expect("cannot compile WAT to wasm");

        let policy_evaluator_builder = PolicyEvaluatorBuilder::new()
            .execution_mode(PolicyExecutionMode::KubewardenWapc)
            .policy_module(module)
            .engine(engine)
            .enable_wasmtime_cache()
            .enable_epoch_interruptions(1, 2);

        _ = policy_evaluator_builder.build_pre().unwrap();
    }
}
