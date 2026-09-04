use std::fmt;

use kubewarden_policy_sdk::{metadata::ProtocolVersion, settings::SettingsValidationResponse};

use crate::{
    admission_response::AdmissionResponse,
    errors::PolicyEvaluatorError,
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicySettings, ValidateRequest},
    runtimes::{
        Runtime, ferricel::Runtime as FerricelRuntime, rego::Runtime as BurregoRuntime,
        wapc::Runtime as WapcRuntime, wasi_cli::Runtime as WasiRuntime,
    },
};

pub struct PolicyEvaluator {
    runtime: Runtime,
    eval_ctx: EvaluationContext,
}

impl PolicyEvaluator {
    pub(crate) fn new(runtime: Runtime, eval_ctx: &EvaluationContext) -> Self {
        Self {
            runtime,
            eval_ctx: eval_ctx.to_owned(),
        }
    }

    #[tracing::instrument(skip(request))]
    pub fn validate(
        &mut self,
        request: ValidateRequest,
        settings: &PolicySettings,
    ) -> AdmissionResponse {
        match self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => {
                WapcRuntime(wapc_stack).validate(settings, &request)
            }
            Runtime::Rego(ref mut burrego_evaluator) => {
                let kube_ctx = burrego_evaluator.build_kubernetes_context(
                    self.eval_ctx.callback_channel.as_ref(),
                    &self.eval_ctx.ctx_aware_resources_allow_list,
                );
                match kube_ctx {
                    Ok(ctx) => BurregoRuntime(burrego_evaluator).validate(settings, &request, &ctx),
                    Err(e) => {
                        AdmissionResponse::reject(request.uid().to_string(), e.to_string(), 500)
                    }
                }
            }
            Runtime::Cli(ref mut cli_stack) => WasiRuntime(cli_stack).validate(settings, &request),
            Runtime::Ferricel(ref mut ferricel_stack) => {
                FerricelRuntime(ferricel_stack).validate(settings, &request)
            }
        }
    }

    #[tracing::instrument]
    pub fn validate_settings(&mut self, settings: &PolicySettings) -> SettingsValidationResponse {
        let settings_str = match serde_json::to_string(settings) {
            Ok(settings) => settings,
            Err(err) => {
                return SettingsValidationResponse {
                    valid: false,
                    message: Some(format!("could not marshal settings: {err}")),
                };
            }
        };

        match self.runtime {
            Runtime::Wapc(ref mut wapc_stack) => {
                WapcRuntime(wapc_stack).validate_settings(settings_str)
            }
            Runtime::Rego(ref mut burrego_evaluator) => {
                BurregoRuntime(burrego_evaluator).validate_settings(settings_str)
            }
            Runtime::Cli(ref mut cli_stack) => {
                WasiRuntime(cli_stack).validate_settings(settings_str)
            }
            Runtime::Ferricel(ref mut ferricel_stack) => {
                FerricelRuntime(ferricel_stack).validate_settings(settings_str)
            }
        }
    }

    pub fn protocol_version(&mut self) -> Result<ProtocolVersion, PolicyEvaluatorError> {
        match &mut self.runtime {
            Runtime::Wapc(wapc_stack) => Ok(WapcRuntime(wapc_stack)
                .protocol_version()
                .map_err(PolicyEvaluatorError::InvokeWapcProtocolVersion)?),
            _ => Err(PolicyEvaluatorError::InvalidProtocolVersion()),
        }
    }
}

impl fmt::Debug for PolicyEvaluator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let runtime = self.runtime.to_string();

        f.debug_struct("PolicyEvaluator")
            .field("runtime", &runtime)
            .finish()
    }
}
