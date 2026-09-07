use std::path::Path;

use anyhow::{Result, anyhow};
use policy_evaluator::{policy_evaluator::PolicyExecutionMode, policy_metadata::Metadata};

use crate::backend::BackendDetector;

/// Determines the policy execution mode based on the provided metadata,
pub(crate) fn determine_execution_mode(
    metadata: Option<&Metadata>,
    user_execution_mode: Option<PolicyExecutionMode>,
    backend_detector: BackendDetector,
    wasm_path: &Path,
) -> Result<PolicyExecutionMode> {
    // Desired behaviour, as documented here: https://github.com/kubewarden/kwctl/issues/58
    //
    // When a wasm file is annotated:
    // *  if the user didn't specify a runtime to be used: kwctl will use
    //    this information to pick the right runtime
    // *  if the user specified a runtime to be used: we error out if the
    //    value provided by the user does not match with the one
    //    inside of the wasm metadata
    //
    //When a wasm file is NOT annotated:
    // * If the user didn't specify a runtime to be used:
    //   - We do a quick heuristic to understand if the policy is Rego base:
    //      - If we do not find the OPA ABI constant -> we assume the policy is
    //        a kubewarden one
    //      - If we do find the policy was built using Rego, kwctl exists with
    //        an error because the user has to specify whether this is a OPA
    //        or Gatekeeper policy (that influences how kwctl builds the input and
    //        data variables)
    // * If the user does provide the --runtime-mode flag: we use the runtime
    //   the user specified

    let is_rego_policy = backend_detector.is_rego_policy(wasm_path)?;

    if let Some(metadata) = metadata {
        // If metadata is set, we can use it to determine the execution mode
        return determine_execution_mode_from_metadata(
            metadata,
            user_execution_mode,
            is_rego_policy,
        );
    }

    if let Some(user_execution_mode) = user_execution_mode {
        // If the user provided an execution mode, we need to verify it
        return verify_user_provided_execution_mode(user_execution_mode, is_rego_policy);
    }

    // no metadata and no user execution mode provided, we can only make sure
    // that the policy is not a Rego one and then default to Kubewarden WAPC
    if is_rego_policy {
        return Err(anyhow!(
            "The policy has been created with Rego, please specify which Opa runtime has to be used"
        ));
    }

    Ok(PolicyExecutionMode::KubewardenWapc)
}

fn determine_execution_mode_from_metadata(
    metadata: &Metadata,
    user_execution_mode: Option<PolicyExecutionMode>,
    is_rego_policy: bool,
) -> Result<PolicyExecutionMode> {
    let mode = match user_execution_mode {
        Some(usermode) if usermode == metadata.execution_mode => Ok(metadata.execution_mode),
        Some(usermode) => Err(anyhow!(
            "The policy execution mode specified via CLI flag is different from the one reported inside of policy's metadata. Metadata reports {} instead of {}",
            metadata.execution_mode,
            usermode
        )),
        None => Ok(metadata.execution_mode),
    }?;

    if (mode != PolicyExecutionMode::OpaGatekeeper && mode != PolicyExecutionMode::Opa)
        && is_rego_policy
    {
        return Err(anyhow!(
            "The policy has been created with Rego, the policy execution mode specified via CLI flag is wrong"
        ));
    }

    if (mode == PolicyExecutionMode::OpaGatekeeper || mode == PolicyExecutionMode::Opa)
        && !is_rego_policy
    {
        return Err(anyhow!(
            "The policy has not been created with Rego, the policy execution mode specified via CLI flag is wrong"
        ));
    }

    Ok(mode)
}

fn verify_user_provided_execution_mode(
    user_execution_mode: PolicyExecutionMode,
    is_rego_policy: bool,
) -> Result<PolicyExecutionMode> {
    if user_execution_mode == PolicyExecutionMode::OpaGatekeeper
        || user_execution_mode == PolicyExecutionMode::Opa
    {
        if is_rego_policy {
            return Ok(user_execution_mode);
        } else {
            return Err(anyhow!(
                "The policy has not been created with Rego, the policy execution mode specified via CLI flag is wrong"
            ));
        }
    }

    if is_rego_policy {
        return Err(anyhow!(
            "The policy has been created with Rego, the policy execution mode specified via CLI flag is wrong"
        ));
    }

    Ok(user_execution_mode)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use policy_evaluator::ProtocolVersion;
    use rstest::rstest;

    use super::*;

    fn mock_protocol_version_detector_v1(_wasm_path: PathBuf) -> Result<ProtocolVersion> {
        Ok(ProtocolVersion::V1)
    }

    fn mock_rego_policy_detector_true(_wasm_path: PathBuf) -> Result<bool> {
        Ok(true)
    }

    fn mock_rego_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    fn mock_ferricel_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    fn beckend_detector_always_rego() -> BackendDetector {
        BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        )
    }

    fn backend_detector_never_rego() -> BackendDetector {
        BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        )
    }

    fn build_metadata(execution_mode: PolicyExecutionMode) -> Metadata {
        Metadata {
            execution_mode,
            ..Default::default()
        }
    }

    #[rstest]
    #[case::metadata_and_user_mode_are_not_aligned_policy_is_not_rego(
        Some(build_metadata(PolicyExecutionMode::Opa)),
        Some(PolicyExecutionMode::KubewardenWapc),
        backend_detector_never_rego(),
        None
    )]
    #[case::metadata_and_user_mode_are_not_aligned_policy_is_rego(
        Some(build_metadata(PolicyExecutionMode::Opa)),
        Some(PolicyExecutionMode::KubewardenWapc),
        beckend_detector_always_rego(),
        None
    )]
    #[case::metadata_and_user_mode_are_not_aligned_policy_is_not_rego(
        Some(build_metadata(PolicyExecutionMode::Wasi)),
        Some(PolicyExecutionMode::Wasi),
        backend_detector_never_rego(),
        Some(PolicyExecutionMode::Wasi)
    )]
    #[case::metadata_and_user_mode_are_not_aligned_policy_but_is_rego(
        Some(build_metadata(PolicyExecutionMode::Wasi)),
        Some(PolicyExecutionMode::Wasi),
        beckend_detector_always_rego(),
        None
    )]
    #[case::metadata_and_user_mode_are_not_aligned_policy_but_is_rego(
        Some(build_metadata(PolicyExecutionMode::OpaGatekeeper)),
        Some(PolicyExecutionMode::OpaGatekeeper),
        backend_detector_never_rego(),
        None
    )]
    #[case::metadata_set_user_mode_is_not_set_is_opa_and_policy_is_rego(
        Some(build_metadata(PolicyExecutionMode::Opa)),
        None,
        beckend_detector_always_rego(),
        Some(PolicyExecutionMode::Opa)
    )]
    #[case::metadata_not_set_user_mode_is_opa_and_policy_is_rego(
        None,
        Some(PolicyExecutionMode::Opa),
        beckend_detector_always_rego(),
        Some(PolicyExecutionMode::Opa)
    )]
    #[case::metadata_not_set_user_mode_is_wapc_and_policy_is_not_rego(
        None,
        Some(PolicyExecutionMode::KubewardenWapc),
        backend_detector_never_rego(),
        Some(PolicyExecutionMode::KubewardenWapc)
    )]
    #[case::metadata_not_set_user_mode_is_wasi_and_policy_is_rego(
        None,
        Some(PolicyExecutionMode::Wasi),
        beckend_detector_always_rego(),
        None
    )]
    #[case::metadata_not_set_user_mode_is_opa_and_policy_is_not_rego(
        None,
        Some(PolicyExecutionMode::Opa),
        backend_detector_never_rego(),
        None
    )]
    #[case::metadata_set_ferricel_user_mode_not_set(
        Some(build_metadata(PolicyExecutionMode::Ferricel)),
        None,
        backend_detector_never_rego(),
        Some(PolicyExecutionMode::Ferricel)
    )]
    #[case::metadata_not_set_user_mode_is_ferricel(
        None,
        Some(PolicyExecutionMode::Ferricel),
        backend_detector_never_rego(),
        Some(PolicyExecutionMode::Ferricel)
    )]
    fn test_determine_execution_mode(
        #[case] metadata: Option<Metadata>,
        #[case] user_execution_mode: Option<PolicyExecutionMode>,
        #[case] backend_detector: BackendDetector,
        #[case] expected: Option<PolicyExecutionMode>,
    ) {
        let mode_result = determine_execution_mode(
            metadata.as_ref(),
            user_execution_mode,
            backend_detector,
            &PathBuf::from("irrelevant.wasm"),
        );

        if let Some(expected) = expected {
            assert!(
                mode_result.is_ok(),
                "Expected to be ok, got error: {:?}",
                mode_result
            );
            assert_eq!(mode_result.unwrap(), expected);
        } else {
            assert!(mode_result.is_err());
        }
    }
}
