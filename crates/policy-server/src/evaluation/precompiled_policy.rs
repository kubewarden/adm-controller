use std::{collections::HashMap, fs, path::Path, vec::Vec};

use anyhow::{Result, anyhow};
use lazy_static::lazy_static;
use policy_evaluator::{
    ProtocolVersion, ferricel_check_abi_version, policy_evaluator::PolicyExecutionMode,
    policy_metadata::Metadata, wasmtime,
};
use semver::{BuildMetadata, Prerelease, Version};
use sha2::{Digest, Sha256};

lazy_static! {
    static ref KUBEWARDEN_VERSION: Version = {
        let mut version = Version::parse(env!("CARGO_PKG_VERSION")).expect("Cannot parse CARGO_PKG_VERSION version");
        // Remove the patch, prerelease and build information to avoid rejections
        // like this: v1.6.0-rc4 < v1.6.0
        version.patch = 0;
        version.pre = Prerelease::EMPTY;
        version.build = BuildMetadata::EMPTY;
        version
    };
}

/// This structure holds a precompiled WebAssembly module
/// representing a policy.
///
/// Compiling a WebAssembly module is an expensive operation. Each
/// worker thread needs to do that, for each policy defined by the user.
///
/// Precompiling the policies ahead of time reduces the bootstrap time by a lot.
///
/// **Warning:** when "rehydrating" the module, you have to use a `wasmtime::Engine`
/// that has been created with the same `wasmtime::Config` used at compilation time.
#[derive(Clone)]
pub(crate) struct PrecompiledPolicy {
    /// A precompiled [`wasmtime::Module`]
    pub precompiled_module: Vec<u8>,

    /// The execution mode of the policy
    pub execution_mode: PolicyExecutionMode,

    /// sha256 digest of the precompiled module
    pub digest: String,
}

impl PrecompiledPolicy {
    /// Load a WebAssembly module from the disk and compiles it
    pub fn new(engine: &wasmtime::Engine, wasm_module_path: &Path) -> Result<Self> {
        let policy_contents = fs::read(wasm_module_path)?;
        let policy_metadata = Metadata::from_contents(&policy_contents)?;
        let metadata = policy_metadata.unwrap_or_default();
        let execution_mode = metadata.execution_mode;
        has_minimum_kubewarden_version(&metadata)?;

        has_valid_protocol_version(&metadata)?;

        // The evaluator receives a precompiled `wasmtime::Module`, which has
        // no custom sections. This is the last place where the raw bytes are
        // available, so the ferricel ABI check must run here.
        if execution_mode == PolicyExecutionMode::Ferricel {
            ferricel_check_abi_version(&policy_contents)?;
        }

        let precompiled_module = engine.precompile_module(&policy_contents)?;

        let mut hasher = Sha256::new();
        hasher.update(&precompiled_module);
        let digest = hasher.finalize();

        Ok(Self {
            precompiled_module,
            execution_mode,
            digest: hex::encode(digest),
        })
    }
}

/// A dictionary with:
/// * Key: the URL of the WebAssembly module
/// * Value: a Result containing the precompiled policy or an error.
///
/// Errors are stored and will be reported to the user in the API response.
pub(crate) type PrecompiledPolicies = HashMap<String, Result<PrecompiledPolicy>>;

/// Check if policy server version is compatible with  minimum kubewarden
/// version required by the policy
fn has_minimum_kubewarden_version(metadata: &Metadata) -> Result<()> {
    if let Some(minimum_kubewarden_version) = &metadata.minimum_kubewarden_version {
        let sanitized_minimum_kubewarden_version = Version {
            major: minimum_kubewarden_version.major,
            minor: minimum_kubewarden_version.minor,
            // Kubewarden stack version ignore patch, prerelease and build version numbers
            patch: 0,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };

        #[allow(clippy::to_string_in_format_args)]
        if *KUBEWARDEN_VERSION < sanitized_minimum_kubewarden_version {
            return Err(anyhow!(
                "Policy required Kubewarden version {} but is running on {}",
                sanitized_minimum_kubewarden_version,
                KUBEWARDEN_VERSION.to_string(),
            ));
        }
    }
    Ok(())
}

// Check if the policy uses a valid protocol version for KubewardenWapc policies
fn has_valid_protocol_version(metadata: &Metadata) -> Result<()> {
    if metadata.execution_mode == PolicyExecutionMode::KubewardenWapc {
        match &metadata.protocol_version {
            Some(ProtocolVersion::V1) => return Ok(()),
            Some(other) => {
                return Err(anyhow!(
                    "Policy uses protocol version {:?} but only V1 is supported",
                    other
                ));
            }
            None => {
                return Err(anyhow!(
                    "Policy is missing protocol version, which is required for KubewardenWapc execution mode"
                ));
            }
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn generate_metadata(major: u64, minor: u64, patch: u64) -> Metadata {
        let minimum_kubewarden_version = Version {
            major,
            minor,
            patch,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };
        Metadata {
            minimum_kubewarden_version: Some(minimum_kubewarden_version),
            ..Default::default()
        }
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major -1, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch))]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor - 1, KUBEWARDEN_VERSION.patch))]
    fn recent_kubewarden_versions_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major +1, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch))]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor + 1, KUBEWARDEN_VERSION.patch))]
    fn old_kubewarden_versions_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_err())
    }

    #[test]
    fn no_minimum_kubewarden_version_is_valid_test() {
        let metadata = Metadata {
            minimum_kubewarden_version: None,
            ..Default::default()
        };
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(generate_metadata(KUBEWARDEN_VERSION.major, KUBEWARDEN_VERSION.minor, KUBEWARDEN_VERSION.patch + 1))]
    fn ignore_patch_version_test(#[case] metadata: Metadata) {
        assert!(has_minimum_kubewarden_version(&metadata).is_ok())
    }

    #[rstest]
    #[case(Metadata {
        execution_mode: PolicyExecutionMode::KubewardenWapc,
        protocol_version: Some(ProtocolVersion::V1),
        ..Default::default()
    }, true)]
    #[case(Metadata {
        execution_mode: PolicyExecutionMode::KubewardenWapc,
        protocol_version: Some(ProtocolVersion::Unknown),
        ..Default::default()
    }, false)]
    #[case(Metadata {
        execution_mode: PolicyExecutionMode::Opa,
        protocol_version: Some(ProtocolVersion::Unknown),
        ..Default::default()
    }, true)]
    fn validate_protocol_version_test(#[case] metadata: Metadata, #[case] is_valid: bool) {
        assert_eq!(is_valid, has_valid_protocol_version(&metadata).is_ok())
    }
}
