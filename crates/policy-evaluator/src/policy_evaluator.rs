pub mod errors;
mod evaluator;
pub mod policy_evaluator_builder;
mod policy_evaluator_pre;
mod stack_pre;

use std::{convert::TryFrom, fmt, result::Result};

pub use evaluator::PolicyEvaluator;
use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
pub use policy_evaluator_pre::PolicyEvaluatorPre;
use serde::{Deserialize, Serialize};
use serde_json::value;

use crate::{admission_request::AdmissionRequest, errors::PolicyEvaluatorBuilderError};

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum PolicyExecutionMode {
    #[serde(rename = "kubewarden-wapc")]
    #[default]
    KubewardenWapc,
    #[serde(rename = "opa")]
    Opa,
    #[serde(rename = "gatekeeper")]
    OpaGatekeeper,
    #[serde(rename = "wasi")]
    Wasi,
    #[serde(rename = "ferricel")]
    Ferricel,
}

impl fmt::Display for PolicyExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error {})?;
        write!(f, "{}", json.replace('"', ""))
    }
}

/// A validation request that can be sent to a policy evaluator.
/// It can be either a raw JSON object, or a Kubernetes AdmissionRequest.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ValidateRequest {
    Raw(serde_json::Value),
    // This enum uses the `Box` type to avoid the need for a large enum size causing memory layout
    // problems. https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant
    AdmissionRequest(Box<AdmissionRequest>),
}

impl ValidateRequest {
    pub fn uid(&self) -> &str {
        match self {
            ValidateRequest::Raw(raw_req) => raw_req
                .get("uid")
                .and_then(value::Value::as_str)
                .unwrap_or_default(),
            ValidateRequest::AdmissionRequest(adm_req) => &adm_req.uid,
        }
    }
}

#[derive(Clone)]
pub(crate) enum RegoPolicyExecutionMode {
    Opa,
    Gatekeeper,
}

impl TryFrom<PolicyExecutionMode> for RegoPolicyExecutionMode {
    type Error = PolicyEvaluatorBuilderError;

    fn try_from(
        execution_mode: PolicyExecutionMode,
    ) -> Result<RegoPolicyExecutionMode, Self::Error> {
        match execution_mode {
            PolicyExecutionMode::Opa => Ok(RegoPolicyExecutionMode::Opa),
            PolicyExecutionMode::OpaGatekeeper => Ok(RegoPolicyExecutionMode::Gatekeeper),
            PolicyExecutionMode::KubewardenWapc
            | PolicyExecutionMode::Wasi
            | PolicyExecutionMode::Ferricel => {
                Err(PolicyEvaluatorBuilderError::ExecutionModeNotRegoCompatible)
            }
        }
    }
}

/// Settings specified by the user for a given policy.
#[derive(Clone, Default, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct PolicySettings(pub serde_json::Map<String, serde_json::Value>);

impl TryFrom<&RawExtension> for PolicySettings {
    type Error = &'static str;

    fn try_from(raw_extension: &RawExtension) -> Result<Self, Self::Error> {
        PolicySettings::try_from(&raw_extension.0)
    }
}

impl TryFrom<&serde_json::Value> for PolicySettings {
    type Error = &'static str;

    fn try_from(value: &serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Ok(PolicySettings::default()),
            serde_json::Value::Object(obj) => Ok(Self(obj.clone())),
            _ => Err("Invalid settings in CRD, not an object"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;
    use serde_json::json;

    use super::*;

    #[test]
    fn serialize_policy_execution_mode() {
        let mut test_data: HashMap<String, PolicyExecutionMode> = HashMap::new();
        test_data.insert(
            serde_json::to_string(&json!("kubewarden-wapc")).unwrap(),
            PolicyExecutionMode::KubewardenWapc,
        );
        test_data.insert(
            serde_json::to_string(&json!("opa")).unwrap(),
            PolicyExecutionMode::Opa,
        );
        test_data.insert(
            serde_json::to_string(&json!("gatekeeper")).unwrap(),
            PolicyExecutionMode::OpaGatekeeper,
        );
        test_data.insert(
            serde_json::to_string(&json!("ferricel")).unwrap(),
            PolicyExecutionMode::Ferricel,
        );

        for (expected, mode) in &test_data {
            let actual = serde_json::to_string(&mode);
            assert!(actual.is_ok());
            assert_eq!(expected, &actual.unwrap());
        }
    }

    #[test]
    fn deserialize_policy_execution_mode() {
        let mut test_data: HashMap<String, PolicyExecutionMode> = HashMap::new();
        test_data.insert(
            serde_json::to_string(&json!("kubewarden-wapc")).unwrap(),
            PolicyExecutionMode::KubewardenWapc,
        );
        test_data.insert(
            serde_json::to_string(&json!("opa")).unwrap(),
            PolicyExecutionMode::Opa,
        );
        test_data.insert(
            serde_json::to_string(&json!("gatekeeper")).unwrap(),
            PolicyExecutionMode::OpaGatekeeper,
        );
        test_data.insert(
            serde_json::to_string(&json!("ferricel")).unwrap(),
            PolicyExecutionMode::Ferricel,
        );

        for (mode_str, expected) in &test_data {
            let actual: std::result::Result<PolicyExecutionMode, serde_json::Error> =
                serde_json::from_str(mode_str);
            assert_eq!(expected, &actual.unwrap());
        }

        // an unknown policy mode should not be deserializable
        let actual: std::result::Result<PolicyExecutionMode, serde_json::Error> =
            serde_json::from_str("hello world");
        assert!(actual.is_err());
    }

    #[rstest]
    #[case::dictionrary(json!({"key1": "value1", "key2": "value2"}), true)]
    #[case::empty_dictionrary(json!({}), true)]
    #[case::nil(serde_json::Value::Null, true)]
    #[case::string(json!("boom"), false)]
    #[case::number(json!(123), false)]
    #[case::bool(json!(true), false)]
    fn convert_raw_extension_to_settings_conversion(
        #[case] settings: serde_json::Value,
        #[case] is_ok: bool,
    ) {
        let conversion_result = PolicySettings::try_from(&settings);
        assert_eq!(
            conversion_result.is_ok(),
            is_ok,
            "Conversion should {}",
            if is_ok { "succeed" } else { "fail" }
        );
    }
}
