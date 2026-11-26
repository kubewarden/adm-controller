use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    str::FromStr,
};

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use k8s_openapi::api::core::v1::ObjectReference;
use policy_evaluator::{
    admission_response_handler::{policy_id::PolicyID, policy_mode::PolicyMode},
    host_capabilities::HostCapabilities,
    kubewarden_policy_sdk::crd::policies::{
        AdmissionPolicy, AdmissionPolicyGroup, ClusterAdmissionPolicy, ClusterAdmissionPolicyGroup,
    },
    policy_evaluator::{PolicyExecutionMode, PolicySettings},
    policy_fetcher::store::Store,
    policy_group_evaluator::PolicyGroupMemberSettings,
    policy_metadata::ContextAwareResource,
};
use serde::Deserialize;

use crate::utils::new_policy_execution_mode_from_str;

/// Contains the definition of a policy
/// This can be an individual policy or a group of policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolicyDefinition {
    /// This is a single policy, could have been defined by a CRD or
    /// could be obtained by consuming the cli-flags provided by the user
    /// when doing `kwctl run` or `kwctl bench`
    Policy {
        id: String,
        uri: String,
        user_execution_cfg: PolicyExecutionConfiguration,
        raw: bool,
        // Whether the policy is operating in `protect` or `monitor` mode
        policy_mode: PolicyMode,
        // Determines if a mutating policy is actually allowed to mutate
        allowed_to_mutate: bool,
        // Determines a custom rejection message for the policy
        custom_rejection_message: Option<String>,
        // The policy-specific settings provided by the user
        settings: PolicySettings,
        // Individual policies can be created from cli parameters,
        // which implies that context aware configuration can be
        // determined after the policy is downloaded locally and its
        // metadata is inspected.
        ctx_aware_cfg: ContextAwareConfiguration,
        // The list of host capabilities the policy is allowed to use.
        // An empty list means no host capabilities are allowed.
        allowed_host_capabilities: Vec<String>,
    },
    /// This is a group of policies. This can be defined only by providing a Kubewarden CRD
    /// file.
    PolicyGroup {
        id: String,
        // Whether the policy is operating in `protect` or `monitor` mode
        policy_mode: PolicyMode,
        policy_members: HashMap<String, PolicyMember>,
        expression: String,
        message: String,
    },
}

impl fmt::Display for PolicyDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDefinition::Policy { id, uri, .. } => write!(f, "Policy {} ({})", id, uri),
            PolicyDefinition::PolicyGroup { id, .. } => write!(f, "Policy Group {}", id),
        }
    }
}

impl PolicyDefinition {
    pub fn get_policy_id(&self) -> Result<PolicyID> {
        match self {
            PolicyDefinition::Policy { id, .. } => {
                PolicyID::from_str(id).map_err(anyhow::Error::new)
            }
            PolicyDefinition::PolicyGroup { id, .. } => {
                PolicyID::from_str(id).map_err(anyhow::Error::new)
            }
        }
    }

    pub fn get_policy_custom_rejection_message(&self) -> Option<String> {
        match self {
            PolicyDefinition::Policy {
                custom_rejection_message,
                ..
            } => custom_rejection_message.to_owned(),
            PolicyDefinition::PolicyGroup { .. } => None,
        }
    }

    pub fn get_policy_allowed_to_mutate(&self) -> bool {
        match self {
            PolicyDefinition::Policy {
                allowed_to_mutate, ..
            } => allowed_to_mutate.to_owned(),
            PolicyDefinition::PolicyGroup { .. } => false,
        }
    }

    pub fn get_policy_mode(&self) -> PolicyMode {
        match self {
            PolicyDefinition::Policy { policy_mode, .. } => policy_mode.to_owned(),
            PolicyDefinition::PolicyGroup { policy_mode, .. } => policy_mode.to_owned(),
        }
    }
}

/// This enum is used to determine how the policy should be executed
/// by the evaluator (e.g.: waPC, OpaGatekeeper, Opa, WASI,...)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolicyExecutionConfiguration {
    UserDefined(PolicyExecutionMode),
    /// Policies defined by CRDs will always have their execution mode
    /// defined by the metadata of the wasm module.
    PolicyDefined,
}

/// This enum is used to determine how the policy should handle
/// context-aware resources.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) enum ContextAwareConfiguration {
    #[default]
    NoAccess,
    TrustPolicyMetadata,
    AllowList(BTreeSet<ContextAwareResource>),
}

/// Represents a member of a policy group, which includes the URI of the policy
/// and its settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyMember {
    pub uri: String,
    pub settings: PolicyGroupMemberSettings,
}

/// Converts a Kubewarden CRD AdmissionPolicy into a PolicyDefinition.
impl TryFrom<AdmissionPolicy> for PolicyDefinition {
    type Error = anyhow::Error;

    fn try_from(ap: AdmissionPolicy) -> Result<Self> {
        let spec = ap.spec.ok_or_else(|| {
            anyhow!("CRD does not have spec, but it is required for AdmissionPolicy")
        })?;

        let uri = spec.module.clone();

        let policy_mode = spec.mode.unwrap_or_default().into();
        let allowed_to_mutate = spec.mutating;
        let custom_rejection_message = spec.message;

        let settings = PolicySettings::try_from(&spec.settings.0).map_err(anyhow::Error::msg)?;

        Ok(PolicyDefinition::Policy {
            id: ap
                .metadata
                .name
                .unwrap_or_else(|| "crd-without-name".to_string()),
            uri,
            user_execution_cfg: PolicyExecutionConfiguration::PolicyDefined,
            raw: false,
            policy_mode,
            allowed_to_mutate,
            custom_rejection_message,
            settings,
            ctx_aware_cfg: ContextAwareConfiguration::NoAccess,
            allowed_host_capabilities: vec![],
        })
    }
}

/// Converts a Kubewarden CRD ClusterAdmissionPolicy into a PolicyDefinition.
impl TryFrom<ClusterAdmissionPolicy> for PolicyDefinition {
    type Error = anyhow::Error;

    fn try_from(cap: ClusterAdmissionPolicy) -> Result<Self> {
        let spec = cap.spec.ok_or_else(|| {
            anyhow!("CRD does not have spec, but it is required for ClusterAdmissionPolicy")
        })?;

        let uri = spec.module.clone();

        let policy_mode = spec.mode.unwrap_or_default().into();
        let allowed_to_mutate = spec.mutating;
        let custom_rejection_message = spec.message;

        let settings = PolicySettings::try_from(&spec.settings.0).map_err(anyhow::Error::msg)?;

        let ctx_aware_allow_list = spec
            .context_aware_resources
            .iter()
            .map(|car| car.into())
            .collect();

        Ok(PolicyDefinition::Policy {
            id: cap
                .metadata
                .name
                .unwrap_or_else(|| "crd-without-name".to_string()),
            uri,
            user_execution_cfg: PolicyExecutionConfiguration::PolicyDefined,
            raw: false,
            policy_mode,
            allowed_to_mutate,
            custom_rejection_message,
            settings,
            ctx_aware_cfg: ContextAwareConfiguration::AllowList(ctx_aware_allow_list),
            allowed_host_capabilities: vec![],
        })
    }
}

impl TryFrom<ClusterAdmissionPolicyGroup> for PolicyDefinition {
    type Error = anyhow::Error;

    fn try_from(cap_group: ClusterAdmissionPolicyGroup) -> Result<Self> {
        let spec = cap_group.spec.ok_or_else(|| {
            anyhow!("CRD does not have spec, but it is required for ClusterAdmissionPolicyGroup")
        })?;

        let mut policy_members = HashMap::new();

        for (policy_id, policy) in &spec.policies {
            let uri = policy.module.clone();
            let settings: PolicyGroupMemberSettings =
                policy.try_into().map_err(anyhow::Error::msg)?;

            policy_members.insert(policy_id.clone(), PolicyMember { uri, settings });
        }

        let policy_mode = spec.mode.unwrap_or_default().into();

        Ok(PolicyDefinition::PolicyGroup {
            id: cap_group
                .metadata
                .name
                .unwrap_or_else(|| "crd-without-name".to_string()),
            policy_members,
            policy_mode,
            expression: spec.expression.clone(),
            message: spec.message.clone(),
        })
    }
}

impl TryFrom<AdmissionPolicyGroup> for PolicyDefinition {
    type Error = anyhow::Error;

    fn try_from(ap_group: AdmissionPolicyGroup) -> Result<Self> {
        let spec = ap_group.spec.ok_or_else(|| {
            anyhow!("CRD does not have spec, but it is required for AdmissionPolicyGroup")
        })?;

        let mut policy_members = HashMap::new();

        for (policy_id, policy) in &spec.policies {
            let uri = policy.module.clone();
            let settings: PolicyGroupMemberSettings =
                policy.try_into().map_err(anyhow::Error::msg)?;

            policy_members.insert(policy_id.clone(), PolicyMember { uri, settings });
        }

        let policy_mode = spec.mode.unwrap_or_default().into();

        Ok(PolicyDefinition::PolicyGroup {
            id: ap_group
                .metadata
                .name
                .unwrap_or_else(|| "crd-without-name".to_string()),
            policy_members,
            policy_mode,
            expression: spec.expression.clone(),
            message: spec.message.clone(),
        })
    }
}

impl PolicyDefinition {
    fn new(value: serde_yaml::Value) -> Result<PolicyDefinition> {
        let obj_ref: ObjectReference = serde_yaml::from_value(value.clone())
            .map_err(|e| anyhow!("cannot extract ObjectReference: {}", e))?;

        if obj_ref.api_version != Some("policies.kubewarden.io/v1".to_string()) {
            return Err(anyhow!("invalid apiVersion {:?}", obj_ref.api_version));
        }

        match obj_ref.kind.as_deref() {
            Some("AdmissionPolicy") => {
                let ap: AdmissionPolicy = serde_yaml::from_value(value)
                    .map_err(|e| anyhow!("cannot parse value into AdmissionPolicy: {}", e))?;
                PolicyDefinition::try_from(ap)
            }
            Some("ClusterAdmissionPolicy") => {
                let cap: ClusterAdmissionPolicy = serde_yaml::from_value(value).map_err(|e| {
                    anyhow!("cannot parse value into ClusterAdmissionPolicy: {}", e)
                })?;
                PolicyDefinition::try_from(cap)
            }
            Some("AdmissionPolicyGroup") => {
                let apg_group: AdmissionPolicyGroup = serde_yaml::from_value(value)
                    .map_err(|e| anyhow!("cannot parse value into AdmissionPolicyGroup: {}", e))?;
                PolicyDefinition::try_from(apg_group)
            }
            Some("ClusterAdmissionPolicyGroup") => {
                let capg_group: ClusterAdmissionPolicyGroup = serde_yaml::from_value(value)
                    .map_err(|e| {
                        anyhow!("cannot parse value into ClusterAdmissionPolicyGroup: {}", e)
                    })?;
                PolicyDefinition::try_from(capg_group)
            }
            _ => Err(anyhow!(
                "unknown kind {:?}, not a Kubewarden policy",
                obj_ref.kind
            )),
        }
    }

    /// reads all the CRDs defined inside of the given file and returns a
    /// list of PolicyDefinition
    pub fn from_yaml_file(
        yaml_path: &str,
        allowed_host_capabilities: &[String],
    ) -> Result<Vec<PolicyDefinition>> {
        let deserializer = serde_yaml::Deserializer::from_reader(
            std::fs::File::open(yaml_path)
                .map_err(|e| anyhow!("Cannot open YAML file {:?}: {}", yaml_path, e))?,
        );

        let mut policies = Vec::new();

        for document in deserializer {
            let value_yaml = serde_yaml::Value::deserialize(document)
                .map_err(|e| anyhow!("Cannot parse YAML file {:?}: {}", yaml_path, e))?;

            let mut policy = PolicyDefinition::new(value_yaml)?;
            // Overwrite the host capabilities with the value provided by the caller.
            // For individual policies this sets the field directly. For group policies
            // the same list is applied uniformly to all members, because host capabilities
            // are not part of the Kubewarden CRD spec and must therefore come from the CLI.
            let hc_allow_list = HostCapabilities::new(allowed_host_capabilities)
                .map_err(|e| anyhow!("Invalid host capabilities pattern: {e}"))?;
            match &mut policy {
                PolicyDefinition::Policy {
                    allowed_host_capabilities: caps,
                    ..
                } => {
                    *caps = allowed_host_capabilities.to_vec();
                }
                PolicyDefinition::PolicyGroup { policy_members, .. } => {
                    for member in policy_members.values_mut() {
                        member.settings.host_capabilities = hc_allow_list.clone();
                    }
                }
            }
            policies.push(policy);
        }

        Ok(policies)
    }

    /// Creates a PolicyDefinition from CLI arguments.
    ///
    /// This will always create an individual PolicyDefinition
    pub fn from_cli(matches: &ArgMatches, store: &Store) -> Result<PolicyDefinition> {
        let uri = matches
            .get_one::<String>("uri_or_sha_prefix_or_yaml_file")
            .map(
                |uri_or_sha_prefix| -> std::result::Result<String, crate::utils::LookupError> {
                    crate::utils::map_path_to_uri(uri_or_sha_prefix, store)
                },
            )
            .transpose()?
            .expect("uri_or_sha_prefix is guaranteed to be Some here");

        let settings = if let Some(settings_path) = matches.get_one::<String>("settings-path") {
            // 1st convert to json data
            let json_value: serde_json::Value = serde_yaml::from_reader(
                std::fs::File::open(settings_path)
                    .map_err(|e| anyhow!("Cannot open settings file {}: {}", settings_path, e))?,
            )
            .map_err(|e| anyhow!("Cannot parse settings file {}: {}", settings_path, e))?;

            // 2nd convert to PolicySettings, this makes sure we got a valid json object (only
            // dictionaries and null are allowed)
            PolicySettings::try_from(&json_value).map_err(anyhow::Error::msg)?
        } else if let Some(json) = matches.get_one::<String>("settings-json") {
            let json_value: serde_json::Value = serde_json::from_str(json)
                .map_err(|e| anyhow!("Cannot parse settings JSON: {}", e))?;

            PolicySettings::try_from(&json_value).map_err(anyhow::Error::msg)?
        } else {
            PolicySettings::default()
        };

        let user_execution_cfg =
            if let Some(mode_name) = matches.get_one::<String>("execution-mode") {
                PolicyExecutionConfiguration::UserDefined(new_policy_execution_mode_from_str(
                    mode_name,
                )?)
            } else {
                PolicyExecutionConfiguration::PolicyDefined
            };

        let allow_context_aware_resources = matches
            .get_one::<bool>("allow-context-aware")
            .unwrap_or(&false)
            .to_owned();
        let ctx_aware_cfg = if allow_context_aware_resources {
            ContextAwareConfiguration::TrustPolicyMetadata
        } else {
            ContextAwareConfiguration::NoAccess
        };

        let raw = matches.get_one::<bool>("raw").unwrap_or(&false).to_owned();

        let allowed_to_mutate = true;
        let policy_mode = PolicyMode::Protect;
        let custom_rejection_message = None;

        let allowed_host_capabilities: Vec<String> = matches
            .get_many::<String>("allowed-host-capabilities")
            .unwrap_or_default()
            .cloned()
            .collect();

        Ok(PolicyDefinition::Policy {
            id: "policy-from-cli".to_string(),
            policy_mode,
            allowed_to_mutate,
            custom_rejection_message,
            uri,
            user_execution_cfg,
            raw,
            settings,
            ctx_aware_cfg,
            allowed_host_capabilities,
        })
    }

    pub(crate) fn uris(&self) -> HashSet<String> {
        match self {
            PolicyDefinition::Policy { uri, .. } => HashSet::from([uri.clone()]),
            PolicyDefinition::PolicyGroup { policy_members, .. } => {
                policy_members.values().map(|pm| pm.uri.clone()).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::runtime::RawExtension;
    use policy_evaluator::kubewarden_policy_sdk::crd::policies::common::{
        ContextAwareResource as ContextAwareResourceSdk, PolicyMode as PolicyModeSdk,
    };
    use serde_json::json;

    use super::*;

    #[test]
    fn policy_definition_from_admission_policy() {
        use policy_evaluator::kubewarden_policy_sdk::crd::policies::admission_policy::AdmissionPolicySpec;

        let name = "test-policy".to_string();
        let module_uri = "https://example.com/policy.wasm".to_string();
        let settings = json!({
            "settings": {
                "key1": "value1",
                "key2": 42
            }
        });
        let expected_settings = PolicySettings::try_from(&settings)
            .expect("Failed to convert settings to PolicySettings");

        let ap = AdmissionPolicy {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.clone()),
                ..Default::default()
            },
            spec: Some(AdmissionPolicySpec {
                module: module_uri.clone(),
                mode: Some(PolicyModeSdk::Protect),
                message: Some("foo".to_string()),
                mutating: false,
                settings: RawExtension(settings),
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy_definition: PolicyDefinition =
            PolicyDefinition::try_from(ap).expect("Failed to convert AdmissionPolicy");

        match policy_definition {
            PolicyDefinition::Policy {
                id,
                uri,
                user_execution_cfg,
                settings,
                raw,
                ctx_aware_cfg,
                policy_mode,
                allowed_to_mutate,
                custom_rejection_message,
                allowed_host_capabilities,
            } => {
                assert_eq!(id, name);
                assert_eq!(uri, module_uri);
                assert!(matches!(
                    user_execution_cfg,
                    PolicyExecutionConfiguration::PolicyDefined
                ));
                assert!(!raw);
                assert_eq!(policy_mode, PolicyMode::Protect);
                assert!(!allowed_to_mutate);
                assert_eq!(custom_rejection_message, Some("foo".to_string()));
                assert_eq!(settings, expected_settings);
                assert!(matches!(ctx_aware_cfg, ContextAwareConfiguration::NoAccess));
                assert!(allowed_host_capabilities.is_empty());
            }
            _ => panic!("Expected Individual PolicyDefinition"),
        }
    }

    #[test]
    fn policy_definition_from_cluster_admission_policy() {
        use policy_evaluator::kubewarden_policy_sdk::crd::policies::cluster_admission_policy::ClusterAdmissionPolicySpec;

        let name = "test-cluster-policy".to_string();
        let module_uri = "https://example.com/cluster_policy.wasm".to_string();
        let settings = json!({
            "settings": {
                "key1": "value1",
                "key2": 42
            }
        });
        let expected_settings = PolicySettings::try_from(&settings)
            .expect("Failed to convert settings to PolicySettings");

        let context_aware_resources_sdk = vec![
            ContextAwareResourceSdk {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            ContextAwareResourceSdk {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
        ];

        let expected_context_aware_resources: BTreeSet<ContextAwareResource> = BTreeSet::from([
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            ContextAwareResource {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
        ]);

        let cap = ClusterAdmissionPolicy {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.clone()),
                ..Default::default()
            },
            spec: Some(ClusterAdmissionPolicySpec {
                module: module_uri.clone(),
                mode: Some(PolicyModeSdk::Protect),
                message: Some("foo".to_string()),
                mutating: false,
                settings: RawExtension(settings),
                context_aware_resources: context_aware_resources_sdk,
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy_definition: PolicyDefinition =
            PolicyDefinition::try_from(cap).expect("Failed to convert ClusterAdmissionPolicy");

        match policy_definition {
            PolicyDefinition::Policy {
                id,
                uri,
                user_execution_cfg,
                settings,
                raw,
                ctx_aware_cfg,
                policy_mode,
                allowed_to_mutate,
                custom_rejection_message,
                allowed_host_capabilities,
            } => {
                assert_eq!(id, name);
                assert_eq!(uri, module_uri);
                assert!(matches!(
                    user_execution_cfg,
                    PolicyExecutionConfiguration::PolicyDefined
                ));
                assert!(!raw);
                assert_eq!(policy_mode, PolicyMode::Protect);
                assert!(!allowed_to_mutate);
                assert_eq!(custom_rejection_message, Some("foo".to_string()));
                assert_eq!(settings, expected_settings);
                assert_eq!(
                    ctx_aware_cfg,
                    ContextAwareConfiguration::AllowList(expected_context_aware_resources)
                );
                assert!(allowed_host_capabilities.is_empty());
            }
            _ => panic!("Expected Individual PolicyDefinition"),
        }
    }

    #[test]
    fn policy_definition_from_cluster_admission_policy_group() {
        use policy_evaluator::kubewarden_policy_sdk::crd::policies::cluster_admission_policy_group::{
            ClusterAdmissionPolicyGroupSpec, PolicyGroupMemberWithContext};

        let name = "cluster-policy-group".to_string();
        let message: String = "This is a test cluster policy group".to_string();
        let expression: String = "policy1() || policy2()".to_string();

        let pgm_1_id = "policy1".to_string();
        let pgm_1_context_aware_resources_sdk = vec![
            ContextAwareResourceSdk {
                api_version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            ContextAwareResourceSdk {
                api_version: "v1".to_string(),
                kind: "Service".to_string(),
            },
        ];
        let pgm_1_expected_context_aware_resources: BTreeSet<ContextAwareResource> =
            BTreeSet::from([
                ContextAwareResource {
                    api_version: "v1".to_string(),
                    kind: "Pod".to_string(),
                },
                ContextAwareResource {
                    api_version: "v1".to_string(),
                    kind: "Service".to_string(),
                },
            ]);
        let pgm_1 = PolicyGroupMemberWithContext {
            module: "https://example.com/policy1.wasm".to_string(),
            settings: RawExtension(json!({
                "settings": {
                    "key1": "value1",
                    "key2": 42
                }
            })),
            context_aware_resources: pgm_1_context_aware_resources_sdk,
            timeout_eval_seconds: None,
        };

        let pgm_2_id = "policy2".to_string();
        let pgm_2 = PolicyGroupMemberWithContext {
            module: "https://example.com/policy2.wasm".to_string(),
            settings: RawExtension(json!({
                "settings": {
                    "key3": "value3",
                    "key4": 84
                }
            })),
            context_aware_resources: vec![],
            timeout_eval_seconds: None,
        };

        let policies = HashMap::from([
            (pgm_1_id.clone(), pgm_1.clone()),
            (pgm_2_id.clone(), pgm_2.clone()),
        ]);

        let capg = ClusterAdmissionPolicyGroup {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.clone()),
                ..Default::default()
            },
            spec: Some(ClusterAdmissionPolicyGroupSpec {
                message: message.clone(),
                expression: expression.clone(),
                mode: Some(PolicyModeSdk::Protect),
                policies,
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy_definition: PolicyDefinition = PolicyDefinition::try_from(capg)
            .expect("Failed to convert ClusterAdmissionPolicyGroup");

        let expected_policy_definition = PolicyDefinition::PolicyGroup {
            id: name.clone(),
            policy_members: HashMap::from([
                (
                    pgm_1_id,
                    PolicyMember {
                        uri: pgm_1.module,
                        settings: PolicyGroupMemberSettings {
                            settings: PolicySettings::try_from(&pgm_1.settings.0)
                                .expect("Failed to convert settings for member 1"),
                            ctx_aware_resources_allow_list: pgm_1_expected_context_aware_resources,
                            epoch_deadline: None,
                            host_capabilities: HostCapabilities::DenyAll,
                        },
                    },
                ),
                (
                    pgm_2_id.clone(),
                    PolicyMember {
                        uri: pgm_2.module,
                        settings: PolicyGroupMemberSettings {
                            settings: PolicySettings::try_from(&pgm_2.settings.0)
                                .expect("Failed to convert settings for member 2"),
                            ctx_aware_resources_allow_list: BTreeSet::new(),
                            epoch_deadline: None,
                            host_capabilities: HostCapabilities::DenyAll,
                        },
                    },
                ),
            ]),
            policy_mode: PolicyMode::Protect,
            expression,
            message,
        };

        assert_eq!(policy_definition, expected_policy_definition);
    }

    #[test]
    fn policy_definition_from_admission_policy_group() {
        use policy_evaluator::kubewarden_policy_sdk::crd::policies::admission_policy_group::{
            AdmissionPolicyGroupSpec, PolicyGroupMember,
        };

        let name = "admission-policy-group".to_string();
        let message: String = "This is a test admission policy group".to_string();
        let expression: String = "policy1() || policy2()".to_string();

        let pgm_1_id = "policy1".to_string();
        let pgm_1 = PolicyGroupMember {
            module: "https://example.com/policy1.wasm".to_string(),
            settings: RawExtension(json!({
                "settings": {
                    "key1": "value1",
                    "key2": 42
                }
            })),
            timeout_eval_seconds: None,
        };

        let pgm_2_id = "policy2".to_string();
        let pgm_2 = PolicyGroupMember {
            module: "https://example.com/policy2.wasm".to_string(),
            settings: RawExtension(json!({
                "settings": {
                    "key3": "value3",
                    "key4": 84
                }
            })),
            timeout_eval_seconds: None,
        };

        let policies = HashMap::from([
            (pgm_1_id.clone(), pgm_1.clone()),
            (pgm_2_id.clone(), pgm_2.clone()),
        ]);

        let capg = AdmissionPolicyGroup {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.clone()),
                ..Default::default()
            },
            spec: Some(AdmissionPolicyGroupSpec {
                message: message.clone(),
                expression: expression.clone(),
                policies,
                ..Default::default()
            }),
            ..Default::default()
        };

        let policy_definition: PolicyDefinition = PolicyDefinition::try_from(capg)
            .expect("Failed to convert ClusterAdmissionPolicyGroup");

        match policy_definition {
            PolicyDefinition::PolicyGroup {
                id,
                policy_members,
                expression,
                policy_mode,
                message,
            } => {
                assert_eq!(id, name);
                assert_eq!(expression, expression);
                assert_eq!(message, message);
                assert_eq!(policy_mode, PolicyMode::Protect);

                assert_eq!(policy_members.len(), 2);

                let member1 = policy_members.get(&pgm_1_id).expect("Member 1 not found");
                assert_eq!(member1.uri, pgm_1.module);

                let pgm_1_settings = &member1.settings;
                assert_eq!(
                    pgm_1_settings.settings,
                    PolicySettings::try_from(&pgm_1.settings.0)
                        .expect("Failed to convert settings for member 1")
                );
                assert!(pgm_1_settings.ctx_aware_resources_allow_list.is_empty());

                let member2 = policy_members.get(&pgm_2_id).expect("Member 2 not found");
                assert_eq!(member2.uri, pgm_2.module);
                let pgm_2_settings = &member2.settings;
                assert_eq!(
                    pgm_2_settings.settings,
                    PolicySettings::try_from(&pgm_2.settings.0)
                        .expect("Failed to convert settings for member 2")
                );
                assert!(pgm_2_settings.ctx_aware_resources_allow_list.is_empty());
            }
            _ => panic!("Expected Group PolicyDefinition"),
        }
    }
}
