use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    str::FromStr,
};

use anyhow::{Result, anyhow};
use hostname_validator::is_valid;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use policy_evaluator::{
    constants::{
        KUBEWARDEN_ANNOTATION_POLICY_CATEGORY, KUBEWARDEN_ANNOTATION_POLICY_SEVERITY,
        KUBEWARDEN_ANNOTATION_POLICY_TITLE,
    },
    policy_fetcher::store::Store,
    policy_metadata::Metadata,
    validator::Validate,
};
use tracing::warn;

use crate::scaffold::kubewarden_crds::{
    AdmissionPolicy, AdmissionPolicySpec, ClusterAdmissionPolicy, ClusterAdmissionPolicySpec,
};

pub(crate) enum ManifestType {
    ClusterAdmissionPolicy,
    AdmissionPolicy,
}

impl FromStr for ManifestType {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "ClusterAdmissionPolicy" => Ok(ManifestType::ClusterAdmissionPolicy),
            "AdmissionPolicy" => Ok(ManifestType::AdmissionPolicy),
            _ => Err(anyhow!("unknown manifest type")),
        }
    }
}

#[derive(Clone)]
struct ScaffoldPolicyData {
    pub uri: String,
    policy_title: Option<String>,
    metadata: Metadata,
    settings: serde_yaml::Mapping,
}

impl TryFrom<ScaffoldPolicyData> for ClusterAdmissionPolicy {
    type Error = anyhow::Error;

    fn try_from(data: ScaffoldPolicyData) -> Result<Self, Self::Error> {
        data.metadata.validate()?;
        Ok(ClusterAdmissionPolicy {
            api_version: String::from("policies.kubewarden.io/v1"),
            kind: String::from("ClusterAdmissionPolicy"),
            metadata: build_objmetadata(data.clone()),
            spec: ClusterAdmissionPolicySpec {
                module: data.uri,
                settings: data.settings,
                rules: data.metadata.rules.clone(),
                mutating: data.metadata.mutating,
                background_audit: data.metadata.background_audit,
                context_aware_resources: data.metadata.context_aware_resources,
                ..Default::default()
            },
        })
    }
}

impl TryFrom<ScaffoldPolicyData> for AdmissionPolicy {
    type Error = anyhow::Error;

    fn try_from(data: ScaffoldPolicyData) -> Result<Self, Self::Error> {
        data.metadata.validate()?;
        Ok(AdmissionPolicy {
            api_version: String::from("policies.kubewarden.io/v1"),
            kind: String::from("AdmissionPolicy"),
            metadata: build_objmetadata(data.clone()),
            spec: AdmissionPolicySpec {
                module: data.uri,
                settings: data.settings,
                rules: data.metadata.rules.clone(),
                mutating: data.metadata.mutating,
                background_audit: data.metadata.background_audit,
            },
        })
    }
}

fn build_objmetadata(data: ScaffoldPolicyData) -> ObjectMeta {
    let mut annots: BTreeMap<String, String> = BTreeMap::new();
    if let Some(an) = data.metadata.annotations {
        if let Some(severity) = an.get(KUBEWARDEN_ANNOTATION_POLICY_SEVERITY) {
            annots.insert(
                String::from(KUBEWARDEN_ANNOTATION_POLICY_SEVERITY),
                severity.to_owned(),
            );
        }
        if let Some(category) = an.get(KUBEWARDEN_ANNOTATION_POLICY_CATEGORY) {
            annots.insert(
                String::from(KUBEWARDEN_ANNOTATION_POLICY_CATEGORY),
                category.to_owned(),
            );
        }
    }

    let annots_option: Option<BTreeMap<String, String>> = match !annots.is_empty() {
        true => Some(annots),
        false => None,
    };

    ObjectMeta {
        name: data.policy_title,
        annotations: annots_option,
        ..Default::default()
    }
}

// Kubernetes hostname validation RFC 1123
fn is_valid_k8s_hostname(hostname: &str) -> bool {
    is_valid(hostname)
        && hostname.to_ascii_lowercase() == hostname
        && !hostname.contains('_')
        && hostname.len() <= 253
}

fn validate_policy_title(title: &str) -> Result<()> {
    if !is_valid_k8s_hostname(title) {
        return Err(anyhow!(
            "Invalid title '{}'. Must conform to RFC 1123: use lowercase alphanumeric chars, '-' or '.', and start/end with an alphanumeric character.",
            title
        ));
    }
    Ok(())
}

pub(crate) fn manifest(
    uri_or_sha_prefix: &str,
    resource_type: ManifestType,
    settings: Option<&str>,
    policy_title: Option<&str>,
    allow_context_aware_resources: bool,
    store: &Store,
) -> Result<()> {
    let uri = crate::utils::get_uri(&uri_or_sha_prefix.to_owned(), store)?;
    let wasm_path = crate::utils::wasm_path(&uri, store)?;

    let metadata = Metadata::from_path(&wasm_path)?
        .ok_or_else(||
            anyhow!(
                "No Kubewarden metadata found inside of '{}'.\nPolicies can be annotated with the `kwctl annotate` command.",
                uri)
        )?;

    let settings_yml: serde_yaml::Mapping = serde_yaml::from_str(settings.unwrap_or("{}"))?;

    let policy_title = get_policy_title_from_cli_or_metadata(policy_title, &metadata);

    // Validate policy title if present
    if let Some(title) = &policy_title {
        validate_policy_title(title)?;
    }

    let scaffold_data = ScaffoldPolicyData {
        uri,
        policy_title,
        metadata,
        settings: settings_yml,
    };

    let resource =
        generate_yaml_resource(scaffold_data, resource_type, allow_context_aware_resources)?;

    let stdout = std::io::stdout();
    let out = stdout.lock();
    serde_yaml::to_writer(out, &resource)?;

    Ok(())
}

fn get_policy_title_from_cli_or_metadata(
    policy_title: Option<&str>,
    metadata: &Metadata,
) -> Option<String> {
    policy_title.map(|t| t.to_string()).or_else(|| {
        metadata
            .annotations
            .as_ref()
            .unwrap_or(&BTreeMap::new())
            .get(KUBEWARDEN_ANNOTATION_POLICY_TITLE)
            .map(|s| s.to_string())
    })
}

fn generate_yaml_resource(
    scaffold_data: ScaffoldPolicyData,
    resource_type: ManifestType,
    allow_context_aware_resources: bool,
) -> Result<serde_yaml::Value> {
    let mut scaffold_data = scaffold_data;

    match resource_type {
        ManifestType::ClusterAdmissionPolicy => {
            if !scaffold_data.metadata.context_aware_resources.is_empty() {
                if allow_context_aware_resources {
                    warn!(
                        "Policy has been granted access to the Kubernetes resources mentioned by its metadata."
                    );
                    warn!(
                        "Carefully review the contents of the `contextAwareResources` attribute for abuses."
                    );
                } else {
                    warn!(
                        "Policy requires access to Kubernetes resources at evaluation time. For safety reasons, the `contextAwareResources` attribute has been left empty."
                    );
                    warn!(
                        "Carefully review which types of Kubernetes resources the policy needs via the `inspect` command an populate the `contextAwareResources` accordingly."
                    );
                    warn!(
                        "Otherwise, invoke the `scaffold` command using the `--allow-context-aware` flag."
                    );

                    scaffold_data.metadata.context_aware_resources = BTreeSet::new();
                }
            }

            serde_yaml::to_value(ClusterAdmissionPolicy::try_from(scaffold_data)?)
                .map_err(|e| anyhow!("{}", e))
        }
        ManifestType::AdmissionPolicy => {
            serde_yaml::to_value(AdmissionPolicy::try_from(scaffold_data)?)
                .map_err(|e| anyhow!("{}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use policy_evaluator::policy_metadata::ContextAwareResource;

    use super::*;

    fn mock_metadata_with_no_annotations() -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: None,
            mutating: false,
            background_audit: true,
            context_aware_resources: BTreeSet::new(),
            host_capabilities: None,
            execution_mode: Default::default(),
            policy_type: Default::default(),
            minimum_kubewarden_version: None,
        }
    }

    fn mock_metadata_with_title(title: &str) -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(BTreeMap::from([(
                KUBEWARDEN_ANNOTATION_POLICY_TITLE.to_string(),
                title.to_string(),
            )])),
            mutating: false,
            background_audit: true,
            context_aware_resources: BTreeSet::new(),
            host_capabilities: None,
            execution_mode: Default::default(),
            policy_type: Default::default(),
            minimum_kubewarden_version: None,
        }
    }

    fn mock_metadata_with_severity_category() -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(BTreeMap::from([
                (
                    KUBEWARDEN_ANNOTATION_POLICY_TITLE.to_string(),
                    String::from("test"),
                ),
                (
                    KUBEWARDEN_ANNOTATION_POLICY_SEVERITY.to_string(),
                    String::from("medium"),
                ),
                (
                    KUBEWARDEN_ANNOTATION_POLICY_CATEGORY.to_string(),
                    String::from("PSP"),
                ),
            ])),
            mutating: false,
            background_audit: true,
            context_aware_resources: BTreeSet::new(),
            host_capabilities: None,
            execution_mode: Default::default(),
            policy_type: Default::default(),
            minimum_kubewarden_version: None,
        }
    }

    #[test]
    fn get_policy_title_from_cli_or_metadata_returns_name_from_cli_if_present() {
        let policy_title = "name";
        assert_eq!(
            Some(policy_title.to_string()),
            get_policy_title_from_cli_or_metadata(
                Some(policy_title),
                &mock_metadata_with_no_annotations()
            )
        )
    }

    #[test]
    fn get_policy_title_from_cli_or_metadata_returns_none_if_both_are_missing() {
        assert_eq!(
            None,
            get_policy_title_from_cli_or_metadata(None, &mock_metadata_with_no_annotations())
        )
    }

    #[test]
    fn get_policy_title_from_cli_or_metadata_returns_title_from_annotation_if_name_from_cli_not_present()
     {
        let policy_title = "title";
        assert_eq!(
            Some(policy_title.to_string()),
            get_policy_title_from_cli_or_metadata(None, &mock_metadata_with_title(policy_title))
        )
    }

    #[test]
    fn build_objmetadata_when_no_annotation() {
        let mut metadata = mock_metadata_with_no_annotations();
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        let scaffold_data = ScaffoldPolicyData {
            uri: "not_relevant".to_string(),
            policy_title: Some("test".to_string()),
            metadata,
            settings: Default::default(),
        };

        let obj_metadata = build_objmetadata(scaffold_data);
        assert!(obj_metadata.annotations.is_none());
    }

    #[test]
    fn build_objmetadata_with_annot_severity_category() {
        let mut metadata = mock_metadata_with_severity_category();
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        let scaffold_data = ScaffoldPolicyData {
            uri: "not_relevant".to_string(),
            policy_title: Some("test".to_string()),
            metadata,
            settings: Default::default(),
        };

        let obj_metadata = build_objmetadata(scaffold_data);
        assert_eq!(
            obj_metadata
                .annotations
                .as_ref()
                .expect("we should have annotations")
                .get(KUBEWARDEN_ANNOTATION_POLICY_SEVERITY)
                .expect("we should have severity"),
            &String::from("medium")
        );
        assert_eq!(
            obj_metadata
                .annotations
                .as_ref()
                .expect("we should have annotations")
                .get(KUBEWARDEN_ANNOTATION_POLICY_CATEGORY)
                .expect("we should have category"),
            &String::from("PSP")
        );
    }

    #[test]
    fn omit_background_audit_during_serialization_when_true() {
        // testing fix for https://github.com/kubewarden/kubewarden-controller/issues/395
        let policy_title = "test";
        let mut metadata = mock_metadata_with_title(policy_title);
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        assert!(metadata.background_audit);

        let scaffold_data = ScaffoldPolicyData {
            uri: "not_relevant".to_string(),
            policy_title: get_policy_title_from_cli_or_metadata(Some(policy_title), &metadata),
            metadata,
            settings: Default::default(),
        };

        let out = serde_yaml::to_string(
            &ClusterAdmissionPolicy::try_from(scaffold_data.clone())
                .expect("cannot build ClusterAdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(!out.contains("backgroundAudit"));

        let out = serde_yaml::to_string(
            &AdmissionPolicy::try_from(scaffold_data).expect("cannot build AdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(!out.contains("backgroundAudit"));
    }

    #[test]
    fn do_not_omit_background_audit_during_serialization_when_false() {
        // testing fix for https://github.com/kubewarden/kubewarden-controller/issues/395
        let policy_title = "test";
        let mut metadata = mock_metadata_with_title(policy_title);
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        metadata.background_audit = false;
        assert!(!metadata.background_audit);

        let scaffold_data = ScaffoldPolicyData {
            uri: "not_relevant".to_string(),
            policy_title: get_policy_title_from_cli_or_metadata(Some(policy_title), &metadata),
            metadata,
            settings: Default::default(),
        };

        let out = serde_yaml::to_string(
            &ClusterAdmissionPolicy::try_from(scaffold_data.clone())
                .expect("cannot build ClusterAdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(out.contains("backgroundAudit"));

        let out = serde_yaml::to_string(
            &AdmissionPolicy::try_from(scaffold_data).expect("cannot build AdmissionPolicy"),
        )
        .expect("serialization error");
        assert!(out.contains("backgroundAudit"));
    }

    #[test]
    fn scaffold_cluster_admission_policy_with_context_aware_enabled() {
        let mut context_aware_resources: BTreeSet<ContextAwareResource> = BTreeSet::new();
        context_aware_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });

        let policy_title = "test";
        let mut metadata = mock_metadata_with_title(policy_title);
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        metadata.context_aware_resources = context_aware_resources;

        let scaffold_data = ScaffoldPolicyData {
            uri: "not_relevant".to_string(),
            policy_title: get_policy_title_from_cli_or_metadata(Some(policy_title), &metadata),
            metadata,
            settings: Default::default(),
        };

        let resource =
            generate_yaml_resource(scaffold_data, ManifestType::ClusterAdmissionPolicy, true)
                .expect("Cannot create yaml resource");

        let resource = resource.as_mapping().expect("resource should be a Map");
        let spec = resource.get("spec").expect("cannot get `Spec`");
        let context_aware_resources = spec.get("contextAwareResources");
        assert!(context_aware_resources.is_some());
    }

    #[test]
    fn scaffold_cluster_admission_policy_with_context_aware_disabled() {
        let mut context_aware_resources: BTreeSet<ContextAwareResource> = BTreeSet::new();
        context_aware_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });

        let policy_title = "test";
        let mut metadata = mock_metadata_with_title(policy_title);
        metadata.protocol_version = Some(policy_evaluator::ProtocolVersion::V1);
        metadata.context_aware_resources = context_aware_resources;

        let scaffold_data = ScaffoldPolicyData {
            uri: "not_relevant".to_string(),
            policy_title: get_policy_title_from_cli_or_metadata(Some(policy_title), &metadata),
            metadata,
            settings: Default::default(),
        };

        let resource =
            generate_yaml_resource(scaffold_data, ManifestType::ClusterAdmissionPolicy, false)
                .expect("Cannot create yaml resource");

        let resource = resource.as_mapping().expect("resource should be a Map");
        let spec = resource.get("spec").expect("cannot get `Spec`");
        let context_aware_resources = spec.get("contextAwareResources");
        assert!(context_aware_resources.is_none());
    }

    #[test]
    fn test_manifest_with_invalid_policy_title() {
        // Test the validation function directly
        let result = validate_policy_title("My_policy");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid title"));
    }
}
