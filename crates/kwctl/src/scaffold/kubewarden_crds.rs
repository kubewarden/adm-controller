use std::collections::BTreeSet;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use policy_evaluator::policy_metadata::{ContextAwareResource, Rule};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterAdmissionPolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: ClusterAdmissionPolicySpec,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClusterAdmissionPolicySpec {
    pub module: String,
    pub settings: serde_yaml::Mapping,
    pub rules: Vec<Rule>,
    pub mutating: bool,
    // Skip serialization when this is true, which is the default case.
    // This is needed as a temporary fix for https://github.com/kubewarden/kubewarden-controller/issues/395
    #[serde(skip_serializing_if = "is_true")]
    pub background_audit: bool,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub context_aware_resources: BTreeSet<ContextAwareResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<LabelSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_selector: Option<LabelSelector>,
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdmissionPolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: AdmissionPolicySpec,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdmissionPolicySpec {
    pub module: String,
    pub settings: serde_yaml::Mapping,
    pub rules: Vec<Rule>,
    pub mutating: bool,
    // Skip serialization when this is true, which is the default case.
    // This is needed as a temporary fix for https://github.com/kubewarden/kubewarden-controller/issues/395
    #[serde(skip_serializing_if = "is_true")]
    pub background_audit: bool,
}
