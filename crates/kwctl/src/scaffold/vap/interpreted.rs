use std::collections::BTreeSet;

use anyhow::Result;
use policy_evaluator::policy_fetcher::oci_client::Reference;
use tracing::warn;

use crate::scaffold::{
    kubewarden_crds::{ClusterAdmissionPolicy, ClusterAdmissionPolicySpec},
    vap::{VapData, vap_uses_kw_k8s, warn_kw_k8s_requires_grants},
};

/// Interpreter path: validates the OCI reference and builds a
/// [`ClusterAdmissionPolicy`] with all CEL config in settings.
pub(crate) fn vap_interpreted(
    cel_policy_module: &str,
    vap_data: VapData,
) -> Result<ClusterAdmissionPolicy> {
    match cel_policy_module.parse::<Reference>() {
        Ok(cel_policy_ref) => match cel_policy_ref.tag() {
            None | Some("latest") => {
                warn!(
                    "Using the 'latest' version of the CEL policy could lead to unexpected behavior. It is recommended to use a specific version to avoid breaking changes."
                );
            }
            _ => {}
        },
        Err(_) => {
            warn!("The CEL policy module specified is not a valid OCI reference");
        }
    }

    // Safety: VapData::new() already validated that spec is present.
    let vap_spec = vap_data.vap.spec.as_ref().unwrap();

    if vap_spec.audit_annotations.is_some() {
        warn!(
            "auditAnnotations are not supported by Kubewarden's CEL policy yet. They will be ignored."
        );
    }
    if vap_spec.match_conditions.is_some() {
        warn!(
            "matchConditions are not supported by Kubewarden's CEL policy yet. They will be ignored."
        );
    }

    let mut settings = vap_data.param_settings;

    if let Some(vap_failure_policy) = vap_spec.failure_policy.clone() {
        // CEL settings.failurePolicy, not to confuse with spec.failurePolicy
        settings.insert(
            "failurePolicy".into(),
            serde_yaml::to_value(vap_failure_policy)?,
        );
    }

    if let Some(vap_variables) = vap_spec.variables.clone() {
        let vap_variables: Vec<serde_yaml::Value> = vap_variables
            .iter()
            .map(|v| serde_yaml::to_value(v).expect("cannot convert VAP variable to YAML"))
            .collect();
        settings.insert("variables".into(), vap_variables.into());
    }

    if let Some(vap_validations) = vap_spec.validations.clone() {
        let kw_cel_validations: Vec<serde_yaml::Value> = vap_validations
            .iter()
            .map(|v| serde_yaml::to_value(v).expect("cannot convert VAP validation to YAML"))
            .collect();
        settings.insert("validations".into(), kw_cel_validations.into());
    }

    let mut context_aware_resources = BTreeSet::new();
    if let Some(param_resource) = &vap_data.param_resource {
        warn!(
            "granting access to {}/{} via spec.contextAwareResources (required by paramKind); review before applying",
            param_resource.api_version, param_resource.kind
        );
        context_aware_resources.insert(param_resource.clone());
    }

    // Unlike `paramKind`, there is no static way (short of parsing the CEL
    // AST ourselves) to know *which* apiVersion/kind a `kw.k8s.get`/`.list`
    // call targets, so we can only warn that `context_aware_resources` may
    // need to be extended by hand, not derive the grants automatically.
    // Detection here is a best-effort textual search over the raw CEL
    // expressions (see `vap_uses_kw_k8s`), since there is no compiled
    // artifact to inspect for actual host-extension usage on this path.
    if vap_uses_kw_k8s(&vap_data.vap) {
        warn_kw_k8s_requires_grants(&context_aware_resources);
    }

    Ok(ClusterAdmissionPolicy {
        api_version: "policies.kubewarden.io/v1".to_string(),
        kind: "ClusterAdmissionPolicy".to_string(),
        metadata: vap_data.metadata,
        spec: ClusterAdmissionPolicySpec {
            module: cel_policy_module.to_string(),
            namespace_selector: vap_data.namespace_selector,
            match_policy: vap_data.match_policy,
            rules: vap_data.rules,
            object_selector: vap_data.object_selector,
            mutating: false,
            background_audit: true,
            context_aware_resources,
            failure_policy: None,
            mode: None, // VAP policies are always in protect mode, which is the default for KW
            settings,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::{convert::TryFrom, fs::File};

    use k8s_openapi::api::admissionregistration::v1::{
        ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
    };
    use policy_evaluator::policy_metadata::{ContextAwareResource, Rule};
    use rstest::*;

    use super::*;
    use crate::scaffold::vap::tests::{CEL_POLICY_MODULE, test_data};

    #[rstest]
    #[case::vap_without_variables(
        "vap/vap-without-variables.yml",
        "vap/vap-binding.yml",
        false,
        false
    )]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml", true, false)]
    #[case::vap_with_params("vap/vap-with-params.yml", "vap/vap-binding-params.yml", false, true)]
    #[case::vap_with_params_no_action(
        "vap/vap-with-params.yml",
        "vap/vap-binding-params-no-action.yml",
        false,
        true
    )]
    #[case::only_param_kind("vap/vap-with-params.yml", "vap/vap-binding.yml", false, true)]
    #[case::only_param_ref(
        "vap/vap-without-variables.yml",
        "vap/vap-binding-params.yml",
        false,
        true
    )]
    fn from_vap_to_cluster_admission_policy(
        #[case] vap_yaml_path: &str,
        #[case] vap_binding_yaml_path: &str,
        #[case] has_variables: bool,
        #[case] has_params: bool,
    ) {
        let yaml_file = File::open(test_data(vap_yaml_path)).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();

        let expected_validations =
            serde_yaml::to_value(vap.clone().spec.unwrap().validations.unwrap()).unwrap();
        let expected_rules = vap
            .clone()
            .spec
            .unwrap()
            .match_constraints
            .unwrap()
            .resource_rules
            .unwrap()
            .iter()
            .map(Rule::try_from)
            .collect::<Result<Vec<Rule>, &str>>()
            .unwrap();
        let expected_failure_policy =
            serde_yaml::to_value(vap.clone().spec.unwrap().failure_policy).unwrap();
        let yaml_file = File::open(test_data(vap_binding_yaml_path)).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        let present_param_kind = vap.clone().spec.unwrap().param_kind.is_some();
        let present_param_ref = vap_binding.clone().spec.unwrap().param_ref.is_some();

        let vap_data_result = VapData::new(vap.clone(), vap_binding.clone());

        if has_params && present_param_kind != present_param_ref {
            assert!(vap_data_result.is_err());
            return;
        }

        let result = vap_interpreted(CEL_POLICY_MODULE, vap_data_result.unwrap());
        let cluster_admission_policy = result.unwrap();

        assert_eq!(CEL_POLICY_MODULE, cluster_admission_policy.spec.module);
        assert!(!cluster_admission_policy.spec.mutating);
        assert_eq!(cluster_admission_policy.spec.rules, expected_rules);
        assert!(cluster_admission_policy.spec.background_audit);
        if has_params {
            // The resource named by paramKind must be granted access to via
            // spec.contextAwareResources, otherwise the policy would be
            // denied when fetching it via paramRef at evaluation time.
            assert!(
                cluster_admission_policy
                    .spec
                    .context_aware_resources
                    .contains(&ContextAwareResource {
                        api_version: "v1".to_string(),
                        kind: "ConfigMap".to_string(),
                    }),
                "context_aware_resources should contain the param resource (v1/ConfigMap), got: {:?}",
                cluster_admission_policy.spec.context_aware_resources
            );
        } else {
            assert!(
                cluster_admission_policy
                    .spec
                    .context_aware_resources
                    .is_empty()
            );
        }
        assert_eq!(
            expected_failure_policy,
            cluster_admission_policy.spec.settings["failurePolicy"]
        );
        assert!(cluster_admission_policy.spec.mode.is_none());
        assert_eq!(
            vap.clone()
                .spec
                .unwrap()
                .match_constraints
                .unwrap()
                .match_policy,
            cluster_admission_policy.spec.match_policy
        );
        assert_eq!(
            vap_binding
                .clone()
                .spec
                .unwrap()
                .match_resources
                .unwrap()
                .namespace_selector,
            cluster_admission_policy.spec.namespace_selector
        );
        assert!(cluster_admission_policy.spec.object_selector.is_none());
        assert_eq!(
            expected_validations,
            cluster_admission_policy.spec.settings["validations"]
        );

        if has_variables {
            let expected_variables =
                serde_yaml::to_value(vap.clone().spec.unwrap().variables.unwrap()).unwrap();
            assert_eq!(
                expected_variables,
                cluster_admission_policy.spec.settings["variables"]
            );
        } else {
            assert!(
                !cluster_admission_policy
                    .spec
                    .settings
                    .contains_key("variables")
            );
        }

        if has_params {
            let expected_param_kind =
                serde_yaml::to_value(vap.clone().spec.unwrap().param_kind.unwrap()).unwrap();
            assert_eq!(
                expected_param_kind,
                cluster_admission_policy.spec.settings["paramKind"]
            );
            // paramRef.parameterNotFoundAction must always be present in the
            // generated settings: it's defaulted to Deny by VapData::new()
            // when the binding omits it (some fixtures set it explicitly,
            // others don't -- both must end up with a value here).
            let mut expected_param_ref = vap_binding.clone().spec.unwrap().param_ref.unwrap();
            if expected_param_ref.parameter_not_found_action.is_none() {
                expected_param_ref.parameter_not_found_action = Some("Deny".to_string());
            }
            let expected_param_ref = serde_yaml::to_value(expected_param_ref).unwrap();
            assert_eq!(
                expected_param_ref,
                cluster_admission_policy.spec.settings["paramRef"]
            );
        } else {
            assert!(
                !cluster_admission_policy
                    .spec
                    .settings
                    .contains_key("paramKind")
            );
            assert!(
                !cluster_admission_policy
                    .spec
                    .settings
                    .contains_key("paramRef")
            );
        }
    }

    /// A VAP that calls `kw.k8s.apiVersion(...).kind(...).get(...)` has no
    /// `paramKind`, so `context_aware_resources` stays empty: the apiVersion/
    /// kind targeted by `kw.k8s` calls is only detected via a best-effort
    /// textual search (see `vap_uses_kw_k8s`), never turned into a grant.
    /// This pins the current (intentionally incomplete) behavior that the
    /// `kw.k8s`-usage warning exists to compensate for.
    #[test]
    fn kw_k8s_usage_does_not_populate_context_aware_resources() {
        let yaml_file = File::open(test_data("vap/vap-with-k8s.yml")).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();
        let yaml_file = File::open(test_data("vap/vap-binding.yml")).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        let vap_data = VapData::new(vap, vap_binding).unwrap();
        let cluster_admission_policy = vap_interpreted(CEL_POLICY_MODULE, vap_data).unwrap();

        assert!(
            cluster_admission_policy
                .spec
                .context_aware_resources
                .is_empty(),
            "context_aware_resources should stay empty: kw.k8s targets are not statically derived, got: {:?}",
            cluster_admission_policy.spec.context_aware_resources
        );
    }
}
