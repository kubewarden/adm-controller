mod compiled;
mod interpreted;

use std::{collections::BTreeSet, convert::TryFrom, fs::File, path::Path};

use anyhow::{Result, anyhow};
use k8s_openapi::{
    api::admissionregistration::v1::{ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding},
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use policy_evaluator::policy_metadata::{ContextAwareResource, Rule};
use tracing::warn;

/// Combine a VAP selector and a binding selector into one selector with
/// AND logic.
///
/// Kubernetes runs the policy on an object only when the object matches
/// two selectors at the same time: the VAP `matchConstraints` selector
/// and the binding `matchResources` selector. A missing selector matches
/// every object, so an absent side adds no condition.
///
/// A `LabelSelector` already combines `matchLabels` and `matchExpressions`
/// with AND logic. This function merges two selectors into one selector
/// that keeps that same AND logic. kwctl copies `matchExpressions` from
/// both selectors into the result, side by side. kwctl also merges
/// `matchLabels` from both selectors.
///
/// When a key has the same value on both sides, kwctl keeps one copy of
/// the key.
///
/// When a key has a different value on each side, the merged selector
/// can match no object: an object cannot have two different values for
/// the same label at once. kwctl returns an error instead of building
/// that selector. `field` names the selector in the error message, for
/// example `"namespaceSelector"`.
fn and_label_selectors(
    field: &str,
    a: Option<LabelSelector>,
    b: Option<LabelSelector>,
) -> Result<Option<LabelSelector>> {
    let (a, b) = match (a, b) {
        (None, None) => return Ok(None),
        (Some(a), None) => return Ok(Some(a)),
        (None, Some(b)) => return Ok(Some(b)),
        (Some(a), Some(b)) => (a, b),
    };

    let mut match_expressions = a.match_expressions.unwrap_or_default();
    match_expressions.extend(b.match_expressions.unwrap_or_default());

    let mut match_labels = a.match_labels.unwrap_or_default();
    for (key, b_value) in b.match_labels.unwrap_or_default() {
        match match_labels.get(&key) {
            Some(a_value) if a_value == &b_value => {
                // The two sides use the same value for this key. Keep
                // one copy.
            }
            Some(a_value) => {
                return Err(anyhow!(
                    "{field}: the ValidatingAdmissionPolicy sets the label '{key}' to '{a_value}', and the ValidatingAdmissionPolicyBinding sets it to '{b_value}'. A selector with both values matches no object. Set the same value on both sides, or remove the label from one side"
                ));
            }
            None => {
                match_labels.insert(key, b_value);
            }
        }
    }

    Ok(Some(LabelSelector {
        match_expressions: if match_expressions.is_empty() {
            None
        } else {
            Some(match_expressions)
        },
        match_labels: if match_labels.is_empty() {
            None
        } else {
            Some(match_labels)
        },
    }))
}

pub(crate) fn vap(
    cel_policy_module: &str,
    vap_path: &Path,
    binding_path: &Path,
    compile_to_wasm: Option<&Path>,
    force: bool,
) -> Result<()> {
    let vap_file = File::open(vap_path)
        .map_err(|e| anyhow!("cannot open {}: {e}", vap_path.to_str().unwrap()))?;
    let binding_file = File::open(binding_path)
        .map_err(|e| anyhow!("cannot open {}: {e}", binding_path.to_str().unwrap()))?;

    let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(vap_file)
        .map_err(|e| anyhow!("cannot convert given data into a ValidatingAdmissionPolicy: {e}"))?;
    let vap_binding: ValidatingAdmissionPolicyBinding = serde_yaml::from_reader(binding_file)
        .map_err(|e| {
            anyhow!("cannot convert given data into a ValidatingAdmissionPolicyBinding: {e}")
        })?;

    let vap_data = VapData::new(vap, vap_binding)?;

    let cluster_admission_policy = match compile_to_wasm {
        Some(wasm_path) => compiled::vap_compiled(vap_data, wasm_path, force)?,
        None => interpreted::vap_interpreted(cel_policy_module, vap_data)?,
    };

    serde_yaml::to_writer(std::io::stdout(), &cluster_admission_policy)?;

    Ok(())
}

/// Warn that this policy calls `kw.k8s`, which reads Kubernetes resources at
/// evaluation time. The `granted` set holds the resources currently allowed
/// in `spec.contextAwareResources` and `metadata.yml`. This set only comes
/// from `paramKind`, so it can miss resources the policy reads through
/// `kw.k8s`.
///
/// The runtime denies a `kw.k8s` call when its apiVersion and kind are not in
/// `granted` (see `EvaluationContext::can_access_kubernetes_resource`). The
/// user must review the generated `contextAwareResources` list and add each
/// missing apiVersion and kind by hand before they apply the policy.
pub(crate) fn warn_kw_k8s_requires_grants(granted: &BTreeSet<ContextAwareResource>) {
    if granted.is_empty() {
        warn!(
            "this policy calls kw.k8s.*, but spec.contextAwareResources is empty. Every kw.k8s get/list call will be denied at evaluation time. Add each apiVersion/kind that the policy reads through kw.k8s to spec.contextAwareResources in the generated ClusterAdmissionPolicy. Add the same entries to contextAwareResources in metadata.yml, if that file was generated."
        );
    } else {
        let granted_list = granted
            .iter()
            .map(|r| format!("{}/{}", r.api_version, r.kind))
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "this policy calls kw.k8s.*. Only {granted_list} is granted through spec.contextAwareResources, derived from paramKind. Add every other apiVersion/kind that the policy reads through kw.k8s to spec.contextAwareResources by hand, and to metadata.yml if that file was generated. Without this, the runtime denies the call at evaluation time."
        );
    }
}

/// Check whether any CEL expression in `vap` mentions `kw.k8s`. The check
/// looks at `validations`, `variables`, and `matchConditions`, and searches
/// only for the text `kw.k8s`.
///
/// The interpreted path uses this check because it has no compiled Wasm
/// module to inspect. The compiled path instead reads the exact list of
/// host extensions from the `ferricel.extensions` section of the module.
///
/// A text search can find `kw.k8s` inside a string literal and report a
/// false positive. It cannot miss a real use in valid CEL, so this check
/// never produces a false negative. A false positive only causes an extra
/// warning. It does not hide a real one.
fn vap_uses_kw_k8s(vap: &ValidatingAdmissionPolicy) -> bool {
    let Some(spec) = vap.spec.as_ref() else {
        return false;
    };

    let validations_use_it = spec
        .validations
        .iter()
        .flatten()
        .any(|v| v.expression.contains("kw.k8s"));
    let variables_use_it = spec
        .variables
        .iter()
        .flatten()
        .any(|v| v.expression.contains("kw.k8s"));
    let match_conditions_use_it = spec
        .match_conditions
        .iter()
        .flatten()
        .any(|m| m.expression.contains("kw.k8s"));

    validations_use_it || variables_use_it || match_conditions_use_it
}

/// Data extracted from a VAP + binding pair, shared by both output paths.
pub(crate) struct VapData {
    pub(crate) vap: ValidatingAdmissionPolicy,
    pub(crate) metadata: ObjectMeta,
    pub(crate) rules: Vec<Rule>,
    pub(crate) match_policy: Option<String>,
    pub(crate) namespace_selector: Option<LabelSelector>,
    pub(crate) object_selector: Option<LabelSelector>,
    /// paramKind + paramRef settings (when both are present).
    pub(crate) param_settings: serde_yaml::Mapping,
    /// The Kubernetes resource (apiVersion/kind) named by `paramKind`, when
    /// present. This is the resource the compiled/interpreted policy fetches
    /// at evaluation time via `paramRef`, and must be granted access to via
    /// `spec.contextAwareResources` for the fetch to succeed.
    pub(crate) param_resource: Option<ContextAwareResource>,
}

impl VapData {
    pub(crate) fn new(
        vap: ValidatingAdmissionPolicy,
        vap_binding: ValidatingAdmissionPolicyBinding,
    ) -> Result<Self> {
        let vap_spec = vap
            .spec
            .as_ref()
            .ok_or_else(|| anyhow!("ValidatingAdmissionPolicy has no spec"))?;
        let vap_binding_spec = vap_binding.spec.unwrap_or_default();

        // The binding only references its policy by name; make sure it
        // actually points at the VAP we were given. Without this check a
        // mismatched pair is silently combined, compiling one policy while
        // applying another policy's binding metadata (name, selectors,
        // paramRef, ...).
        let vap_name = vap
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| anyhow!("ValidatingAdmissionPolicy has no metadata.name"))?;
        let policy_name = vap_binding_spec
            .policy_name
            .as_deref()
            .ok_or_else(|| anyhow!("ValidatingAdmissionPolicyBinding has no spec.policyName"))?;
        if policy_name != vap_name {
            return Err(anyhow!(
                "ValidatingAdmissionPolicyBinding spec.policyName '{policy_name}' does not match ValidatingAdmissionPolicy metadata.name '{vap_name}'"
            ));
        }

        // Params: both must be present together or both absent.
        let mut param_settings = serde_yaml::Mapping::new();
        let mut param_resource = None;
        match (&vap_spec.param_kind, vap_binding_spec.param_ref) {
            (Some(vap_param_kind), Some(mut vap_param_ref)) => {
                // The Kubernetes API marks `parameterNotFoundAction` as
                // required, but a hand-written binding may omit it. Default
                // to `Deny` (fail-closed) rather than silently forwarding an
                // incomplete paramRef, which the ferricel/cel-policy runtime
                // would reject at settings-validation time.
                if vap_param_ref.parameter_not_found_action.is_none() {
                    warn!(
                        "paramRef.parameterNotFoundAction not set in the binding; defaulting to Deny"
                    );
                    vap_param_ref.parameter_not_found_action = Some("Deny".to_string());
                }

                param_settings.insert("paramKind".into(), serde_yaml::to_value(vap_param_kind)?);
                param_settings.insert("paramRef".into(), serde_yaml::to_value(&vap_param_ref)?);

                if let (Some(api_version), Some(kind)) =
                    (&vap_param_kind.api_version, &vap_param_kind.kind)
                {
                    param_resource = Some(ContextAwareResource {
                        api_version: api_version.clone(),
                        kind: kind.clone(),
                    });
                }
            }
            (None, None) => {}
            _ => {
                return Err(anyhow!(
                    "Both paramKind and paramRef must be present together, or both absent"
                ));
            }
        }

        // Kubernetes runs the policy on a request only when the request
        // matches two match sets at the same time: `matchConstraints`
        // (set on the VAP) and `matchResources` (set on the binding).
        // See the function `and_label_selectors` for more information.
        // kwctl must merge or reject every field that can narrow that
        // match. If kwctl does not, the generated ClusterAdmissionPolicy
        // can run against resources that the original VAP and binding
        // pair excluded.
        let vap_match_constraints = vap_spec.match_constraints.clone().unwrap_or_default();
        let binding_match_resources = vap_binding_spec.match_resources.unwrap_or_default();

        if vap_match_constraints
            .exclude_resource_rules
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
        {
            return Err(anyhow!(
                "ValidatingAdmissionPolicy spec.matchConstraints.excludeResourceRules is not supported. ClusterAdmissionPolicy has no matching field. Remove excludeResourceRules, and narrow spec.matchConstraints.resourceRules instead"
            ));
        }
        if binding_match_resources
            .exclude_resource_rules
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
        {
            return Err(anyhow!(
                "ValidatingAdmissionPolicyBinding spec.matchResources.excludeResourceRules is not supported. ClusterAdmissionPolicy has no matching field. Remove excludeResourceRules, and narrow spec.matchConstraints.resourceRules on the ValidatingAdmissionPolicy instead"
            ));
        }
        if binding_match_resources
            .resource_rules
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
        {
            return Err(anyhow!(
                "ValidatingAdmissionPolicyBinding spec.matchResources.resourceRules is not supported. kwctl only translates spec.matchConstraints.resourceRules from the ValidatingAdmissionPolicy. Move the narrowing into the ValidatingAdmissionPolicy, or remove it from the binding"
            ));
        }
        if let Some(binding_match_policy) = binding_match_resources.match_policy.as_deref() {
            // This field defaults to "Equivalent" on both the VAP and
            // the binding. Kubernetes uses this default when a user
            // leaves the field unset.
            let vap_match_policy = vap_match_constraints
                .match_policy
                .as_deref()
                .unwrap_or("Equivalent");
            if binding_match_policy != vap_match_policy {
                return Err(anyhow!(
                    "ValidatingAdmissionPolicyBinding spec.matchResources.matchPolicy is '{binding_match_policy}'. ValidatingAdmissionPolicy spec.matchConstraints.matchPolicy is '{vap_match_policy}'. The two values differ. Make the two values equal, or remove matchPolicy from the binding"
                ));
            }
        }

        let namespace_selector = and_label_selectors(
            "namespaceSelector",
            vap_match_constraints.namespace_selector.clone(),
            binding_match_resources.namespace_selector,
        )?;
        let object_selector = and_label_selectors(
            "objectSelector",
            vap_match_constraints.object_selector.clone(),
            binding_match_resources.object_selector,
        )?;
        let match_policy = vap_match_constraints.match_policy.clone();
        let rules = vap_match_constraints
            .resource_rules
            .unwrap_or_default()
            .iter()
            .map(Rule::try_from)
            .collect::<Result<Vec<Rule>, &'static str>>()
            .map_err(|e| anyhow!("error converting VAP matchConstraints into rules: {e}"))?;

        Ok(VapData {
            vap,
            metadata: vap_binding.metadata,
            rules,
            match_policy,
            namespace_selector,
            object_selector,
            param_settings,
            param_resource,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{collections::BTreeMap, fs::File, path::Path};

    use k8s_openapi::{
        api::admissionregistration::v1::{
            MatchResources, NamedRuleWithOperations, ValidatingAdmissionPolicy,
            ValidatingAdmissionPolicyBinding,
        },
        apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement},
    };
    use rstest::*;

    use super::{VapData, and_label_selectors};

    pub(crate) const CEL_POLICY_MODULE: &str = "ghcr.io/kubewarden/policies/cel-policy:latest";

    pub(crate) fn test_data(path: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(path)
            .to_string_lossy()
            .to_string()
    }

    fn open_vap_data(vap_yaml_path: &str, vap_binding_yaml_path: &str) -> VapData {
        let (vap, vap_binding) = open_raw(vap_yaml_path, vap_binding_yaml_path);
        VapData::new(vap, vap_binding).expect("cannot build VapData")
    }

    fn open_raw(
        vap_yaml_path: &str,
        vap_binding_yaml_path: &str,
    ) -> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
        let yaml_file = File::open(test_data(vap_yaml_path)).expect("cannot open VAP yaml file");
        let vap: ValidatingAdmissionPolicy =
            serde_yaml::from_reader(yaml_file).expect("cannot parse VAP yaml file");

        let yaml_file = File::open(test_data(vap_binding_yaml_path))
            .expect("cannot open VAP binding yaml file");
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).expect("cannot parse VAP binding yaml file");

        (vap, vap_binding)
    }

    fn open_vap(vap_yaml_path: &str) -> ValidatingAdmissionPolicy {
        let yaml_file = File::open(test_data(vap_yaml_path)).expect("cannot open VAP yaml file");
        serde_yaml::from_reader(yaml_file).expect("cannot parse VAP yaml file")
    }

    /// Build a VAP and binding pair. The match-field tests start from
    /// this pair and change it.
    #[fixture]
    fn vap_pair() -> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
        open_raw("vap/vap-without-variables.yml", "vap/vap-binding.yml")
    }

    /// Return a mutable reference to `vap.spec.matchConstraints`. When
    /// the field is absent, insert a default value first.
    fn vap_match_constraints(vap: &mut ValidatingAdmissionPolicy) -> &mut MatchResources {
        vap.spec
            .as_mut()
            .expect("vap has a spec")
            .match_constraints
            .get_or_insert_with(Default::default)
    }

    /// Return a mutable reference to `binding.spec.matchResources`. When
    /// the field is absent, insert a default value first.
    fn binding_match_resources(
        binding: &mut ValidatingAdmissionPolicyBinding,
    ) -> &mut MatchResources {
        binding
            .spec
            .as_mut()
            .expect("binding has a spec")
            .match_resources
            .get_or_insert_with(Default::default)
    }

    #[test]
    fn vap_uses_kw_k8s_detects_it_in_validations() {
        let vap = open_vap("vap/vap-with-k8s.yml");
        assert!(super::vap_uses_kw_k8s(&vap));
    }

    #[rstest]
    #[case::without_variables("vap/vap-without-variables.yml")]
    #[case::with_variables("vap/vap-with-variables.yml")]
    #[case::with_host_capabilities("vap/vap-with-host-capabilities.yml")]
    fn vap_uses_kw_k8s_is_false_when_not_used(#[case] vap_yaml_path: &str) {
        let vap = open_vap(vap_yaml_path);
        assert!(!super::vap_uses_kw_k8s(&vap));
    }

    #[test]
    fn param_ref_parameter_not_found_action_defaults_to_deny_when_absent() {
        let vap_data = open_vap_data(
            "vap/vap-with-params.yml",
            "vap/vap-binding-params-no-action.yml",
        );

        assert_eq!(
            "Deny",
            vap_data.param_settings["paramRef"]["parameterNotFoundAction"]
                .as_str()
                .expect("parameterNotFoundAction should be a string")
        );
    }

    #[test]
    fn param_ref_parameter_not_found_action_is_preserved_when_present() {
        // The fixture explicitly sets parameterNotFoundAction to Deny; this
        // pins that an explicit value is forwarded as-is (not overwritten).
        let vap_data = open_vap_data("vap/vap-with-params.yml", "vap/vap-binding-params.yml");

        assert_eq!(
            "Deny",
            vap_data.param_settings["paramRef"]["parameterNotFoundAction"]
                .as_str()
                .expect("parameterNotFoundAction should be a string")
        );
    }

    #[rstest]
    fn new_rejects_binding_whose_policy_name_does_not_match_the_vap(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (vap, mut vap_binding) = vap_pair;
        vap_binding
            .spec
            .as_mut()
            .expect("binding has a spec")
            .policy_name = Some("some-other-policy".to_string());

        let err = match VapData::new(vap, vap_binding) {
            Ok(_) => panic!("mismatched policyName/metadata.name should be rejected"),
            Err(e) => e,
        };

        let message = err.to_string();
        assert!(message.contains("some-other-policy"), "{message}");
        assert!(message.contains("vap-test"), "{message}");
    }

    #[rstest]
    fn new_rejects_vap_with_no_metadata_name(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (mut vap, vap_binding) = vap_pair;
        vap.metadata.name = None;

        let err = match VapData::new(vap, vap_binding) {
            Ok(_) => panic!("VAP with no metadata.name is rejected"),
            Err(e) => e,
        };

        assert!(err.to_string().contains("metadata.name"));
    }

    fn label_selector(labels: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            match_expressions: None,
        }
    }

    fn in_requirement(key: &str, value: &str) -> LabelSelectorRequirement {
        LabelSelectorRequirement {
            key: key.to_string(),
            operator: "In".to_string(),
            values: Some(vec![value.to_string()]),
        }
    }

    fn expressions_selector(requirements: Vec<LabelSelectorRequirement>) -> LabelSelector {
        LabelSelector {
            match_labels: None,
            match_expressions: Some(requirements),
        }
    }

    #[rstest]
    #[case::both_absent(None, None, None)]
    #[case::only_vap(
        Some(label_selector(&[("env", "prod")])),
        None,
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::only_binding(
        None,
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::disjoint_labels_are_merged(
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("team", "platform")])),
        Some(label_selector(&[("env", "prod"), ("team", "platform")]))
    )]
    #[case::same_label_same_value_keeps_one_copy(
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::match_expressions_are_concatenated(
        Some(expressions_selector(vec![in_requirement("env", "prod")])),
        Some(expressions_selector(vec![in_requirement("team", "platform")])),
        Some(expressions_selector(vec![
            in_requirement("env", "prod"),
            in_requirement("team", "platform"),
        ]))
    )]
    fn and_label_selectors_cases(
        #[case] vap: Option<LabelSelector>,
        #[case] binding: Option<LabelSelector>,
        #[case] expected: Option<LabelSelector>,
    ) {
        assert_eq!(
            and_label_selectors("namespaceSelector", vap, binding).expect("no label conflict"),
            expected
        );
    }

    #[test]
    fn and_label_selectors_rejects_a_label_with_different_values() {
        let vap = label_selector(&[("env", "prod")]);
        let binding = label_selector(&[("env", "staging")]);

        let err = match and_label_selectors("namespaceSelector", Some(vap), Some(binding)) {
            Ok(_) => panic!("a label with two different values should be rejected"),
            Err(e) => e,
        };

        let message = err.to_string();
        assert!(message.contains("namespaceSelector"), "{message}");
        assert!(message.contains("env"), "{message}");
        assert!(message.contains("prod"), "{message}");
        assert!(message.contains("staging"), "{message}");
    }

    #[rstest]
    fn new_merges_namespace_selector_from_vap_and_binding(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (mut vap, vap_binding) = vap_pair;
        vap_match_constraints(&mut vap).namespace_selector =
            Some(label_selector(&[("team", "platform")]));
        // The fixture binding already sets `namespaceSelector` to
        // kubernetes.io/metadata.name=default.

        let vap_data = VapData::new(vap, vap_binding).expect("VapData::new should succeed");

        let namespace_selector = vap_data
            .namespace_selector
            .expect("namespace_selector should be present");
        assert_eq!(
            namespace_selector.match_labels,
            Some(BTreeMap::from([
                (
                    "kubernetes.io/metadata.name".to_string(),
                    "default".to_string()
                ),
                ("team".to_string(), "platform".to_string()),
            ]))
        );
    }

    #[rstest]
    fn new_keeps_binding_object_selector_that_the_vap_does_not_set(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (vap, mut vap_binding) = vap_pair;
        binding_match_resources(&mut vap_binding).object_selector =
            Some(label_selector(&[("app", "web")]));

        let vap_data = VapData::new(vap, vap_binding).expect("VapData::new should succeed");

        assert_eq!(
            vap_data
                .object_selector
                .expect("object_selector should be present")
                .match_labels,
            Some(BTreeMap::from([("app".to_string(), "web".to_string())]))
        );
    }

    type MutatePair = fn(&mut ValidatingAdmissionPolicy, &mut ValidatingAdmissionPolicyBinding);

    #[rstest]
    #[case::vap_exclude_resource_rules(
        (|vap: &mut ValidatingAdmissionPolicy, _: &mut ValidatingAdmissionPolicyBinding| {
            vap_match_constraints(vap).exclude_resource_rules =
                Some(vec![NamedRuleWithOperations::default()]);
        }) as MutatePair,
        Some("matchConstraints.excludeResourceRules")
    )]
    #[case::binding_exclude_resource_rules(
        (|_: &mut ValidatingAdmissionPolicy, binding: &mut ValidatingAdmissionPolicyBinding| {
            binding_match_resources(binding).exclude_resource_rules =
                Some(vec![NamedRuleWithOperations::default()]);
        }) as MutatePair,
        Some("matchResources.excludeResourceRules")
    )]
    #[case::binding_resource_rules(
        (|_: &mut ValidatingAdmissionPolicy, binding: &mut ValidatingAdmissionPolicyBinding| {
            binding_match_resources(binding).resource_rules =
                Some(vec![NamedRuleWithOperations::default()]);
        }) as MutatePair,
        Some("matchResources.resourceRules")
    )]
    #[case::binding_match_policy_differs_from_the_vap(
        // The VAP fixture does not set `matchPolicy`. This field
        // defaults to "Equivalent". The binding sets `matchPolicy` to
        // "Exact". The two values differ.
        (|_: &mut ValidatingAdmissionPolicy, binding: &mut ValidatingAdmissionPolicyBinding| {
            binding_match_resources(binding).match_policy = Some("Exact".to_string());
        }) as MutatePair,
        Some("matchPolicy")
    )]
    #[case::binding_match_policy_equals_the_vap_default(
        // The VAP fixture leaves `matchPolicy` unset. This field
        // defaults to "Equivalent". The binding sets `matchPolicy` to
        // the same value. Kubernetes allows this.
        (|_: &mut ValidatingAdmissionPolicy, binding: &mut ValidatingAdmissionPolicyBinding| {
            binding_match_resources(binding).match_policy = Some("Equivalent".to_string());
        }) as MutatePair,
        None
    )]
    #[case::vap_and_binding_namespace_selector_conflict(
        // The fixture binding sets `namespaceSelector` to
        // kubernetes.io/metadata.name=default. Setting the same key to a
        // different value on the VAP makes the merge fail.
        (|vap: &mut ValidatingAdmissionPolicy, _: &mut ValidatingAdmissionPolicyBinding| {
            vap_match_constraints(vap).namespace_selector =
                Some(label_selector(&[("kubernetes.io/metadata.name", "other")]));
        }) as MutatePair,
        Some("namespaceSelector")
    )]
    fn new_checks_match_fields(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
        #[case] mutate: MutatePair,
        #[case] expected_error: Option<&str>,
    ) {
        let (mut vap, mut vap_binding) = vap_pair;
        mutate(&mut vap, &mut vap_binding);

        let result = VapData::new(vap, vap_binding);
        match expected_error {
            None => {
                result.expect("VapData::new should succeed");
            }
            Some(needle) => {
                let err = match result {
                    Ok(_) => panic!("expected an error that mentions '{needle}'"),
                    Err(e) => e,
                };
                assert!(err.to_string().contains(needle), "{err}");
            }
        }
    }
}
