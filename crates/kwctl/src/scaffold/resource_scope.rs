//! Static scope information for built-in Kubernetes resources, used by the
//! AdmissionPolicy scaffold to refuse generating manifests that target
//! cluster-scoped resources (an `AdmissionPolicy` is namespaced, and a
//! cluster-scoped target would never be evaluated against it).

use std::collections::BTreeSet;

use policy_evaluator::policy_metadata::Rule;

/// Resource API group and plural pair, used as a key into the built-in
/// resource scope table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ResourceKey {
    api_group: &'static str,
    resource: &'static str,
}

/// List of well-known cluster-scoped Kubernetes resources from the standard
/// API groups shipped with kube-apiserver (v1.33). Subresources (`pods/log`,
/// `nodes/proxy`, ...) inherit the scope of their parent resource and are not
/// listed here.
const CLUSTER_SCOPED_RESOURCES: &[ResourceKey] = &[
    // core / ""
    ResourceKey {
        api_group: "",
        resource: "componentstatuses",
    },
    ResourceKey {
        api_group: "",
        resource: "namespaces",
    },
    ResourceKey {
        api_group: "",
        resource: "nodes",
    },
    ResourceKey {
        api_group: "",
        resource: "persistentvolumes",
    },
    // admissionregistration.k8s.io
    ResourceKey {
        api_group: "admissionregistration.k8s.io",
        resource: "mutatingwebhookconfigurations",
    },
    ResourceKey {
        api_group: "admissionregistration.k8s.io",
        resource: "validatingwebhookconfigurations",
    },
    ResourceKey {
        api_group: "admissionregistration.k8s.io",
        resource: "validatingadmissionpolicies",
    },
    ResourceKey {
        api_group: "admissionregistration.k8s.io",
        resource: "validatingadmissionpolicybindings",
    },
    ResourceKey {
        api_group: "admissionregistration.k8s.io",
        resource: "mutatingadmissionpolicies",
    },
    ResourceKey {
        api_group: "admissionregistration.k8s.io",
        resource: "mutatingadmissionpolicybindings",
    },
    // apiextensions.k8s.io
    ResourceKey {
        api_group: "apiextensions.k8s.io",
        resource: "customresourcedefinitions",
    },
    // apiregistration.k8s.io
    ResourceKey {
        api_group: "apiregistration.k8s.io",
        resource: "apiservices",
    },
    // authentication.k8s.io
    ResourceKey {
        api_group: "authentication.k8s.io",
        resource: "tokenreviews",
    },
    // authorization.k8s.io
    ResourceKey {
        api_group: "authorization.k8s.io",
        resource: "selfsubjectaccessreviews",
    },
    ResourceKey {
        api_group: "authorization.k8s.io",
        resource: "selfsubjectrulesreviews",
    },
    ResourceKey {
        api_group: "authorization.k8s.io",
        resource: "subjectaccessreviews",
    },
    // certificates.k8s.io
    ResourceKey {
        api_group: "certificates.k8s.io",
        resource: "certificatesigningrequests",
    },
    ResourceKey {
        api_group: "certificates.k8s.io",
        resource: "clustertrustbundles",
    },
    // flowcontrol.apiserver.k8s.io
    ResourceKey {
        api_group: "flowcontrol.apiserver.k8s.io",
        resource: "flowschemas",
    },
    ResourceKey {
        api_group: "flowcontrol.apiserver.k8s.io",
        resource: "prioritylevelconfigurations",
    },
    // networking.k8s.io
    ResourceKey {
        api_group: "networking.k8s.io",
        resource: "ingressclasses",
    },
    ResourceKey {
        api_group: "networking.k8s.io",
        resource: "ipaddresses",
    },
    ResourceKey {
        api_group: "networking.k8s.io",
        resource: "servicecidrs",
    },
    // node.k8s.io
    ResourceKey {
        api_group: "node.k8s.io",
        resource: "runtimeclasses",
    },
    // rbac.authorization.k8s.io
    ResourceKey {
        api_group: "rbac.authorization.k8s.io",
        resource: "clusterroles",
    },
    ResourceKey {
        api_group: "rbac.authorization.k8s.io",
        resource: "clusterrolebindings",
    },
    // resource.k8s.io
    ResourceKey {
        api_group: "resource.k8s.io",
        resource: "deviceclasses",
    },
    ResourceKey {
        api_group: "resource.k8s.io",
        resource: "resourceslices",
    },
    // scheduling.k8s.io
    ResourceKey {
        api_group: "scheduling.k8s.io",
        resource: "priorityclasses",
    },
    // storage.k8s.io
    ResourceKey {
        api_group: "storage.k8s.io",
        resource: "csidrivers",
    },
    ResourceKey {
        api_group: "storage.k8s.io",
        resource: "csinodes",
    },
    ResourceKey {
        api_group: "storage.k8s.io",
        resource: "storageclasses",
    },
    ResourceKey {
        api_group: "storage.k8s.io",
        resource: "volumeattachments",
    },
    // storagemigration.k8s.io
    ResourceKey {
        api_group: "storagemigration.k8s.io",
        resource: "storageversionmigrations",
    },
];

/// API groups that ship as part of the kube-apiserver core distribution. Any
/// other API group is treated as a Custom Resource Definition for the purpose
/// of the scaffold check (we cannot tell its scope statically).
const BUILT_IN_API_GROUPS: &[&str] = &[
    "",
    "admissionregistration.k8s.io",
    "apiextensions.k8s.io",
    "apiregistration.k8s.io",
    "apps",
    "authentication.k8s.io",
    "authorization.k8s.io",
    "autoscaling",
    "batch",
    "certificates.k8s.io",
    "coordination.k8s.io",
    "discovery.k8s.io",
    "events.k8s.io",
    "flowcontrol.apiserver.k8s.io",
    "networking.k8s.io",
    "node.k8s.io",
    "policy",
    "rbac.authorization.k8s.io",
    "resource.k8s.io",
    "scheduling.k8s.io",
    "storage.k8s.io",
    "storagemigration.k8s.io",
];

/// Inspect the rules and classify each (api_group, resource) pair into one of
/// the three categories the scaffold cares about: a known cluster-scoped
/// built-in, an unknown resource (likely a CRD, or one we cannot disambiguate
/// because the rule uses wildcards), or a known namespaced built-in.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct AdmissionPolicyScopeFindings {
    /// (api_group, resource) pairs that match a known cluster-scoped built-in
    /// Kubernetes resource. Targeting these from an `AdmissionPolicy` always
    /// produces a manifest that will never be evaluated by the cluster.
    pub cluster_scoped: Vec<(String, String)>,
    /// (api_group, resource) pairs that we cannot classify statically. This
    /// covers Custom Resource Definitions (any api_group outside the well-
    /// known kube-apiserver set) and wildcard rules that may resolve to either
    /// scope at runtime.
    pub unknown: Vec<(String, String)>,
}

impl AdmissionPolicyScopeFindings {
    pub(crate) fn has_cluster_scoped(&self) -> bool {
        !self.cluster_scoped.is_empty()
    }

    pub(crate) fn has_unknown(&self) -> bool {
        !self.unknown.is_empty()
    }
}

pub(crate) fn classify_admission_policy_rules(rules: &[Rule]) -> AdmissionPolicyScopeFindings {
    let mut cluster_scoped = BTreeSet::new();
    let mut unknown = BTreeSet::new();

    for rule in rules {
        for api_group in &rule.api_groups {
            for resource in &rule.resources {
                let base_resource = resource.split('/').next().unwrap_or(resource);
                let pair = (api_group.clone(), resource.clone());

                if api_group == "*" || base_resource == "*" {
                    unknown.insert(pair);
                    continue;
                }

                if is_known_cluster_scoped(api_group, base_resource) {
                    cluster_scoped.insert(pair);
                } else if !is_built_in_api_group(api_group) {
                    unknown.insert(pair);
                }
                // Otherwise it is a known namespaced built-in: nothing to flag.
            }
        }
    }

    AdmissionPolicyScopeFindings {
        cluster_scoped: cluster_scoped.into_iter().collect(),
        unknown: unknown.into_iter().collect(),
    }
}

fn is_known_cluster_scoped(api_group: &str, resource: &str) -> bool {
    CLUSTER_SCOPED_RESOURCES
        .iter()
        .any(|key| key.api_group == api_group && key.resource == resource)
}

fn is_built_in_api_group(api_group: &str) -> bool {
    BUILT_IN_API_GROUPS.contains(&api_group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use policy_evaluator::policy_metadata::{Operation, Rule};

    fn rule(api_groups: &[&str], resources: &[&str]) -> Rule {
        Rule {
            api_groups: api_groups.iter().map(|s| s.to_string()).collect(),
            api_versions: vec!["v1".to_string()],
            resources: resources.iter().map(|s| s.to_string()).collect(),
            operations: vec![Operation::Create],
        }
    }

    #[test]
    fn namespaced_built_in_resource_produces_no_findings() {
        let rules = vec![rule(&[""], &["pods"]), rule(&["apps"], &["deployments"])];
        let findings = classify_admission_policy_rules(&rules);
        assert!(findings.cluster_scoped.is_empty());
        assert!(findings.unknown.is_empty());
    }

    #[test]
    fn core_cluster_scoped_resource_is_detected() {
        let rules = vec![rule(&[""], &["namespaces"])];
        let findings = classify_admission_policy_rules(&rules);
        assert_eq!(
            findings.cluster_scoped,
            vec![("".to_string(), "namespaces".to_string())]
        );
        assert!(findings.unknown.is_empty());
    }

    #[test]
    fn cluster_scoped_in_named_group_is_detected() {
        let rules = vec![rule(&["rbac.authorization.k8s.io"], &["clusterroles"])];
        let findings = classify_admission_policy_rules(&rules);
        assert_eq!(
            findings.cluster_scoped,
            vec![(
                "rbac.authorization.k8s.io".to_string(),
                "clusterroles".to_string()
            )]
        );
    }

    #[test]
    fn authentication_and_authorization_review_resources_are_cluster_scoped() {
        let rules = vec![
            rule(&["authentication.k8s.io"], &["tokenreviews"]),
            rule(
                &["authorization.k8s.io"],
                &[
                    "selfsubjectaccessreviews",
                    "selfsubjectrulesreviews",
                    "subjectaccessreviews",
                ],
            ),
        ];
        let findings = classify_admission_policy_rules(&rules);
        assert_eq!(
            findings.cluster_scoped,
            vec![
                (
                    "authentication.k8s.io".to_string(),
                    "tokenreviews".to_string()
                ),
                (
                    "authorization.k8s.io".to_string(),
                    "selfsubjectaccessreviews".to_string()
                ),
                (
                    "authorization.k8s.io".to_string(),
                    "selfsubjectrulesreviews".to_string()
                ),
                (
                    "authorization.k8s.io".to_string(),
                    "subjectaccessreviews".to_string()
                ),
            ]
        );
        assert!(findings.unknown.is_empty());
    }

    #[test]
    fn custom_resource_is_classified_as_unknown() {
        let rules = vec![rule(&["example.com"], &["widgets"])];
        let findings = classify_admission_policy_rules(&rules);
        assert!(findings.cluster_scoped.is_empty());
        assert_eq!(
            findings.unknown,
            vec![("example.com".to_string(), "widgets".to_string())]
        );
    }

    #[test]
    fn wildcard_api_group_is_classified_as_unknown() {
        let rules = vec![rule(&["*"], &["pods"])];
        let findings = classify_admission_policy_rules(&rules);
        assert!(findings.cluster_scoped.is_empty());
        assert_eq!(
            findings.unknown,
            vec![("*".to_string(), "pods".to_string())]
        );
    }

    #[test]
    fn wildcard_resource_is_classified_as_unknown() {
        let rules = vec![rule(&[""], &["*"])];
        let findings = classify_admission_policy_rules(&rules);
        assert!(findings.cluster_scoped.is_empty());
        assert_eq!(findings.unknown, vec![("".to_string(), "*".to_string())]);
    }

    #[test]
    fn subresource_inherits_parent_scope() {
        let rules = vec![rule(&[""], &["pods/status"])];
        let findings = classify_admission_policy_rules(&rules);
        // `pods` is namespaced, so `pods/status` is too.
        assert!(findings.cluster_scoped.is_empty());
        assert!(findings.unknown.is_empty());

        let rules = vec![rule(&[""], &["nodes/proxy"])];
        let findings = classify_admission_policy_rules(&rules);
        // `nodes` is cluster-scoped, so the rule must be flagged as such.
        assert_eq!(
            findings.cluster_scoped,
            vec![("".to_string(), "nodes/proxy".to_string())]
        );
    }

    #[test]
    fn mixed_rules_are_all_classified() {
        let rules = vec![
            rule(&[""], &["pods"]),                         // namespaced built-in
            rule(&[""], &["namespaces"]),                   // cluster-scoped built-in
            rule(&["example.com"], &["widgets"]),           // unknown (CRD)
            rule(&["storage.k8s.io"], &["storageclasses"]), // cluster-scoped built-in
            rule(&["apps"], &["statefulsets"]),             // namespaced built-in
        ];
        let findings = classify_admission_policy_rules(&rules);
        assert_eq!(
            findings.cluster_scoped,
            vec![
                ("".to_string(), "namespaces".to_string()),
                ("storage.k8s.io".to_string(), "storageclasses".to_string()),
            ]
        );
        assert_eq!(
            findings.unknown,
            vec![("example.com".to_string(), "widgets".to_string())]
        );
    }

    #[test]
    fn duplicate_findings_are_deduplicated_and_sorted() {
        let rules = vec![
            rule(&["storage.k8s.io"], &["storageclasses"]),
            rule(&["storage.k8s.io"], &["storageclasses"]),
            rule(&["example.com"], &["widgets", "widgets"]),
            rule(&[""], &["namespaces", "namespaces"]),
        ];
        let findings = classify_admission_policy_rules(&rules);
        assert_eq!(
            findings.cluster_scoped,
            vec![
                ("".to_string(), "namespaces".to_string()),
                ("storage.k8s.io".to_string(), "storageclasses".to_string()),
            ]
        );
        assert_eq!(
            findings.unknown,
            vec![("example.com".to_string(), "widgets".to_string())]
        );
    }

    #[test]
    fn empty_rules_produces_no_findings() {
        let findings = classify_admission_policy_rules(&[]);
        assert!(findings.cluster_scoped.is_empty());
        assert!(findings.unknown.is_empty());
    }
}
