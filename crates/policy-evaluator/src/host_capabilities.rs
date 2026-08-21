use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};

use crate::errors::HostCapabilitiesPatternError;

/// A node in the host-capability path tree.
/// Leaf nodes (complete, addressable operations) have a `None` value.
/// Intermediate nodes carry a `Some` map of named children.
struct CapabilityNode(BTreeMap<&'static str, Option<Box<CapabilityNode>>>);

impl CapabilityNode {
    fn leaf() -> Option<Box<Self>> {
        None
    }

    fn node(children: BTreeMap<&'static str, Option<Box<Self>>>) -> Option<Box<Self>> {
        Some(Box::new(Self(children)))
    }
}

static CAPABILITY_TREE: LazyLock<CapabilityNode> = LazyLock::new(|| {
    CapabilityNode(BTreeMap::from([
        (
            "oci",
            CapabilityNode::node(BTreeMap::from([
                (
                    "v1",
                    CapabilityNode::node(BTreeMap::from([
                        ("verify", CapabilityNode::leaf()),
                        ("manifest_digest", CapabilityNode::leaf()),
                        ("oci_manifest", CapabilityNode::leaf()),
                        ("oci_manifest_config", CapabilityNode::leaf()),
                    ])),
                ),
                (
                    "v2",
                    CapabilityNode::node(BTreeMap::from([("verify", CapabilityNode::leaf())])),
                ),
            ])),
        ),
        (
            "net",
            CapabilityNode::node(BTreeMap::from([(
                "v1",
                CapabilityNode::node(BTreeMap::from([(
                    "dns_lookup_host",
                    CapabilityNode::leaf(),
                )])),
            )])),
        ),
        (
            "crypto",
            CapabilityNode::node(BTreeMap::from([(
                "v1",
                CapabilityNode::node(BTreeMap::from([(
                    "is_certificate_trusted",
                    CapabilityNode::leaf(),
                )])),
            )])),
        ),
        (
            "kubernetes",
            CapabilityNode::node(BTreeMap::from([
                ("list_resources_by_namespace", CapabilityNode::leaf()),
                ("list_resources_all", CapabilityNode::leaf()),
                ("get_resource", CapabilityNode::leaf()),
                ("can_i", CapabilityNode::leaf()),
            ])),
        ),
        (
            "cache",
            CapabilityNode::node(HashMap::from([
                ("set", CapabilityNode::leaf()),
                ("get", CapabilityNode::leaf()),
            ])),
        ),
    ]))
});

/// Validates one capability pattern against `CAPABILITY_TREE`.
///
/// `*` (global wildcard) is accepted without tree lookup — it is handled by
/// the caller before this function is reached.
///
/// For prefix wildcards (`oci/*`, `oci/v1/*`) every segment *before* the
/// wildcard is verified to be a known intermediate node; the wildcard itself
/// is then accepted without further checking (the user is intentionally broad).
///
/// For exact paths every segment must lead to a known node, and the final
/// segment must be a leaf.
fn validate_against_tree(pattern: &str) -> Result<(), HostCapabilitiesPatternError> {
    let parts: Vec<&str> = pattern.split('/').collect();
    let mut node: &CapabilityNode = &CAPABILITY_TREE;

    for (i, &part) in parts.iter().enumerate() {
        if part == "*" {
            // Already guaranteed to be the last segment by the wildcard syntax
            // check that runs before this function.  The parent node exists
            // (we reached this point), so the wildcard is valid.
            return Ok(());
        }

        match node.0.get(part) {
            None => {
                let valid: Vec<&str> = node.0.keys().copied().collect();
                return Err(HostCapabilitiesPatternError::UnknownSegment {
                    pattern: pattern.to_string(),
                    segment: part.to_string(),
                    valid_options: valid.join(", "),
                });
            }
            Some(None) => {
                // Leaf reached; the path must end here.
                if i != parts.len() - 1 {
                    // There are more segments after the leaf — already caught
                    // by the wildcard-syntax check, but guard here for safety.
                    return Err(HostCapabilitiesPatternError::UnknownSegment {
                        pattern: pattern.to_string(),
                        segment: parts[i + 1].to_string(),
                        valid_options: String::new(),
                    });
                }
                return Ok(());
            }
            Some(Some(child)) => {
                if i == parts.len() - 1 {
                    // Stopped at an intermediate node without a wildcard.
                    return Err(HostCapabilitiesPatternError::IncompleteCapabilityPath {
                        pattern: pattern.to_string(),
                        suggestion: format!("{pattern}/*"),
                    });
                }
                node = child;
            }
        }
    }

    Ok(())
}

/// Represents the set of host capabilities a policy is allowed to use.
///
/// Host capability paths follow the format `{namespace}/{operation}`, e.g.
/// `oci/v1/verify`, `net/v1/dns_lookup_host`, `kubernetes/can_i`.
///
/// Supported patterns:
/// - `*`: allow all capabilities
/// - `oci/*`: allow all OCI capabilities regardless of version
/// - `oci/v2/*`: allow all OCI v2 capabilities
/// - `oci/v1/verify`: allow only the exact capability
///
/// Invalid patterns (rejected at parse time):
/// - `oci*`: wildcard must follow a `/`
/// - `oci/v1/oci_*`: wildcard must be the entire last segment
/// - `unknown/v1/op`: unknown segments are rejected against the capability tree
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub enum HostCapabilities {
    /// Deny all host capabilities (empty pattern list).
    #[default]
    DenyAll,
    /// Allow all host capabilities (the `*` pattern was specified).
    AllowAll,
    /// Allow specific capabilities matched by prefix or exact patterns.
    Patterns {
        /// Prefix patterns (e.g., `oci/` from `oci/*`, `oci/v2/` from `oci/v2/*`)
        prefixes: BTreeSet<String>,
        /// Exact capability paths (e.g., `oci/v1/verify`)
        exact: BTreeSet<String>,
    },
}

impl HostCapabilities {
    /// Returns all known host-capability operations as `(namespace, operation)` pairs,
    /// e.g. `("oci", "v1/verify")`, `("kubernetes", "can_i")`.
    ///
    /// The list is derived by recursively walking `CAPABILITY_TREE` and collecting
    /// every leaf path.
    pub fn enumerate_operations() -> Vec<(String, String)> {
        fn walk(
            node: &CapabilityNode,
            path: &mut Vec<&'static str>,
            out: &mut Vec<(String, String)>,
        ) {
            for (&segment, child) in &node.0 {
                path.push(segment);
                match child {
                    None => {
                        // Leaf: first segment is the namespace, the rest is the operation.
                        let namespace = path[0].to_string();
                        let operation = path[1..].join("/");
                        out.push((namespace, operation));
                    }
                    Some(inner) => walk(inner, path, out),
                }
                path.pop();
            }
        }

        let mut out = Vec::new();
        walk(&CAPABILITY_TREE, &mut vec![], &mut out);
        out.sort();
        out
    }

    /// Creates a new allow list from a list of patterns.
    ///
    /// Returns an error if any pattern is syntactically invalid or refers to
    /// an unknown capability namespace/operation.
    pub fn new(
        patterns: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, HostCapabilitiesPatternError> {
        let mut prefixes = BTreeSet::new();
        let mut exact = BTreeSet::new();

        for pattern in patterns {
            let pattern = pattern.as_ref();
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                return Err(HostCapabilitiesPatternError::Empty);
            }

            if trimmed == "*" {
                return Ok(Self::AllowAll);
            }

            if trimmed.contains('*') && !trimmed.ends_with("/*") {
                return Err(HostCapabilitiesPatternError::InvalidWildcard {
                    pattern: pattern.to_string(),
                });
            }

            validate_against_tree(trimmed)?;

            if let Some(prefix) = trimmed.strip_suffix("*") {
                prefixes.insert(prefix.to_string());
            } else {
                exact.insert(trimmed.to_string());
            }
        }

        if prefixes.is_empty() && exact.is_empty() {
            return Ok(Self::DenyAll);
        }

        Ok(Self::Patterns { prefixes, exact })
    }

    /// Returns `true` if the given capability path is allowed by this allow list.
    ///
    /// The capability path is constructed as `{namespace}/{operation}`, matching
    /// the waPC host callback namespace and operation parameters.
    pub fn is_allowed(&self, capability_path: &str) -> bool {
        match self {
            Self::AllowAll => true,
            Self::DenyAll => false,
            Self::Patterns { exact, prefixes } => {
                exact.contains(capability_path)
                    || prefixes
                        .iter()
                        .any(|p| capability_path.starts_with(p.as_str()))
            }
        }
    }
}

impl TryFrom<Vec<String>> for HostCapabilities {
    type Error = HostCapabilitiesPatternError;

    fn try_from(patterns: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(patterns)
    }
}

impl From<HostCapabilities> for Vec<String> {
    fn from(allow_list: HostCapabilities) -> Self {
        match allow_list {
            HostCapabilities::AllowAll => vec!["*".to_string()],
            HostCapabilities::DenyAll => vec![],
            HostCapabilities::Patterns { prefixes, exact } => {
                let mut result: Vec<String> =
                    prefixes.into_iter().map(|p| format!("{p}*")).collect();
                result.extend(exact);
                result
            }
        }
    }
}

impl fmt::Display for HostCapabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowAll => write!(f, "[*]"),
            Self::DenyAll => write!(f, "[]"),
            Self::Patterns { prefixes, exact } => {
                let mut items: Vec<String> = prefixes.iter().map(|p| format!("{p}*")).collect();
                items.extend(exact.iter().cloned());
                write!(f, "[{}]", items.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::empty_allows_nothing(vec![], "oci/v1/verify", false)]
    #[case::wildcard_allows_all(vec!["*"], "oci/v1/verify", true)]
    #[case::wildcard_allows_all_2(vec!["*"], "kubernetes/can_i", true)]
    #[case::exact_match(vec!["oci/v1/verify"], "oci/v1/verify", true)]
    #[case::exact_no_match(vec!["oci/v1/verify"], "oci/v2/verify", false)]
    #[case::prefix_oci(vec!["oci/*"], "oci/v1/verify", true)]
    #[case::prefix_oci_v2(vec!["oci/*"], "oci/v2/verify", true)]
    #[case::prefix_oci_manifest(vec!["oci/*"], "oci/v1/manifest_digest", true)]
    #[case::prefix_no_match(vec!["oci/*"], "net/v1/dns_lookup_host", false)]
    #[case::prefix_versioned(vec!["oci/v2/*"], "oci/v2/verify", true)]
    #[case::prefix_versioned_no_match(vec!["oci/v2/*"], "oci/v1/verify", false)]
    #[case::multiple_patterns(
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],
        "oci/v1/verify",
        true
    )]
    #[case::multiple_patterns_second(
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],
        "net/v1/dns_lookup_host",
        true
    )]
    #[case::multiple_patterns_no_match(
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],
        "kubernetes/can_i",
        false
    )]
    #[case::mixed_prefix_and_exact(
        vec!["oci/*", "kubernetes/can_i"],
        "oci/v1/manifest_digest",
        true
    )]
    #[case::mixed_prefix_and_exact_2(
        vec!["oci/*", "kubernetes/can_i"],
        "kubernetes/can_i",
        true
    )]
    #[case::mixed_no_match(
        vec!["oci/*", "kubernetes/can_i"],
        "net/v1/dns_lookup_host",
        false
    )]
    fn is_capability_allowed(
        #[case] patterns: Vec<&str>,
        #[case] capability: &str,
        #[case] expected: bool,
    ) {
        let allow_list = HostCapabilities::new(patterns).expect("patterns should be valid");
        assert_eq!(
            allow_list.is_allowed(capability),
            expected,
            "capability={capability}"
        );
    }

    #[rstest]
    #[case::partial_wildcard("oci*")]
    #[case::mid_wildcard("oci/v1/oci_*")]
    #[case::wildcard_not_last("*/oci")]
    #[case::empty("")]
    fn invalid_syntax_patterns(#[case] pattern: &str) {
        let result = HostCapabilities::new([pattern]);
        assert!(result.is_err(), "pattern {pattern:?} should be invalid");
    }

    #[rstest]
    #[case::unknown_namespace("unknown/v1/op")]
    #[case::unknown_version("oci/v99/verify")]
    #[case::unknown_operation("oci/v1/nonexistent")]
    #[case::unknown_kubernetes_op("kubernetes/nonexistent")]
    #[case::unknown_namespace_wildcard("unknown/*")]
    #[case::unknown_version_wildcard("oci/v99/*")]
    #[case::incomplete_path_oci("oci")]
    #[case::incomplete_path_oci_v1("oci/v1")]
    #[case::incomplete_path_net("net")]
    #[case::incomplete_path_kubernetes("kubernetes")]
    fn invalid_tree_patterns(#[case] pattern: &str) {
        let result = HostCapabilities::new([pattern]);
        assert!(result.is_err(), "pattern {pattern:?} should be invalid");
    }

    #[test]
    fn unknown_segment_error_lists_valid_options() {
        let err = HostCapabilities::new(["oci/v99/verify"]).unwrap_err();
        assert!(
            matches!(err, HostCapabilitiesPatternError::UnknownSegment { ref segment, .. } if segment == "v99"),
            "unexpected error: {err}"
        );
        // The error message should mention the valid versions
        let msg = err.to_string();
        assert!(msg.contains("v1"), "error should mention v1: {msg}");
        assert!(msg.contains("v2"), "error should mention v2: {msg}");
    }

    #[test]
    fn incomplete_path_error_suggests_wildcard() {
        let err = HostCapabilities::new(["oci/v1"]).unwrap_err();
        assert!(
            matches!(
                err,
                HostCapabilitiesPatternError::IncompleteCapabilityPath {
                    ref suggestion,
                    ..
                } if suggestion == "oci/v1/*"
            ),
            "unexpected error: {err}"
        );
    }

    #[rstest]
    #[case::standalone(vec!["*"])]
    #[case::wildcard_with_others(vec!["*", "oci/*", "kubernetes/can_i"])]
    fn wildcard_parses_to_allow_all(#[case] patterns: Vec<&str>) {
        let result = HostCapabilities::new(patterns);
        assert_eq!(result.unwrap(), HostCapabilities::AllowAll);
    }

    #[test]
    fn valid_patterns_parse() {
        let patterns = vec![
            "oci/*",
            "oci/v2/*",
            "oci/v1/verify",
            "oci/v1/manifest_digest",
            "oci/v1/oci_manifest",
            "oci/v1/oci_manifest_config",
            "net/v1/dns_lookup_host",
            "net/*",
            "crypto/v1/is_certificate_trusted",
            "crypto/*",
            "kubernetes/can_i",
            "kubernetes/get_resource",
            "kubernetes/list_resources_all",
            "kubernetes/list_resources_by_namespace",
            "kubernetes/*",
            "cache/set",
            "cache/get",
            "cache/*",
        ];
        let result = HostCapabilities::new(patterns);
        assert!(
            result.is_ok(),
            "unexpected error: {:?}",
            result.unwrap_err()
        );
    }

    #[rstest]
    #[case::oci("oci/v1/verify")]
    #[case::kubernetes("kubernetes/can_i")]
    fn deny_all_denies_all(#[case] capability: &str) {
        assert!(!HostCapabilities::DenyAll.is_allowed(capability));
    }

    #[test]
    fn serde_roundtrip() {
        let patterns = vec!["oci/*".to_string(), "kubernetes/can_i".to_string()];
        let allow_list = HostCapabilities::new(patterns).unwrap();
        let json = serde_json::to_string(&allow_list).unwrap();
        let deserialized: HostCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(allow_list, deserialized);
    }

    #[test]
    fn enumerate_operations_returns_all_known_leaf_paths() {
        let ops = HostCapabilities::enumerate_operations();

        // Every result must be parseable as a valid exact pattern.
        for (ns, op) in &ops {
            let path = format!("{ns}/{op}");
            assert!(
                HostCapabilities::new([&path]).is_ok(),
                "{path:?} returned by enumerate_operations is not a valid capability path"
            );
        }

        // The expected complete set of leaf paths, kept in sync with CAPABILITY_TREE.
        let mut expected: Vec<(String, String)> = vec![
            ("cache", "get"),
            ("cache", "set"),
            ("crypto", "v1/is_certificate_trusted"),
            ("kubernetes", "can_i"),
            ("kubernetes", "get_resource"),
            ("kubernetes", "list_resources_all"),
            ("kubernetes", "list_resources_by_namespace"),
            ("net", "v1/dns_lookup_host"),
            ("oci", "v1/manifest_digest"),
            ("oci", "v1/oci_manifest"),
            ("oci", "v1/oci_manifest_config"),
            ("oci", "v1/verify"),
            ("oci", "v2/verify"),
        ]
        .into_iter()
        .map(|(ns, op)| (ns.to_string(), op.to_string()))
        .collect();
        expected.sort();

        assert_eq!(ops, expected);
    }

    #[rstest]
    #[case::allow_all(HostCapabilities::AllowAll, "[*]")]
    #[case::deny_all(HostCapabilities::DenyAll, "[]")]
    #[case::patterns(
        HostCapabilities::new(["oci/*", "kubernetes/can_i"]).unwrap(),
        "[oci/*, kubernetes/can_i]"
    )]
    fn display(#[case] allow_list: HostCapabilities, #[case] expected: &str) {
        assert_eq!(allow_list.to_string(), expected);
    }
}
