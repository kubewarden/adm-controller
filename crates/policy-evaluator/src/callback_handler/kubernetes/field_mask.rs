use std::collections::BTreeMap;

use serde_json::Value;

/// Prepares a Kubernetes object for caching/returning to a policy: clears
/// fields that are not useful outside of the API server (managed fields,
/// the last-applied-configuration annotation) and, if a field mask is
/// provided, prunes the object down to only the masked fields.
pub(crate) fn modify_object(
    obj: &mut kube::core::DynamicObject,
    field_masker: Option<&FieldMaskNode>,
) {
    // clear managed fields to reduce memory usage
    obj.managed_fields_mut().clear();
    // clear last-applied-configuration to reduce memory usage
    obj.annotations_mut()
        .remove("kubectl.kubernetes.io/last-applied-configuration");
    // apply field masks, if any
    if let Some(mask) = field_masker {
        prune_in_place(&mut obj.data, mask);
    }
}

/// Represents a node in a field mask tree.
///
/// This structure is used to define and operate on masks that specify which parts of a JSON object should
/// be retained or pruned.
#[derive(Default)]
pub struct FieldMaskNode {
    children: BTreeMap<String, FieldMaskNode>,
}

impl FieldMaskNode {
    /// Iterator should yield dot-separated paths, e.g. "metadata.name", "spec.containers.name", "status"
    pub fn new(iterator: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut root = FieldMaskNode::default();
        for path in iterator {
            root.insert(path.as_ref());
        }
        root
    }

    /// Inserts a new path into the field mask tree.
    fn insert(&mut self, path: &str) {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = self;
        for part in parts {
            current = current.children.entry(part.to_string()).or_default();
        }
    }
}

impl std::fmt::Debug for FieldMaskNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn debug_recursive(
            node: &FieldMaskNode,
            indent: usize,
            f: &mut std::fmt::Formatter<'_>,
        ) -> std::fmt::Result {
            let prefix = " ".repeat(indent);
            writeln!(f, "{}", prefix)?;
            for (key, child) in &node.children {
                writeln!(f, "{}- {}", prefix, key)?;
                debug_recursive(child, indent + 2, f)?;
            }
            Ok(())
        }
        debug_recursive(self, 0, f)
    }
}

/// Prunes the JSON value in place, removing fields not present in the specified mask.
///
/// # Example
///
/// ```rust,ignore
/// use serde_json::{Value, json};
///
/// let mut data: Value = json!({
///     "name": "Alice",
///     "age": 30,
///     "metadata": {
///         "id": 1,
///         "active": true
///     }
/// });
///
/// let mut mask_root = FieldMaskNode::new(vec!["name", "metadata.id"]);
///
/// prune_in_place(&mut data, &mask_root);
///
/// let expected: Value = json!({
///     "name": "Alice",
///     "metadata": {
///         "id": 1
///     }
/// });
///
/// assert_eq!(data, expected);
/// ```
/// Returns nothing; modifies the value directly.
pub fn prune_in_place(val: &mut Value, node: &FieldMaskNode) {
    // Optimization: If the mask says "keep everything below this point", stop working.
    if node.children.is_empty() {
        return;
    }

    match val {
        Value::Object(map) => {
            map.retain(|key, value| {
                if let Some(child_node) = node.children.get(key) {
                    // key in mask -> we need to keep it, recurse deeper to prune children
                    prune_in_place(value, child_node);
                    true // Keep this key
                } else {
                    false // Key not in mask: drop it!
                }
            });
        }
        Value::Array(arr) => {
            // Arrays are transparent: apply the CURRENT node to all items.
            for item in arr {
                prune_in_place(item, node);
            }
        }
        _ => {
            // Primitive (String, Number, Bool).
            // If we are here, the parent key was allowed.
            // We can't prune "inside" a string, so we just stop.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::objects(
        json!({
            "a": {
                "b": 1,
                "c": 2
            },
            "d": 3
        }),
        json!({
            "a": {
                "b": 1
            },
            "d": 3
        }),
        &["a.b", "d"])
    ]
    #[case::nested_objects(
        json!({
            "user": {
                "name": "Alice",
                "age": 30,
                "metadata": {
                    "id": 1,
                    "active": true
                }
            },
            "other": "data"
        }),
        json!({
            "user": {
                "name": "Alice",
                "metadata": {
                    "id": 1
                }
            }
        }),
        &["user.name", "user.metadata.id"]
    )]
    #[case::arrays(
        json!({
            "users": [
                {"name": "Alice", "age": 30},
                {"name": "Bob", "age": 25}
            ],
            "metadata": {
                "count": 2
            }
        }),
        json!({
            "users": [
                {"name": "Alice"},
                {"name": "Bob"}
            ]
        }),
        &["users.name"]
    )]
    #[case::arrays_with_nested_objects(
        json!({
            "users": [
                {"name": "Alice", "age": 30, "metadata": {"id": 1}},
                {"name": "Bob", "age": 25, "metadata": {"id": 2}}
            ],
            "metadata": {
                "count": 2
            }
        }),
        json!({
            "users": [
                {
                    "name": "Alice",
                     "metadata": {"id": 1}
                },
                {
                    "name": "Bob",
                    "metadata": {"id": 2}
                }
            ]
        }),
        &["users.name", "users.metadata"]
    )]
    #[case::keep_all_below(
        json!({
            "user": {
                "name": "Alice",
                "age": 30,
                "metadata": {
                    "id": 1,
                    "active": true
                }
            },
            "other": "data"
        }),
        json!({
            "user": {
                "name": "Alice",
                "age": 30,
                "metadata": {
                    "id": 1,
                    "active": true
                }
            }
        }),
        &["user"]
    )]
    fn test_prune_in_place(
        #[case] mut input: Value,
        #[case] expected: Value,
        #[case] mask: &[&str],
    ) {
        let root = FieldMaskNode::new(mask);

        prune_in_place(&mut input, &root);
        assert_eq!(input, expected);
    }
}
