use std::{path::PathBuf, str::FromStr};

use anyhow::{Result, anyhow};
use policy_evaluator::{
    policy_evaluator::PolicyExecutionMode,
    policy_fetcher::{
        oci_client::Reference,
        store::{Store, errors::StoreError},
    },
};
use regex::Regex;
use serde_json::json;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LookupError {
    #[error("Cannot find policy with uri: {0}")]
    PolicyMissing(String),
    #[error("{0}")]
    StoreError(#[from] StoreError),
    #[error("Unknown scheme: {0}")]
    UnknownScheme(String),
    #[error("{0}")]
    UrlParserError(#[from] url::ParseError),
    #[error("Error while converting URL to string")]
    UrlToStringConversionError(),
    #[error("{0}")]
    IoError(#[from] std::io::Error),
}

/// Normalizes a `registry://` URI to include an explicit tag.
/// If no tag is specified, defaults to `:latest`, making the URI consistent
/// with how the local store paths are keyed.
/// Non-registry URIs (e.g. `file://`, `http://`) are returned unchanged.
pub(crate) fn normalize_uri(uri: &str) -> String {
    if let Some(image) = uri.strip_prefix("registry://")
        && let Ok(reference) = Reference::from_str(image)
    {
        return format!("registry://{}", reference.whole());
    }
    uri.to_string()
}

pub(crate) fn map_path_to_uri(uri_or_sha_prefix: &str) -> std::result::Result<String, LookupError> {
    let uri_has_schema = Regex::new(r"^\w+://").unwrap();
    if uri_has_schema.is_match(uri_or_sha_prefix) {
        return Ok(normalize_uri(uri_or_sha_prefix));
    }

    let path = PathBuf::from(uri_or_sha_prefix);
    if path.exists() {
        let path = path.canonicalize()?;

        Ok(Url::from_file_path(path).unwrap().to_string())
    } else {
        let store = Store::default();
        if let Some(policy) = store.get_policy_by_sha_prefix(uri_or_sha_prefix)? {
            Ok(policy.uri.clone())
        } else {
            Err(LookupError::PolicyMissing(uri_or_sha_prefix.to_string()))
        }
    }
}

pub(crate) fn get_uri(uri_or_sha_prefix: &String) -> std::result::Result<String, LookupError> {
    let normalized = normalize_uri(uri_or_sha_prefix);
    map_path_to_uri(&normalized).or_else(|_| {
        Reference::from_str(&normalized)
            .map(|oci_reference| format!("registry://{}", oci_reference.whole()))
            .map_err(|_| LookupError::PolicyMissing(uri_or_sha_prefix.to_string()))
    })
}

pub(crate) fn get_wasm_path(uri_or_sha_prefix: &str) -> std::result::Result<PathBuf, LookupError> {
    let uri = get_uri(&uri_or_sha_prefix.to_owned())?;
    wasm_path(&uri)
}

pub(crate) fn wasm_path(uri: &str) -> std::result::Result<PathBuf, LookupError> {
    let url = Url::parse(uri)?;
    match url.scheme() {
        "file" => url
            .to_file_path()
            .map_err(|_| LookupError::UrlToStringConversionError()),
        "http" | "https" | "registry" => {
            let store = Store::default();
            let policy = store.get_policy_by_uri(uri)?;

            if let Some(policy) = policy {
                Ok(policy.local_path)
            } else {
                Err(LookupError::PolicyMissing(uri.to_string()))
            }
        }
        _ => Err(LookupError::UnknownScheme(url.scheme().to_string())),
    }
}

pub(crate) fn new_policy_execution_mode_from_str(name: &str) -> Result<PolicyExecutionMode> {
    let execution_mode: PolicyExecutionMode =
        serde_json::from_value(json!(name)).map_err(|_| {
            anyhow!(
                "Unknown policy execution mode \"{}\". Valid values are {}, {}, {}, {}, {}",
                name,
                serde_json::to_string(&PolicyExecutionMode::KubewardenWapc).unwrap(),
                serde_json::to_string(&PolicyExecutionMode::Opa).unwrap(),
                serde_json::to_string(&PolicyExecutionMode::OpaGatekeeper).unwrap(),
                serde_json::to_string(&PolicyExecutionMode::Wasi).unwrap(),
                serde_json::to_string(&PolicyExecutionMode::Ferricel).unwrap(),
            )
        })?;
    Ok(execution_mode)
}

pub(crate) fn find_file_matching_file(possible_names: &[&str]) -> Option<PathBuf> {
    possible_names
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case(
        "registry://ghcr.io/kubewarden/policies/pod-privileged",
        "registry://ghcr.io/kubewarden/policies/pod-privileged:latest"
    )]
    #[case(
        "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
        "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2"
    )]
    #[case(
        "registry://ghcr.io/kubewarden/policies/pod-privileged@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "registry://ghcr.io/kubewarden/policies/pod-privileged@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )]
    #[case("file:///some/path/policy.wasm", "file:///some/path/policy.wasm")]
    #[case("https://example.com/policy.wasm", "https://example.com/policy.wasm")]
    fn test_normalize_uri(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(normalize_uri(input), expected);
    }

    #[test]
    fn test_map_path_to_uri_remote_scheme() -> Result<()> {
        assert_eq!(
            map_path_to_uri("registry://some-registry.com/some-path/some-policy:0.0.1")?,
            String::from("registry://some-registry.com/some-path/some-policy:0.0.1"),
        );

        Ok(())
    }

    #[test]
    fn test_map_path_to_uri_local_scheme() -> Result<()> {
        assert_eq!(
            map_path_to_uri("file:///absolute/directory/some-policy-0.0.1.wasm")?,
            "file:///absolute/directory/some-policy-0.0.1.wasm",
        );

        Ok(())
    }

    #[test]
    fn test_build_policy_execution_mode_from_valid_input() {
        let mut data: HashMap<String, PolicyExecutionMode> = HashMap::new();
        data.insert(String::from("opa"), PolicyExecutionMode::Opa);
        data.insert(
            String::from("gatekeeper"),
            PolicyExecutionMode::OpaGatekeeper,
        );
        data.insert(
            String::from("kubewarden-wapc"),
            PolicyExecutionMode::KubewardenWapc,
        );

        for (name, mode) in data {
            let actual = new_policy_execution_mode_from_str(name.as_str());
            assert!(
                actual.is_ok(),
                "Error while converting {}: {:?}",
                name,
                actual
            );

            let actual = actual.unwrap();
            assert_eq!(actual, mode, "Expected {}, got {}", mode, actual);
        }
    }

    #[test]
    fn test_build_policy_execution_mode_from_invalid_input() {
        let actual = new_policy_execution_mode_from_str("test");
        assert!(actual.is_err(),);
    }
}
