use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use errors::StoreError;
use lazy_static::lazy_static;
use path_slash::PathExt;
use url::Url;
use walkdir::WalkDir;

use self::errors::StoreResult;
use crate::policy::Policy;

pub mod errors;
pub mod path;
mod scheme;

lazy_static! {
    pub static ref DEFAULT_ROOT: ProjectDirs =
        ProjectDirs::from("io.kubewarden", "", "kubewarden").unwrap();
    pub static ref DEFAULT_STORE_ROOT: PathBuf = DEFAULT_ROOT.cache_dir().join("store");
}

pub enum PolicyPath {
    PrefixOnly,
    PrefixAndFilename,
}

/// Store represents a structure that is able to save and retrieve
/// WebAssembly modules from a central and local location.
///
/// In the local filesystem, the structure of the directory is the
/// following:
///
/// <root>/<scheme>/<host>/<image>:<tag>.wasm
///
/// for each image. No index or embedded database is implemented
/// yet. Assuming we have pulled the following images:
///
/// - https://internal.host.company/some/path/to/1.0.0/wasm-module.wasm
/// - registry://ghcr.io/some-org/some/path/to/wasm-module.wasm:1.0.0
/// - registry://internal.host.company:5000/some/path/to/wasm-module.wasm:1.0.0
///
/// The structure of the folder would look like the following:
///
/// <root>
///     - https
///         - internal.host.company
///             - some
///                 - path
///                     - 1.0.0        
///                         - to
///                             - wasm-module.wasm
///     - registry
///         - ghcr.io
///             - some
///                 - path
///                     - to
///                         - wasm-module.wasm:1.0.0
///         - internal.host.company:5000
///             - some
///                 - path
///                     - to
///                         - wasm-module.wasm:1.0.0
#[derive(Debug, PartialEq, Eq)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn new(root: &Path) -> Self {
        Store {
            root: root.to_path_buf(),
        }
    }

    /// Creates all directories provided in `path` starting from the
    /// root of this store.
    pub fn ensure(&self, path: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(self.root.join(path))
    }

    /// Returns the full path of a policy coming from the URL `url` in
    /// this store. If `policy_path` is set to `PrefixOnly`, the
    /// filename of the policy will be omitted, otherwise it will be
    /// included.
    pub fn policy_full_path(&self, url: &str, policy_path: PolicyPath) -> StoreResult<PathBuf> {
        let path = self.policy_path(url, policy_path)?;

        Ok(self.root.join(path))
    }

    /// Returns the path of a policy coming from the URL `url`
    /// without the store. If `policy_path` is set to `PrefixOnly`, the
    /// filename of the policy will be omitted, otherwise it will be
    /// included.
    pub fn policy_path(&self, url: &str, policy_path: PolicyPath) -> StoreResult<PathBuf> {
        let url = Url::parse(url)?;
        validate_http_module_url(&url)?;
        let filename = policy_file_name(&url);
        let policy_prefix = self.policy_prefix(&url);

        Ok(match policy_path {
            PolicyPath::PrefixOnly => policy_prefix,
            PolicyPath::PrefixAndFilename => policy_prefix.join(filename),
        })
    }

    /// Returns the prefix of the policy as a `PathBuf`.
    /// This prefix does not include the root of the store.
    pub(crate) fn policy_prefix(&self, url: &Url) -> PathBuf {
        let element_count = url.path().split('/').count();
        let elements = url.path().split('/');
        let path: PathBuf = elements
            .skip(1)
            .take(
                element_count - 2, /* skip empty root after split and leaf filename */
            )
            .collect();
        let policy_prefix = PathBuf::from(url.scheme())
            .join(host_and_port(url))
            .join(path);

        path::encode_path(policy_prefix)
    }

    /// Lists all policies in this store
    pub fn list(&self) -> StoreResult<Vec<Policy>> {
        let mut policies = Vec::new();

        if !self.root.exists() {
            return Ok(policies);
        }

        let store_root_path = std::fs::read_dir(self.root.as_path())?;
        for scheme in store_root_path {
            let scheme = scheme?;
            match scheme.file_name().to_str() {
                Some(scheme) => {
                    if !scheme::is_known_remote_scheme(scheme) {
                        continue;
                    }
                }
                None => continue,
            }
            for host in std::fs::read_dir(scheme.path())? {
                let host = host?;
                for policy in WalkDir::new(host.path()) {
                    let policy = policy?;

                    let metadata = std::fs::metadata(policy.path())?;
                    if metadata.is_file() {
                        let policy_store_path =
                            Path::new("/").join(policy.path().strip_prefix(host.path())?);
                        policies.push(Policy {
                            uri: format!(
                                "{}://{}{}",
                                scheme.file_name().to_str().unwrap(),
                                path::decode_path(host.file_name())?.to_str().unwrap(),
                                path::decode_path(policy_store_path)?.to_slash_lossy()
                            ),
                            local_path: policy.path().to_path_buf(),
                        })
                    }
                }
            }
        }
        Ok(policies)
    }

    /// Get a policy by its URI, if it exists.
    pub fn get_policy_by_uri(&self, uri: &str) -> StoreResult<Option<Policy>> {
        let uri = Url::parse(uri)?;

        if !scheme::is_known_remote_scheme(uri.scheme()) {
            return Err(StoreError::UnknownSchemeError(uri.scheme().to_owned()));
        }

        let policy_path = self.policy_full_path(uri.as_str(), PolicyPath::PrefixAndFilename)?;
        if policy_path.exists() {
            Ok(Some(Policy {
                uri: uri.to_string(),
                local_path: policy_path,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get a policy that matches the given SHA prefix, if it exists.
    pub fn get_policy_by_sha_prefix(&self, sha_prefix: &str) -> StoreResult<Option<Policy>> {
        self.list()?.into_iter().try_fold(None, |acc, policy| {
            if !policy.digest()?.starts_with(sha_prefix) {
                return Ok(acc);
            }

            if acc.is_some() {
                Err(StoreError::MultiplePoliciesFoundError(
                    sha_prefix.to_owned(),
                ))
            } else {
                Ok(Some(policy))
            }
        })
    }
}

impl Default for Store {
    fn default() -> Self {
        Self {
            root: DEFAULT_STORE_ROOT.clone(),
        }
    }
}

/// Returns the filename of the policy.
fn policy_file_name(url: &Url) -> String {
    let filename = url.path().split('/').next_back().unwrap();

    path::encode_filename(filename)
}

/// Returns the host and port (if any) as a string.
fn host_and_port(url: &Url) -> String {
    url.host_str()
        .map(|host| {
            if let Some(port) = url.port() {
                format!("{host}:{port}")
            } else {
                host.into()
            }
        })
        .unwrap_or_default()
}

/// Rejects `http` and `https` URLs that two policies can share in the store.
pub fn validate_http_module_url(url: &Url) -> StoreResult<()> {
    if !matches!(url.scheme(), "http" | "https") {
        return Ok(());
    }

    let has_collision_risk = url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        // The url crate gives "http://host" the path "/", so this also rejects a URL
        // with no file path.
        || url.path().ends_with('/')
        || url.path().contains("//");
    if has_collision_risk {
        return Err(StoreError::InvalidHttpModuleUrl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::Store;

    #[rstest(
        input_url,
        input_policy_path,
        expected_relative_path,
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixAndFilename,
            "registry/ghcr.io/kubewarden/policies/pod-privileged:v0.2.2"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixAndFilename,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm"
        ),
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixOnly,
            "registry/ghcr.io/kubewarden/policies"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixOnly,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6"
        )
    )]
    fn policy_full_path(
        input_url: &str,
        input_policy_path: PolicyPath,
        expected_relative_path: &str,
    ) {
        let default = Store::default();
        let path = default.policy_full_path(input_url, input_policy_path);
        assert!(path.is_ok());
        assert_eq!(
            default.root.join(path::encode_path(expected_relative_path)),
            path.unwrap_or_default()
        );
    }

    #[rstest(
        input_url,
        input_policy_path,
        expected_path,
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixAndFilename,
            "registry/ghcr.io/kubewarden/policies/pod-privileged:v0.2.2"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixAndFilename,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm"
        ),
        case(
            "registry://ghcr.io/kubewarden/policies/pod-privileged:v0.2.2",
            PolicyPath::PrefixOnly,
            "registry/ghcr.io/kubewarden/policies"
        ),
        case(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            PolicyPath::PrefixOnly,
            "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6"
        )
    )]
    fn policy_path(
        input_url: &str,
        input_policy_path: PolicyPath,
        expected_path: &str,
    ) -> StoreResult<()> {
        let default = Store::default();
        let path = default.policy_path(input_url, input_policy_path)?;
        assert_eq!(path::encode_path(expected_path), path);

        Ok(())
    }

    #[rstest]
    #[case("https://example.com/policy.wasm")]
    #[case("http://example.com:8080/path/to/policy.wasm")]
    #[case("registry://ghcr.io/org/policy:v1")]
    #[case("file:///tmp/policy.wasm")]
    fn accepted_http_module_url(#[case] input_url: &str) {
        let url = Url::parse(input_url).expect("the test URL is valid");
        assert!(validate_http_module_url(&url).is_ok());
    }

    #[rstest]
    #[case("https://example.com/policy.wasm?id=1")]
    #[case("https://example.com/policy.wasm?")]
    #[case("https://example.com/policy.wasm#a")]
    #[case("https://example.com/policy.wasm#")]
    #[case("https://user@example.com/policy.wasm")]
    #[case("https://user:secret@example.com/policy.wasm")]
    #[case("https://example.com")]
    #[case("https://example.com/")]
    #[case("https://example.com/path/")]
    #[case("https://example.com//policy.wasm")]
    #[case("https://example.com/a//policy.wasm")]
    #[case("HTTPS://example.com/policy.wasm?id=1")]
    fn rejected_http_module_url(#[case] input_url: &str) {
        let url = Url::parse(input_url).expect("the test URL is valid");
        let error = validate_http_module_url(&url).expect_err("the URL must be rejected");
        assert!(matches!(error, StoreError::InvalidHttpModuleUrl));
        assert_eq!(
            "the module URL is not valid. An http or https module URL must have only the host, \
             an optional port, and the full path to the file.",
            error.to_string()
        );
        assert!(!error.to_string().contains("secret"));
        assert!(!error.to_string().contains("example.com"));

        let error = Store::default()
            .policy_path(input_url, PolicyPath::PrefixAndFilename)
            .expect_err("policy_path must reject the URL");
        assert!(matches!(error, StoreError::InvalidHttpModuleUrl));
    }
}
