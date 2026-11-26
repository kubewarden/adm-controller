//! Deprecated support for policies served from `http://` and `https://` URLs.
//!
//! The store derives the cache path of these URLs from the URL path only, and
//! drops the query. Two URLs that differ only in the query share one cache
//! entry. Thus the support is disabled by default, and the
//! `--enable-http-policies` flag of kwctl and policy-server enables it.
//!
//! All the code of this support is temporary. When the support is removed,
//! delete this module, `https.rs`, and the `enable_http_policies` parameters.

use std::path::Path;

use url::Url;

use crate::store::{
    Store,
    errors::{StoreError, StoreResult},
};

const HTTP_SCHEMES: &[&str] = &["http", "https"];

/// Returns true if the scheme is `http` or `https`.
pub fn is_http_scheme(scheme: &str) -> bool {
    HTTP_SCHEMES.contains(&scheme)
}

/// Returns an error if `scheme` is `http` or `https` and the support for
/// these policies is disabled. `policy` identifies the policy in the error.
pub(crate) fn check(policy: &str, scheme: &str, enable_http_policies: bool) -> StoreResult<()> {
    if is_http_scheme(scheme) && !enable_http_policies {
        return Err(StoreError::HttpPoliciesDisabled(policy.to_owned()));
    }
    Ok(())
}

/// Returns the number of policies in the store at `store_root` that come from
/// `http://` and `https://` URLs.
pub fn count_hidden(store_root: &Path) -> StoreResult<usize> {
    Store::new(store_root, true)
        .list()?
        .iter()
        .try_fold(0, |count, policy| {
            let url = Url::parse(&policy.uri)?;
            Ok(count + usize::from(is_http_scheme(url.scheme())))
        })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tempfile::tempdir;

    use super::*;

    #[rstest]
    #[case::http_disabled("http", false, false)]
    #[case::https_disabled("https", false, false)]
    #[case::http_enabled("http", true, true)]
    #[case::https_enabled("https", true, true)]
    #[case::registry_disabled("registry", false, true)]
    #[case::registry_enabled("registry", true, true)]
    fn http_policies_check(
        #[case] scheme: &str,
        #[case] enable_http_policies: bool,
        #[case] allowed: bool,
    ) {
        let result = check("some-policy", scheme, enable_http_policies);

        assert_eq!(result.is_ok(), allowed);
        if !allowed {
            assert!(matches!(
                result,
                Err(StoreError::HttpPoliciesDisabled(policy)) if policy == "some-policy"
            ));
        }
    }

    #[test]
    fn http_policies_count_hidden() {
        let store_root = tempdir().expect("cannot create the temporary directory");
        for path in [
            "https/host.example.com/policy.wasm",
            "http/host.example.com/policy.wasm",
            "registry/ghcr.io/kubewarden/policy:v1",
        ] {
            let path = store_root
                .path()
                .join(crate::store::path::encode_path(path));
            std::fs::create_dir_all(path.parent().expect("the path has a parent"))
                .expect("cannot create the store directory");
            std::fs::write(&path, b"").expect("cannot write the policy file");
        }

        assert_eq!(
            count_hidden(store_root.path()).expect("cannot count the policies"),
            2
        );
    }

    #[test]
    fn http_policies_count_hidden_empty_store() {
        let store_root = tempdir().expect("cannot create the temporary directory");

        assert_eq!(
            count_hidden(store_root.path()).expect("cannot count the policies"),
            0
        );
    }
}
