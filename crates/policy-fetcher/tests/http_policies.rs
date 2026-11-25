//! Tests of the deprecated support for `http://` and `https://` policy URLs.
//! Delete this file when the support is removed.

use std::{path::Path, slice};

use policy_fetcher::{
    PullDestination,
    errors::FetcherError,
    fetch_policy,
    policy::Policy,
    store::{PolicyPath, Store, errors::StoreError, path},
};
use rstest::rstest;
use tempfile::tempdir;

const POLICY_URI: &str = "https://internal.host.company/some/path/to/1.0.0/wasm-module.wasm";
const POLICY_STORE_PATH: &str = "https/internal.host.company/some/path/to/1.0.0/wasm-module.wasm";

fn https_policy(store_root: &Path) -> Policy {
    Policy {
        uri: POLICY_URI.to_owned(),
        local_path: store_root.join(path::encode_path(POLICY_STORE_PATH)),
    }
}

fn setup_store(policies: &[Policy]) {
    for policy in policies {
        std::fs::create_dir_all(policy.local_path.parent().expect("the path has a parent"))
            .expect("cannot create the store directory");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/simple.wasm"),
            &policy.local_path,
        )
        .expect("cannot copy the policy to the store");
    }
}

#[rstest]
#[case::http("http://127.0.0.1:1/policy.wasm")]
#[case::https("https://127.0.0.1:1/policy.wasm")]
#[tokio::test]
async fn http_policies_fetch_policy_disabled(#[case] url: &str) {
    let store_root = tempdir().expect("cannot create the temporary directory");

    let result = fetch_policy(
        url,
        PullDestination::Store(store_root.path().to_path_buf()),
        None,
        false,
    )
    .await;

    assert!(matches!(
        result,
        Err(FetcherError::StoreError(StoreError::HttpPoliciesDisabled(policy))) if policy == url
    ));
    assert!(
        std::fs::read_dir(store_root.path())
            .expect("cannot read the store root")
            .next()
            .is_none(),
        "the store must stay empty"
    );
}

#[rstest]
#[case::store(true)]
#[case::local_file(false)]
#[tokio::test]
async fn http_policies_fetch_policy_disabled_destination(#[case] store_destination: bool) {
    let root = tempdir().expect("cannot create the temporary directory");
    let destination = if store_destination {
        PullDestination::Store(root.path().to_path_buf())
    } else {
        PullDestination::LocalFile(root.path().to_path_buf())
    };

    let result = fetch_policy(POLICY_URI, destination, None, false).await;

    assert!(matches!(
        result,
        Err(FetcherError::StoreError(StoreError::HttpPoliciesDisabled(
            _
        )))
    ));
}

// Two URLs that differ only in the query share one store path. When the
// support is disabled, the cached module of the other URL must not be used.
#[tokio::test]
async fn http_policies_fetch_policy_query_clash_disabled() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    setup_store(slice::from_ref(&https_policy(store_root.path())));

    let result = fetch_policy(
        &format!("{POLICY_URI}?v=2"),
        PullDestination::Store(store_root.path().to_path_buf()),
        None,
        false,
    )
    .await;

    assert!(matches!(
        result,
        Err(FetcherError::StoreError(StoreError::HttpPoliciesDisabled(
            _
        )))
    ));
}

#[tokio::test]
async fn http_policies_fetch_policy_enabled_uses_cache() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let policy = fetch_policy(
        POLICY_URI,
        PullDestination::Store(store_root.path().to_path_buf()),
        None,
        true,
    )
    .await
    .expect("cannot fetch the cached policy");

    assert_eq!(expected_policy, policy);
}

#[test]
fn http_policies_list() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let enabled = Store::new(store_root.path(), true)
        .list()
        .expect("cannot list the policies");
    assert_eq!(vec![expected_policy], enabled);

    let disabled = Store::new(store_root.path(), false)
        .list()
        .expect("cannot list the policies");
    assert!(disabled.is_empty());
}

#[test]
fn http_policies_get_policy_by_uri() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let policy = Store::new(store_root.path(), true)
        .get_policy_by_uri(POLICY_URI)
        .expect("cannot get the policy by uri");
    assert_eq!(Some(expected_policy), policy);

    let result = Store::new(store_root.path(), false).get_policy_by_uri(POLICY_URI);
    assert!(matches!(
        result,
        Err(StoreError::HttpPoliciesDisabled(policy)) if policy == POLICY_URI
    ));
}

#[test]
fn http_policies_get_policy_by_sha_prefix() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let policy = Store::new(store_root.path(), true)
        .get_policy_by_sha_prefix("93a")
        .expect("cannot get the policy by sha prefix");
    assert_eq!(Some(expected_policy), policy);

    let policy = Store::new(store_root.path(), false)
        .get_policy_by_sha_prefix("93a")
        .expect("cannot get the policy by sha prefix");
    assert_eq!(None, policy);
}

#[rstest]
#[case::http_disabled("http", false, false)]
#[case::https_disabled("https", false, false)]
#[case::http_enabled("http", true, true)]
#[case::https_enabled("https", true, true)]
fn http_policies_check_scheme(
    #[case] scheme: &str,
    #[case] enable_http_policies: bool,
    #[case] accepted: bool,
) {
    let store = Store::with_default_root(enable_http_policies);

    let result = store.check_scheme("some-policy", scheme);

    assert_eq!(result.is_ok(), accepted);
    if !accepted {
        assert!(matches!(result, Err(StoreError::HttpPoliciesDisabled(_))));
    }
}

#[rstest]
#[case::prefix_and_filename(
    PolicyPath::PrefixAndFilename,
    "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm"
)]
#[case::prefix_only(
    PolicyPath::PrefixOnly,
    "https/github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6"
)]
fn http_policies_policy_path(#[case] input_policy_path: PolicyPath, #[case] expected: &str) {
    let store = Store::with_default_root(true);

    let path = store
        .policy_path(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm",
            input_policy_path,
        )
        .expect("cannot compute the policy path");

    assert_eq!(path::encode_path(expected), path);
}

#[rstest]
#[case::http("http://host.example.com/policy.wasm")]
#[case::https("https://host.example.com/policy.wasm")]
fn http_policies_policy_path_disabled(#[case] url: &str) {
    let store = Store::with_default_root(false);

    let result = store.policy_full_path(url, PolicyPath::PrefixAndFilename);

    assert!(matches!(
        result,
        Err(StoreError::HttpPoliciesDisabled(policy)) if policy == url
    ));
}
