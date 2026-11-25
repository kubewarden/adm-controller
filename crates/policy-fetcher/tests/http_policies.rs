//! Tests of the support for `http://` and `https://` policy URLs.

use std::{path::Path, slice};

use policy_fetcher::{
    policy::Policy,
    store::{PolicyPath, Store, path},
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

#[test]
fn http_policies_list() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let policies = Store::new(store_root.path())
        .list()
        .expect("cannot list the policies");
    assert_eq!(vec![expected_policy], policies);
}

#[test]
fn http_policies_get_policy_by_uri() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let policy = Store::new(store_root.path())
        .get_policy_by_uri(POLICY_URI)
        .expect("cannot get the policy by uri");
    assert_eq!(Some(expected_policy), policy);
}

#[test]
fn http_policies_get_policy_by_sha_prefix() {
    let store_root = tempdir().expect("cannot create the temporary directory");
    let expected_policy = https_policy(store_root.path());
    setup_store(slice::from_ref(&expected_policy));

    let policy = Store::new(store_root.path())
        .get_policy_by_sha_prefix("93a")
        .expect("cannot get the policy by sha prefix");
    assert_eq!(Some(expected_policy), policy);
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
    let store = Store::default();

    let path = store
        .policy_path(
            "https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm",
            input_policy_path,
        )
        .expect("cannot compute the policy path");

    assert_eq!(path::encode_path(expected), path);
}
