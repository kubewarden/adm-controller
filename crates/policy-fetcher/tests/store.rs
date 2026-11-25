use std::{path::Path, slice};

use policy_fetcher::{
    policy::Policy,
    store::{Store, path},
};
use tempfile::tempdir;

#[test]
fn test_list() {
    let store_root = tempdir().unwrap();

    let mut expected_policies = vec![
        Policy {
            uri: "registry://internal.host.company/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/internal.host.company/some/path/to/wasm-module.wasm:1.0.0",
            )),
        },
        Policy {
            uri: "registry://ghcr.io/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/ghcr.io/some/path/to/wasm-module.wasm:1.0.0",
            )),
        },
        Policy {
            uri: "registry://internal.host.company:5000/some/path/to/wasm-module.wasm:1.0.0"
                .to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/internal.host.company:5000/some/path/to/wasm-module.wasm:1.0.0",
            )),
        },
    ];

    setup_store(&expected_policies).unwrap();

    let store = Store::new(store_root.path());
    let mut list = store.list().expect("failed to list policies");

    expected_policies.sort_by_key(|p| p.uri.clone());
    list.sort_by_key(|p| p.uri.clone());

    assert_eq!(expected_policies, list);
}

#[test]
fn test_list_non_existing_store_root() {
    let store = Store::new(Path::new("./does/not/exist"));

    let list = store.list().expect("failed to list policies");

    assert!(list.is_empty());
}

#[test]
fn test_get_policy_by_uri() {
    let store_root = tempdir().unwrap();

    let expected_policy = Policy {
        uri: "registry://internal.host.company/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
        local_path: store_root.path().join(path::encode_path(
            "registry/internal.host.company/some/path/to/wasm-module.wasm:1.0.0",
        )),
    };

    setup_store(slice::from_ref(&expected_policy)).unwrap();

    let store = Store::new(store_root.path());
    let policy = store
        .get_policy_by_uri(&expected_policy.uri)
        .expect("failed to get policy by uri");

    assert_eq!(Some(expected_policy), policy);
}

#[test]
fn test_get_policy_by_uri_not_found() {
    let store_root = tempdir().unwrap();
    let store = Store::new(store_root.path());

    let result = store
        .get_policy_by_uri("registry://does/not/exist:1.0.0")
        .unwrap();

    assert!(result.is_none());
}

#[test]
fn test_get_policy_by_uri_unknown_scheme() {
    let store_root = tempdir().unwrap();

    let policies = vec![Policy {
        uri: "registry://internal.host.company/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
        local_path: store_root.path().join(path::encode_path(
            "registry/internal.host.company/some/path/to/wasm-module.wasm:1.0.0",
        )),
    }];

    setup_store(&policies).unwrap();

    let store = Store::new(store_root.path());
    let result =
        store.get_policy_by_uri("ftp://internal.host.company/some/path/to/1.0.0/wasm-module.wasm");

    assert!(result.is_err());
}

#[test]
fn test_get_policy_by_sha_prefix() {
    let store_root = tempdir().unwrap();

    let expected_policy = Policy {
        uri: "registry://internal.host.company/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
        local_path: store_root.path().join(path::encode_path(
            "registry/internal.host.company/some/path/to/wasm-module.wasm:1.0.0",
        )),
    };

    setup_store(slice::from_ref(&expected_policy)).unwrap();

    let store = Store::new(store_root.path());
    let policy = store
        .get_policy_by_sha_prefix("93a")
        .expect("failed to get policy by sha prefix");

    assert_eq!(Some(expected_policy), policy);
}

#[test]
fn test_get_policy_by_sha_prefix_not_found() {
    let store_root = tempdir().unwrap();
    let store = Store::new(store_root.path());

    let result = store.get_policy_by_sha_prefix("93a").unwrap();

    assert!(result.is_none());
}

#[test]
fn test_get_policy_by_sha_prefix_duplicate() {
    let store_root = tempdir().unwrap();
    let store = Store::new(store_root.path());

    let policies = vec![
        Policy {
            uri: "registry://internal.host.company/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/internal.host.company/some/path/to/wasm-module.wasm:1.0.0",
            )),
        },
        Policy {
            uri: "registry://ghcr.io/some/path/to/wasm-module.wasm:1.0.0".to_owned(),
            local_path: store_root.path().join(path::encode_path(
                "registry/internal.host.company/some/path/to/1.0.0/wasm-module.wasm:1.0.0",
            )),
        },
    ];

    setup_store(&policies).unwrap();

    let result = store.get_policy_by_sha_prefix("93a");

    assert!(result.is_err());
}

fn setup_store(policies: &[Policy]) -> std::result::Result<(), std::io::Error> {
    for policy in policies {
        std::fs::create_dir_all(policy.local_path.parent().unwrap())?;

        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/simple.wasm"),
            &policy.local_path,
        )?;
    }

    Ok(())
}
