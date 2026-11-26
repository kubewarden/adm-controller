use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::tempdir;
use testcontainers::{core::WaitFor, runners::SyncRunner};

mod common;

#[test]
fn test_airgap() {
    let tempdir = tempdir().unwrap();
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Run registry
    let registry_image = testcontainers::GenericImage::new("docker.io/library/registry", "2")
        .with_wait_for(WaitFor::message_on_stderr("listening on "));
    let testcontainer = registry_image
        .start()
        .expect("Failed to start registry container");
    let port = testcontainer
        .get_host_port_ipv4(5000)
        .expect("Failed to get host port");

    // Save policies
    let mut save_policies_script = setup_airgap_script_command(
        &project_root
            .join("../../scripts/kubewarden-save-policies.sh")
            .canonicalize()
            .expect("Failed to canonicalize path to kubewarden-save-policies.sh"),
        tempdir.path(),
    );
    save_policies_script
        .arg("--policies-list")
        .arg(project_root.join("tests/data/airgap/policies.txt"))
        .arg("--policies")
        .arg(tempdir.path().join("policies.tar.gz"))
        .arg("--enable-http-policies")
        .assert()
        .success();

    // Remove policies from store
    let mut kwctl = common::setup_command(tempdir.path());
    kwctl
        .arg("rm")
        .arg("registry://ghcr.io/kubewarden/tests/pod-privileged:v0.1.9")
        .assert()
        .success();

    let mut kwctl = common::setup_command(tempdir.path());
    kwctl
        .arg("--enable-http-policies")
        .arg("rm")
        .arg("https://github.com/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm")
        .assert()
        .success();

    // Create sources.yml
    let sources_yaml = format!(
        r#"
        insecure_sources:
            - "localhost:{}"
        "#,
        port
    );
    std::fs::write(tempdir.path().join("sources.yml"), sources_yaml).unwrap();

    // Load policies
    let mut load_policies_script = setup_airgap_script_command(
        &project_root
            .join("../../scripts/kubewarden-load-policies.sh")
            .canonicalize()
            .expect("Failed to canonicalize path to kubewarden-load-policies.sh"),
        tempdir.path(),
    );
    load_policies_script
        .arg("--policies")
        .arg(tempdir.path().join("policies.tar.gz"))
        .arg("--policies-list")
        .arg(project_root.join("tests/data/airgap/policies.txt"))
        .arg("--registry")
        .arg(format!("localhost:{}", port))
        .arg("--sources-path")
        .arg(tempdir.path().join("sources.yml"))
        .arg("--enable-http-policies")
        .assert()
        .success();

    // Verify policies in local registry
    let mut kwctl = common::setup_command(tempdir.path());
    kwctl
        .arg("pull")
        .arg(format!(
            "registry://localhost:{}/kubewarden/tests/pod-privileged:v0.1.9",
            port
        ))
        .arg("--sources-path")
        .arg(tempdir.path().join("sources.yml"))
        .assert()
        .success();

    let mut kwctl = common::setup_command(tempdir.path());
    kwctl
        .arg("pull")
        .arg(format!(
            "registry://localhost:{}/kubewarden/pod-privileged-policy/releases/download/v0.1.6/policy.wasm ",
            port
        ))
        .arg("--sources-path")
        .arg(tempdir.path().join("sources.yml"))
        .assert()
        .success();
}

fn setup_airgap_script_command(script: &Path, tempdir: &Path) -> Command {
    let mut cmd = Command::new(script);

    cmd.current_dir(tempdir)
        .env("XDG_CONFIG_HOME", tempdir.join(".config"))
        .env("XDG_CACHE_HOME", tempdir.join(".cache"))
        .env("XDG_DATA_HOME", tempdir.join(".local/share"))
        .env("KWCTL_CMD", env!("CARGO_BIN_EXE_kwctl"));

    cmd
}
