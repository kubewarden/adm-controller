use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use ferricel_core::compiler::Builder as CompilerBuilder;
use policy_evaluator::{
    ferricel_compiler_builder_chains, ferricel_compiler_extension_decls,
    ferricel_host_capabilities,
    policy_evaluator::PolicyExecutionMode,
    policy_metadata::{ContextAwareResource, Metadata, PolicyType},
};
use tempfile::NamedTempFile;
use tracing::warn;

use crate::scaffold::{
    kubewarden_crds::{ClusterAdmissionPolicy, ClusterAdmissionPolicySpec},
    vap::{VapData, warn_kw_k8s_requires_grants},
};

/// Derive the path of the `metadata.yml` file that sits alongside `wasm_path`.
fn metadata_path_for(wasm_path: &Path) -> Result<PathBuf> {
    Ok(parent_dir_of(wasm_path).join("metadata.yml"))
}

/// Directory `path` lives in, defaulting to `.` when `path` has no parent
/// component (e.g. a bare file name like `policy.wasm`).
fn parent_dir_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Write `contents` to `path` atomically: the data is first staged in a
/// temporary file created in the same directory as `path` (so the final
/// rename is guaranteed to be an atomic same-filesystem operation), fsync'd,
/// and then moved into place. `path` therefore either ends up holding the
/// complete new content, or is left exactly as it was before the call -
/// never truncated or partially written, regardless of where a failure
/// occurs.
///
/// Unless `force` is set, the rename fails (leaving both the temp file
/// cleaned up and `path` untouched) if `path` already exists.
fn write_output_file(path: &Path, contents: &[u8], force: bool, what: &str) -> Result<()> {
    let dir = parent_dir_of(path);

    let mut tmp = NamedTempFile::new_in(&dir).map_err(|e| {
        anyhow!(
            "cannot create temporary file for {what} in {}: {e}",
            dir.display()
        )
    })?;

    tmp.write_all(contents)
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|e| anyhow!("cannot write {what} to {}: {e}", path.display()))?;

    // NamedTempFile is created with 0600 permissions; restore the usual
    // world-readable mode the previous fs::write()-based implementation
    // produced for these output files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|e| anyhow!("cannot set permissions on {what}: {e}"))?;
    }

    if force {
        tmp.persist(path)
            .map_err(|e| anyhow!("cannot write {what} to {}: {}", path.display(), e.error))?;
    } else {
        tmp.persist_noclobber(path).map_err(|e| {
            if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!(
                    "{what} already exists at {}, use --force to overwrite",
                    path.display()
                )
            } else {
                anyhow!("cannot write {what} to {}: {}", path.display(), e.error)
            }
        })?;
    }

    Ok(())
}

/// Compiled path: compiles the VAP CEL expressions to Wasm, writes the module
/// to `wasm_path`, generates a `metadata.yml` alongside it, and builds a
/// [`ClusterAdmissionPolicy`] with only paramKind + paramRef in settings.
///
/// Unless `force` is set, neither `wasm_path` nor the `metadata.yml` written
/// alongside it are allowed to already exist: the check happens before any
/// compilation or write happens, so a conflict on either destination leaves
/// both untouched.
pub(crate) fn vap_compiled(
    vap_data: VapData,
    wasm_path: &Path,
    force: bool,
) -> Result<ClusterAdmissionPolicy> {
    let metadata_path = metadata_path_for(wasm_path)?;

    if !force {
        if wasm_path.exists() {
            return Err(anyhow!(
                "{} already exists, use --force to overwrite",
                wasm_path.display()
            ));
        }
        if metadata_path.exists() {
            return Err(anyhow!(
                "metadata.yml already exists at {}, use --force to overwrite",
                metadata_path.display()
            ));
        }
    }

    // Register all Kubewarden host-capability builder chains and extension
    // declarations so the compiler accepts CEL expressions that call kw.oci,
    // kw.net, kw.crypto, etc. in addition to kw.k8s (auto-registered by ferricel-core).
    let mut builder = CompilerBuilder::new();
    for chain in ferricel_compiler_builder_chains() {
        builder = builder.with_builder_chain(chain);
    }
    for decl in ferricel_compiler_extension_decls() {
        builder = builder.with_extension(decl);
    }
    let wasm_bytes = builder
        .build()
        .compile_vap_from_policy(&vap_data.vap)
        .map_err(|e| anyhow!("failed to compile VAP to Wasm: {e}"))?;

    write_output_file(wasm_path, &wasm_bytes, force, "Wasm module")?;

    // Canonicalize only after the file has been written: a relative,
    // not-yet-existing output path cannot be canonicalized, so this must
    // happen after `write_output_file` has created it.
    let wasm_path_abs = wasm_path
        .canonicalize()
        .map_err(|e| anyhow!("cannot canonicalize {}: {e}", wasm_path.display()))?;

    // Derive host capabilities from the extensions section embedded in the
    // compiled wasm so metadata.yml accurately reflects what the policy uses.
    let used = ferricel_core::extensions_used(&wasm_bytes)
        .map_err(|e| anyhow!("failed to read host extensions from compiled module: {e}"))?;
    let caps = ferricel_host_capabilities(&used);
    let host_capabilities = if caps.is_empty() { None } else { Some(caps) };

    let context_aware_resources = context_aware_resources_from_param(&vap_data);

    // The `ferricel.extensions` section records every host extension the
    // compiled module actually calls, including `kw.k8s.get`/`kw.k8s.list`.
    // Unlike `paramKind`, there is no static way (short of parsing the CEL
    // AST ourselves) to know *which* apiVersion/kind those calls target, so
    // we can only warn that `context_aware_resources` may need to be
    // extended by hand, not derive the grants automatically.
    if used
        .iter()
        .any(|extension| extension.namespace.as_deref() == Some("kw.k8s"))
    {
        warn_kw_k8s_requires_grants(&context_aware_resources);
    }

    if let Err(e) = write_metadata_file(
        &vap_data,
        &metadata_path,
        host_capabilities,
        context_aware_resources.clone(),
        force,
    ) {
        if !force {
            // Best-effort rollback: metadata.yml failed to write and `force`
            // was not set, so `wasm_path` is guaranteed to have been freshly
            // created by the `persist_noclobber()` call above (the earlier
            // pre-check plus the noclobber rename together rule out it
            // having existed before this invocation). Remove it so the
            // failure leaves no artifacts behind, matching the guarantee we
            // give for the `metadata.yml`-already-exists case.
            let _ = fs::remove_file(wasm_path);
        }
        return Err(e);
    }

    let module = url::Url::from_file_path(&wasm_path_abs)
        .map_err(|_| anyhow!("cannot convert {} to a file URI", wasm_path_abs.display()))?
        .to_string();

    Ok(ClusterAdmissionPolicy {
        api_version: "policies.kubewarden.io/v1".to_string(),
        kind: "ClusterAdmissionPolicy".to_string(),
        metadata: vap_data.metadata,
        spec: ClusterAdmissionPolicySpec {
            module,
            namespace_selector: vap_data.namespace_selector,
            match_policy: vap_data.match_policy,
            rules: vap_data.rules,
            object_selector: vap_data.object_selector,
            mutating: false,
            background_audit: true,
            context_aware_resources,
            failure_policy: None,
            mode: None,
            settings: vap_data.param_settings,
        },
    })
}

/// Build the `spec.contextAwareResources` allow list granting the policy
/// access to the resource named by `paramKind`, when present. Without this
/// grant, a parameterized policy would be denied access to the resource it
/// fetches via `paramRef` at evaluation time (see
/// `EvaluationContext::can_access_kubernetes_resource`).
fn context_aware_resources_from_param(vap_data: &VapData) -> BTreeSet<ContextAwareResource> {
    let mut context_aware_resources = BTreeSet::new();
    if let Some(param_resource) = &vap_data.param_resource {
        warn!(
            "granting access to {}/{} via spec.contextAwareResources (required by paramKind); review before applying",
            param_resource.api_version, param_resource.kind
        );
        context_aware_resources.insert(param_resource.clone());
    }
    context_aware_resources
}

/// Write a `metadata.yml` file at `metadata_path`. Existence of the file was
/// already checked (unless `force` is set) before any Wasm/metadata write
/// took place; `force` is only forwarded here to pick the right write
/// strategy.
fn write_metadata_file(
    vap_data: &VapData,
    metadata_path: &Path,
    host_capabilities: Option<BTreeSet<String>>,
    context_aware_resources: BTreeSet<ContextAwareResource>,
    force: bool,
) -> Result<()> {
    let mut annotations = std::collections::BTreeMap::new();
    if let Some(name) = vap_data.metadata.name.as_deref() {
        annotations.insert("io.kubewarden.policy.title".to_string(), name.to_string());
    }

    let policy_metadata = Metadata {
        protocol_version: None,
        rules: vap_data.rules.clone(),
        annotations: if annotations.is_empty() {
            None
        } else {
            Some(annotations)
        },
        mutating: false,
        background_audit: true,
        execution_mode: PolicyExecutionMode::Ferricel,
        policy_type: PolicyType::Kubernetes,
        context_aware_resources,
        host_capabilities,
        minimum_kubewarden_version: None,
    };

    let metadata_yaml = serde_yaml::to_string(&policy_metadata)
        .map_err(|e| anyhow!("cannot serialize metadata to YAML: {e}"))?;
    write_output_file(
        metadata_path,
        metadata_yaml.as_bytes(),
        force,
        "metadata.yml",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{convert::TryFrom, fs::File};

    use k8s_openapi::api::admissionregistration::v1::{
        ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
    };
    use policy_evaluator::policy_metadata::Rule;
    use rstest::*;
    use tempfile::TempDir;

    use super::*;
    use crate::scaffold::vap::tests::test_data;

    fn open_vap_data(vap_yaml_path: &str, vap_binding_yaml_path: &str) -> VapData {
        let yaml_file = File::open(test_data(vap_yaml_path)).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();

        let yaml_file = File::open(test_data(vap_binding_yaml_path)).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        VapData::new(vap, vap_binding).unwrap()
    }

    /// Names of the entries directly inside `dir`, for asserting that no
    /// stray temporary files (e.g. leftover `.tmp*` staging files) are left
    /// behind after a `vap_compiled` call, success or failure.
    fn dir_entry_names(dir: &Path) -> std::collections::BTreeSet<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml", false)]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml", false)]
    #[case::vap_with_params("vap/vap-with-params.yml", "vap/vap-binding-params.yml", true)]
    #[case::vap_with_params_no_action(
        "vap/vap-with-params.yml",
        "vap/vap-binding-params-no-action.yml",
        true
    )]
    fn compile_vap_to_wasm(
        #[case] vap_yaml_path: &str,
        #[case] vap_binding_yaml_path: &str,
        #[case] has_params: bool,
    ) {
        let yaml_file = File::open(test_data(vap_yaml_path)).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();

        let yaml_file = File::open(test_data(vap_binding_yaml_path)).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        let expected_rules = vap
            .clone()
            .spec
            .unwrap()
            .match_constraints
            .unwrap()
            .resource_rules
            .unwrap()
            .iter()
            .map(Rule::try_from)
            .collect::<Result<Vec<Rule>, &str>>()
            .unwrap();

        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = VapData::new(vap, vap_binding).unwrap();
        let cap = vap_compiled(vap_data, &wasm_path, false).unwrap();

        // `spec.module` must be a valid `file://` URI that round-trips back
        // to the canonicalized wasm path via `Url::to_file_path()`, which is
        // how consumers (policy-fetcher, kwctl) resolve it.
        let module_url = url::Url::parse(&cap.spec.module).unwrap();
        assert_eq!("file", module_url.scheme());
        assert_eq!(
            wasm_path.canonicalize().unwrap(),
            module_url.to_file_path().unwrap()
        );
        assert!(!cap.spec.mutating);
        assert!(cap.spec.background_audit);
        assert!(cap.spec.failure_policy.is_none());
        assert!(cap.spec.mode.is_none());

        // validations, variables, failurePolicy must NOT be in settings
        assert!(!cap.spec.settings.contains_key("validations"));
        assert!(!cap.spec.settings.contains_key("variables"));
        assert!(!cap.spec.settings.contains_key("failurePolicy"));

        if has_params {
            assert!(cap.spec.settings.contains_key("paramKind"));
            assert!(cap.spec.settings.contains_key("paramRef"));
            // The resource named by paramKind must be granted access to via
            // spec.contextAwareResources, otherwise the policy would be
            // denied when fetching it via paramRef at evaluation time.
            assert!(
                cap.spec
                    .context_aware_resources
                    .contains(&ContextAwareResource {
                        api_version: "v1".to_string(),
                        kind: "ConfigMap".to_string(),
                    }),
                "context_aware_resources should contain the param resource (v1/ConfigMap), got: {:?}",
                cap.spec.context_aware_resources
            );
            // paramRef.parameterNotFoundAction must always be present in the
            // generated settings (defaulted to Deny by VapData::new() when
            // the binding omits it), otherwise the ferricel runtime's
            // settings validation would reject the policy at load time.
            assert_eq!(
                "Deny",
                cap.spec.settings["paramRef"]["parameterNotFoundAction"]
                    .as_str()
                    .expect("parameterNotFoundAction should be a string")
            );
        } else {
            assert!(!cap.spec.settings.contains_key("paramKind"));
            assert!(!cap.spec.settings.contains_key("paramRef"));
            assert!(cap.spec.context_aware_resources.is_empty());
        }

        assert_eq!(cap.spec.rules, expected_rules);
    }

    /// A wasm output path containing a space (a reserved character in URIs)
    /// must still produce a `spec.module` that is a valid, parsable `file://`
    /// URI resolving back to the original path - i.e. the space must be
    /// percent-encoded rather than copied verbatim.
    #[test]
    fn module_uri_percent_encodes_reserved_characters_in_path() {
        let dir = TempDir::new().unwrap();
        let sub_dir = dir.path().join("dir with spaces");
        fs::create_dir(&sub_dir).unwrap();
        let wasm_path = sub_dir.join("my policy.wasm");

        let vap_data = open_vap_data("vap/vap-without-variables.yml", "vap/vap-binding.yml");
        let cap = vap_compiled(vap_data, &wasm_path, false).unwrap();

        assert!(
            cap.spec.module.contains("%20"),
            "expected the space in the path to be percent-encoded, got: {}",
            cap.spec.module
        );

        let module_url = url::Url::parse(&cap.spec.module).unwrap_or_else(|e| {
            panic!("spec.module is not a valid URI: {} ({e})", cap.spec.module)
        });
        assert_eq!(
            wasm_path.canonicalize().unwrap(),
            module_url
                .to_file_path()
                .unwrap_or_else(|()| panic!("spec.module does not resolve back to a file path"))
        );
    }

    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml")]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml")]
    fn metadata_yml_is_generated(#[case] vap_yaml_path: &str, #[case] vap_binding_yaml_path: &str) {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data(vap_yaml_path, vap_binding_yaml_path);
        vap_compiled(vap_data, &wasm_path, false).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        assert!(metadata_path.exists(), "metadata.yml should be created");

        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();
        assert_eq!(metadata.execution_mode, PolicyExecutionMode::Ferricel);
        assert!(!metadata.mutating);
        assert!(metadata.background_audit);
        assert!(metadata.context_aware_resources.is_empty());
        assert!(metadata.protocol_version.is_none());
        assert!(!metadata.rules.is_empty());
        // No leftover staging file from either atomic rename.
        assert_eq!(
            std::collections::BTreeSet::from([
                "policy.wasm".to_string(),
                "metadata.yml".to_string()
            ]),
            dir_entry_names(dir.path()),
            "no temporary staging files should be left behind"
        );
    }

    #[test]
    fn metadata_yml_contains_context_aware_resources_for_params() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data("vap/vap-with-params.yml", "vap/vap-binding-params.yml");
        let cap = vap_compiled(vap_data, &wasm_path, false).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();

        let expected_resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
        };

        assert!(
            metadata
                .context_aware_resources
                .contains(&expected_resource),
            "context_aware_resources should contain the param resource (v1/ConfigMap), got: {:?}",
            metadata.context_aware_resources
        );

        // The CRD's spec.contextAwareResources must match metadata.yml,
        // otherwise the parameterized policy would be denied access to the
        // resource it fetches via paramRef at evaluation time.
        assert!(
            cap.spec
                .context_aware_resources
                .contains(&expected_resource),
            "spec.contextAwareResources should contain the param resource (v1/ConfigMap), got: {:?}",
            cap.spec.context_aware_resources
        );
    }

    #[test]
    fn metadata_yml_already_exists_returns_error() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        // pre-create metadata.yml to trigger the conflict
        let metadata_path = dir.path().join("metadata.yml");
        fs::write(&metadata_path, b"existing content").unwrap();

        let vap_data = open_vap_data("vap/vap-without-variables.yml", "vap/vap-binding.yml");
        let result = vap_compiled(vap_data, &wasm_path, false);

        let e = result.expect_err("expected an error");
        assert!(
            e.to_string().contains("metadata.yml already exists"),
            "unexpected error: {e}"
        );
        // A conflict on metadata.yml must not leave a policy.wasm behind.
        assert!(
            !wasm_path.exists(),
            "policy.wasm should not have been created when metadata.yml already exists"
        );
        // Only the pre-existing metadata.yml should remain: no leftover
        // staging file from the aborted wasm write.
        assert_eq!(
            std::collections::BTreeSet::from(["metadata.yml".to_string()]),
            dir_entry_names(dir.path()),
            "no temporary staging files should be left behind"
        );
    }

    #[test]
    fn wasm_already_exists_returns_error() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        // pre-create policy.wasm to trigger the conflict
        fs::write(&wasm_path, b"existing wasm content").unwrap();

        let vap_data = open_vap_data("vap/vap-without-variables.yml", "vap/vap-binding.yml");
        let result = vap_compiled(vap_data, &wasm_path, false);

        let e = result.expect_err("expected an error");
        assert!(
            e.to_string().contains("already exists"),
            "unexpected error: {e}"
        );
        assert_eq!(
            b"existing wasm content".to_vec(),
            fs::read(&wasm_path).unwrap(),
            "existing policy.wasm must not be overwritten"
        );
        assert!(
            !dir.path().join("metadata.yml").exists(),
            "metadata.yml should not have been created when policy.wasm already exists"
        );
        // Only the pre-existing policy.wasm should remain: no leftover
        // staging file from the aborted metadata write.
        assert_eq!(
            std::collections::BTreeSet::from(["policy.wasm".to_string()]),
            dir_entry_names(dir.path()),
            "no temporary staging files should be left behind"
        );
    }

    #[test]
    fn force_overwrites_existing_outputs() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");
        let metadata_path = dir.path().join("metadata.yml");

        fs::write(&wasm_path, b"stale wasm content").unwrap();
        fs::write(&metadata_path, b"stale metadata content").unwrap();

        let vap_data = open_vap_data("vap/vap-without-variables.yml", "vap/vap-binding.yml");
        vap_compiled(vap_data, &wasm_path, true).unwrap();

        assert_ne!(
            b"stale wasm content".to_vec(),
            fs::read(&wasm_path).unwrap(),
            "policy.wasm should have been overwritten with --force"
        );
        let metadata: Metadata = serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap())
            .expect("metadata.yml should have been overwritten with valid YAML");
        assert_eq!(metadata.execution_mode, PolicyExecutionMode::Ferricel);
        // No leftover staging file from either atomic rename.
        assert_eq!(
            std::collections::BTreeSet::from([
                "policy.wasm".to_string(),
                "metadata.yml".to_string()
            ]),
            dir_entry_names(dir.path()),
            "no temporary staging files should be left behind"
        );
    }

    #[test]
    fn write_output_file_does_not_overwrite_on_conflict_and_leaves_no_staging_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("out.txt");
        fs::write(&path, b"original").unwrap();

        let err = write_output_file(&path, b"new content", false, "test file")
            .expect_err("expected a conflict error");
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
        assert_eq!(b"original".to_vec(), fs::read(&path).unwrap());
        assert_eq!(
            std::collections::BTreeSet::from(["out.txt".to_string()]),
            dir_entry_names(dir.path()),
            "no temporary staging file should be left behind after a conflict"
        );
    }

    #[test]
    fn write_output_file_force_replaces_content_atomically() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("out.txt");
        fs::write(&path, b"original").unwrap();

        write_output_file(&path, b"replaced", true, "test file").unwrap();

        assert_eq!(b"replaced".to_vec(), fs::read(&path).unwrap());
        assert_eq!(
            std::collections::BTreeSet::from(["out.txt".to_string()]),
            dir_entry_names(dir.path()),
            "no temporary staging file should be left behind after a forced replace"
        );
    }

    /// VAPs that use no host-capability extensions (kw.oci / kw.net / etc.)
    /// must produce metadata.yml with `hostCapabilities: null` (field absent).
    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml")]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml")]
    fn metadata_yml_has_no_host_capabilities_when_none_used(
        #[case] vap_yaml_path: &str,
        #[case] vap_binding_yaml_path: &str,
    ) {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data(vap_yaml_path, vap_binding_yaml_path);
        vap_compiled(vap_data, &wasm_path, false).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();
        assert!(
            metadata.host_capabilities.is_none(),
            "expected no host_capabilities for a plain VAP, got: {:?}",
            metadata.host_capabilities
        );
    }

    /// A VAP that uses `kw.net.lookupHost` and `kw.oci.image(...).manifestDigest()`
    /// must produce metadata.yml with those capabilities populated.
    #[test]
    fn metadata_yml_contains_host_capabilities_when_used() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data("vap/vap-with-host-capabilities.yml", "vap/vap-binding.yml");
        vap_compiled(vap_data, &wasm_path, false).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();

        let caps = metadata
            .host_capabilities
            .as_ref()
            .expect("host_capabilities should be Some for a policy using kw.net and kw.oci");

        assert!(
            caps.contains("net/v1/dns_lookup_host"),
            "expected net/v1/dns_lookup_host in host_capabilities, got: {caps:?}"
        );
        assert!(
            caps.contains("oci/v1/manifest_digest"),
            "expected oci/v1/manifest_digest in host_capabilities, got: {caps:?}"
        );
    }

    /// A VAP that calls `kw.k8s.apiVersion(...).kind(...).get(...)` must
    /// produce metadata.yml with the `kubernetes/get_resource` host
    /// capability populated, even though (pending manual review by the user)
    /// `context_aware_resources` stays empty: there is no `paramKind` for
    /// this VAP, and the apiVersion/kind targeted by `kw.k8s` calls is not
    /// statically derived. This pins the current (intentionally incomplete)
    /// behavior that the `kw.k8s`-usage warning exists to compensate for.
    #[test]
    fn metadata_yml_contains_host_capabilities_for_kw_k8s_but_no_context_aware_resources() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data("vap/vap-with-k8s.yml", "vap/vap-binding.yml");
        let cap = vap_compiled(vap_data, &wasm_path, false).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();

        let caps = metadata
            .host_capabilities
            .as_ref()
            .expect("host_capabilities should be Some for a policy using kw.k8s");
        assert!(
            caps.contains("kubernetes/get_resource"),
            "expected kubernetes/get_resource in host_capabilities, got: {caps:?}"
        );

        assert!(
            metadata.context_aware_resources.is_empty(),
            "context_aware_resources should stay empty: kw.k8s targets are not statically derived, got: {:?}",
            metadata.context_aware_resources
        );
        assert!(
            cap.spec.context_aware_resources.is_empty(),
            "spec.context_aware_resources should stay empty: kw.k8s targets are not statically derived, got: {:?}",
            cap.spec.context_aware_resources
        );
    }
}
