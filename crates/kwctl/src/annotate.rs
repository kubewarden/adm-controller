use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow};
use policy_evaluator::{
    ProtocolVersion, constants::*, host_capabilities::HostCapabilities, policy_metadata::Metadata,
    validator::Validate,
};
use tracing::warn;

use crate::{
    backend::{Backend, BackendDetector},
    wasm_scanner,
};

/// Input for [`write_annotation`].
pub(crate) struct AnnotateRequest {
    pub(crate) wasm_path: PathBuf,
    pub(crate) metadata: MetadataSource,
    pub(crate) destination: PathBuf,
    /// `KEY=VALUE` or `KEY=@PATH` overrides.
    /// kwctl applies them on top of the base metadata that `metadata`
    /// resolves to.
    pub(crate) annotations: Vec<String>,
    pub(crate) usage_path: Option<PathBuf>,
    /// Permits [`MetadataSource::File`] to replace the metadata of a policy
    /// that already has one. [`MetadataSource::Policy`] never discards
    /// anything, so this field has no effect on it.
    pub(crate) force: bool,
}

/// Where `annotate` takes the base metadata from, before the overrides
/// apply to it.
pub(crate) enum MetadataSource {
    /// `--metadata-path` was given. Replace the policy's metadata with the
    /// file at this path.
    File(PathBuf),
    /// No `--metadata-path`. Patch the metadata already in the policy.
    Policy,
}

impl MetadataSource {
    /// Returns the metadata that the overrides apply to.
    ///
    /// `existing` is the raw content of the metadata section already in the
    /// policy, if the policy has one.
    ///
    /// [`MetadataSource::File`] only asks whether the section exists. If it
    /// does, `force` permits the replace. kwctl does not parse content that
    /// it is about to discard.
    ///
    /// [`MetadataSource::Policy`] parses the section, because the overrides
    /// apply on top of its content.
    fn resolve(self, existing: Option<&[u8]>, force: bool) -> Result<Metadata> {
        match self {
            Self::File(path) => {
                if existing.is_some() {
                    if !force {
                        return Err(anyhow!(
                            "The policy is already annotated. Use `annotate --force` to overwrite the existing metadata"
                        ));
                    }
                    warn!("policy is already annotated, overwriting existing metadata");
                }
                load_metadata_file(&path)
            }
            Self::Policy => {
                let raw = existing.ok_or_else(|| {
                    anyhow!(
                        "The policy is not annotated. Use `annotate --metadata-path` to annotate it"
                    )
                })?;
                serde_json::from_slice(raw)
                    .map_err(|e| anyhow!("Error reading the policy's existing metadata: {}", e))
            }
        }
    }
}

pub(crate) fn write_annotation(request: AnnotateRequest) -> Result<()> {
    let overrides = build_overrides(&request.annotations, request.usage_path.as_deref())?;

    let wasm_bytes =
        std::fs::read(&request.wasm_path).map_err(|e| anyhow!("Error reading wasm file: {}", e))?;

    let mut module = walrus::Module::from_buffer(&wasm_bytes)
        .map_err(|e| anyhow!("Error parsing wasm module: {}", e))?;

    // The module is only in memory at this point. Nothing reaches the disk
    // before `write_annotated_wasm_file`. As a result, it is safe to take
    // the section out before `resolve` decides whether the command goes on.
    let existing_metadata = take_metadata_section(&mut module);

    let base_metadata = request
        .metadata
        .resolve(existing_metadata.as_deref(), request.force)?;

    let detected_capabilities =
        wasm_scanner::scan(&module).map_err(|e| anyhow!("Error scanning wasm module: {}", e))?;

    let backend_detector = BackendDetector::default();
    let metadata = prepare_metadata(
        base_metadata,
        request.wasm_path,
        backend_detector,
        overrides,
    )?;
    write_annotated_wasm_file(
        &mut module,
        request.destination,
        metadata,
        &detected_capabilities,
    )
}

fn load_metadata_file(path: &Path) -> Result<Metadata> {
    let metadata_file =
        File::open(path).map_err(|e| anyhow!("Error opening metadata file: {}", e))?;
    serde_yaml::from_reader(&metadata_file)
        .map_err(|e| anyhow!("Error unmarshalling metadata {}", e))
}

/// Removes every Kubewarden metadata custom section from `module`. Returns
/// the raw content of the first section, if the module had one.
///
/// `Metadata::from_contents` also reads the first section. As a result,
/// the two agree on which metadata a double-annotated policy carries.
///
/// This step also clears space for [`write_annotated_wasm_file`] to add
/// one fresh section.
fn take_metadata_section(module: &mut walrus::Module) -> Option<Vec<u8>> {
    let first = module
        .customs
        .remove_raw(KUBEWARDEN_CUSTOM_SECTION_METADATA)
        .map(|section| section.data);
    while module
        .customs
        .remove_raw(KUBEWARDEN_CUSTOM_SECTION_METADATA)
        .is_some()
    {}
    first
}

/// One `--annotation` value: a literal string, or the path to a file that
/// holds the value.
#[derive(Debug, PartialEq)]
enum AnnotationValue {
    Literal(String),
    File(PathBuf),
}

#[derive(Debug, thiserror::Error, PartialEq)]
enum AnnotationOverrideError {
    #[error("invalid annotation {0:?}: expected KEY=VALUE or KEY=@PATH")]
    MissingValue(String),
    #[error("invalid annotation {0:?}: the key must not be empty")]
    EmptyKey(String),
}

/// Parses one `--annotation` argument into its key and value.
///
/// `KEY=VALUE` sets a literal value. `KEY=@PATH` reads the value from the
/// file at `PATH`, the same convention `curl -d` uses.
///
/// kwctl rejects a missing `=` or an empty key. It does not treat a missing
/// `=` as an unset. The likely cause is a forgotten `=value`, and a typo
/// must not delete an annotation in silence.
fn parse_annotation_override(
    input: &str,
) -> std::result::Result<(String, AnnotationValue), AnnotationOverrideError> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| AnnotationOverrideError::MissingValue(input.to_string()))?;

    if key.is_empty() {
        return Err(AnnotationOverrideError::EmptyKey(input.to_string()));
    }

    let value = match value.strip_prefix('@') {
        Some(path) => AnnotationValue::File(PathBuf::from(path)),
        None => AnnotationValue::Literal(value.to_string()),
    };

    Ok((key.to_string(), value))
}

/// Builds the map of annotation overrides for the base metadata. It
/// combines the `--annotation` values with `--usage-path`, which kwctl
/// treats as an override of `io.kubewarden.policy.usage`.
fn build_overrides(
    annotations: &[String],
    usage_path: Option<&Path>,
) -> Result<BTreeMap<String, String>> {
    let mut overrides = BTreeMap::new();

    for input in annotations {
        let (key, value) = parse_annotation_override(input)?;
        let resolved = match value {
            AnnotationValue::Literal(s) => s,
            AnnotationValue::File(path) => fs::read_to_string(&path).map_err(|e| {
                anyhow!(
                    "Error reading annotation value file '{}': {}",
                    path.display(),
                    e
                )
            })?,
        };
        overrides.insert(key, resolved);
    }

    if let Some(path) = usage_path {
        if overrides.contains_key(KUBEWARDEN_ANNOTATION_POLICY_USAGE) {
            return Err(anyhow!(
                "conflicting values for '{}': both --usage-path and --annotation set it",
                KUBEWARDEN_ANNOTATION_POLICY_USAGE
            ));
        }
        let usage =
            fs::read_to_string(path).map_err(|e| anyhow!("Error reading usage file: {}", e))?;
        overrides.insert(String::from(KUBEWARDEN_ANNOTATION_POLICY_USAGE), usage);
    }

    Ok(overrides)
}

fn prepare_metadata(
    mut metadata: Metadata,
    wasm_path: PathBuf,
    backend_detector: BackendDetector,
    overrides: BTreeMap<String, String>,
) -> Result<Metadata> {
    let backend = backend_detector.detect(wasm_path, &metadata)?;

    match backend {
        Backend::Opa | Backend::OpaGatekeeper | Backend::Wasi | Backend::Ferricel => {
            metadata.protocol_version = Some(ProtocolVersion::Unknown)
        }
        Backend::KubewardenWapc(protocol_version) => {
            metadata.protocol_version = Some(protocol_version)
        }
    };

    let mut annotations = metadata.annotations.unwrap_or_default();
    for (key, value) in overrides {
        if annotations.insert(key.clone(), value).is_some() {
            warn!(annotation = %key, "overwriting an existing annotation");
        }
    }
    annotations.insert(
        String::from(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
        String::from(env!("CARGO_PKG_VERSION")),
    );
    metadata.annotations = Some(annotations);

    metadata
        .validate()
        .map_err(|e| anyhow!("Metadata is invalid: {:?}", e))
        .and(Ok(metadata))
}

/// Holds the result of comparing detected host capabilities against declared ones.
#[derive(Debug, Default, PartialEq)]
struct CapabilitiesMismatch {
    /// Capability paths detected in the policy binary that are not covered by
    /// any declared pattern.
    used_but_undeclared: BTreeSet<String>,
    /// Declared patterns that do not cover any capability path detected in the
    /// binary.  For [`HostCapabilities::AllowAll`] this always contains `"*"`
    /// to signal that the wildcard is too permissive.
    declared_but_unused: BTreeSet<String>,
}

/// Pure helper: given the set of detected capability paths and the parsed
/// `HostCapabilities`, returns a [`CapabilitiesMismatch`] describing patterns
/// that are used-but-undeclared and declared-but-unused.
fn compute_capabilities_mismatch(
    detected_set: &BTreeSet<String>,
    host_capabilities: &HostCapabilities,
) -> CapabilitiesMismatch {
    // Capabilities the policy uses but that are not covered by the declarations.
    let used_but_undeclared: BTreeSet<String> = detected_set
        .iter()
        .filter(|cap| !host_capabilities.is_allowed(cap.as_str()))
        .cloned()
        .collect();

    // Declared patterns that don't match anything in the detected set.
    let declared_but_unused: BTreeSet<String> = match host_capabilities {
        HostCapabilities::DenyAll => BTreeSet::new(),
        // The `*` wildcard is always considered too permissive — the caller
        // will emit a dedicated warning regardless of what was detected.
        HostCapabilities::AllowAll => BTreeSet::from(["*".to_string()]),
        HostCapabilities::Patterns { prefixes, exact } => {
            let mut unused: BTreeSet<String> = exact.difference(detected_set).cloned().collect();
            for prefix in prefixes {
                if !detected_set
                    .iter()
                    .any(|cap| cap.starts_with(prefix.as_str()))
                {
                    // Re-attach the `*` that was stripped during parsing so
                    // the warning is human-readable (e.g. `oci/*`).
                    unused.insert(format!("{prefix}*"));
                }
            }
            unused
        }
    };

    CapabilitiesMismatch {
        used_but_undeclared,
        declared_but_unused,
    }
}

fn warn_on_capabilities_mismatch(
    detected: &[wasm_scanner::DetectedHostCapability],
    metadata: &Metadata,
) {
    let detected_set: BTreeSet<String> = detected
        .iter()
        .map(|c| format!("{}/{}", c.namespace, c.operation))
        .collect();

    let host_capabilities =
        match HostCapabilities::new(metadata.host_capabilities.iter().flat_map(|s| s.iter())) {
            Ok(hc) => hc,
            Err(e) => {
                warn!("invalid host_capabilities pattern in metadata: {}", e);
                return;
            }
        };

    let mismatch = compute_capabilities_mismatch(&detected_set, &host_capabilities);

    if !mismatch.used_but_undeclared.is_empty() {
        warn!(
            capabilities = ?mismatch.used_but_undeclared,
            "host capabilities used by the policy but not declared in metadata"
        );
    }

    if !mismatch.declared_but_unused.is_empty() {
        if matches!(host_capabilities, HostCapabilities::AllowAll) {
            warn!(
                "metadata declares all host capabilities (*); consider restricting \
                 to only the capabilities actually used by the policy"
            );
        } else {
            warn!(
                capabilities = ?mismatch.declared_but_unused,
                "host capabilities declared in metadata but not detected in the policy"
            );
        }
    }
}

fn write_annotated_wasm_file(
    module: &mut walrus::Module,
    output_path: PathBuf,
    metadata: Metadata,
    detected_capabilities: &[wasm_scanner::DetectedHostCapability],
) -> Result<()> {
    warn_on_capabilities_mismatch(detected_capabilities, &metadata);

    let metadata_json = serde_json::to_vec(&metadata)?;

    let custom_section = walrus::RawCustomSection {
        name: String::from(KUBEWARDEN_CUSTOM_SECTION_METADATA),
        data: metadata_json,
    };
    module.customs.add(custom_section);

    // Rewrite the import from `kubewarden:javy/host` to just `host` so that the
    // runtime can provide the right implementation.
    //
    // This is needed to make JavaScript/TypeScript WASI policies work out
    // of the box.
    module.imports.iter_mut().for_each(|import| {
        if let walrus::ImportKind::Function(_) = import.kind
            && import.module == "kubewarden:javy/host"
            && import.name == "call"
        {
            import.module = "host".to_string();
        }
    });

    module.emit_wasm_file(output_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tempfile::tempdir;

    use super::*;

    fn detected(caps: &[(&str, &str)]) -> BTreeSet<String> {
        caps.iter().map(|(ns, op)| format!("{ns}/{op}")).collect()
    }

    #[rstest]
    #[case::deny_all_nothing_detected(
        vec![],                  // detected
        vec![],                  // declared
        vec![],                  // used_but_undeclared
        vec![],                  // declared_but_unused
    )]
    #[case::deny_all_with_detected(
        vec![("oci", "v1/verify")], // detected
        vec![],                     // declared
        vec!["oci/v1/verify"],      // used_but_undeclared
        vec![],                     // declared_but_unused
    )]
    #[case::allow_all_with_detected(
        vec![("oci", "v1/verify")], // detected
        vec!["*"],                  // declared
        vec![],                     // used_but_undeclared
        vec!["*"],                  // declared_but_unused
    )]
    #[case::allow_all_nothing_detected(
        vec![],    // detected
        vec!["*"], // declared
        vec![],    // used_but_undeclared
        vec!["*"], // declared_but_unused
    )]
    #[case::prefix_covers_single(
        vec![("oci", "v1/verify")], // detected
        vec!["oci/*"],              // declared
        vec![],                     // used_but_undeclared
        vec![],                     // declared_but_unused
    )]
    #[case::prefix_covers_multiple(
        vec![("oci", "v1/verify"), ("oci", "v1/manifest_digest")], // detected
        vec!["oci/*"],                                              // declared
        vec![],                                                     // used_but_undeclared
        vec![],                                                     // declared_but_unused
    )]
    #[case::prefix_declared_nothing_detected(
        vec![],        // detected
        vec!["oci/*"], // declared
        vec![],        // used_but_undeclared
        vec!["oci/*"], // declared_but_unused
    )]
    #[case::prefix_other_namespace(
        vec![("net", "v1/dns_lookup_host")], // detected
        vec!["oci/*"],                       // declared
        vec!["net/v1/dns_lookup_host"],      // used_but_undeclared
        vec!["oci/*"],                       // declared_but_unused
    )]
    #[case::exact_match(
        vec![("oci", "v1/verify")], // detected
        vec!["oci/v1/verify"],      // declared
        vec![],                     // used_but_undeclared
        vec![],                     // declared_but_unused
    )]
    #[case::exact_used_but_undeclared(
        vec![("oci", "v1/verify"), ("net", "v1/dns_lookup_host")], // detected
        vec!["oci/v1/verify"],                                      // declared
        vec!["net/v1/dns_lookup_host"],                             // used_but_undeclared
        vec![],                                                     // declared_but_unused
    )]
    #[case::exact_declared_but_unused(
        vec![("oci", "v1/verify")],                        // detected
        vec!["oci/v1/verify", "net/v1/dns_lookup_host"],   // declared
        vec![],                                            // used_but_undeclared
        vec!["net/v1/dns_lookup_host"],                    // declared_but_unused
    )]
    #[case::versioned_prefix_covers(
        vec![("oci", "v2/verify")], // detected
        vec!["oci/v2/*"],           // declared
        vec![],                     // used_but_undeclared
        vec![],                     // declared_but_unused
    )]
    #[case::versioned_prefix_other_version(
        vec![("oci", "v1/verify")], // detected
        vec!["oci/v2/*"],           // declared
        vec!["oci/v1/verify"],      // used_but_undeclared
        vec!["oci/v2/*"],           // declared_but_unused
    )]
    fn compute_mismatch(
        #[case] detected_caps: Vec<(&str, &str)>,
        #[case] declared_patterns: Vec<&str>,
        #[case] expected_used_but_undeclared: Vec<&str>,
        #[case] expected_declared_but_unused: Vec<&str>,
    ) {
        let hc = HostCapabilities::new(declared_patterns).unwrap();
        let mismatch = compute_capabilities_mismatch(&detected(&detected_caps), &hc);
        let expected_used: BTreeSet<String> = expected_used_but_undeclared
            .into_iter()
            .map(str::to_string)
            .collect();
        let expected_unused: BTreeSet<String> = expected_declared_but_unused
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(mismatch.used_but_undeclared, expected_used);
        assert_eq!(mismatch.declared_but_unused, expected_unused);
    }

    /// Builds a module with `count` metadata sections. Each section holds
    /// its own index as content. A test can then tell which section
    /// `take_metadata_section` returned.
    fn module_with_metadata_sections(count: usize) -> walrus::Module {
        let mut module = walrus::Module::default();
        for index in 0..count {
            module.customs.add(walrus::RawCustomSection {
                name: String::from(KUBEWARDEN_CUSTOM_SECTION_METADATA),
                data: index.to_string().into_bytes(),
            });
        }
        module
    }

    fn metadata_section_count(module: &walrus::Module) -> usize {
        module
            .customs
            .iter()
            .filter(|(_, section)| section.name() == KUBEWARDEN_CUSTOM_SECTION_METADATA)
            .count()
    }

    #[test]
    fn take_metadata_section_returns_none_when_there_is_no_section() {
        let mut module = module_with_metadata_sections(0);

        assert_eq!(take_metadata_section(&mut module), None);
        assert_eq!(metadata_section_count(&module), 0);
    }

    #[rstest]
    #[case::one_section(1)]
    #[case::already_double_annotated(2)]
    fn take_metadata_section_returns_the_first_and_removes_every_section(
        #[case] existing_sections: usize,
    ) {
        let mut module = module_with_metadata_sections(existing_sections);

        let taken = take_metadata_section(&mut module);

        assert_eq!(taken, Some(b"0".to_vec()));
        assert_eq!(metadata_section_count(&module), 0);
    }

    fn sample_metadata() -> Metadata {
        Metadata {
            protocol_version: Some(ProtocolVersion::V1),
            ..Default::default()
        }
    }

    fn sample_metadata_json() -> Vec<u8> {
        serde_json::to_vec(&sample_metadata()).expect("sample metadata serializes")
    }

    #[test]
    fn metadata_source_file_without_existing_metadata_uses_the_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("metadata.yml");
        fs::write(&path, serde_yaml::to_string(&sample_metadata()).unwrap()).unwrap();

        let metadata = MetadataSource::File(path).resolve(None, false).unwrap();
        assert_eq!(metadata.protocol_version, Some(ProtocolVersion::V1));
    }

    /// `File` does not read the existing section, so its content must not
    /// change the result. Without `--force`, `File` refuses. With `--force`,
    /// `File` replaces the section.
    #[rstest]
    #[case::readable_section(sample_metadata_json())]
    #[case::unreadable_section(b"not json".to_vec())]
    fn metadata_source_file_with_existing_metadata_without_force_fails(#[case] existing: Vec<u8>) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("metadata.yml");
        fs::write(&path, serde_yaml::to_string(&sample_metadata()).unwrap()).unwrap();

        let err = MetadataSource::File(path)
            .resolve(Some(&existing), false)
            .unwrap_err();
        assert!(err.to_string().contains("already annotated"));
    }

    #[rstest]
    #[case::readable_section(sample_metadata_json())]
    #[case::unreadable_section(b"not json".to_vec())]
    fn metadata_source_file_with_existing_metadata_and_force_uses_the_file(
        #[case] existing: Vec<u8>,
    ) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("metadata.yml");
        let mut from_file = sample_metadata();
        from_file.mutating = true;
        fs::write(&path, serde_yaml::to_string(&from_file).unwrap()).unwrap();

        let metadata = MetadataSource::File(path)
            .resolve(Some(&existing), true)
            .unwrap();
        assert!(metadata.mutating);
    }

    #[test]
    fn metadata_source_policy_with_unreadable_existing_metadata_fails() {
        let err = MetadataSource::Policy
            .resolve(Some(b"not json"), false)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Error reading the policy's existing metadata")
        );
    }

    #[rstest]
    #[case::literal(
        "io.kubewarden.policy.title=foo",
        "io.kubewarden.policy.title",
        AnnotationValue::Literal(String::from("foo"))
    )]
    #[case::value_with_embedded_equals("k=a=b", "k", AnnotationValue::Literal(String::from("a=b")))]
    #[case::empty_value("k=", "k", AnnotationValue::Literal(String::new()))]
    #[case::file_reference(
        "k=@path/to/file",
        "k",
        AnnotationValue::File(PathBuf::from("path/to/file"))
    )]
    fn parse_annotation_override_accepts(
        #[case] input: &str,
        #[case] expected_key: &str,
        #[case] expected_value: AnnotationValue,
    ) {
        let (key, value) = parse_annotation_override(input).unwrap();
        assert_eq!(key, expected_key);
        assert_eq!(value, expected_value);
    }

    #[rstest]
    #[case::no_equals_sign("novalue")]
    #[case::empty_key("=value")]
    fn parse_annotation_override_rejects(#[case] input: &str) {
        assert!(parse_annotation_override(input).is_err());
    }

    #[test]
    fn build_overrides_reads_a_referenced_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("usage.md");
        fs::write(&path, "file contents").unwrap();

        let overrides = build_overrides(
            &[format!("io.kubewarden.policy.usage=@{}", path.display())],
            None,
        )
        .unwrap();

        assert_eq!(
            overrides.get("io.kubewarden.policy.usage"),
            Some(&String::from("file contents")),
        );
    }

    #[test]
    fn build_overrides_rejects_conflicting_usage_sources() {
        let dir = tempdir().unwrap();
        let usage_path = dir.path().join("usage.md");
        fs::write(&usage_path, "from --usage-path").unwrap();

        let err = build_overrides(
            &[String::from("io.kubewarden.policy.usage=from --annotation")],
            Some(&usage_path),
        )
        .unwrap_err();
        assert!(err.to_string().contains("conflicting values"));
    }

    fn mock_protocol_version_detector_v1(_wasm_path: PathBuf) -> Result<ProtocolVersion> {
        Ok(ProtocolVersion::V1)
    }

    fn mock_rego_policy_detector_true(_wasm_path: PathBuf) -> Result<bool> {
        Ok(true)
    }

    fn mock_rego_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    fn mock_ferricel_policy_detector_false(_wasm_path: PathBuf) -> Result<bool> {
        Ok(false)
    }

    fn metadata_from_yaml(raw: &str) -> Metadata {
        serde_yaml::from_str(raw).expect("test fixture must parse")
    }

    #[test]
    fn test_kwctl_version_is_added_to_already_populated_annotations() {
        let expected_policy_title = "psp-test";
        let raw_metadata = format!(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        annotations:
          io.kubewarden.policy.title: {}
        "#,
            expected_policy_title
        );

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            metadata_from_yaml(&raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            BTreeMap::new(),
        )
        .unwrap();
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );
    }

    #[test]
    fn test_kwctl_version_is_overwrote_when_user_accidentally_provides_it() {
        let expected_policy_title = "psp-test";
        let raw_metadata = format!(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        annotations:
          io.kubewarden.policy.title: {}
          {}: NOT_VALID
        "#,
            expected_policy_title, KUBEWARDEN_ANNOTATION_KWCTL_VERSION,
        );

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            metadata_from_yaml(&raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            BTreeMap::new(),
        )
        .unwrap();
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );
    }

    #[test]
    fn test_kwctl_version_is_added_when_annotations_is_none() {
        let raw_metadata = r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        "#;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            metadata_from_yaml(raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            BTreeMap::new(),
        )
        .unwrap();
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );
    }

    #[test]
    fn test_kwctl_usage_is_added_when_annotations_is_none() {
        let raw_metadata = r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        "#;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let overrides = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
            String::from("readme contents"),
        )]);
        let metadata = prepare_metadata(
            metadata_from_yaml(raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            overrides,
        )
        .unwrap();
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
            Some(&String::from("readme contents")),
        );
    }

    #[test]
    fn test_final_metadata_for_a_rego_policy() {
        let raw_metadata = r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: opa
        "#;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            metadata_from_yaml(raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            BTreeMap::new(),
        );
        assert!(metadata.is_ok());
        assert_eq!(
            metadata.unwrap().protocol_version,
            Some(ProtocolVersion::Unknown)
        );
    }

    #[test]
    fn prepare_metadata_override_beats_base_value() {
        let raw_metadata = r#"
        rules: []
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        annotations:
          io.kubewarden.policy.title: original-title
        "#;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let overrides = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            String::from("patched-title"),
        )]);
        let metadata = prepare_metadata(
            metadata_from_yaml(raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            overrides,
        )
        .unwrap();
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from("patched-title")),
        );
    }

    #[test]
    fn prepare_metadata_keeps_fields_not_targeted_by_an_override() {
        let raw_metadata = r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        annotations:
          io.kubewarden.policy.title: original-title
          io.kubewarden.policy.author: original-author
        "#;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let overrides = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            String::from("patched-title"),
        )]);
        let metadata = prepare_metadata(
            metadata_from_yaml(raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            overrides,
        )
        .unwrap();

        assert_eq!(metadata.rules.len(), 1);
        let annotations = metadata.annotations.unwrap();
        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            Some(&String::from("original-author")),
        );
    }

    #[test]
    fn prepare_metadata_cannot_be_used_to_override_the_kwctl_version() {
        let raw_metadata = r#"
        rules: []
        mutating: false
        backgroundAudit: true
        executionMode: kubewarden-wapc
        "#;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let overrides = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            String::from("NOT_VALID"),
        )]);
        let metadata = prepare_metadata(
            metadata_from_yaml(raw_metadata),
            PathBuf::from("irrelevant.wasm"),
            backend_detector,
            overrides,
        )
        .unwrap();
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );
    }
}
