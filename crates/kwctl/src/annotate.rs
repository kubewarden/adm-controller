use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::PathBuf,
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

pub(crate) fn write_annotation(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    destination: PathBuf,
    usage_path: Option<PathBuf>,
) -> Result<()> {
    let usage = usage_path
        .map(|path| {
            fs::read_to_string(path).map_err(|e| anyhow!("Error reading usage file: {}", e))
        })
        .transpose()?;

    let wasm_bytes =
        std::fs::read(&wasm_path).map_err(|e| anyhow!("Error reading wasm file: {}", e))?;

    let mut module = walrus::Module::from_buffer(&wasm_bytes)
        .map_err(|e| anyhow!("Error parsing wasm module: {}", e))?;

    let detected_capabilities =
        wasm_scanner::scan(&module).map_err(|e| anyhow!("Error scanning wasm module: {}", e))?;

    let backend_detector = BackendDetector::default();
    let metadata = prepare_metadata(wasm_path, metadata_path, backend_detector, usage.as_deref())?;
    write_annotated_wasm_file(&mut module, destination, metadata, &detected_capabilities)
}

fn prepare_metadata(
    wasm_path: PathBuf,
    metadata_path: PathBuf,
    backend_detector: BackendDetector,
    usage: Option<&str>,
) -> Result<Metadata> {
    let metadata_file =
        File::open(metadata_path).map_err(|e| anyhow!("Error opening metadata file: {}", e))?;
    let mut metadata: Metadata = serde_yaml::from_reader(&metadata_file)
        .map_err(|e| anyhow!("Error unmarshalling metadata {}", e))?;

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
    annotations.insert(
        String::from(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
        String::from(env!("CARGO_PKG_VERSION")),
    );
    if let Some(s) = usage {
        annotations.insert(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
            String::from(s),
        );
    }
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
    use std::io::Write;

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

    #[test]
    fn test_kwctl_version_is_added_to_already_populated_annotations() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

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

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }

    #[test]
    fn test_kwctl_version_is_overwrote_when_user_accidentally_provides_it() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

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

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
            Some(&String::from(expected_policy_title))
        );

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }

    #[test]
    fn test_kwctl_version_is_added_when_annotations_is_none() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

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

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_KWCTL_VERSION),
            Some(&String::from(env!("CARGO_PKG_VERSION"))),
        );

        Ok(())
    }

    #[test]
    fn test_kwctl_usage_is_added_when_annotations_is_none() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

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

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_false,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            Some("readme contents"),
        )?;
        let annotations = metadata.annotations.unwrap();

        assert_eq!(
            annotations.get(KUBEWARDEN_ANNOTATION_POLICY_USAGE),
            Some(&String::from("readme contents")),
        );

        Ok(())
    }

    #[test]
    fn test_final_metadata_for_a_rego_policy() -> Result<()> {
        let dir = tempdir()?;

        let file_path = dir.path().join("metadata.yml");
        let mut file = File::create(file_path.clone())?;

        let raw_metadata = String::from(
            r#"
        rules:
        - apiGroups: [""]
          apiVersions: ["v1"]
          resources: ["pods"]
          operations: ["CREATE", "UPDATE"]
        mutating: false
        backgroundAudit: true
        executionMode: opa
        "#,
        );

        write!(file, "{}", raw_metadata)?;

        let backend_detector = BackendDetector::new(
            mock_rego_policy_detector_true,
            mock_protocol_version_detector_v1,
            mock_ferricel_policy_detector_false,
        );
        let metadata = prepare_metadata(
            PathBuf::from("irrelevant.wasm"),
            file_path,
            backend_detector,
            None,
        );
        assert!(metadata.is_ok());
        assert_eq!(
            metadata.unwrap().protocol_version,
            Some(ProtocolVersion::Unknown)
        );

        Ok(())
    }
}
