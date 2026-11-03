use std::{collections::BTreeMap, str::FromStr};

use email_address::*;
use policy_fetcher::oci_client::{ParseError, Reference};
use semver::Version;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::{
    constants::{
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_CONTEXTAWARE_RESOURCES,
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_MUTATION, ARTIFACTHUB_ANNOTATION_KUBEWARDEN_QUESTIONSUI,
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RESOURCES, ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RULES,
        ARTIFACTHUB_ANNOTATION_RANCHER_HIDDENUI, KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME,
        KUBEWARDEN_ANNOTATION_ARTIFACTHUB_HIDDENUI, KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS,
        KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES, KUBEWARDEN_ANNOTATION_GITHUB_RELEASE_TAG,
        KUBEWARDEN_ANNOTATION_POLICY_AUTHOR, KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION,
        KUBEWARDEN_ANNOTATION_POLICY_LICENSE, KUBEWARDEN_ANNOTATION_POLICY_OCIURL,
        KUBEWARDEN_ANNOTATION_POLICY_SOURCE, KUBEWARDEN_ANNOTATION_POLICY_TITLE,
        KUBEWARDEN_ANNOTATION_POLICY_URL, KUBEWARDEN_ANNOTATION_POLICY_VERSION,
    },
    errors::ArtifactHubError,
    policy_metadata::Metadata,
};

pub type Result<T> = std::result::Result<T, ArtifactHubError>;

/// Partial implementation of the format of artifacthub-pkg.yml file as defined
/// in
/// <https://github.com/artifacthub/hub/blob/master/docs/metadata/artifacthub-pkg.yml>
/// and
/// <https://artifacthub.io/docs/topics/repositories/kubewarden-policies>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactHubPkg {
    /// Semver version of the policy, e.g: "0.2.0"
    version: Version,
    /// ArtifactHub package name, e.g: verify-image-signatures
    name: String,
    /// Display name, e.g: Verify Image Signatures
    display_name: String,
    /// Time at creation in RFC3339 format, e.g: 2023-01-19T14:46:21+02:00
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    /// One-line description of policy
    description: String,
    /// License in SPDX format, e.g: Apache-2.0
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<String>,
    /// Home URL of policy (source repository)
    /// E.g:  <https://github.com/kubewarden/verify-image-signatures>
    #[serde(rename = "homeURL", skip_serializing_if = "Option::is_none")]
    home_url: Option<Url>,
    /// List of images of the ArtifactHub package
    /// E.g: ("policy", <url to wasm module>)
    #[serde(skip_serializing_if = "Option::is_none")]
    containers_images: Option<Vec<ContainerImage>>,
    /// List of keywords. E.g: ["pod", "signature", "sigstore"]
    #[serde(skip_serializing_if = "Option::is_none")]
    keywords: Option<Vec<String>>,
    /// List of links in tuple (name, url) format
    /// E.g: {"policy", <url>}, {"source", <url>}
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<Link>>,
    /// Install instructions
    #[serde(skip_serializing_if = "Option::is_none")]
    install: Option<String>,
    /// List of maintainers in tuple (name, email) format
    #[serde(skip_serializing_if = "Option::is_none")]
    maintainers: Option<Vec<Maintainer>>,
    /// Provider of policy, for us, hardcoded to {name: "kubewarden"}
    provider: Provider,
    /// Recommendations of policy, for us, hardcoded to:
    /// [{url: <url of kubewarden controller repo>}]
    recommendations: Vec<Recommendation>,
    /// List of annotations. Contains kubewarden-specific annotations
    annotations: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct ContainerImage {
    /// name is always "policy"
    name: ConstContainerImageName,
    /// URL of the policy wasm module
    /// E.g: ghcr.io/kubewarden/policies/verify-image-signatures:v0.2.1
    image: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
enum ConstContainerImageName {
    #[serde(rename = "policy")]
    Policy,
}

/// Link, of either the policy wasm module or the policy source repository
/// Example:
///  - name: policy
///    url: https://github.com/kubewarden/verify-image-signatures/releases/download/v0.2.1/policy.wasm
///  - name: source
///    url: https://github.com/kubewarden/verify-image-signatures
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
struct Link {
    /// Either "policy" or "source"
    name: ConstLinkName,
    /// Either URL of policy repository or URL of policy wasm module
    url: Url,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
enum ConstLinkName {
    #[serde(rename = "policy")]
    Policy,
    #[serde(rename = "source")]
    Source,
}

/// Hardcoded recommendation with url of kubewarden controller
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Recommendation {
    url: String,
}
impl Default for Recommendation {
    fn default() -> Self {
        Recommendation {
            url: String::from(
                "https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller",
            ),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Maintainer {
    name: String,
    email: String,
}

/// Hardcoded provider with "kubewarden"
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Provider {
    name: String,
}
impl Default for Provider {
    fn default() -> Self {
        Provider {
            name: String::from("kubewarden"),
        }
    }
}

impl ArtifactHubPkg {
    pub fn from_metadata(
        metadata: &Metadata,
        created_at: OffsetDateTime,
        questions: Option<&str>,
    ) -> Result<Self> {
        // validate inputs
        let metadata_annots = metadata
            .annotations
            .as_ref()
            .ok_or(ArtifactHubError::NoAnnotations)?;
        if metadata_annots.is_empty() {
            return Err(ArtifactHubError::NoAnnotations);
        }
        let version = metadata_annots
            .get(KUBEWARDEN_ANNOTATION_POLICY_VERSION)
            .ok_or(ArtifactHubError::MissingAnnotation(String::from(
                KUBEWARDEN_ANNOTATION_POLICY_VERSION,
            )))?;
        let gh_release_tag = metadata_annots
            .get(KUBEWARDEN_ANNOTATION_GITHUB_RELEASE_TAG)
            .map(|annotation| annotation.as_str());

        let semver_version = Version::parse(version)
            .map_err(|e| ArtifactHubError::NoSemverVersion(e.to_string()))?;
        if questions.filter(|&q| q.is_empty()).is_some() {
            return Err(ArtifactHubError::EmptyQuestionsUI);
        }

        // build struct
        let name = parse_name(metadata_annots)?;
        let display_name = parse_display_name(metadata_annots)?;
        let description = parse_description(metadata_annots)?;
        let home_url = parse_home_url(metadata_annots)?;
        let containers_images = parse_containers_images(metadata_annots, &semver_version)?;
        let keywords = parse_keywords(metadata_annots)?;
        let links = parse_links(metadata_annots, &semver_version, gh_release_tag)?;
        let install = parse_oci_url(metadata_annots, &semver_version)?.map(compose_install);
        let maintainers = parse_maintainers(metadata_annots)?;
        let annotations = parse_annotations(metadata_annots, metadata, questions)?;

        let artifacthubpkg = ArtifactHubPkg {
            version: semver_version,
            name,
            display_name,
            created_at,
            description,
            license: metadata_annots
                .get(KUBEWARDEN_ANNOTATION_POLICY_LICENSE)
                .cloned(),
            home_url,
            containers_images,
            keywords,
            links,
            install,
            maintainers,
            provider: Default::default(),
            recommendations: vec![Recommendation::default()],
            annotations,
        };

        Ok(artifacthubpkg)
    }
}

fn parse_name(metadata_annots: &BTreeMap<String, String>) -> Result<String> {
    metadata_annots
        .get(KUBEWARDEN_ANNOTATION_POLICY_TITLE)
        .ok_or_else(|| {
            ArtifactHubError::MissingAnnotation(String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE))
        })
        .cloned()
}

fn parse_display_name(metadata_annots: &BTreeMap<String, String>) -> Result<String> {
    metadata_annots
        .get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME)
        .ok_or_else(|| {
            ArtifactHubError::MissingAnnotation(String::from(
                KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME,
            ))
        })
        .cloned()
}

fn parse_description(metadata_annots: &BTreeMap<String, String>) -> Result<String> {
    metadata_annots
        .get(KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION)
        .ok_or_else(|| {
            ArtifactHubError::MissingAnnotation(String::from(
                KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION,
            ))
        })
        .cloned()
}

fn parse_home_url(metadata_annots: &BTreeMap<String, String>) -> Result<Option<Url>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_URL) {
        Some(s) => {
            let url = Url::parse(s).map_err(|e| ArtifactHubError::MalformedURL {
                annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_URL),
                error: e.to_string(),
            })?;
            Ok(Some(url))
        }
        None => Ok(None),
    }
}

fn parse_oci_url(
    metadata_annots: &BTreeMap<String, String>,
    version: &Version,
) -> Result<Option<String>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_OCIURL) {
        Some(s) => {
            let oci_url: Reference =
                format!("{}:v{}", s, version)
                    .parse()
                    .map_err(|e: ParseError| ArtifactHubError::MalformedURL {
                        annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                        error: e.to_string(),
                    })?;
            Ok(Some(oci_url.to_string()))
        }
        None => Ok(None),
    }
}

fn parse_containers_images(
    metadata_annots: &BTreeMap<String, String>,
    version: &Version,
) -> Result<Option<Vec<ContainerImage>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_OCIURL) {
        Some(s) => {
            let oci_url: Reference =
                format!("{s}:v{version}").parse().map_err(|e: ParseError| {
                    ArtifactHubError::MalformedURL {
                        annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                        error: e.to_string(),
                    }
                })?;
            let container_images = vec![ContainerImage {
                name: ConstContainerImageName::Policy,
                image: oci_url.to_string(),
            }];
            Ok(Some(container_images))
        }
        None => Err(ArtifactHubError::MissingAnnotation(String::from(
            KUBEWARDEN_ANNOTATION_POLICY_OCIURL,
        ))),
    }
}

/// parses the value of annotation KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS of
/// csv of keywords into a vector of keywords, making sure is well formed
fn parse_keywords(metadata_annots: &BTreeMap<String, String>) -> Result<Option<Vec<String>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS) {
        Some(s) => {
            let csv = s
                .split(',')
                .map(|s| s.trim_start_matches(' '))
                .map(|s| s.trim_end_matches(' '))
                .map(str::to_string)
                .collect::<Vec<String>>();
            if csv.clone().into_iter().any(|word| word.is_empty()) {
                Err(ArtifactHubError::MalformedCSV(String::from(
                    KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS,
                )))
            } else {
                Ok(Some(csv))
            }
        }
        None => Ok(None),
    }
}

/// parses the value of annotation KUBEWARDEN_ANNOTATION_POLICY_SOURCE
/// into a vector of Link, making sure is well formed
fn parse_links(
    metadata_annots: &BTreeMap<String, String>,
    version: &Version,
    gh_release_tag: Option<&str>,
) -> Result<Option<Vec<Link>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_SOURCE) {
        Some(s) => {
            let policy_source = Url::parse(s).map_err(|e| ArtifactHubError::MalformedURL {
                annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
                error: e.to_string(),
            })?;
            match policy_source.host_str() == Some("github.com") {
                true => {
                    let release = if let Some(tag) = gh_release_tag {
                        url::form_urlencoded::byte_serialize(tag.as_bytes()).collect::<String>()
                    } else {
                        format!("v{}", version)
                    };

                    let url = Url::parse(
                        format!(
                            "{}/releases/download/{}/policy.wasm",
                            policy_source.as_str(),
                            release
                        )
                        .as_str(),
                    )
                    .map_err(|e| ArtifactHubError::MalformedURL {
                        annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
                        error: e.to_string(),
                    })?;
                    Ok(Some(vec![
                        Link {
                            name: ConstLinkName::Policy,
                            url,
                        },
                        Link {
                            name: ConstLinkName::Source,
                            url: policy_source,
                        },
                    ]))
                }
                false => Ok(Some(vec![Link {
                    name: ConstLinkName::Source,
                    url: policy_source,
                }])),
            }
        }
        None => Ok(None),
    }
}

fn compose_install(oci_url: String) -> String {
    format!(
        r#"The policy can be obtained using [kwctl](https://docs.kubewarden.io/howtos/install-kwctl):
```console
kwctl pull {oci_url}
```
Then, generate the policy manifest and tune it to your liking. For example:
```console
kwctl scaffold manifest -t ClusterAdmissionPolicy registry://{oci_url}
```
"#
    )
}

// parses the value of annotation KUBEWARDEN_ANNOTATION_POLICY_AUTHOR into a
// vector of maintainers, making sure the csv input and emails are well formed
fn parse_maintainers(
    metadata_annots: &BTreeMap<String, String>,
) -> Result<Option<Vec<Maintainer>>> {
    match metadata_annots.get(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR) {
        Some(s) => {
            // name-addr https://www.rfc-editor.org/rfc/rfc5322#section-3.4
            let mut maintainers: Vec<Maintainer> = vec![];
            let to = format!("To: {s}");
            let msg = mail_parser::MessageParser::new()
                .parse(to.as_bytes())
                .ok_or(ArtifactHubError::MalformedCSVEmail(String::from(
                    KUBEWARDEN_ANNOTATION_POLICY_AUTHOR,
                )))?;

            let addresses = msg
                .to()
                .ok_or(ArtifactHubError::MalformedCSVEmail(String::from(
                    KUBEWARDEN_ANNOTATION_POLICY_AUTHOR,
                )))?;

            for mailbox in addresses.mailboxes() {
                let email =
                    EmailAddress::from_str(mailbox.address().unwrap_or_default()).map_err(|e| {
                        ArtifactHubError::MalformedEmail {
                            annot: String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
                            error: e.to_string(),
                        }
                    })?;
                maintainers.push(Maintainer {
                    name: mailbox.name().unwrap_or_default().to_owned(),
                    email: email.to_string(),
                });
            }

            Ok(Some(maintainers))
        }
        None => Ok(None),
    }
}

fn parse_annotations(
    metadata_annots: &BTreeMap<String, String>,
    metadata: &Metadata,
    questions: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    // add required annotations
    let mut annotations: BTreeMap<String, String> = BTreeMap::new();
    annotations.insert(
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_MUTATION.to_string(),
        metadata.mutating.to_string(),
    );
    if !metadata.context_aware_resources.is_empty() {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_KUBEWARDEN_CONTEXTAWARE_RESOURCES.to_string(),
            serde_yaml::to_string(&metadata.context_aware_resources)
                .expect("cannot convert context_aware_resources to yaml"),
        );
    }
    annotations.insert(
        ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RULES.to_string(),
        serde_yaml::to_string(&metadata.rules).expect("cannot convert rules to yaml"),
    );

    // add optional annotations
    if let Some(s) = questions {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_KUBEWARDEN_QUESTIONSUI.to_string(),
            s.to_string(),
        );
    };
    if let Some(string_bool) = metadata_annots.get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_HIDDENUI) {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_RANCHER_HIDDENUI.to_string(),
            FromStr::from_str(string_bool).map_err(|_| {
                ArtifactHubError::MalformedBoolString(String::from(
                    KUBEWARDEN_ANNOTATION_ARTIFACTHUB_HIDDENUI,
                ))
            })?,
        );
    };
    if let Some(s) = metadata_annots.get(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES) {
        annotations.insert(
            ARTIFACTHUB_ANNOTATION_KUBEWARDEN_RESOURCES.to_string(),
            s.to_string(),
        );
    };

    Ok(annotations)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use super::*;
    use crate::policy_metadata::{ContextAwareResource, PolicyType};

    fn mock_metadata_with_minimum_required() -> Metadata {
        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(BTreeMap::from([
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_VERSION),
                    String::from("0.2.1"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
                    String::from("verify-image-signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME),
                    String::from("Verify Image Signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION),
                    String::from("A description"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                    String::from("ghcr.io/ocirepo/namespace/verify-image-signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES),
                    String::from("Pod, Deployment"),
                ),
            ])),
            mutating: false,
            background_audit: true,
            context_aware_resources: BTreeSet::new(),
            execution_mode: Default::default(),
            policy_type: PolicyType::Kubernetes,
            minimum_kubewarden_version: None,
            host_capabilities: None,
        }
    }

    fn mock_metadata_with_all() -> Metadata {
        let mut context_aware_resources: BTreeSet<ContextAwareResource> = BTreeSet::new();
        context_aware_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
        });

        Metadata {
            protocol_version: None,
            rules: vec![],
            annotations: Some(BTreeMap::from([
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_VERSION),
                    String::from("0.2.1"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_TITLE),
                    String::from("verify-image-signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_DESCRIPTION),
                    String::from("A description"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
                    String::from("Tux Tuxedo <tux@example.com>, Pidgin <pidgin@example.com>"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_URL),
                    String::from("https://github.com/home"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL),
                    String::from("ghcr.io/ocirepo/namespace/verify-image-signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
                    String::from("https://github.com/repo"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_POLICY_LICENSE),
                    String::from("Apache-2.0"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_RESOURCES),
                    String::from("Pod, Deployment"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_DISPLAYNAME),
                    String::from("Verify Image Signatures"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
                    String::from("pod, signature"),
                ),
                (
                    String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_HIDDENUI),
                    String::from("true"),
                ),
            ])),
            mutating: false,
            background_audit: true,
            context_aware_resources,
            execution_mode: Default::default(),
            minimum_kubewarden_version: None,
            policy_type: Default::default(),
            host_capabilities: None,
        }
    }

    #[test]
    fn artifacthubpkg_validate_inputs() -> Result<()> {
        // check annotations None
        let arthub =
            ArtifactHubPkg::from_metadata(&Metadata::default(), OffsetDateTime::UNIX_EPOCH, None);
        assert_eq!(arthub.unwrap_err(), ArtifactHubError::NoAnnotations);

        // check annotations empty
        let metadata = Metadata {
            annotations: Some(BTreeMap::from([])),
            ..Default::default()
        };
        let arthub = ArtifactHubPkg::from_metadata(&metadata, OffsetDateTime::UNIX_EPOCH, None);
        assert_eq!(arthub.unwrap_err(), ArtifactHubError::NoAnnotations);

        // check version annotations is missing
        let mut annotations = mock_metadata_with_minimum_required().annotations.unwrap();
        annotations.remove(KUBEWARDEN_ANNOTATION_POLICY_VERSION);
        let metadata = Metadata {
            annotations: Some(annotations),
            ..Default::default()
        };
        let arthub = ArtifactHubPkg::from_metadata(&metadata, OffsetDateTime::UNIX_EPOCH, None);
        assert_eq!(
            arthub.unwrap_err(),
            ArtifactHubError::MissingAnnotation(String::from(KUBEWARDEN_ANNOTATION_POLICY_VERSION))
        );

        // check version is semver
        let mut annotations = mock_metadata_with_minimum_required().annotations.unwrap();
        annotations.insert(
            KUBEWARDEN_ANNOTATION_POLICY_VERSION.to_string(),
            "not-semver".to_string(),
        );

        let arthub = ArtifactHubPkg::from_metadata(
            &Metadata {
                annotations: Some(annotations),
                ..Default::default()
            },
            OffsetDateTime::UNIX_EPOCH,
            None,
        );
        assert!(matches!(
            arthub.unwrap_err(),
            ArtifactHubError::NoSemverVersion(_)
        ));

        // check questions is some and not empty
        let arthub = ArtifactHubPkg::from_metadata(
            &mock_metadata_with_minimum_required(),
            OffsetDateTime::UNIX_EPOCH,
            Some(""),
        );
        assert_eq!(arthub.unwrap_err(), ArtifactHubError::EmptyQuestionsUI);

        Ok(())
    }

    #[test]
    fn check_parse_keywords() -> Result<()> {
        let keywords_annot = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
            String::from(" foo,bar, faz fiz, baz"),
        )]);
        let keywords_annot_empty = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
            String::from(""),
        )]);
        let keywords_annot_commas = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS),
            String::from("foo,,bar"),
        )]);

        assert_eq!(
            parse_keywords(&keywords_annot).unwrap(),
            Some(
                vec!["foo", "bar", "faz fiz", "baz"]
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            )
        );
        assert_eq!(
            parse_keywords(&keywords_annot_empty).unwrap_err(),
            ArtifactHubError::MalformedCSV(String::from(
                KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS
            ))
        );
        assert_eq!(
            parse_keywords(&keywords_annot_commas).unwrap_err(),
            ArtifactHubError::MalformedCSV(String::from(
                KUBEWARDEN_ANNOTATION_ARTIFACTHUB_KEYWORDS
            ))
        );
        Ok(())
    }

    #[test]
    fn check_parse_links() -> Result<()> {
        let semver_version = Version::parse("0.2.1").unwrap();
        let source_annot = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
            String::from("https://github.com/repo"),
        )]);
        let source_annot_not_github = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
            String::from("https://notgithub.com/repo"),
        )]);
        let source_annot_badurl = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_SOURCE),
            String::from("@&*foo"),
        )]);

        assert_eq!(
            parse_links(&source_annot, &semver_version, None).unwrap(),
            Some(vec![
                Link {
                    name: ConstLinkName::Policy,
                    url: Url::parse("https://github.com/repo/releases/download/v0.2.1/policy.wasm")
                        .unwrap(),
                },
                Link {
                    name: ConstLinkName::Source,
                    url: Url::parse("https://github.com/repo").unwrap(),
                }
            ])
        );
        assert_eq!(
            parse_links(&source_annot, &semver_version, Some("SomePolicy/v0.2.1")).unwrap(),
            Some(vec![
                Link {
                    name: ConstLinkName::Policy,
                    url: Url::parse(
                        "https://github.com/repo/releases/download/SomePolicy%2Fv0.2.1/policy.wasm"
                    )
                    .unwrap(),
                },
                Link {
                    name: ConstLinkName::Source,
                    url: Url::parse("https://github.com/repo").unwrap(),
                }
            ])
        );
        assert_eq!(
            parse_links(&source_annot_not_github, &semver_version, None).unwrap(),
            Some(vec![Link {
                name: ConstLinkName::Source,
                url: Url::parse("https://notgithub.com/repo").unwrap(),
            }])
        );
        assert!(matches!(
            parse_links(&source_annot_badurl, &semver_version, None).unwrap_err(),
            ArtifactHubError::MalformedURL { .. }
        ));

        Ok(())
    }

    #[test]
    fn check_parse_maintainers() -> Result<()> {
        let author_annot = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Tux Tuxedo <tux@example.com>, Pidgin <pidgin@example.com>"),
        )]);
        let author_annot_empty = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from(""),
        )]);
        let author_annot_commas = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Foo <foo@example.com>,,Bar <bar@example.com>"),
        )]);
        let author_annot_nameemail = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Foo missing@chevrons.com, Bar <bar@example.com>"),
        )]);
        let author_annot_bademail = BTreeMap::from([(
            String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR),
            String::from("Bar <#$%#$%>"),
        )]);

        assert_eq!(
            parse_maintainers(&author_annot).unwrap(),
            Some(vec![
                Maintainer {
                    name: String::from("Tux Tuxedo"),
                    email: String::from("tux@example.com"),
                },
                Maintainer {
                    name: String::from("Pidgin"),
                    email: String::from("pidgin@example.com"),
                }
            ])
        );
        assert_eq!(
            parse_maintainers(&author_annot_empty).unwrap_err(),
            ArtifactHubError::MalformedCSVEmail(String::from(KUBEWARDEN_ANNOTATION_POLICY_AUTHOR))
        );

        assert_eq!(
            parse_maintainers(&author_annot_commas).unwrap(),
            Some(vec![
                Maintainer {
                    name: String::from("Foo"),
                    email: String::from("foo@example.com"),
                },
                Maintainer {
                    name: String::from("Bar"),
                    email: String::from("bar@example.com"),
                }
            ])
        );
        assert!(matches!(
            parse_maintainers(&author_annot_nameemail).unwrap_err(),
            ArtifactHubError::MalformedEmail { .. }
        ));
        assert!(matches!(
            parse_maintainers(&author_annot_bademail).unwrap_err(),
            ArtifactHubError::MalformedEmail { .. }
        ));

        Ok(())
    }

    #[test]
    fn artifacthubpkg_missing_required() -> Result<()> {
        let semver_version = Version::parse("0.2.1").unwrap();
        let invalid_annotations = BTreeMap::from([(String::from("foo"), String::from("bar"))]);

        assert!(parse_name(&invalid_annotations).is_err());
        assert!(parse_display_name(&invalid_annotations).is_err());
        assert_eq!(
            parse_containers_images(&invalid_annotations, &semver_version).unwrap_err(),
            ArtifactHubError::MissingAnnotation(String::from(KUBEWARDEN_ANNOTATION_POLICY_OCIURL))
        );

        Ok(())
    }

    #[test]
    fn artifacthubpkg_with_minimum_required() -> Result<()> {
        let artif = ArtifactHubPkg::from_metadata(
            &mock_metadata_with_minimum_required(),
            OffsetDateTime::UNIX_EPOCH,
            None,
        )
        .unwrap();
        let expected = json!({
            "version": "0.2.1",
            "name": "verify-image-signatures",
            "displayName": "Verify Image Signatures",
            "createdAt": "1970-01-01T00:00:00Z",
            "description": "A description",
            "annotations": {
                "kubewarden/mutation": "false",
                "kubewarden/rules": "[]\n",
                "kubewarden/resources": "Pod, Deployment",
            },
            "install": r#"The policy can be obtained using [kwctl](https://docs.kubewarden.io/howtos/install-kwctl):
```console
kwctl pull ghcr.io/ocirepo/namespace/verify-image-signatures:v0.2.1
```
Then, generate the policy manifest and tune it to your liking. For example:
```console
kwctl scaffold manifest -t ClusterAdmissionPolicy registry://ghcr.io/ocirepo/namespace/verify-image-signatures:v0.2.1
```
"#,
            "containersImages": [
            {
                "name": "policy",
                "image": "ghcr.io/ocirepo/namespace/verify-image-signatures:v0.2.1",
            },
            ],
            "provider": {
               "name":  "kubewarden"
            },
            "recommendations": [
                {
                    "url": "https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller"
                }
            ],
        });

        let actual = serde_json::to_value(&artif).unwrap();
        assert_json_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn artifacthubpkg_with_all() -> Result<()> {
        let artif = ArtifactHubPkg::from_metadata(
            &mock_metadata_with_all(),
            OffsetDateTime::UNIX_EPOCH,
            Some("questions contents"),
        )
        .unwrap();
        let expected = json!({
            "version": "0.2.1",
            "name": "verify-image-signatures",
            "displayName": "Verify Image Signatures",
            "createdAt": "1970-01-01T00:00:00Z",
            "description": "A description",
            "license": "Apache-2.0",
            "homeURL": "https://github.com/home",
            "containersImages": [
            {
                "name": "policy",
                "image": "ghcr.io/ocirepo/namespace/verify-image-signatures:v0.2.1",
            },
            ],
            "keywords": [
                "pod",
                "signature"
            ],
            "links": [
            {
                "name": "policy",
                "url": "https://github.com/repo/releases/download/v0.2.1/policy.wasm"
            },
            {
                "name": "source",
                "url": "https://github.com/repo"
            }
            ],
            "install": r#"The policy can be obtained using [kwctl](https://docs.kubewarden.io/howtos/install-kwctl):
```console
kwctl pull ghcr.io/ocirepo/namespace/verify-image-signatures:v0.2.1
```
Then, generate the policy manifest and tune it to your liking. For example:
```console
kwctl scaffold manifest -t ClusterAdmissionPolicy registry://ghcr.io/ocirepo/namespace/verify-image-signatures:v0.2.1
```
"#,

            "maintainers": [
            {
                "name": "Tux Tuxedo",
                "email": "tux@example.com"
            },
            {
                "name": "Pidgin",
                "email": "pidgin@example.com"
            }
            ],
            "provider": {
                "name": "kubewarden"
            },
            "recommendations": [
                {
                    "url": "https://artifacthub.io/packages/helm/kubewarden/kubewarden-controller"
                }
            ],
            "annotations": {
                "kubewarden/resources": "Pod, Deployment",
                "kubewarden/mutation": "false",
                "kubewarden/contextAwareResources": "- apiVersion: v1\n  kind: Pod\n",
                "kubewarden/hidden-ui": "true",
                "kubewarden/rules": "[]\n",
                "kubewarden/questions-ui": "questions contents"
            }
        });

        let actual = serde_json::to_value(&artif).unwrap();
        assert_json_eq!(expected, actual);
        Ok(())
    }
}
