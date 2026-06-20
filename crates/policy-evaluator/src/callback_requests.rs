use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use kubewarden_policy_sdk::host_capabilities::{
    SigstoreVerificationInputV1, SigstoreVerificationInputV2,
    crypto_v1::CertificateVerificationRequest,
    kubernetes::{CanIRequest, SubjectAccessReview as KWSubjectAccessReview},
    verification::{KeylessInfo, KeylessPrefixInfo},
};
use serde::{Deserialize, Serialize};
use tokio::{sync::oneshot, time::Instant};

/// Holds the response to a waPC evaluation request
#[derive(Debug, Clone)]
pub struct CallbackResponse {
    /// The data to be given back to the waPC guest
    pub payload: Vec<u8>,
}

/// A request sent by some synchronous code (usually waPC's host_callback)
/// that can be evaluated only inside of asynchronous code.
#[derive(Debug)]
pub struct CallbackRequest {
    /// The actual request to be evaluated
    pub request: CallbackRequestType,
    /// A tokio oneshot channel over which the evaluation response has to be sent
    pub response_channel: oneshot::Sender<Result<CallbackResponse>>,
}

/// Describes the different kinds of request a waPC guest can make to
/// our host.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CallbackRequestType {
    /// Require the computation of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    OciManifestDigest {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the OCI object manifest returned by the registry (be it an image or anything else
    /// that can be stored into an OCI registry)
    OciManifest {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the OCI object manifest and digest returned by the registry (be it an image or anything else
    /// that can be stored into an OCI registry) and the config used to run the container
    OciManifestAndConfig {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
    },

    /// Require the verification of the manifest digest of an OCI object (be
    /// it an image or anything else that can be stored into an OCI registry)
    /// to be signed by Sigstore, using public keys mode
    SigstorePubKeyVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of PEM encoded keys that must have been used to sign the OCI object
        pub_keys: Vec<String>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore, using keyless mode
    SigstoreKeylessVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of keyless signatures that must be found
        keyless: Vec<KeylessInfo>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore using keyless mode, where the passed subject is a URL
    /// prefix of the subject to match
    SigstoreKeylessPrefixVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// List of keyless signatures that must be found
        keyless_prefix: Vec<KeylessPrefixInfo>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object to be
    /// signed by Sigstore using keyless mode and performed in GitHub Actions
    SigstoreGithubActionsVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// owner of the repository. E.g: octocat
        owner: String,
        /// Optional - Repo of the GH Action workflow that signed the artifact. E.g: example-repo
        repo: Option<String>,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Require the verification of the manifest digest of an OCI object
    /// using the user provided certificate
    SigstoreCertificateVerify {
        /// String pointing to the object (e.g.: `registry.testing.lan/busybox:1.0.0`)
        image: String,
        /// PEM encoded certificate used to verify the signature
        certificate: Vec<u8>,
        /// Optional - the certificate chain that is used to verify the provided
        /// certificate. When not specified, the certificate is assumed to be trusted
        certificate_chain: Option<Vec<Vec<u8>>>,
        /// Require the  signature layer to have a Rekor bundle.
        /// Having a Rekor bundle allows further checks to be performed,
        /// like ensuring the signature has been produced during the validity
        /// time frame of the certificate.
        ///
        /// It is recommended to set this value to `true` to have a more secure
        /// verification process.
        require_rekor_bundle: bool,
        /// Optional - Annotations that must have been provided by all signers when they signed the OCI artifact
        annotations: Option<BTreeMap<String, String>>,
    },

    /// Lookup the addresses for a given hostname via DNS
    DNSLookupHost { host: String },

    /// Get all the Kubernetes resources defined inside of the given
    /// namespace
    /// Note: cannot be used with cluster-wide resources
    KubernetesListResourceNamespace {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// Namespace scoping the search
        namespace: String,
        /// A selector to restrict the list of returned objects by their labels.
        /// Defaults to everything if `None`
        label_selector: Option<String>,
        /// A selector to restrict the list of returned objects by their fields.
        /// Defaults to everything if `None`
        field_selector: Option<String>,
        /// Disable the use of a watch-based reflector to serve and cache this query.
        /// By default, list queries are served by a reflector that keeps an in-memory,
        /// continuously updated copy of the matching resources running for the lifetime
        /// of the policy server process.
        /// When set to `true`, the query is performed directly against the Kubernetes API
        /// Server and no reflector is created. This avoids the memory and connection cost
        /// of a long-lived watch for queries that are rarely repeated, at the cost of
        /// hitting the Kubernetes API Server on every call.
        #[serde(default)]
        disable_cache: bool,
        /// A list of fields to include in the response.
        ///
        /// If strictly defined, the host will prune the Kubernetes resource to contain *only*
        /// the specified fields, reducing memory usage and serialization overhead.
        ///
        /// # Behavior
        /// - **Dot Notation:** Use `.` to traverse nested objects (e.g., `metadata.name`).
        /// - **Implicit Arrays:** Paths automatically traverse through arrays. A path like
        ///   `spec.containers.image` will include the `image` field for *every* item in the
        ///   `spec.containers` list.
        /// - **Allow-List:** Fields not specified in the mask are discarded. If the list is
        ///   empty or `None`, the full resource is returned.
        ///
        /// # Example
        /// ```json
        /// [
        ///   "metadata.name",
        ///   "metadata.namespace",
        ///   "spec.containers.image"
        /// ]
        /// ```
        field_masks: Option<BTreeSet<String>>,
    },

    /// Get all the Kubernetes resources defined inside of the given
    /// cluster
    /// Cluster level resources, or resources viewed across all namespaces.
    KubernetesListResourceAll {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// A selector to restrict the list of returned objects by their labels.
        /// Defaults to everything if `None`
        label_selector: Option<String>,
        /// A selector to restrict the list of returned objects by their fields.
        /// Defaults to everything if `None`
        field_selector: Option<String>,
        /// Disable the use of a watch-based reflector to serve and cache this query.
        /// By default, list queries are served by a reflector that keeps an in-memory,
        /// continuously updated copy of the matching resources running for the lifetime
        /// of the policy server process.
        /// When set to `true`, the query is performed directly against the Kubernetes API
        /// Server and no reflector is created. This avoids the memory and connection cost
        /// of a long-lived watch for queries that are rarely repeated, at the cost of
        /// hitting the Kubernetes API Server on every call.
        #[serde(default)]
        disable_cache: bool,
        /// A list of fields to include in the response.
        ///
        /// If strictly defined, the host will prune the Kubernetes resource to contain *only*
        /// the specified fields, reducing memory usage and serialization overhead.
        ///
        /// # Behavior
        /// - **Dot Notation:** Use `.` to traverse nested objects (e.g., `metadata.name`).
        /// - **Implicit Arrays:** Paths automatically traverse through arrays. A path like
        ///   `spec.containers.image` will include the `image` field for *every* item in the
        ///   `spec.containers` list.
        /// - **Allow-List:** Fields not specified in the mask are discarded. If the list is
        ///   empty or `None`, the full resource is returned.
        ///
        /// # Example
        /// ```json
        /// [
        ///   "metadata.name",
        ///   "metadata.namespace",
        ///   "spec.containers.image"
        /// ]
        /// ```
        field_masks: Option<BTreeSet<String>>,
    },

    /// Get a Kubernetes resource with the specified `name`.
    /// Namespaced resources must provide a `namespace` name to scope the search.
    KubernetesGetResource {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// The name of the resource
        name: String,
        /// The namespace used to search namespaced resources. Cluster level resources
        /// must set this parameter to `None`
        namespace: Option<String>,
        /// Disable caching of results obtained from Kubernetes API Server
        /// By default query results are cached for 5 seconds, that might cause
        /// stale data to be returned.
        /// However, making too many requests against the Kubernetes API Server
        /// might cause issues to the cluster
        disable_cache: bool,
        /// A list of fields to include in the response.
        ///
        /// If strictly defined, the host will prune the Kubernetes resource to contain *only*
        /// the specified fields, reducing memory usage and serialization overhead.
        ///
        /// # Behavior
        /// - **Dot Notation:** Use `.` to traverse nested objects (e.g., `metadata.name`).
        /// - **Implicit Arrays:** Paths automatically traverse through arrays. A path like
        ///   `spec.containers.image` will include the `image` field for *every* item in the
        ///   `spec.containers` list.
        /// - **Allow-List:** Fields not specified in the mask are discarded. If the list is
        ///   empty or `None`, the full resource is returned.
        ///
        /// # Example
        /// ```json
        /// [
        ///   "metadata.name",
        ///   "metadata.namespace",
        ///   "spec.containers.image"
        /// ]
        /// ```
        field_masks: Option<BTreeSet<String>>,
    },

    /// Get the plural name of a Kubernetes resource. E.g. `v1/Service` -> `services`
    KubernetesGetResourcePluralName {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
    },

    /// Checks if the data of the reflector tracking this query changed since the given instant
    HasKubernetesListResourceAllResultChangedSinceInstant {
        /// apiVersion of the resource (v1 for core group, groupName/groupVersions for other).
        api_version: String,
        /// Singular PascalCase name of the resource
        kind: String,
        /// A selector to restrict the list of returned objects by their labels.
        /// Defaults to everything if `None`
        label_selector: Option<String>,
        /// A selector to restrict the list of returned objects by their fields.
        /// Defaults to everything if `None`
        field_selector: Option<String>,
        /// A list of fields to include in the response.
        ///
        /// If strictly defined, the host will prune the Kubernetes resource to contain *only*
        /// the specified fields, reducing memory usage and serialization overhead.
        ///
        /// # Behavior
        /// - **Dot Notation:** Use `.` to traverse nested objects (e.g., `metadata.name`).
        /// - **Implicit Arrays:** Paths automatically traverse through arrays. A path like
        ///   `spec.containers.image` will include the `image` field for *every* item in the
        ///   `spec.containers` list.
        /// - **Allow-List:** Fields not specified in the mask are discarded. If the list is
        ///   empty or `None`, the full resource is returned.
        ///
        /// # Example
        /// ```json
        /// [
        ///   "metadata.name",
        ///   "metadata.namespace",
        ///   "spec.containers.image"
        /// ]
        /// ```
        field_masks: Option<BTreeSet<String>>,
        /// The instant in time to compare the last change of the resources
        #[serde(with = "tokio_instant_serializer")]
        since: Instant,
    },

    /// Check if the user can permissions to perform some operations
    KubernetesCanI {
        /// Describe the set of parameters used by the `can_i` function. The values in this struct
        /// will be used to build the SubjectAccessReview resources sent to the Kubernetes API to
        /// verify if the user is allowed to perform some operation
        request: KWSubjectAccessReview,

        /// Disable caching of results obtained from Kubernetes API Server
        /// By default query results are cached for 5 seconds, that might cause
        /// stale data to be returned.
        /// However, making too many requests against the Kubernetes API Server
        /// might cause issues to the cluster
        ///
        /// This field is also defined in the `KWSubjectAccessReviewRequest`. However, we duplicate
        /// the value here to keep the same pattern used by the other Kubernetes requests
        disable_cache: bool,
    },

    /// Check if the given certificate is trusted by the certificate chain and if
    /// it is not expired
    CryptoIsCertificateTrusted {
        /// CertificateVerificationRequest holds information about a certificate and
        /// a chain to validate it with.
        request: CertificateVerificationRequest,
    },
}
mod tokio_instant_serializer {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;
    use tokio::time::Instant;

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = instant.elapsed();
        duration.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let duration = Duration::deserialize(deserializer)?;
        let now = Instant::now();
        let instant = now
            .checked_sub(duration)
            .ok_or_else(|| Error::custom("Error checked_sub"))?;
        Ok(instant)
    }
}

impl From<SigstoreVerificationInputV2> for CallbackRequestType {
    fn from(val: SigstoreVerificationInputV2) -> Self {
        match val {
            SigstoreVerificationInputV2::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            } => CallbackRequestType::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            } => CallbackRequestType::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreKeylessPrefixVerify {
                image,
                keyless_prefix,
                annotations,
            } => CallbackRequestType::SigstoreKeylessPrefixVerify {
                image,
                keyless_prefix,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreGithubActionsVerify {
                image,
                owner,
                repo,
                annotations,
            } => CallbackRequestType::SigstoreGithubActionsVerify {
                image,
                owner,
                repo,
                annotations,
            },
            SigstoreVerificationInputV2::SigstoreCertificateVerify {
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            } => CallbackRequestType::SigstoreCertificateVerify {
                image,
                certificate,
                certificate_chain,
                require_rekor_bundle,
                annotations,
            },
        }
    }
}

impl From<SigstoreVerificationInputV1> for CallbackRequestType {
    fn from(val: SigstoreVerificationInputV1) -> Self {
        match val {
            SigstoreVerificationInputV1::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            } => CallbackRequestType::SigstorePubKeyVerify {
                image,
                pub_keys,
                annotations,
            },
            SigstoreVerificationInputV1::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            } => CallbackRequestType::SigstoreKeylessVerify {
                image,
                keyless,
                annotations,
            },
        }
    }
}

impl From<kubewarden_policy_sdk::host_capabilities::kubernetes::ListResourcesByNamespaceRequest>
    for CallbackRequestType
{
    fn from(
        req: kubewarden_policy_sdk::host_capabilities::kubernetes::ListResourcesByNamespaceRequest,
    ) -> Self {
        CallbackRequestType::KubernetesListResourceNamespace {
            api_version: req.api_version,
            kind: req.kind,
            namespace: req.namespace,
            label_selector: req.label_selector,
            field_selector: req.field_selector,
            disable_cache: false,
            field_masks: req.field_masks,
        }
    }
}

impl From<kubewarden_policy_sdk::host_capabilities::kubernetes::ListAllResourcesRequest>
    for CallbackRequestType
{
    fn from(
        req: kubewarden_policy_sdk::host_capabilities::kubernetes::ListAllResourcesRequest,
    ) -> Self {
        CallbackRequestType::KubernetesListResourceAll {
            api_version: req.api_version,
            kind: req.kind,
            label_selector: req.label_selector,
            field_selector: req.field_selector,
            disable_cache: false,
            field_masks: req.field_masks,
        }
    }
}

impl From<kubewarden_policy_sdk::host_capabilities::kubernetes::GetResourceRequest>
    for CallbackRequestType
{
    fn from(req: kubewarden_policy_sdk::host_capabilities::kubernetes::GetResourceRequest) -> Self {
        CallbackRequestType::KubernetesGetResource {
            api_version: req.api_version,
            kind: req.kind,
            name: req.name,
            namespace: req.namespace,
            disable_cache: req.disable_cache,
            field_masks: req.field_masks,
        }
    }
}

impl From<CanIRequest> for CallbackRequestType {
    fn from(req: CanIRequest) -> Self {
        CallbackRequestType::KubernetesCanI {
            disable_cache: req.disable_cache,
            request: req.subject_access_review,
        }
    }
}

impl From<CertificateVerificationRequest> for CallbackRequestType {
    fn from(request: CertificateVerificationRequest) -> Self {
        CallbackRequestType::CryptoIsCertificateTrusted { request }
    }
}
