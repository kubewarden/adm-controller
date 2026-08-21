use std::collections::BTreeSet;

mod client;
pub(crate) mod field_mask;
mod reflector;

use anyhow::{Result, anyhow};
use cached::macros::cached;
use k8s_openapi::api::authorization::v1::SubjectAccessReviewStatus;
use kube::core::ObjectList;
use kubewarden_policy_sdk::host_capabilities::kubernetes::SubjectAccessReview as KWSubjectAccessReview;
use serde::Serialize;

pub(crate) use client::Client;

#[derive(Eq, Hash, PartialEq)]
struct ApiVersionKind {
    api_version: String,
    kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct KubeResource {
    pub resource: kube::api::ApiResource,
    pub namespaced: bool,
}

pub(crate) async fn list_resources_by_namespace(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    namespace: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
    field_masks: Option<BTreeSet<String>>,
) -> Result<cached::Return<ObjectList<kube::core::DynamicObject>>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    client
        .unwrap()
        .list_resources_by_namespace(
            api_version,
            kind,
            namespace,
            label_selector,
            field_selector,
            field_masks,
        )
        .await
        .map(cached::Return::new)
}

pub(crate) async fn list_resources_all(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
    field_masks: Option<BTreeSet<String>>,
) -> Result<cached::Return<ObjectList<kube::core::DynamicObject>>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    client
        .unwrap()
        .list_resources_all(
            api_version,
            kind,
            label_selector,
            field_selector,
            field_masks,
        )
        .await
        .map(cached::Return::new)
}

/// Like [`list_resources_by_namespace`], but performs a direct, one-shot call to the
/// Kubernetes API Server instead of relying on a reflector.
pub(crate) async fn list_resources_by_namespace_direct(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    namespace: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
    field_masks: Option<BTreeSet<String>>,
) -> Result<cached::Return<ObjectList<kube::core::DynamicObject>>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    client
        .unwrap()
        .list_resources_by_namespace_direct(
            api_version,
            kind,
            namespace,
            label_selector,
            field_selector,
            field_masks,
        )
        .await
        .map(cached::Return::new)
}

/// Like [`list_resources_all`], but performs a direct, one-shot call to the
/// Kubernetes API Server instead of relying on a reflector.
pub(crate) async fn list_resources_all_direct(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
    field_masks: Option<BTreeSet<String>>,
) -> Result<cached::Return<ObjectList<kube::core::DynamicObject>>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    client
        .unwrap()
        .list_resources_all_direct(
            api_version,
            kind,
            label_selector,
            field_selector,
            field_masks,
        )
        .await
        .map(cached::Return::new)
}

pub(crate) async fn get_resource(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    name: &str,
    namespace: Option<&str>,
) -> Result<cached::Return<kube::core::DynamicObject>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly"));
    }

    client
        .unwrap()
        .get_resource(api_version, kind, name, namespace)
        .await
        .map(|value| cached::Return {
            was_cached: false,
            value,
        })
}

#[cached(
    ttl = 5,
    sync_writes = "default",
    key = "String",
    convert = r#"{ format!("get_resource_cached({},{}),{},{:?}", api_version, kind, name, namespace) }"#,
    with_cached_flag = true
)]
pub(crate) async fn get_resource_cached(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    name: &str,
    namespace: Option<&str>,
) -> Result<cached::Return<kube::core::DynamicObject>> {
    get_resource(client, api_version, kind, name, namespace).await
}

pub(crate) async fn get_resource_plural_name(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
) -> Result<cached::Return<String>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly"));
    }

    client
        .unwrap()
        .get_resource_plural_name(api_version, kind)
        .await
        .map(|value| cached::Return {
            // this is always cached, because the client builds an overview of
            // the cluster resources at bootstrap time
            was_cached: true,
            value,
        })
}

/// Check if the results of the "list all resources" query have changed since the provided instant
/// This is done by querying the reflector that keeps track of this query
pub(crate) async fn has_list_resources_all_result_changed_since_instant(
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    label_selector: Option<String>,
    field_selector: Option<String>,
    field_masks: Option<BTreeSet<String>>,
    since: tokio::time::Instant,
) -> Result<cached::Return<bool>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly")).map(cached::Return::new);
    }

    client
        .unwrap()
        .has_list_resources_all_result_changed_since_instant(
            api_version,
            kind,
            label_selector,
            field_selector,
            field_masks,
            since,
        )
        .await
        .map(cached::Return::new)
}

pub(crate) async fn can_i(
    client: Option<&mut Client>,
    request: KWSubjectAccessReview,
) -> Result<cached::Return<SubjectAccessReviewStatus>> {
    if client.is_none() {
        return Err(anyhow!("kube::Client was not initialized properly"));
    }

    client
        .unwrap()
        .can_i(request)
        .await
        .map(|value| cached::Return {
            was_cached: false,
            value,
        })
}

#[cached(
    ttl = 5,
    // We can use the request type as key because cached requires the key to implement Hash + Eq
    // traits. As we already implement these traits, there is no need to have a custom logic for key
    // generation. If we do that, we will only convert it into a type (e.g. string)  that
    // implements the traits as well. 
    key = "KWSubjectAccessReview",
    convert = r#"{request.clone()}"#,
    sync_writes = "default",
    with_cached_flag = true
)]
pub(crate) async fn can_i_cached(
    client: Option<&mut Client>,
    request: KWSubjectAccessReview,
) -> Result<cached::Return<SubjectAccessReviewStatus>> {
    can_i(client, request).await
}
