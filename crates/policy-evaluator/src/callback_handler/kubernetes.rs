use std::collections::BTreeSet;
use std::time::Duration;

mod client;
pub(crate) mod field_mask;
mod reflector;

use anyhow::{Result, anyhow};
use k8s_openapi::api::authorization::v1::SubjectAccessReviewStatus;
use kube::core::ObjectList;
use kubewarden_policy_sdk::host_capabilities::kubernetes::SubjectAccessReview as KWSubjectAccessReview;
use serde::Serialize;

use super::cache;

pub(crate) use client::Client;

/// Queries against the Kubernetes API are kept in the shared cache for this
/// long. It is deliberately short, since cluster state can change at any moment.
const KUBERNETES_CACHE_TTL: Duration = Duration::from_secs(5);

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

pub(crate) async fn get_resource_cached(
    cache: &dyn cache::Cache,
    client: Option<&mut Client>,
    api_version: &str,
    kind: &str,
    name: &str,
    namespace: Option<&str>,
) -> Result<cached::Return<kube::core::DynamicObject>> {
    let sub_key = format!("get_resource:{api_version}/{kind}:{name}:{namespace:?}");
    cache::internal_cached(cache, &sub_key, KUBERNETES_CACHE_TTL, || async move {
        get_resource(client, api_version, kind, name, namespace)
            .await
            .map(|ret| ret.value)
    })
    .await
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

pub(crate) async fn can_i_cached(
    cache: &dyn cache::Cache,
    client: Option<&mut Client>,
    request: KWSubjectAccessReview,
) -> Result<cached::Return<SubjectAccessReviewStatus>> {
    // The previous `#[cached]` macro used the request itself as the key (it
    // implements Hash + Eq). The shared backend is keyed by String, so we
    // serialize the request to derive an equivalent, stable key.
    let sub_key = format!(
        "can_i:{}",
        serde_json::to_string(&request).unwrap_or_default()
    );
    cache::internal_cached(cache, &sub_key, KUBERNETES_CACHE_TTL, || async move {
        can_i(client, request).await.map(|ret| ret.value)
    })
    .await
}
