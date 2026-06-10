use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use k8s_openapi::api::authorization::v1::{SubjectAccessReview, SubjectAccessReviewStatus};
use kube::{
    Api,
    api::PostParams,
    core::{DynamicObject, ObjectList},
};
use kubewarden_policy_sdk::host_capabilities::kubernetes::SubjectAccessReview as KWSubjectAccessReview;
use tokio::{sync::RwLock, time::Instant};

use crate::callback_handler::kubernetes::{ApiVersionKind, KubeResource, field_mask, reflector::Reflector};

#[derive(Clone)]
pub(crate) struct Client {
    kube_client: kube::Client,
    kube_resources: Arc<RwLock<HashMap<ApiVersionKind, KubeResource>>>,
    reflectors: Arc<RwLock<HashMap<String, Reflector>>>,
}

impl Client {
    pub fn new(client: kube::Client) -> Self {
        Self {
            kube_client: client,
            kube_resources: Arc::new(RwLock::new(HashMap::new())),
            reflectors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Build a KubeResource using the apiVersion and Kind "coordinates" provided.
    /// The result is then cached locally to avoid further interactions with
    /// the Kubernetes API Server
    async fn build_kube_resource(&mut self, api_version: &str, kind: &str) -> Result<KubeResource> {
        let avk = ApiVersionKind {
            api_version: api_version.to_owned(),
            kind: kind.to_owned(),
        };

        // take a reader lock and search for the resource inside of the
        // known resources
        let kube_resource = {
            let known_resources = self.kube_resources.read().await;
            known_resources.get(&avk).map(|r| r.to_owned())
        };
        if let Some(kr) = kube_resource {
            return Ok(kr);
        }

        // the resource is not known yet, we have to search it
        let resources_list = match api_version {
            "v1" => {
                self.kube_client
                    .list_core_api_resources(api_version)
                    .await?
            }
            _ => self
                .kube_client
                .list_api_group_resources(api_version)
                .await
                .map_err(|e| anyhow!("error finding resource {api_version} / {kind}: {e}"))?,
        };

        let resource = resources_list
            .resources
            .iter()
            .find(|r| r.kind == kind)
            .ok_or_else(|| anyhow!("Cannot find resource {api_version}/{kind}"))?
            .to_owned();

        let (group, version) = match api_version {
            "v1" => ("", "v1"),
            _ => api_version
                .split_once('/')
                .ok_or_else(|| anyhow!("cannot determine group and version for {api_version}"))?,
        };

        let kube_resource = KubeResource {
            resource: kube::api::ApiResource {
                group: group.to_owned(),
                version: version.to_owned(),
                api_version: api_version.to_owned(),
                kind: kind.to_owned(),
                plural: resource.name,
            },
            namespaced: resource.namespaced,
        };

        // Take a writer lock and cache the resource we just found
        let mut known_resources = self.kube_resources.write().await;
        known_resources.insert(avk, kube_resource.clone());

        Ok(kube_resource)
    }

    async fn get_reflector_reader(
        &mut self,
        reflector_id: &str,
        resource: KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<kube::runtime::reflector::Store<kube::core::DynamicObject>> {
        let reader = {
            let reflectors = self.reflectors.read().await;
            reflectors
                .get(reflector_id)
                .map(|reflector| reflector.reader.clone())
        };
        if let Some(reader) = reader {
            return Ok(reader);
        }

        let reflector = Reflector::create_and_run(
            self.kube_client.clone(),
            resource,
            namespace,
            label_selector,
            field_selector,
            field_masks,
        )
        .await?;
        let reader = reflector.reader.clone();

        {
            let mut reflectors = self.reflectors.write().await;
            reflectors.insert(reflector_id.to_string(), reflector);
        }

        Ok(reader)
    }

    pub async fn list_resources_by_namespace(
        &mut self,
        api_version: &str,
        kind: &str,
        namespace: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let resource = self.build_kube_resource(api_version, kind).await?;
        if !resource.namespaced {
            return Err(anyhow!(
                "resource {api_version}/{kind} is cluster wide. Cannot search for it inside of a namespace"
            ));
        }

        self.list_resources_from_reflector(
            resource,
            Some(namespace.to_owned()),
            label_selector,
            field_selector,
            field_masks,
        )
        .await
    }

    pub async fn list_resources_all(
        &mut self,
        api_version: &str,
        kind: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        self.list_resources_from_reflector(
            resource,
            None,
            label_selector,
            field_selector,
            field_masks,
        )
        .await
    }

    /// List resources matching the given criteria with a direct, one-shot call to the
    /// Kubernetes API Server, bypassing the reflector cache.
    pub async fn list_resources_by_namespace_direct(
        &mut self,
        api_version: &str,
        kind: &str,
        namespace: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let resource = self.build_kube_resource(api_version, kind).await?;
        if !resource.namespaced {
            return Err(anyhow!(
                "resource {api_version}/{kind} is cluster wide. Cannot search for it inside of a namespace"
            ));
        }

        let api = kube::api::Api::<kube::core::DynamicObject>::namespaced_with(
            self.kube_client.clone(),
            namespace,
            &resource.resource,
        );

        list_resources_direct(api, label_selector, field_selector, field_masks).await
    }

    /// List resources matching the given criteria with a direct, one-shot call to the
    /// Kubernetes API Server, bypassing the reflector cache.
    pub async fn list_resources_all_direct(
        &mut self,
        api_version: &str,
        kind: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        let api = kube::api::Api::<kube::core::DynamicObject>::all_with(
            self.kube_client.clone(),
            &resource.resource,
        );

        list_resources_direct(api, label_selector, field_selector, field_masks).await
    }

    pub async fn has_list_resources_all_result_changed_since_instant(
        &mut self,
        api_version: &str,
        kind: &str,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
        since: Instant,
    ) -> Result<bool> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        Ok(self
            .have_reflector_resources_changed_since(
                &resource,
                None,
                label_selector,
                field_selector,
                field_masks,
                since,
            )
            .await)
    }

    async fn list_resources_from_reflector(
        &mut self,
        resource: KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<ObjectList<kube::core::DynamicObject>> {
        let api_version = resource.resource.api_version.clone();
        let kind = resource.resource.kind.clone();

        let reflector_id = Reflector::compute_id(
            &resource,
            namespace.as_deref(),
            label_selector.as_deref(),
            field_selector.as_deref(),
            field_masks.as_ref(),
        );

        let reader = self
            .get_reflector_reader(
                &reflector_id,
                resource,
                namespace,
                label_selector,
                field_selector,
                field_masks,
            )
            .await?;

        Ok(ObjectList {
            types: kube::core::TypeMeta {
                api_version,
                kind: format!("{kind}List"),
            },
            metadata: Default::default(),
            items: reader
                .state()
                .iter()
                .map(|v| DynamicObject::clone(v))
                .collect(),
        })
    }

    /// Check if the resources cached by the reflector have changed since the provided instant
    async fn have_reflector_resources_changed_since(
        &mut self,
        resource: &KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
        since: Instant,
    ) -> bool {
        let reflector_id = Reflector::compute_id(
            resource,
            namespace.as_deref(),
            label_selector.as_deref(),
            field_selector.as_deref(),
            field_masks.as_ref(),
        );

        let last_change_seen_at = {
            let reflectors = self.reflectors.read().await;
            match reflectors.get(&reflector_id) {
                Some(reflector) => reflector.last_change_seen_at().await,
                None => return true,
            }
        };

        last_change_seen_at > since
    }

    pub async fn get_resource(
        &mut self,
        api_version: &str,
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> Result<kube::core::DynamicObject> {
        let resource = self.build_kube_resource(api_version, kind).await?;

        let api = match resource.namespaced {
            true => kube::api::Api::<kube::core::DynamicObject>::namespaced_with(
                self.kube_client.clone(),
                namespace.ok_or_else(|| {
                    anyhow!(
                        "Resource {}/{} is namespaced, but no namespace was provided",
                        api_version,
                        kind
                    )
                })?,
                &resource.resource,
            ),
            false => kube::api::Api::<kube::core::DynamicObject>::all_with(
                self.kube_client.clone(),
                &resource.resource,
            ),
        };

        api.get_opt(name)
            .await
            .map_err(anyhow::Error::new)?
            .ok_or_else(|| anyhow!("Cannot find {api_version}/{kind} named '{name}' inside of namespace '{namespace:?}'"))
    }

    pub async fn get_resource_plural_name(
        &mut self,
        api_version: &str,
        kind: &str,
    ) -> Result<String> {
        let resource = self.build_kube_resource(api_version, kind).await?;
        Ok(resource.resource.plural)
    }

    pub async fn can_i(
        &mut self,
        request: KWSubjectAccessReview,
    ) -> Result<SubjectAccessReviewStatus> {
        let subject_access_review = SubjectAccessReview {
            spec: request.into(),
            ..Default::default()
        };
        let sar_api: Api<SubjectAccessReview> = Api::all(self.kube_client.clone());

        let response = sar_api
            .create(&PostParams::default(), &subject_access_review)
            .await;
        response.map_err(anyhow::Error::new).and_then(|response| {
            response
                .status
                .ok_or(anyhow!("SubjectAccessReview did not return a response"))
        })
    }
}

/// Perform a one-shot list call against the Kubernetes API Server, applying the same
/// object pruning (managed fields, last-applied-configuration annotation, field masks)
/// that the reflector applies to the objects it caches.
async fn list_resources_direct(
    api: kube::api::Api<kube::core::DynamicObject>,
    label_selector: Option<String>,
    field_selector: Option<String>,
    field_masks: Option<BTreeSet<String>>,
) -> Result<ObjectList<kube::core::DynamicObject>> {
    let mut list_params = kube::api::ListParams::default();
    if let Some(label_selector) = label_selector {
        list_params = list_params.labels(&label_selector);
    }
    if let Some(field_selector) = field_selector {
        list_params = list_params.fields(&field_selector);
    }

    let mut list = api.list(&list_params).await.map_err(anyhow::Error::new)?;

    let field_masker: Option<field_mask::FieldMaskNode> =
        field_masks.map(field_mask::FieldMaskNode::new);
    for item in &mut list.items {
        field_mask::modify_object(item, field_masker.as_ref());
    }

    Ok(list)
}
