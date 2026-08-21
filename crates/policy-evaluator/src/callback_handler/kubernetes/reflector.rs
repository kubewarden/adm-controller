use std::{collections::BTreeSet, hash::Hash};

use anyhow::Result;
use futures::{Stream, StreamExt, TryStreamExt, future::ready};
use kube::{
    Resource,
    runtime::{
        WatchStreamExt,
        reflector::store::{self, Writer},
        watcher,
    },
};
use tokio::{sync::watch, time::Instant};
use tracing::{debug, info, warn};

use crate::callback_handler::kubernetes::{KubeResource, field_mask};

/// Like `kube::runtime::reflector::reflector`, but also sends the time of the last change to a
/// watch channel
pub fn reflector_tracking_changes_instant<K, W>(
    mut writer: store::Writer<K>,
    stream: W,
    last_change_seen_at: watch::Sender<Instant>,
) -> impl Stream<Item = W::Item>
where
    K: Resource + Clone,
    K::DynamicType: Eq + Hash + Clone,
    W: Stream<Item = watcher::Result<watcher::Event<K>>>,
{
    stream.inspect_ok(move |event| {
        if let Err(err) = last_change_seen_at.send(Instant::now()) {
            warn!(error = ?err, "failed to set last_change_seen_at");
        }
        writer.apply_watcher_event(event)
    })
}

/// A reflector fetches Kubernetes objects based on filtering criteria.
/// When created, the list is populated slowly, to prevent hammering the Kubernetes API server.
/// The items are stored in-memory. The `managedFields` attribute is stripped from all the objects
/// to reduce memory consumption. All the other fields are retained unless field masks
/// are provided by the caller. When that happens, only the fields specified by the field masks are retained in the objects, all the
/// other fields are pruned. The field masks are applied in-place, so the objects stored in the Reflector
/// only contain the fields specified by the field masks.
/// A Kubernetes Watch is then created to keep the contents of the list updated.
///
/// This is code relies heavily on the `kube::runtime::reflector` module.
///
/// ## Stale date
///
/// There's always some delay involved with Kubernetes notifications. That depends on
/// different factors like: the load on the Kubernetes API server, the number of watchers to be
/// notifies,... That means, changes are not propagated immediately, hence the cache can have stale
/// data.
///
/// Finally, when started, the Reflector takes some time to make the loaded data available to
/// consumers.
pub(crate) struct Reflector {
    /// Read-only access to the data cached by the Reflector
    pub reader: kube::runtime::reflector::Store<kube::core::DynamicObject>,
    last_change_seen_at: watch::Receiver<Instant>,
}

impl Reflector {
    /// Compute a unique identifier for the Reflector. This is used to prevent the creation of two
    /// Reflectors watching the same set of resources.
    pub fn compute_id(
        resource: &KubeResource,
        namespace: Option<&str>,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
        field_masks: Option<&BTreeSet<String>>,
    ) -> String {
        format!(
            "{}|{}|{namespace:?}|{label_selector:?}|{field_selector:?}|{field_masks:?}",
            resource.resource.api_version, resource.resource.kind
        )
    }

    /// Create the reflector and start a tokio task in the background that keeps
    /// the contents of the Reflector updated
    pub async fn create_and_run(
        kube_client: kube::Client,
        resource: KubeResource,
        namespace: Option<String>,
        label_selector: Option<String>,
        field_selector: Option<String>,
        field_masks: Option<BTreeSet<String>>,
    ) -> Result<Self> {
        let group = resource.resource.group.clone();
        let version = resource.resource.version.clone();
        let kind = resource.resource.kind.clone();

        info!(
            group,
            version,
            kind,
            ?namespace,
            ?label_selector,
            ?field_selector,
            "creating new reflector"
        );

        let api = match namespace {
            Some(ref ns) => kube::api::Api::<kube::core::DynamicObject>::namespaced_with(
                kube_client,
                ns,
                &resource.resource,
            ),
            None => kube::api::Api::<kube::core::DynamicObject>::all_with(
                kube_client,
                &resource.resource,
            ),
        };

        let writer = Writer::new(resource.resource);
        let reader = writer.as_reader();

        let filter = watcher::Config {
            label_selector: label_selector.clone(),
            field_selector: field_selector.clone(),
            ..Default::default()
        };

        let field_masker: Option<field_mask::FieldMaskNode> =
            field_masks.map(field_mask::FieldMaskNode::new);

        let stream = watcher(api, filter).map_ok(move |ev| {
            ev.modify(|obj| {
                field_mask::modify_object(obj, field_masker.as_ref());
            })
        });

        // this is a watch channel that tracks the last time the reflector saw a change
        let (updated_at_watch_tx, updated_at_watch_rx) = watch::channel(Instant::now());

        let rf = reflector_tracking_changes_instant(writer, stream, updated_at_watch_tx);

        tokio::spawn(async move {
            let infinite_watch = rf.default_backoff().touched_objects().for_each(|obj| {
                match obj {
                    Ok(o) => debug!(
                        group,
                        version,
                        kind,
                        ?namespace,
                        ?label_selector,
                        ?field_selector,
                        object=?o,
                        "watcher saw object"
                    ),
                    Err(e) => warn!(
                        group,
                        version,
                        kind,
                        ?namespace,
                        ?label_selector,
                        ?field_selector,
                        error=?e,
                        "watcher error"
                    ),
                };
                ready(())
            });
            infinite_watch.await
        });

        reader.wait_until_ready().await?;

        Ok(Reflector {
            reader,
            last_change_seen_at: updated_at_watch_rx,
        })
    }

    /// Get the last time a change was seen by the reflector
    pub async fn last_change_seen_at(&self) -> Instant {
        *self.last_change_seen_at.borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use field_mask::modify_object;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry;
    use kube::core::{DynamicObject, ObjectMeta};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn test_modify_object_clears_managed_fields() {
        let mut obj = DynamicObject {
            metadata: ObjectMeta {
                managed_fields: Some(vec![ManagedFieldsEntry::default()]),
                ..Default::default()
            },
            types: None,
            data: json!({}),
        };

        modify_object(&mut obj, None);

        assert!(obj.metadata.managed_fields.unwrap().is_empty());
    }

    #[test]
    fn test_modify_object_removes_last_applied_configuration() {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            "kubectl.kubernetes.io/last-applied-configuration".to_string(),
            "{}".to_string(),
        );
        annotations.insert("other-annotation".to_string(), "value".to_string());

        let mut obj = DynamicObject {
            metadata: ObjectMeta {
                annotations: Some(annotations),
                ..Default::default()
            },
            types: None,
            data: json!({}),
        };

        modify_object(&mut obj, None);

        let annotations = obj.metadata.annotations.unwrap();
        assert!(!annotations.contains_key("kubectl.kubernetes.io/last-applied-configuration"));
        assert!(annotations.contains_key("other-annotation"));
    }

    #[test]
    fn test_modify_object_applies_field_masks() {
        let mut obj = DynamicObject::new(
            "Pod",
            &kube::api::ApiResource::erase::<k8s_openapi::api::core::v1::Pod>(&()),
        );
        obj.types = None;
        obj.data = json!({
            "spec": {
                "containers": [
                    {
                        "name": "nginx",
                        "image": "nginx:latest"
                    }
                ]
            },
            "status": {
                "phase": "Running"
            }
        });

        let masks = ["spec.containers.image"];

        let field_masker = field_mask::FieldMaskNode::new(masks);

        modify_object(&mut obj, Some(&field_masker));

        let expected_data = json!({
            "spec": {
                "containers": [
                    {
                        "image": "nginx:latest"
                    }
                ]
            }
        });

        assert_eq!(obj.data, expected_data);
    }

    #[test]
    fn test_modify_object_applies_field_masks_with_sbomscanner_vulnerability_report() {
        let sbom_data = std::fs::read_to_string("tests/data/sbomscanner_vulnerability_report.json")
            .expect("Failed to read sbomscanner_vulnerability_report.json");
        let vulnerability_report_json: serde_json::Value =
            serde_json::from_str(&sbom_data).expect("Failed to parse JSON");

        let mut obj = DynamicObject::new(
            "VulnerabilityReport",
            // Wrong resource, but it doesn't matter for this test, we just want to check that the field masking works as expected
            &kube::api::ApiResource::erase::<k8s_openapi::api::core::v1::Pod>(&()),
        );
        obj.types = None;
        obj.data = vulnerability_report_json;

        let field_masks = [
            "report.results.vulnerabilities.cve",
            "report.results.vulnerabilities.fixedVersions",
            "report.results.vulnerabilities.severity",
            "report.results.vulnerabilities.suppressed",
        ];
        let field_masker = field_mask::FieldMaskNode::new(field_masks);

        modify_object(&mut obj, Some(&field_masker));

        // Validation
        let report = obj.data.get("report").expect("report field missing");

        assert!(
            report.get("imageMetadata").is_none(),
            "imageMetadata should be removed"
        );

        let results = report.get("results").expect("results field missing");
        let results_arr = results.as_array().expect("results should be an array");

        for result in results_arr {
            let vulnerabilities = result
                .get("vulnerabilities")
                .expect("vulnerabilities field missing");
            let vulns_arr = vulnerabilities
                .as_array()
                .expect("vulnerabilities should be an array");

            for vuln in vulns_arr {
                let vuln_obj = vuln.as_object().expect("vulnerability should be an object");

                assert!(
                    vuln_obj.keys().count() == 4,
                    "vulnerability should only have 4 fields"
                );

                // Check expected fields exist
                assert!(vuln.get("cve").is_some(), "cve missing");
                assert!(vuln.get("fixedVersions").is_some(), "fixedVersions missing");
                assert!(vuln.get("severity").is_some(), "severity missing");
                assert!(vuln.get("suppressed").is_some(), "suppressed missing");
            }
        }
    }
}
