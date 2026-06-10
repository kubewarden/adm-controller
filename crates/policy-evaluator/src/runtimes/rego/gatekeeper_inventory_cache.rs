use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock},
};
use tokio::{sync::mpsc, time::Instant};

use crate::runtimes::rego::context_aware::{
    get_allowed_resources, have_allowed_resources_changed_since_instant,
};
use crate::{
    callback_requests::CallbackRequest,
    policy_metadata::ContextAwareResource,
    runtimes::rego::{
        errors::{RegoRuntimeError, Result},
        gatekeeper_inventory::GatekeeperInventory,
    },
};

lazy_static! {
    /// Global cache for the Gatekeeper inventories
    pub(crate) static ref GATEKEEPER_INVENTORY_CACHE: GateKeeperInventoryCache =
        GateKeeperInventoryCache::new();
}

/// A serialized Gatekeeper inventory. Building and serializing the inventory can
/// be quite expensive when many Kubernetes resources are involved. This cache
/// is used to avoid recomputing the inventory on every request.
#[derive(Clone)]
pub(crate) struct CachedInventory {
    /// The serialized inventory
    pub data: Vec<u8>,
    /// The instant when the inventory was last computed. This is used to invalidate the cache
    pub cache_time: Instant,
}

/// This defines how Gatekeeper policy expects the `input` attribute to be structured.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct GatekeeperInput {
    /// The actual inventory
    inventory: GatekeeperInventory,
}

/// Hold all the inventories for the Gatekeeper runtime
///
/// The inventories are stored inside of a dictionary that has the list of resources
/// the inventory is allowed to access as key. The value is the serialized inventory.
///
/// Two different policies that access the same set of resources will share the same
/// inventory.
/// However, two policies sharing an overlapping set of resources will have different
/// inventories, leading to some duplication of information.
/// Unfortunately there's nothing we can do to prevent that. We need to keep in cache
/// the serialized version of the inventories to speed up the policy evaluation.
pub(crate) struct GateKeeperInventoryCache {
    // Note: the Arc is used to make some `clone` invocation faster. The `clone` operations
    // are required because the whole `inventories` variable is located inside of a RwLock
    inventories: RwLock<HashMap<BTreeSet<ContextAwareResource>, Arc<CachedInventory>>>,
}

impl GateKeeperInventoryCache {
    pub fn new() -> Self {
        Self {
            inventories: RwLock::new(HashMap::new()),
        }
    }

    /// This function returns the serialized inventory for the given set of resources.
    /// The inventory is computed and serialized only if it's not already present in the cache.
    /// The inventory is also recreated if the set of resources has changed since the time
    /// the inventory was computed
    pub fn get_inventory(
        &self,
        callback_channel: &mpsc::Sender<CallbackRequest>,
        ctx_aware_resources: &BTreeSet<ContextAwareResource>,
    ) -> Result<Vec<u8>> {
        let inventory = {
            let inventories = self.inventories.read().unwrap();
            inventories.get(ctx_aware_resources).cloned()
        };
        let inventory = match inventory {
            None => self.create_and_register_inventory(ctx_aware_resources, callback_channel),
            Some(cached_inventory) => {
                if have_allowed_resources_changed_since_instant(
                    callback_channel,
                    ctx_aware_resources,
                    cached_inventory.cache_time,
                )? {
                    self.create_and_register_inventory(ctx_aware_resources, callback_channel)
                } else {
                    Ok(cached_inventory)
                }
            }
        }?;
        Ok(inventory.data.clone())
    }

    /// Create the inventory and register it in the cache. A prior entry of the inventory is
    /// automatically removed from the cache.
    fn create_and_register_inventory(
        &self,
        ctx_aware_resources: &BTreeSet<ContextAwareResource>,
        callback_channel: &mpsc::Sender<CallbackRequest>,
    ) -> Result<Arc<CachedInventory>> {
        let now = Instant::now();
        let cluster_resources = get_allowed_resources(callback_channel, ctx_aware_resources)?;
        let inventory = GatekeeperInput {
            inventory: GatekeeperInventory::new(&cluster_resources)?,
        };
        let cached_inventory = Arc::new(CachedInventory {
            data: serde_json::to_vec(&inventory)
                .map_err(RegoRuntimeError::GatekeeperInventorySerializationError)?,
            cache_time: now,
        });

        self.inventories
            .write()
            .unwrap()
            .insert(ctx_aware_resources.to_owned(), cached_inventory.clone());
        Ok(cached_inventory)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::callback_requests::{CallbackRequestType, CallbackResponse};
    use serial_test::serial;
    use std::collections::BTreeMap;

    use crate::runtimes::rego::context_aware::tests::{
        dynamic_object_from_fixture, object_list_from_dynamic_objects,
    };

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_create_entry_because_cache_does_not_exist() {
        let (callback_tx, mut callback_rx) = mpsc::channel::<CallbackRequest>(10);
        let resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
        };
        let expected_resource = resource.clone();
        let services = [
            dynamic_object_from_fixture("services", Some("kube-system"), "kube-dns").unwrap(),
            dynamic_object_from_fixture("services", Some("kube-system"), "metrics-server").unwrap(),
        ];
        let services_list = object_list_from_dynamic_objects(&services).unwrap();
        let kube_resources = BTreeMap::from([(resource.clone(), services_list.clone())]);
        let expected_inventory = GatekeeperInventory::new(&kube_resources).unwrap();

        tokio::spawn(async move {
            loop {
                let req = match callback_rx.recv().await {
                    Some(r) => r,
                    None => return,
                };
                let callback_response = match req.request {
                    CallbackRequestType::KubernetesListResourceAll {
                        api_version,
                        kind,
                        label_selector,
                        field_selector,
                        disable_cache: _,
                        field_masks: _,
                    } => {
                        assert_eq!(api_version, expected_resource.api_version);
                        assert_eq!(kind, expected_resource.kind);
                        assert!(label_selector.is_none());
                        assert!(field_selector.is_none());
                        CallbackResponse {
                            payload: serde_json::to_vec(&services_list).unwrap(),
                        }
                    }
                    _ => {
                        panic!("not the expected request type");
                    }
                };

                req.response_channel.send(Ok(callback_response)).unwrap();
            }
        });

        tokio::task::spawn_blocking(move || {
            {
                // ensure the cache is empty
                let mut inventories = GATEKEEPER_INVENTORY_CACHE.inventories.write().unwrap();
                inventories.clear();
            }

            let resources: BTreeSet<ContextAwareResource> = BTreeSet::from([resource]);

            let cached_inventory = GATEKEEPER_INVENTORY_CACHE
                .get_inventory(&callback_tx, &resources)
                .unwrap();
            assert!(!cached_inventory.is_empty());

            {
                let inventories = GATEKEEPER_INVENTORY_CACHE.inventories.read().unwrap();
                let cached_input_json = inventories.get(&resources).unwrap();
                let actual_inventory =
                    serde_json::from_slice::<GatekeeperInput>(&cached_input_json.data)
                        .unwrap()
                        .inventory;
                assert_eq!(expected_inventory, actual_inventory);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_cached_entry_is_still_valid() {
        let (callback_tx, mut callback_rx) = mpsc::channel::<CallbackRequest>(10);
        let resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
        };
        let expected_resource = resource.clone();

        let resources: BTreeSet<ContextAwareResource> = BTreeSet::from([resource.clone()]);

        let expected_cached_inventory = CachedInventory {
            data: "cached_inventory".as_bytes().to_vec(),
            cache_time: Instant::now()
                .checked_sub(tokio::time::Duration::from_secs(60))
                .unwrap(),
        };
        {
            let mut inventories = GATEKEEPER_INVENTORY_CACHE.inventories.write().unwrap();
            inventories.insert(
                resources.clone(),
                Arc::new(expected_cached_inventory.clone()),
            );
        }

        tokio::spawn(async move {
            loop {
                let req = match callback_rx.recv().await {
                    Some(r) => r,
                    None => return,
                };
                let callback_response = match req.request {
                    CallbackRequestType::HasKubernetesListResourceAllResultChangedSinceInstant {
                        api_version,
                        kind,
                        label_selector,
                        field_selector,
                        since: _,
                        field_masks: _,
                    } => {
                        assert_eq!(api_version, expected_resource.api_version);
                        assert_eq!(kind, expected_resource.kind);
                        assert!(label_selector.is_none());
                        assert!(field_selector.is_none());

                        CallbackResponse {
                            payload: serde_json::to_vec(&false).unwrap(),
                        }
                    }
                    _ => {
                        panic!("not the expected request type");
                    }
                };

                req.response_channel.send(Ok(callback_response)).unwrap();
            }
        });

        tokio::task::spawn_blocking(move || {
            let actual = GATEKEEPER_INVENTORY_CACHE
                .get_inventory(&callback_tx, &resources)
                .unwrap();
            assert_eq!(expected_cached_inventory.data, actual);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_cached_entry_is_no_longer_valid() {
        let (callback_tx, mut callback_rx) = mpsc::channel::<CallbackRequest>(10);
        let resource = ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
        };
        let expected_resource = resource.clone();

        let resources: BTreeSet<ContextAwareResource> = BTreeSet::from([resource.clone()]);

        let services = [
            dynamic_object_from_fixture("services", Some("kube-system"), "kube-dns").unwrap(),
            dynamic_object_from_fixture("services", Some("kube-system"), "metrics-server").unwrap(),
        ];
        let services_list = object_list_from_dynamic_objects(&services).unwrap();

        let kube_resources = BTreeMap::from([(resource, services_list.clone())]);
        let expected_inventory = GatekeeperInventory::new(&kube_resources).unwrap();

        let stale_cached_inventory = CachedInventory {
            data: b"cached_inventory_stale".to_vec(),
            cache_time: Instant::now()
                .checked_sub(tokio::time::Duration::from_secs(60))
                .unwrap(),
        };

        {
            let mut inventories = GATEKEEPER_INVENTORY_CACHE.inventories.write().unwrap();
            inventories.insert(resources.clone(), Arc::new(stale_cached_inventory.clone()));
        }

        tokio::spawn(async move {
            loop {
                let req = match callback_rx.recv().await {
                    Some(r) => r,
                    None => return,
                };
                let callback_response = match req.request {
                    CallbackRequestType::KubernetesListResourceAll {
                        api_version,
                        kind,
                        label_selector,
                        field_selector,
                        disable_cache: _,
                        field_masks: _,
                    } => {
                        assert_eq!(api_version, expected_resource.api_version);
                        assert_eq!(kind, expected_resource.kind);
                        assert!(label_selector.is_none());
                        assert!(field_selector.is_none());
                        CallbackResponse {
                            payload: serde_json::to_vec(&services_list).unwrap(),
                        }
                    }
                    CallbackRequestType::HasKubernetesListResourceAllResultChangedSinceInstant {
                        api_version,
                        kind,
                        label_selector,
                        field_selector,
                        since: _,
                        field_masks: _,
                    } => {
                        assert_eq!(api_version, expected_resource.api_version);
                        assert_eq!(kind, expected_resource.kind);
                        assert!(label_selector.is_none());
                        assert!(field_selector.is_none());

                        CallbackResponse {
                            payload: serde_json::to_vec(&true).unwrap(),
                        }
                    }
                    _ => {
                        panic!("not the expected request type");
                    }
                };

                req.response_channel.send(Ok(callback_response)).unwrap();
            }
        });

        tokio::task::spawn_blocking(move || {
            let actual = GATEKEEPER_INVENTORY_CACHE
                .get_inventory(&callback_tx, &resources)
                .unwrap();
            assert!(actual != stale_cached_inventory.data);
            let actual_inventory = serde_json::from_slice::<GatekeeperInput>(&actual).unwrap();
            assert_eq!(expected_inventory, actual_inventory.inventory);

            {
                let inventories = GATEKEEPER_INVENTORY_CACHE.inventories.read().unwrap();
                let actual_inventory = inventories.get(&resources).unwrap();
                assert!(actual_inventory.cache_time > stale_cached_inventory.cache_time);
            }

            {
                let inventories = GATEKEEPER_INVENTORY_CACHE.inventories.read().unwrap();
                let actual_inventory = inventories.get(&resources).unwrap();
                assert!(actual_inventory.cache_time > stale_cached_inventory.cache_time);
            }
        })
        .await
        .unwrap();
    }
}
