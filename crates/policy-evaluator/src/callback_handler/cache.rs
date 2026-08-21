// The `cache` host capability, as described in RFC 0024.
//
// It exposes two operations to policy authors:
//   * `kubewarden.cache.set` - store arbitrary bytes under a key, with a
//     caller-provided TTL.
//   * `kubewarden.cache.get` - retrieve the bytes stored under a key. A cache
//     miss is not an error: it is reported with a success code and an empty
//     value.
//
// The backend is modeled as a trait object (`Arc<dyn Cache>`) so that the
// concrete implementation can be selected at runtime. Today the only backend is
// an in-memory store backed by the `cached` crate's `ExpiringCache`; the trait
// leaves the door open for shared/distributed backends (e.g. Redis) in the
// future without touching the host capability or any policy.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use cached::{Cached, Expires, ExpiringCache};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::callback_requests::CallbackResponse;

/// Reserved key prefix for the caches owned by Kubewarden's internal host
/// capabilities. Policies are not allowed to `set` keys using this prefix, so
/// that policy-authored keys can never collide with the framework's own entries
/// on the shared backend.
pub const RESERVED_KEY_PREFIX: &str = "kubewarden_internal_";

/// Default interval used by the background eviction task.
pub const DEFAULT_EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// Response code returned to the guest when an operation succeeds.
const CODE_SUCCESS: u32 = 0;
/// Response code returned to the guest when an operation is rejected.
const CODE_ERROR: u32 = 1;

/// Payload of a `kubewarden.cache.set` request.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct CacheSetRequest {
    /// The unique identifier for the data being stored.
    pub key: String,
    /// The arbitrary data to be stored in the cache.
    pub value: Vec<u8>,
    /// The lifespan of the data, in seconds.
    pub ttl: u64,
}

/// Payload of a `kubewarden.cache.get` request.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct CacheGetRequest {
    /// The key of the data to retrieve.
    pub key: String,
}

/// Response of a `kubewarden.cache.set` operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSetResponse {
    /// `0` on success, non-zero otherwise.
    pub code: u32,
    /// Human readable description of the outcome.
    pub message: String,
}

/// Response of a `kubewarden.cache.get` operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheGetResponse {
    /// `0` on success, non-zero otherwise.
    pub code: u32,
    /// Human readable description of the outcome.
    pub message: String,
    /// The data stored under the requested key. `None` on a cache miss.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Vec<u8>>,
}

/// Backend contract for the cache host capability.
///
/// Implemented as a trait object so the backend can be swapped at runtime. The
/// `cached` crate's stores can serve as a foundation for additional
/// implementations of this contract.
pub trait Cache: Send + Sync {
    /// Store `value` under `key`, keeping it for `ttl`.
    fn set(&self, key: String, value: Vec<u8>, ttl: Duration);
    /// Retrieve the value stored under `key`, if present and not expired.
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    /// Remove every expired entry. Invoked periodically by the eviction task.
    fn flush_expired(&self);
}

/// A cached value that carries its own expiration instant.
///
/// `ExpiringCache` determines expiry per value through the [`Expires`] trait,
/// which is exactly what backs the per-key TTL required by the host capability:
/// each entry expires on its own schedule, derived from the caller-provided TTL.
struct ExpiringEntry {
    value: Vec<u8>,
    expires_at: Instant,
}

impl Expires for ExpiringEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Default, in-memory cache backend.
///
/// Wraps the `cached` crate's [`ExpiringCache`] (the RFC refers to this store by
/// its older name, `ExpiringValueCache`; it was renamed to `ExpiringCache` in
/// `cached` 2.0). `ExpiringCache` has no cache-wide TTL: each value decides when
/// it has expired via [`Expires`], giving the per-key TTL the capability needs.
/// It is kept behind the [`Cache`] trait so it can be swapped later. The
/// `ExpiringCache` methods take `&mut self`, so the store is guarded by a
/// `Mutex` to satisfy the shared-reference [`Cache`] contract.
pub struct InMemoryCache {
    store: Mutex<ExpiringCache<String, ExpiringEntry>>,
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self {
            store: Mutex::new(ExpiringCache::default()),
        }
    }
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Cache for InMemoryCache {
    fn set(&self, key: String, value: Vec<u8>, ttl: Duration) {
        let entry = ExpiringEntry {
            value,
            expires_at: Instant::now() + ttl,
        };
        let mut store = self.store.lock().expect("cache mutex poisoned");
        store.cache_set(key, entry);
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut store = self.store.lock().expect("cache mutex poisoned");
        // `cache_get` evaluates `Expires::is_expired`, returning `None` (and
        // evicting the entry) when it has expired, so per-key TTL is enforced.
        store.cache_get(key).map(|entry| entry.value.clone())
    }

    fn flush_expired(&self) {
        let mut store = self.store.lock().expect("cache mutex poisoned");
        // `evict` sweeps and removes every expired entry in one pass.
        store.evict();
    }
}

/// Handle a `cache.set` request.
///
/// Enforces the reserved-prefix rule: keys starting with [`RESERVED_KEY_PREFIX`]
/// are rejected with a non-zero code, leaving that namespace for the framework's
/// own internal caches.
pub fn handle_set(cache: &dyn Cache, req: CacheSetRequest) -> Result<CallbackResponse> {
    let response = if req.key.starts_with(RESERVED_KEY_PREFIX) {
        CacheSetResponse {
            code: CODE_ERROR,
            message: format!(
                "the key prefix '{RESERVED_KEY_PREFIX}' is reserved for internal use and cannot be set by policies"
            ),
        }
    } else {
        cache.set(req.key, req.value, Duration::from_secs(req.ttl));
        CacheSetResponse {
            code: CODE_SUCCESS,
            message: "ok".to_string(),
        }
    };

    let payload = serde_json::to_vec(&response)
        .map_err(|e| anyhow!("error serializing cache.set response: {e:?}"))?;
    Ok(CallbackResponse { payload })
}

/// Handle a `cache.get` request. A miss is reported with a success code and an
/// empty value, not as an error.
pub fn handle_get(cache: &dyn Cache, req: CacheGetRequest) -> Result<CallbackResponse> {
    let value = cache.get(&req.key);
    let response = CacheGetResponse {
        code: CODE_SUCCESS,
        message: if value.is_some() {
            "hit".to_string()
        } else {
            "miss".to_string()
        },
        value,
    };

    let payload = serde_json::to_vec(&response)
        .map_err(|e| anyhow!("error serializing cache.get response: {e:?}"))?;
    Ok(CallbackResponse { payload })
}

/// Look up a framework-internal entry in the shared cache, computing and
/// storing it on a miss.
///
/// This backs the built-in host capabilities (OCI, sigstore, Kubernetes) so they
/// share the single cache backend instead of each owning a private store (which
/// is what the `#[cached]` macro used to do). `sub_key` is namespaced with
/// [`RESERVED_KEY_PREFIX`], so these entries can never collide with
/// policy-authored keys. The returned `cached::Return` carries the `was_cached`
/// flag the `#[cached]` macro used to provide for logging.
///
/// Only successful results are cached. A (de)serialization failure is treated as
/// a cache miss rather than an error, so it never changes the call's outcome.
pub(crate) async fn internal_cached<T, Fut>(
    cache: &dyn Cache,
    sub_key: &str,
    ttl: Duration,
    compute: impl FnOnce() -> Fut,
) -> Result<cached::Return<T>>
where
    T: Serialize + DeserializeOwned,
    Fut: Future<Output = Result<T>>,
{
    let key = format!("{RESERVED_KEY_PREFIX}{sub_key}");

    if let Some(bytes) = cache.get(&key) {
        if let Ok(value) = serde_json::from_slice::<T>(&bytes) {
            return Ok(cached::Return {
                was_cached: true,
                value,
            });
        }
    }

    let value = compute().await?;
    if let Ok(bytes) = serde_json::to_vec(&value) {
        cache.set(key, bytes, ttl);
    }

    Ok(cached::Return {
        was_cached: false,
        value,
    })
}

/// Spawn a background task that periodically evicts expired entries.
///
/// Expired entries are also reclaimed lazily on access, but without this task a
/// key that is written once and never read again would occupy memory until the
/// process restarts.
pub fn spawn_eviction_task(cache: Arc<dyn Cache>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Skip missed ticks instead of bursting on a loaded system.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            cache.flush_expired();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_then_get_returns_value() {
        let cache = InMemoryCache::new();
        cache.set("k".to_string(), b"v".to_vec(), Duration::from_secs(60));
        assert_eq!(cache.get("k"), Some(b"v".to_vec()));
    }

    #[test]
    fn missing_key_returns_none() {
        let cache = InMemoryCache::new();
        assert_eq!(cache.get("missing"), None);
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let cache = InMemoryCache::new();
        cache.set("k".to_string(), b"v".to_vec(), Duration::from_secs(0));
        // TTL of zero means the entry is already expired.
        assert_eq!(cache.get("k"), None);
    }

    #[test]
    fn flush_expired_removes_only_expired_entries() {
        let cache = InMemoryCache::new();
        cache.set("fresh".to_string(), b"v".to_vec(), Duration::from_secs(60));
        cache.set("stale".to_string(), b"v".to_vec(), Duration::from_secs(0));
        cache.flush_expired();
        assert_eq!(cache.get("fresh"), Some(b"v".to_vec()));
        assert_eq!(cache.get("stale"), None);
    }

    #[test]
    fn set_rejects_reserved_prefix() {
        let cache = InMemoryCache::new();
        let req = CacheSetRequest {
            key: format!("{RESERVED_KEY_PREFIX}oci_digest"),
            value: b"v".to_vec(),
            ttl: 60,
        };
        let resp = handle_set(&cache, req).expect("handle_set should not fail");
        let parsed: CacheSetResponse = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(parsed.code, CODE_ERROR);
        // Nothing was stored.
        assert_eq!(cache.get(&format!("{RESERVED_KEY_PREFIX}oci_digest")), None);
    }

    #[test]
    fn set_accepts_regular_key() {
        let cache = InMemoryCache::new();
        let req = CacheSetRequest {
            key: "my-key".to_string(),
            value: b"v".to_vec(),
            ttl: 60,
        };
        let resp = handle_set(&cache, req).expect("handle_set should not fail");
        let parsed: CacheSetResponse = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(parsed.code, CODE_SUCCESS);
        assert_eq!(cache.get("my-key"), Some(b"v".to_vec()));
    }

    #[test]
    fn handle_get_reports_hit_and_miss() {
        let cache = InMemoryCache::new();
        cache.set("k".to_string(), b"v".to_vec(), Duration::from_secs(60));

        let hit = handle_get(
            &cache,
            CacheGetRequest {
                key: "k".to_string(),
            },
        )
        .unwrap();
        let parsed: CacheGetResponse = serde_json::from_slice(&hit.payload).unwrap();
        assert_eq!(parsed.code, CODE_SUCCESS);
        assert_eq!(parsed.value, Some(b"v".to_vec()));

        let miss = handle_get(
            &cache,
            CacheGetRequest {
                key: "absent".to_string(),
            },
        )
        .unwrap();
        let parsed: CacheGetResponse = serde_json::from_slice(&miss.payload).unwrap();
        assert_eq!(parsed.code, CODE_SUCCESS);
        assert_eq!(parsed.value, None);
    }
}
