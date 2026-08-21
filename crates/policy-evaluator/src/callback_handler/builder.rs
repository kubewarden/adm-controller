use anyhow::Result;
use policy_fetcher::sigstore::trust::sigstore::SigstoreTrustRoot;
use policy_fetcher::sources::Sources;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use super::CallbackHandler;
use super::cache::{Cache, InMemoryCache};
use super::{oci, sigstore_verification};
use crate::callback_requests::CallbackRequest;

const DEFAULT_CHANNEL_BUFF_SIZE: usize = 100;

/// Helper struct that creates CallbackHandler objects
pub struct CallbackHandlerBuilder {
    oci_sources: Option<Sources>,
    channel_buffer_size: usize,
    shutdown_channel: oneshot::Receiver<()>,
    trust_root: Option<Arc<SigstoreTrustRoot>>,
    kube_client: Option<kube::Client>,
    cache: Option<Arc<dyn Cache>>,
}

impl CallbackHandlerBuilder {
    pub fn new(shutdown_channel: oneshot::Receiver<()>) -> Self {
        CallbackHandlerBuilder {
            oci_sources: None,
            shutdown_channel,
            channel_buffer_size: DEFAULT_CHANNEL_BUFF_SIZE,
            trust_root: None,
            kube_client: None,
            cache: None,
        }
    }

    /// Provide all the information needed to access OCI registries. Optional
    pub fn registry_config(mut self, sources: Option<Sources>) -> Self {
        self.oci_sources = sources;
        self
    }

    pub fn trust_root(mut self, trust_root: Option<Arc<SigstoreTrustRoot>>) -> Self {
        self.trust_root = trust_root;
        self
    }

    /// Set the size of the channel used by the sync world to communicate with
    /// the CallbackHandler. Optional
    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = size;
        self
    }

    /// Set the `kube::Client` to be used by context aware policies.
    /// Optional, but strongly recommended to have context aware policies
    /// work as expected
    pub fn kube_client(mut self, client: kube::Client) -> Self {
        self.kube_client = Some(client);
        self
    }

    /// Set the backend used by the `cache` host capability. Optional: when not
    /// provided, an in-memory backend is used. policy-server injects the backend
    /// it owns (so it can also drive the eviction task).
    pub fn cache(mut self, cache: Arc<dyn Cache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Create a CallbackHandler object
    pub async fn build(self) -> Result<CallbackHandler> {
        let (tx, rx) = mpsc::channel::<CallbackRequest>(self.channel_buffer_size);
        let oci_client = Arc::new(oci::Client::new(self.oci_sources.clone()));
        let sigstore_client =
            sigstore_verification::Client::new(self.oci_sources.clone(), self.trust_root.clone())
                .await?
                .to_owned();

        let kubernetes_client = self.kube_client.map(super::kubernetes::Client::new);

        let cache = self
            .cache
            .unwrap_or_else(|| Arc::new(InMemoryCache::new()));

        Ok(CallbackHandler {
            oci_client,
            sigstore_client,
            kubernetes_client,
            cache,
            tx,
            rx,
            shutdown_channel: self.shutdown_channel,
        })
    }
}
