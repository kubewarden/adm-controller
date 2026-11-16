mod certs;
mod evaluation;
mod policy_downloader;
mod task;

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod cli;

pub mod api;
pub mod config;
pub mod metrics;
pub mod profiling;
pub mod tracing;

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use ::tracing::{Level, debug, info, trace, warn};
use anyhow::{Result, anyhow};
use axum::{
    Router,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use certs::create_tls_config_and_watch_certificate_changes;
use config::Config;
use evaluation::EvaluationEnvironmentBuilder;
use policy_evaluator::{
    callback_handler::{CallbackHandler, CallbackHandlerBuilder},
    kube, policy_evaluator_builder,
    policy_fetcher::sigstore::trust::sigstore::SigstoreTrustRoot,
    wasmtime,
};
use profiling::activate_memory_profiling;
use rayon::prelude::*;
use sigstore_protobuf_specs::dev::sigstore::trustroot::v1::ClientTrustConfig;
use tikv_jemallocator::Jemalloc;
use tokio::{
    sync::{Notify, Semaphore, oneshot},
    time,
};
use tower_http::trace::{self, TraceLayer};

use crate::{
    api::{
        handlers::{
            audit_handler, pprof_get_cpu, pprof_get_heap, readiness_handler, validate_handler,
            validate_raw_handler,
        },
        state::ApiServerState,
    },
    evaluation::precompiled_policy::{PrecompiledPolicies, PrecompiledPolicy},
    policy_downloader::{Downloader, FetchedPolicies},
};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
/// Prioritize memory usage, then enable features request by pprof but do not activate them by
/// default. When pprof is activate there's a CPU overhead.
pub static malloc_conf: &[u8] = b"background_thread:true,tcache_max:4096,dirty_decay_ms:5000,muzzy_decay_ms:5000,abort_conf:true,prof:true,prof_active:false,lg_prof_sample:19\0";

pub struct PolicyServer {
    router: Router,
    readiness_probe_router: Router,
    callback_handler: CallbackHandler,
    callback_handler_shutdown_channel_tx: oneshot::Sender<()>,
    addr: SocketAddr,
    tls_config: Option<RustlsConfig>,
    /// Ends with an error when the certificate watch can no longer detect a change of the
    /// TLS files. The server must stop then, so that a restart loads the files from disk.
    /// Dropping it before that aborts the watch task.
    cert_watcher: Option<task::AbortOnDrop<anyhow::Error>>,
    readiness_probe_addr: SocketAddr,
}

/// Closes every accepted connection of both servers when dropped, by sending each a hard
/// shutdown signal. `run` keeps one of these alive for as long as it waits on the servers,
/// so a connection accepted before that point does not keep running in its own task after
/// `run` stops waiting.
struct ServerShutdownGuard {
    api: axum_server::Handle<SocketAddr>,
    readiness: axum_server::Handle<SocketAddr>,
}

impl Drop for ServerShutdownGuard {
    fn drop(&mut self) {
        self.api.shutdown();
        self.readiness.shutdown();
    }
}

impl PolicyServer {
    pub async fn new_from_config(config: Config) -> Result<Self> {
        // This is a channel used to stop the tokio task that is run
        // inside of the CallbackHandler
        let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
            oneshot::channel();

        let sigstore_trust_root = match create_sigstore_trustroot(&config).await {
            Ok(trust_root) => Some(trust_root),
            Err(e) => {
                // Do not exit, only policies making use of sigstore's keyless/certificate based signatures will fail
                // There are good chances everything is going to work fine in the majority of cases
                warn!(
                    "Cannot create Sigstore trust root, verification relying on Rekor and Fulcio will fail"
                );
                // Only log the error if the log level is set to trace. This is to avoid
                // spamming the logs with errors that are not relevant to most users
                trace!(?e);
                None
            }
        };

        let mut callback_handler_builder =
            CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx)
                .registry_config(config.sources.clone())
                .trust_root(sigstore_trust_root.clone());

        let kube_client: Option<kube::Client> = match kube::Client::try_default().await {
            Ok(client) => Some(client),
            Err(e) => {
                // We cannot rely on `tracing` yet, because the tracing system has not
                // been initialized yet
                eprintln!("Cannot connect to Kubernetes cluster: {e}");
                None
            }
        };

        match kube_client {
            Some(client) => {
                callback_handler_builder = callback_handler_builder.kube_client(client);
            }
            None => {
                if config.ignore_kubernetes_connection_failure {
                    // We cannot rely on `tracing` yet, because the tracing system has not
                    // been initialized yet
                    eprintln!(
                        "Cannot connect to Kubernetes, context aware policies will not work properly"
                    );
                } else {
                    return Err(anyhow!(
                        "Cannot connect to Kubernetes, context aware policies would not work properly"
                    ));
                }
            }
        };

        let callback_handler = callback_handler_builder.build().await?;
        let callback_sender_channel = callback_handler.sender_channel();

        // Download policies
        let downloader_sigstore_trust_root = if config.verification_config.is_some() {
            sigstore_trust_root.clone()
        } else {
            None
        };
        let mut downloader =
            Downloader::new(config.sources.clone(), downloader_sigstore_trust_root).await?;

        let fetched_policies = downloader
            .download_policies(
                &config.policies,
                &config.policies_download_dir,
                config.verification_config.as_ref(),
            )
            .await;

        let timeout_protection = config.policy_evaluation_limit_seconds.is_some();
        if !timeout_protection && config::any_policy_has_timeout(&config.policies) {
            warn!(
                "timeout protection is disabled: the timeoutEvalSeconds setting of policies \
                 will be ignored"
            );
        }

        let engine = build_engine(timeout_protection)?;
        let precompiled_policies = precompile_policies(&engine, &fetched_policies);

        if !config.continue_on_errors {
            for result in precompiled_policies.values() {
                if let Err(error) = result {
                    return Err(anyhow!(error.to_string()));
                }
            }
        }

        let mut evaluation_environment_builder = EvaluationEnvironmentBuilder::new(
            &engine,
            &precompiled_policies,
            callback_sender_channel.clone(),
        )
        .with_continue_on_errors(config.continue_on_errors);
        if let Some(namespace) = config.always_accept_admission_reviews_on_namespace {
            evaluation_environment_builder = evaluation_environment_builder
                .with_always_accept_admission_reviews_on_namespace(namespace);
        }
        if let Some(limit) = config.policy_evaluation_limit_seconds {
            evaluation_environment_builder =
                evaluation_environment_builder.with_global_policy_evaluation_limit_seconds(limit);
        }
        if let Some(limit) = config.policy_memory_limit_bytes {
            evaluation_environment_builder =
                evaluation_environment_builder.with_policy_memory_limit(limit);
        }
        let evaluation_environment = evaluation_environment_builder.build(&config.policies)?;

        if let Some(limit) = config.policy_evaluation_limit_seconds {
            info!(
                execution_limit_seconds = limit,
                "policy timeout protection is enabled"
            );

            let engine = engine.clone();
            tokio::spawn(async move {
                let mut interval = time::interval(time::Duration::from_secs(1));

                // The default MissedTickBehavior::Burst behaves like so:
                //   Expected ticks: |     1     |     2     |     3     |     4     |     5     |     6     |
                //   Actual ticks:   | work -----|          delay          | work | work | work -| work -----|
                //
                // This means that in loaded systems, the engine will increment epochs too fast,
                // without giving time to the wasm host to perform work. This is usually triggered
                // as a timeout when performing an init in rehydrate(), as the init suddenly goes
                // through several ticks.
                //
                // Instead, use MissedTickBehavior::Skip:
                //   Expected ticks: |     1     |     2     |     3     |     4     |     5     |     6     |
                //   Actual ticks:   | work -----|          delay          | work ---| work -----| work -----|
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    engine.increment_epoch();
                }
            });
        } else {
            info!("policy timeout protection is disabled");
        }

        if let Some(limit) = config.policy_memory_limit_bytes {
            info!(
                policy_memory_limit_bytes = limit,
                "policy memory limit is enabled"
            );
        } else {
            warn!("policy memory limit is disabled");
        }

        let state = Arc::new(ApiServerState {
            semaphore: Semaphore::new(config.pool_size),
            evaluation_environment: Arc::new(evaluation_environment),
        });

        let (tls_config, cert_watcher) = if let Some(tls_config) = config.tls_config {
            let (tls_config, cert_watcher) =
                create_tls_config_and_watch_certificate_changes(tls_config).await?;
            (Some(tls_config), Some(cert_watcher))
        } else {
            (None, None)
        };

        let mut router = Router::new()
            .route("/audit/{policy_id}", post(audit_handler))
            .route("/validate/{policy_id}", post(validate_handler))
            .route("/validate_raw/{policy_id}", post(validate_raw_handler))
            .with_state(state.clone())
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            );

        if config.enable_pprof {
            activate_memory_profiling().await?;

            let pprof_router = Router::new()
                .route("/debug/pprof/cpu", get(pprof_get_cpu))
                .route("/debug/pprof/heap", get(pprof_get_heap));
            router = Router::new().merge(router).merge(pprof_router);
        }

        let readiness_probe_router = Router::new().route("/readiness", get(readiness_handler));

        Ok(Self {
            router,
            readiness_probe_router,
            callback_handler,
            callback_handler_shutdown_channel_tx,
            addr: config.addr,
            tls_config,
            cert_watcher,
            readiness_probe_addr: config.readiness_probe_addr,
        })
    }

    pub async fn run(self) -> Result<()> {
        let notify = Notify::new();

        let mut callback_handler = self.callback_handler;
        let callback_handler = tokio::spawn(async move {
            info!(status = "init", "CallbackHandler task");
            callback_handler.loop_eval().await;
            info!(status = "exit", "CallbackHandler task");
        });

        let api_handle = axum_server::Handle::new();
        let readiness_handle = axum_server::Handle::new();
        // Close every accepted connection of both servers as soon as `run` stops waiting on
        // them, for any reason: one of the two servers failing, the certificate watch
        // stopping, or the caller cancelling `run` itself. Without this, a connection
        // accepted before that point keeps its own task running, unseen.
        let _shutdown_guard = ServerShutdownGuard {
            api: api_handle.clone(),
            readiness: readiness_handle.clone(),
        };

        let api_server = async {
            if let Some(tls_config) = self.tls_config {
                let server_with_tls =
                    axum_server::bind_rustls(self.addr, tls_config).handle(api_handle);
                notify.notify_one();

                server_with_tls
                    .serve(self.router.into_make_service())
                    .await
                    .map_err(anyhow::Error::from)
            } else {
                let server = axum_server::bind(self.addr).handle(api_handle);
                notify.notify_one();

                server
                    .serve(self.router.into_make_service())
                    .await
                    .map_err(anyhow::Error::from)
            }
        };

        let readiness_probe_server = async {
            notify.notified().await;

            axum_server::bind(self.readiness_probe_addr)
                .handle(readiness_handle)
                .serve(self.readiness_probe_router.into_make_service())
                .await
                .map_err(anyhow::Error::from)
        };

        // Ends only when the certificate watch can no longer detect a change of the TLS
        // files. Without TLS there is no watch, so this future never ends, and try_join!
        // below waits on the two servers instead.
        let cert_watcher = async {
            match self.cert_watcher {
                Some(watcher) => {
                    let e = match watcher.await {
                        Ok(e) => e,
                        Err(e) => anyhow!("Certificate watch task failed: {e}"),
                    };
                    Err::<(), anyhow::Error>(anyhow!("Certificate watch stopped: {e}"))
                }
                None => std::future::pending().await,
            }
        };

        tokio::try_join!(api_server, readiness_probe_server, cert_watcher)?;

        self.callback_handler_shutdown_channel_tx
            .send(())
            .expect("Cannot send shutdown signal to CallbackHandler");
        callback_handler
            .await
            .expect("Cannot wait for CallbackHandler to exit");

        Ok(())
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }
}

fn build_engine(epoch_interruption: bool) -> Result<wasmtime::Engine> {
    let mut wasmtime_config = policy_evaluator_builder::wasmtime_config();
    wasmtime_config.epoch_interruption(epoch_interruption);
    Ok(wasmtime::Engine::new(&wasmtime_config)?)
}

fn precompile_policies(
    engine: &wasmtime::Engine,
    fetched_policies: &FetchedPolicies,
) -> PrecompiledPolicies {
    debug!(
        wasm_modules_count = fetched_policies.len(),
        "instantiating wasmtime::Module objects"
    );

    fetched_policies
        .par_iter()
        .map(|(policy_url, fetched_policy)| match fetched_policy {
            Ok(policy) => {
                let precompiled_policy = PrecompiledPolicy::new(engine, policy);
                debug!(?policy_url, "module compiled");
                (policy_url.clone(), precompiled_policy)
            }
            Err(error) => (policy_url.clone(), Err(anyhow!(error.to_string()))),
        })
        .collect()
}

async fn create_sigstore_trustroot(config: &Config) -> Result<Arc<SigstoreTrustRoot>> {
    // If user provided a trust config file, use it
    if let Some(trust_config_path) = &config.sigstore_trust_config_path {
        return build_sigstore_trust_root_from_config(trust_config_path);
    }

    // Otherwise, use default Sigstore TUF repository
    if !config.sigstore_cache_dir.exists() {
        fs::create_dir_all(&config.sigstore_cache_dir)
            .map_err(|e| anyhow!("Cannot create directory to cache sigstore data: {}", e))?;
    }

    let trust_root = SigstoreTrustRoot::new(Some(config.sigstore_cache_dir.as_path())).await?;

    Ok(Arc::new(trust_root))
}

/// Build a Sigstore trust root from a user-provided ClientTrustConfig JSON file.
///
/// # Security Note
/// This function uses `from_trusted_root_json_unchecked` which does not perform
/// cryptographic validation of the trust root. The caller must ensure that the
/// source ConfigMap is properly protected with RBAC to prevent unauthorized
/// modifications. Users with write access to this ConfigMap can influence
/// policy signature verification.
fn build_sigstore_trust_root_from_config(pki_file: &PathBuf) -> Result<Arc<SigstoreTrustRoot>> {
    debug!(
        "Using user specified Sigstore trust root location: {}",
        pki_file.display()
    );
    let json_bytes = fs::read(pki_file).map_err(|e| {
        anyhow!(
            "could not read Sigstore trust config file {}: {:?}",
            pki_file.display(),
            e
        )
    })?;

    let client_trust_config: ClientTrustConfig = serde_json::from_slice(json_bytes.as_slice())
        .map_err(|e| {
            anyhow!(
                "could not parse Sigstore trust config file {}: {:?}",
                pki_file.display(),
                e
            )
        })?;

    let trust_root = client_trust_config.trusted_root.ok_or_else(|| {
        anyhow!(
            "Sigstore trust config file {} missing trusted_root field",
            pki_file.display()
        )
    })?;

    let trust_root_bytes = serde_json::to_vec(&trust_root)?;
    let trust_root =
        SigstoreTrustRoot::from_trusted_root_json_unchecked(trust_root_bytes.as_slice())?;

    Ok(Arc::new(trust_root))
}
