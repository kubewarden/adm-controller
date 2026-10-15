use std::{path::Path, sync::Arc};

use ::tracing::{info, warn};
use anyhow::{Result, anyhow};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::SliceIter};
// This is required by certificate hot reload when using inotify, which is available only on linux
#[cfg(target_os = "linux")]
use tokio_stream::StreamExt;

use crate::config::TlsConfig;

/// There's no watching of the certificate files on non-linux platforms
/// since we rely on inotify to watch for changes
#[cfg(not(target_os = "linux"))]
async fn create_tls_config_and_watch_certificate_changes(
    tls_config: TlsConfig,
) -> Result<RustlsConfig> {
    let cfg = RustlsConfig::from_pem_file(tls_config.cert_file, tls_config.key_file).await?;
    Ok(cfg)
}

/// Return the RustlsConfig and watch for changes in the certificate files
/// using inotify.
/// When both the certificate and its key are changed, the RustlsConfig is reloaded,
/// causing the https server to use the new certificate.
///
/// The watches are on the directories of the files, not on the files. The kubelet
/// updates a Secret or ConfigMap volume without writing to the files: it writes a new
/// directory and swaps the `..data` symlink with a rename. A watch on a file follows
/// the old inode, and the kernel removes that watch when the kubelet deletes the old
/// directory, so the next updates are not detected. A watch on the directory survives
/// every update.
///
/// Relying on inotify is only available on linux
#[cfg(target_os = "linux")]
pub(crate) async fn create_tls_config_and_watch_certificate_changes(
    tls_config: TlsConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use std::collections::{BTreeSet, HashMap};

    use ::tracing::error;
    use axum_server::tls_rustls::RustlsConfig;
    use inotify::{EventMask, WatchMask};

    // Add the watches before the first load, so that an update between the two is not lost.
    let inotify =
        inotify::Inotify::init().map_err(|e| anyhow!("Cannot initialize inotify: {e}"))?;
    let dirs: BTreeSet<&Path> = [&tls_config.cert_file, &tls_config.key_file]
        .into_iter()
        .chain(tls_config.client_ca_file.iter())
        .map(|path| parent_dir(path))
        .collect();
    let mut watched_dirs = HashMap::new();
    for dir in dirs {
        let watch = inotify
            .watches()
            .add(
                dir,
                WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::ONLYDIR,
            )
            .map_err(|e| anyhow!("Cannot watch directory {}: {e}", dir.display()))?;
        watched_dirs.insert(watch, dir.to_path_buf());
    }

    // Build initial TLS configuration
    let (mut cert, mut key) =
        load_server_cert_and_key(&tls_config.cert_file, &tls_config.key_file).await?;
    let mut client_verifier = if tls_config.client_ca_file.is_empty() {
        None
    } else {
        Some(load_client_ca_certs(tls_config.client_ca_file.clone()).await?)
    };
    let initial_config =
        build_tls_server_config(cert.clone(), key.clone_key(), client_verifier.clone())?;

    let rust_config = RustlsConfig::from_config(Arc::new(initial_config));
    let reloadable_rust_config = rust_config.clone();

    let buffer = [0; 1024];
    let stream = inotify
        .into_event_stream(buffer)
        .map_err(|e| anyhow!("Cannot create inotify event stream: {e}"))?;

    tokio::spawn(async move {
        tokio::pin!(stream);
        let mut cert_changed = false;
        let mut key_changed = false;
        let mut client_ca_changed = false;

        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    warn!("Cannot read inotify event: {e}");
                    continue;
                }
            };

            let changed = if event.mask.contains(EventMask::Q_OVERFLOW) {
                warn!("Inotify event queue overflowed, reloading all the TLS files");
                ChangedFiles {
                    cert: true,
                    key: true,
                    client_ca: !tls_config.client_ca_file.is_empty(),
                }
            } else {
                let Some(dir) = watched_dirs.get(&event.wd) else {
                    continue;
                };
                if event.mask.contains(EventMask::IGNORED) {
                    error!(
                        directory = %dir.display(),
                        "Directory is no longer watched, changes of the TLS files in it will not be detected"
                    );
                    continue;
                }
                let Some(name) = &event.name else {
                    continue;
                };
                changed_files(&tls_config, dir, name)
            };

            if changed.cert {
                info!("TLS certificate file has been modified");
                cert_changed = true;
            }
            if changed.key {
                info!("TLS key file has been modified");
                key_changed = true;
            }
            if changed.client_ca {
                info!("TLS client CA file has been modified");
                client_ca_changed = true;
            }

            if !client_ca_changed && !(cert_changed && key_changed) {
                continue;
            }

            // Reload the client CA certificates if they have changed, keeping the current server certificates unchanged
            if client_ca_changed {
                info!("Reloading client CA certificates");

                client_ca_changed = false;

                match load_client_ca_certs(tls_config.client_ca_file.clone()).await {
                    Ok(cv) => {
                        client_verifier = Some(cv);
                    }
                    Err(e) => {
                        error!("Failed to reload TLS certificates: {e}");
                        continue;
                    }
                }
            }

            // Reload the server certificates if they have changed keeping the current client CA certificates unchanged
            if key_changed && cert_changed {
                info!("Reloading Server TLS certificates");

                cert_changed = false;
                key_changed = false;

                match load_server_cert_and_key(&tls_config.cert_file, &tls_config.key_file).await {
                    Ok(ck) => {
                        (cert, key) = ck;
                    }
                    Err(e) => {
                        error!("Failed to reload TLS certificates: {e}");
                        continue;
                    }
                }
            }

            match build_tls_server_config(cert.clone(), key.clone_key(), client_verifier.clone()) {
                Ok(server_config) => {
                    reloadable_rust_config.reload_from_config(Arc::new(server_config));
                }
                Err(e) => {
                    error!("Failed to reload TLS certificate: {e}");
                }
            }
        }
    });

    Ok(rust_config)
}

/// The name of the symlink that the kubelet swaps when it updates a Secret or ConfigMap volume.
#[cfg(target_os = "linux")]
const KUBELET_DATA_DIR: &str = "..data";

/// The files of the TLS configuration that an inotify event changes.
#[cfg(target_os = "linux")]
#[derive(Debug, Default, PartialEq)]
struct ChangedFiles {
    cert: bool,
    key: bool,
    client_ca: bool,
}

/// Return the directory of the path. The directory of a relative path without a parent is `.`.
#[cfg(target_os = "linux")]
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Return the files of the TLS configuration that an inotify event on `event_name` in `dir` changes.
///
/// An event on `..data` changes all the files in `dir`, because the kubelet swaps them together.
#[cfg(target_os = "linux")]
fn changed_files(tls_config: &TlsConfig, dir: &Path, event_name: &std::ffi::OsStr) -> ChangedFiles {
    let is_changed = |path: &Path| {
        parent_dir(path) == dir
            && (event_name == KUBELET_DATA_DIR || path.file_name() == Some(event_name))
    };

    ChangedFiles {
        cert: is_changed(&tls_config.cert_file),
        key: is_changed(&tls_config.key_file),
        client_ca: tls_config
            .client_ca_file
            .iter()
            .any(|path| is_changed(path)),
    }
}

// Build the TLS server
fn build_tls_server_config(
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> Result<rustls::ServerConfig> {
    if let Some(client_verifier) = client_verifier {
        return Ok(ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert, key)?);
    }

    Ok(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?)
}

// Load the server certificate and key
async fn load_server_cert_and_key(
    cert_file: &Path,
    key_file: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_contents = tokio::fs::read(cert_file).await?;
    let key_contents = tokio::fs::read(key_file).await?;

    let cert_iterator: SliceIter<CertificateDer> =
        rustls_pki_types::pem::SliceIter::new(&cert_contents[..]);

    let certs: Vec<_> = cert_iterator
        .filter_map(|it| {
            if let Err(ref e) = it {
                warn!("Cannot parse client CA certificate: {e}");
            }
            it.ok()
        })
        .collect();

    if certs.len() != 1 {
        return Err(anyhow!(
            "Expected exactly one certificate in certificate file, found {}",
            certs.len()
        ));
    }

    let key_iterator: SliceIter<PrivateKeyDer> =
        rustls_pki_types::pem::SliceIter::new(&key_contents[..]);
    let keys: Vec<PrivateKeyDer> = key_iterator
        .filter_map(|it| {
            if let Err(ref e) = it {
                warn!("Cannot parse private key: {e}");
            }
            it.ok()
        })
        .collect();

    if keys.len() != 1 {
        return Err(anyhow!(
            "Expected exactly one key in key file, found {}",
            keys.len()
        ));
    }

    Ok((certs, keys[0].clone_key()))
}

// Load the client CA certificates and build the client verifier
async fn load_client_ca_certs(
    client_cas: Vec<std::path::PathBuf>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let mut store = RootCertStore::empty();
    for client_ca_file in client_cas {
        let client_ca_contents = tokio::fs::read(&client_ca_file).await?;
        let cert_iterator: SliceIter<CertificateDer> =
            rustls_pki_types::pem::SliceIter::new(&client_ca_contents[..]);

        let client_ca_certs: Vec<_> = cert_iterator
            .filter_map(|it| {
                if let Err(ref e) = it {
                    warn!("Cannot parse client CA certificate: {e}");
                }
                it.ok()
            })
            .collect();
        let (cert_added, cert_ignored) = store.add_parsable_certificates(client_ca_certs);
        info!(
            client_ca_certs_added = cert_added,
            client_ca_certs_ignored = cert_ignored,
            "Loaded client CA certificates"
        );
    }

    WebPkiClientVerifier::builder(Arc::new(store))
        .build()
        .map_err(|e| anyhow!("Cannot build client verifier: {e}"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{ffi::OsStr, path::PathBuf};

    use rstest::rstest;

    use super::*;

    fn tls_config() -> TlsConfig {
        TlsConfig {
            cert_file: PathBuf::from("/pki/tls.crt"),
            key_file: PathBuf::from("/pki/tls.key"),
            client_ca_file: vec![PathBuf::from("/client-ca/client-ca.crt")],
        }
    }

    #[rstest]
    #[case::kubelet_swap_of_the_certificate_volume("/pki", "..data", true, true, false)]
    #[case::kubelet_swap_of_the_client_ca_volume("/client-ca", "..data", false, false, true)]
    #[case::certificate_file("/pki", "tls.crt", true, false, false)]
    #[case::key_file("/pki", "tls.key", false, true, false)]
    #[case::client_ca_file("/client-ca", "client-ca.crt", false, false, true)]
    #[case::kubelet_temporary_symlink("/pki", "..data_tmp", false, false, false)]
    #[case::kubelet_timestamped_directory("/pki", "..2026_10_14_12_00_00.123", false, false, false)]
    #[case::same_name_in_another_directory("/client-ca", "tls.crt", false, false, false)]
    #[case::unrelated_file("/pki", "other.pem", false, false, false)]
    fn test_changed_files(
        #[case] dir: &str,
        #[case] event_name: &str,
        #[case] cert: bool,
        #[case] key: bool,
        #[case] client_ca: bool,
    ) {
        assert_eq!(
            changed_files(&tls_config(), Path::new(dir), OsStr::new(event_name)),
            ChangedFiles {
                cert,
                key,
                client_ca
            }
        );
    }

    #[test]
    fn test_changed_files_with_relative_paths() {
        let tls_config = TlsConfig {
            cert_file: PathBuf::from("tls.crt"),
            key_file: PathBuf::from("tls.key"),
            client_ca_file: vec![],
        };

        assert_eq!(
            changed_files(&tls_config, Path::new("."), OsStr::new("..data")),
            ChangedFiles {
                cert: true,
                key: true,
                client_ca: false
            }
        );
    }

    #[rstest]
    #[case::absolute_path("/pki/tls.crt", "/pki")]
    #[case::relative_path_with_a_directory("certs/tls.crt", "certs")]
    #[case::relative_path_without_a_directory("tls.crt", ".")]
    fn test_parent_dir(#[case] path: &str, #[case] expected: &str) {
        assert_eq!(parent_dir(Path::new(path)), Path::new(expected));
    }
}
