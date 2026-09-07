extern crate directories;
extern crate reqwest;
extern crate rustls;
extern crate walkdir;

use std::{boxed::Box, fs};

use errors::FetcherResult;
use store::errors::{StoreError, StoreResult};
use url::Url;

pub mod errors;
pub mod fetcher;
mod https;
pub mod policy;
pub mod proxy;
pub mod registry;
pub mod sources;
pub mod store;
pub mod verify;

use crate::{
    errors::{CannotCreateStoragePathError, FetcherError},
    fetcher::{ClientProtocol, PolicyFetcher, TlsVerificationMode},
    https::Https,
    policy::Policy,
    registry::{Registry, build_fully_resolved_reference},
    sources::Sources,
    store::Store,
};

#[macro_use]
extern crate lazy_static;

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

// re-export for usage by kwctl, policy-server, policy-evaluator,...
pub use oci_client;
pub use sigstore;
use tracing::debug;
use url::ParseError;

lazy_static! {
    static ref KNOWN_SCHEMES: HashSet<&'static str> = {
        let mut s = HashSet::new();
        s.insert("file");
        s.insert("http");
        s.insert("https");
        s.insert("registry");
        s
    };
}

#[derive(Debug)]
pub enum PullDestination {
    MainStore,
    Store(PathBuf),
    LocalFile(PathBuf),
}

fn parse_url(url: &str) -> std::result::Result<reqwest::Url, url::ParseError> {
    match Url::parse(url) {
        Ok(u) => {
            if !KNOWN_SCHEMES.contains(u.scheme()) && !url.contains("://") {
                // something like "ghcr.io:443/kubewarden/policy1:latest"
                // is not parsed properly, "ghcr.io" becomes the scheme
                parse_url(format!("registry://{url}").as_str())
            } else {
                Ok(u)
            }
        }
        Err(ParseError::RelativeUrlWithoutBase) => Url::parse(format!("registry://{url}").as_str()),
        Err(e) => Err(e),
    }
}

pub async fn fetch_policy(
    url: &str,
    destination: PullDestination,
    sources: Option<&Sources>,
) -> FetcherResult<Policy> {
    let url = parse_url(url)?;
    match url.scheme() {
        "file" => {
            // no-op: return early
            return Ok(Policy {
                uri: url.to_string(),
                local_path: url
                    .to_file_path()
                    .map_err(|_| FetcherError::InvalidFilePathError(url.to_string()))?,
            });
        }
        "registry" | "http" | "https" => Ok(()),
        _ => Err(StoreError::UnknownSchemeError(url.scheme().to_owned())),
    }?;
    let (store, mut destination) = pull_destination(&url, &destination)?;
    if let Some(store) = store {
        store
            .ensure(&store.policy_full_path(url.as_str(), store::PolicyPath::PrefixOnly)?)
            .map_err(CannotCreateStoragePathError)?;
    }
    match url.scheme() {
        "registry" => {
            // On a registry, the `latest` tag always pulls the latest version
            let reference = build_fully_resolved_reference(url.as_str())?;
            if reference.tag() != Some("latest") && Path::exists(&destination) {
                return Ok(Policy {
                    uri: url.to_string(),
                    local_path: destination,
                });
            }
            // If the reference tag is `latest` and the URL does not contain `:latest`
            // we need to add it to the destination
            if Some("latest") == reference.tag() && !str::ends_with(url.as_str(), ":latest") {
                destination = PathBuf::from(destination.to_string_lossy().to_string() + ":latest");
            }
        }
        "http" | "https" => {
            if Path::exists(&destination) {
                return Ok(Policy {
                    uri: url.to_string(),
                    local_path: destination,
                });
            }
        }
        _ => unreachable!(),
    }
    debug!(?url, "pulling policy");
    let policy_fetcher = url_fetcher(url.scheme())?;
    let sources_default = Sources::default();
    let sources = sources.unwrap_or(&sources_default);

    match policy_fetcher
        .fetch(&url, client_protocol(&url, sources)?, sources)
        .await
    {
        Err(err) => {
            if !sources.is_insecure_source(&host_and_port(&url)?) {
                return Err(FetcherError::SourceError(err));
            }
        }
        Ok(bytes) => return create_file_if_valid(&bytes, &destination, url.to_string()),
    }
    if let Ok(bytes) = policy_fetcher
        .fetch(
            &url,
            ClientProtocol::Https(TlsVerificationMode::NoTlsVerification),
            sources,
        )
        .await
    {
        return create_file_if_valid(&bytes, &destination, url.to_string());
    }

    match policy_fetcher
        .fetch(&url, ClientProtocol::Http, sources)
        .await
    {
        Ok(bytes) => create_file_if_valid(&bytes, &destination, url.to_string()),
        Err(e) => Err(FetcherError::SourceError(e)),
    }
}

fn client_protocol(
    url: &Url,
    sources: &Sources,
) -> std::result::Result<ClientProtocol, errors::InvalidURLError> {
    if let Some(certificates) = sources.source_authority(&host_and_port(url)?) {
        return Ok(ClientProtocol::Https(
            TlsVerificationMode::CustomCaCertificates(certificates),
        ));
    }
    Ok(ClientProtocol::Https(TlsVerificationMode::SystemCa))
}

fn pull_destination(
    url: &Url,
    destination: &PullDestination,
) -> FetcherResult<(Option<Store>, PathBuf)> {
    Ok(match destination {
        PullDestination::MainStore => {
            let store = Store::default();
            let policy_path =
                store.policy_full_path(url.as_str(), store::PolicyPath::PrefixAndFilename)?;
            (Some(store), policy_path)
        }
        PullDestination::Store(root) => {
            let store = Store::new(root);
            let policy_path =
                store.policy_full_path(url.as_str(), store::PolicyPath::PrefixAndFilename)?;
            (Some(store), policy_path)
        }
        PullDestination::LocalFile(destination) => {
            if Path::is_dir(destination) {
                let filename = url.path().split('/').next_back().unwrap();
                (None, destination.join(filename))
            } else {
                (None, PathBuf::from(destination))
            }
        }
    })
}

// Helper function, takes the URL of the policy and allocates the
// right struct to interact with it
#[allow(clippy::box_default)]
fn url_fetcher(scheme: &str) -> StoreResult<Box<dyn PolicyFetcher + Send>> {
    match scheme {
        "http" | "https" => Ok(Box::new(Https::default())),
        "registry" => Ok(Box::new(Registry::new())),
        _ => Err(StoreError::UnknownSchemeError(scheme.to_owned())),
    }
}

pub(crate) fn host_and_port(url: &Url) -> std::result::Result<String, errors::InvalidURLError> {
    Ok(format!(
        "{}{}",
        url.host_str()
            .ok_or_else(|| errors::InvalidURLError(url.to_string()))?,
        url.port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default(),
    ))
}

// Each Wasm file begins with a well known bytes sequence, known as
// "magic bytes" (see https://en.wikipedia.org/wiki/List_of_file_signatures).
//
// The Wasm magic bytes sequence is defined inside of its official specification:
// https://webassembly.github.io/spec/core/bikeshed/#binary-magic
const WASM_MAGIC_NUMBER: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

fn create_file_if_valid(bytes: &[u8], destination: &Path, url: String) -> FetcherResult<Policy> {
    if !bytes.starts_with(&WASM_MAGIC_NUMBER) {
        return Err(FetcherError::InvalidWasmFileError);
    };
    fs::write(destination, bytes).map_err(|e| {
        FetcherError::CannotWriteWasmModuleFile(destination.to_string_lossy().to_string(), e)
    })?;

    Ok(Policy {
        uri: url,
        local_path: destination.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use rstest::*;
    use tempfile::NamedTempFile;

    use super::*;

    fn read_fixture(filename: &Path) -> Vec<u8> {
        let test_data_file = std::env::current_dir()
            .unwrap_or_else(|_| panic!("[test setup error] could not read the current directory"))
            .join("tests")
            .join("test_data")
            .join(filename);

        fs::read(&test_data_file).unwrap_or_else(|_| {
            panic!(
                "[test setup error] could not read file {:?}",
                test_data_file
            )
        })
    }

    fn store_path(path: &str) -> PathBuf {
        Store::default().root.join(store::path::encode_path(path))
    }

    struct UrlParseDetails {
        scheme: String,
        host: Option<String>,
        port: Option<u16>,
        path: String,
    }

    #[rstest]
    #[case("file:///tmp/policy.wasm", Ok(UrlParseDetails{
        scheme: "file".to_string(),
        host: None,
        port: None,
        path: "/tmp/policy.wasm".to_string(),
    }))]
    #[case("registry://ghcr.io/kubewarden/policies/test:1.2", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("ghcr.io".to_string()),
        port: None,
        path: "/kubewarden/policies/test:1.2".to_string(),
    }))]
    #[case("ghcr.io/kubewarden/policies/test:1.2", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("ghcr.io".to_string()),
        port: None,
        path: "/kubewarden/policies/test:1.2".to_string(),
    }))]
    #[case("registry://ghcr.io/kubewarden/policies/test:latest", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("ghcr.io".to_string()),
        port: None,
        path: "/kubewarden/policies/test:latest".to_string(),
    }))]
    #[case("ghcr.io/kubewarden/policies/test:latest", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("ghcr.io".to_string()),
        port: None,
        path: "/kubewarden/policies/test:latest".to_string(),
    }))]
    #[case("registry://ghcr.io/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("ghcr.io".to_string()),
        port: None,
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("ghcr.io/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("ghcr.io".to_string()),
        port: None,
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("registry://registry.local.lan/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("registry.local.lan".to_string()),
        port: None,
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("registry.local.lan/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("registry.local.lan".to_string()),
        port: None,
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("registry://registry.local.lan:5000/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("registry.local.lan".to_string()),
        port: Some(5000),
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("registry.local.lan:5000/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("registry.local.lan".to_string()),
        port: Some(5000),
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("registry://192.168.1.2/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("192.168.1.2".to_string()),
        port: None,
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("registry://192.168.1.2:5000/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "registry".to_string(),
        host: Some("192.168.1.2".to_string()),
        port: Some(5000),
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("http://192.168.1.2:5000/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "http".to_string(),
        host: Some("192.168.1.2".to_string()),
        port: Some(5000),
        path: "/kubewarden/policies/test".to_string(),
    }))]
    #[case("https://registry.local.lan:5000/kubewarden/policies/test", Ok(UrlParseDetails{
        scheme: "https".to_string(),
        host: Some("registry.local.lan".to_string()),
        port: Some(5000),
        path: "/kubewarden/policies/test".to_string(),
    }))]
    fn url_parsing(#[case] url: &str, #[case] expected: FetcherResult<UrlParseDetails>) {
        let res = parse_url(url);
        println!("{url} -> {res:?}");
        assert_eq!(res.is_ok(), expected.is_ok());
        if let Ok(u) = res {
            let expected = expected.unwrap();
            assert_eq!(
                u.scheme(),
                expected.scheme.as_str(),
                "scheme expectation for {url} not met"
            );

            assert_eq!(
                u.host_str().map(|h| h.to_string()),
                expected.host,
                "host expectation for {url} not met"
            );

            assert_eq!(
                u.port(),
                expected.port,
                "port expectation for {url} not met"
            );

            assert_eq!(
                u.path(),
                expected.path.as_str(),
                "path expectation for {url} not met"
            );
        }
    }

    #[test]
    fn local_file_pull_destination_excluding_filename() {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com:1234/path/to/policy.wasm").unwrap(),
                &PullDestination::LocalFile(std::env::current_dir().unwrap()),
            )
            .expect("pull_destination failed"),
            (None, std::env::current_dir().unwrap().join("policy.wasm"),),
        );
    }

    #[test]
    fn local_file_pull_destination_including_filename() {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com:1234/path/to/policy.wasm").unwrap(),
                &PullDestination::LocalFile(
                    std::env::current_dir().unwrap().join("named-policy.wasm")
                ),
            )
            .expect("pull_destination failed"),
            (
                None,
                std::env::current_dir().unwrap().join("named-policy.wasm"),
            ),
        );
    }

    #[test]
    fn store_pull_destination_from_http_with_port() {
        assert_eq!(
            pull_destination(
                &Url::parse("http://host.example.com:1234/path/to/policy.wasm").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("http/host.example.com:1234/path/to/policy.wasm"),
            ),
        );
    }

    #[test]
    fn store_pull_destination_from_http() {
        assert_eq!(
            pull_destination(
                &Url::parse("http://host.example.com/path/to/policy.wasm").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("http/host.example.com/path/to/policy.wasm"),
            ),
        );
    }

    #[test]
    fn store_pull_destination_from_https() {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com/path/to/policy.wasm").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("https/host.example.com/path/to/policy.wasm"),
            ),
        );
    }

    #[test]
    fn store_pull_destination_from_https_with_port() {
        assert_eq!(
            pull_destination(
                &Url::parse("https://host.example.com:1234/path/to/policy.wasm").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("https/host.example.com:1234/path/to/policy.wasm"),
            ),
        );
    }

    #[test]
    fn store_pull_destination_from_registry() {
        assert_eq!(
            pull_destination(
                &Url::parse("registry://host.example.com/path/to/policy:tag").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("registry/host.example.com/path/to/policy:tag"),
            ),
        );
        assert_eq!(
            pull_destination(
                &Url::parse("registry://host.example.com/policy:tag").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("registry/host.example.com/policy:tag"),
            ),
        );
    }

    #[test]
    fn store_pull_destination_from_registry_with_port() {
        assert_eq!(
            pull_destination(
                &Url::parse("registry://host.example.com:1234/path/to/policy:tag").unwrap(),
                &PullDestination::MainStore,
            )
            .expect("pull_destination failed"),
            (
                Some(Store::default()),
                store_path("registry/host.example.com:1234/path/to/policy:tag"),
            ),
        );
    }

    #[test]
    fn save_wasm_files_to_invalid_path() {
        //simulate a write with a invalid file name for linux and windows
        let dest = Path::new(r"\/");
        let file_contents = read_fixture(Path::new("simple.wasm"));

        let outcome = create_file_if_valid(&file_contents, dest, "not relevant".to_string());
        assert!(matches!(
            outcome,
            Err(FetcherError::CannotWriteWasmModuleFile(..))
        ));
    }

    #[rstest]
    #[case::valid_wasm_file("simple.wasm", true)]
    #[case::invalid_wasm_file("auth-present.json", false)]
    fn save_only_wasm_files_to_disk(#[case] fixture_file: &str, #[case] success: bool) {
        let dest = NamedTempFile::new().expect("Cannot create tmp file");
        let file_contents = read_fixture(Path::new(fixture_file));

        let outcome = create_file_if_valid(&file_contents, dest.path(), "not relevant".to_string());
        assert_eq!(outcome.is_ok(), success);
        assert_eq!(
            matches!(outcome, Err(FetcherError::InvalidWasmFileError),),
            !success
        );
    }
}
