static KNOWN_REMOTE_SCHEMES: &[&str] = &["registry"];

/// Returns true if the scheme is a known remote scheme.
pub(crate) fn is_known_remote_scheme(scheme: &str) -> bool {
    KNOWN_REMOTE_SCHEMES.contains(&scheme)
}
