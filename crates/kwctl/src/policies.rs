use anyhow::{Result, anyhow};
use policy_evaluator::{
    policy_fetcher::{http_policies, policy::Policy, store::Store},
    policy_metadata::Metadata as PolicyMetadata,
};
use prettytable::{Table, format, row};
use tracing::warn;

pub(crate) fn list(store: &Store, enable_http_policies: bool) -> Result<()> {
    if !enable_http_policies {
        // Best effort: hidden entries must not prevent the listing of usable policies.
        if let Err(error) = warn_about_hidden_http_policies(store) {
            warn!(%error, "cannot count the hidden policies from http:// or https:// URLs");
        }
    }

    let policies = policy_list(store)?;
    if policies.is_empty() {
        return Ok(());
    }
    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    table.set_titles(row![
        "Policy",
        "Mutating",
        "Context aware",
        "SHA-256",
        "Size"
    ]);
    for policy in policies {
        let (mutating, context_aware) = if let Some(policy_metadata) =
            PolicyMetadata::from_path(&policy.local_path)
                .map_err(|e| anyhow!("error processing metadata of policy {}: {:?}", policy, e))?
        {
            let mutating = if policy_metadata.mutating {
                "yes"
            } else {
                "no"
            };

            let context_aware = if policy_metadata.context_aware_resources.is_empty() {
                "no"
            } else {
                "yes"
            };

            (mutating, context_aware)
        } else {
            ("unknown", "no")
        };

        let mut sha256sum = policy.digest()?;
        sha256sum.truncate(12);

        let policy_filesystem_metadata = std::fs::metadata(&policy.local_path)?;

        table.add_row(row![
            format!("{policy}"),
            mutating,
            context_aware,
            sha256sum,
            humansize::format_size(policy_filesystem_metadata.len(), humansize::DECIMAL),
        ]);
    }
    table.printstd();
    Ok(())
}

fn policy_list(store: &Store) -> Result<Vec<Policy>> {
    store.list().map_err(anyhow::Error::new)
}

fn warn_about_hidden_http_policies(store: &Store) -> Result<()> {
    let hidden = http_policies::count_hidden(&store.root)?;
    if hidden > 0 {
        warn!(
            "{hidden} policies from http:// or https:// URLs are hidden. Use --enable-http-policies to show them"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A dangling symlink makes the walk of the `https` directory fail. The
    // store skips that directory when the flag is off, so the listing must
    // not fail because of it.
    #[cfg(unix)]
    #[test]
    fn http_policies_list_ignores_unreadable_hidden_entries() {
        let store_root = tempfile::tempdir().expect("cannot create the temporary directory");
        let host_dir = store_root.path().join("https/host.example.com");
        std::fs::create_dir_all(&host_dir).expect("cannot create the store directory");
        std::os::unix::fs::symlink(
            store_root.path().join("does-not-exist"),
            host_dir.join("policy.wasm"),
        )
        .expect("cannot create the symlink");

        list(&Store::new(store_root.path(), false), false).expect("cannot list the policies");
    }
}
