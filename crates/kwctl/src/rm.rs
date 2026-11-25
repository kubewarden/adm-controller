use std::path::PathBuf;

use anyhow::{Result, anyhow};
use policy_evaluator::policy_fetcher::store::{PolicyPath, Store};

use crate::utils::LookupError;

pub(crate) fn rm(uri_or_sha_prefix: &str, store: &Store) -> Result<()> {
    let uri = crate::utils::get_uri(&uri_or_sha_prefix.to_string(), store)?;

    if store.get_policy_by_uri(&uri)?.is_none() {
        return Err(anyhow!(LookupError::PolicyMissing(uri)));
    }

    let policy_path = store.policy_full_path(&uri, PolicyPath::PrefixAndFilename)?;
    std::fs::remove_file(&policy_path)
        .map_err(|err| anyhow!("could not delete policy {}: {}", uri, err))?;

    // Given a policy in the store, try to cleanup all intermediate
    // directories up to the store root, from the innermost to the
    // outermost. We don't care about errors: we just try to `rmdir`
    // every directory up to the store root in reverse order to clean
    // up as much as possible -- if possible.
    {
        let mut prefix = store.root.clone();
        let policy_leading_store_components = policy_path
            .iter()
            .map(|component| {
                prefix = prefix.join(component);
                prefix.clone()
            })
            .collect::<Vec<PathBuf>>();

        policy_leading_store_components
            .iter()
            .rev()
            .skip(1) // policy name
            .take(policy_leading_store_components.len() - store.root.components().count())
            .for_each(|store_component| {
                #[allow(unused_must_use)]
                {
                    // try to clean up empty dirs. Ignore errors.
                    std::fs::remove_dir(store.root.join(store_component));
                }
            });
    }

    Ok(())
}
