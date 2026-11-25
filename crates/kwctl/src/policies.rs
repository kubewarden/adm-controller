use anyhow::{Result, anyhow};
use policy_evaluator::{
    policy_fetcher::{policy::Policy, store::Store},
    policy_metadata::Metadata as PolicyMetadata,
};
use prettytable::{Table, format, row};

pub(crate) fn list(store: &Store) -> Result<()> {
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
