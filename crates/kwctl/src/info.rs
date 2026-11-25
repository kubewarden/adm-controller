use anyhow::Result;
use clap::crate_version;
use itertools::Itertools;
use policy_evaluator::{
    burrego,
    policy_fetcher::store::{DEFAULT_ROOT, DEFAULT_STORE_ROOT},
};

pub(crate) fn info() -> Result<()> {
    let builtins: String = burrego::get_builtins()
        .keys()
        .sorted()
        .map(|builtin| format!("  - {builtin}"))
        .join("\n");

    println!(
        r#"kwctl version: {}

Open Policy Agent/Gatekeeper implemented builtins:
{}

Policy store: {}
Config directory: {}
kwctl cache directory: {}
    "#,
        crate_version!(),
        builtins,
        DEFAULT_STORE_ROOT.to_string_lossy(),
        DEFAULT_ROOT.config_dir().to_string_lossy(),
        crate::scaffold::DEFAULT_KWCTL_CACHE.to_string_lossy(),
    );

    Ok(())
}
