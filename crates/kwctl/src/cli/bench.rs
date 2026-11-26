use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use policy_evaluator::policy_fetcher::store::Store;

use crate::config::pull_and_run::{parse_policy_definitions, parse_pull_and_run_settings};

pub(crate) async fn exec(
    matches: &ArgMatches,
    store: &Store,
    enable_http_policies: bool,
) -> Result<()> {
    let policy_definitions = parse_policy_definitions(matches, store)?;
    let pull_and_run_settings =
        parse_pull_and_run_settings(matches, &policy_definitions, enable_http_policies).await?;
    let benchmark_config = create_benchmark_config(matches)?;

    crate::command::bench::exec(
        &policy_definitions,
        &pull_and_run_settings,
        &benchmark_config,
    )
    .await
}

fn create_benchmark_config(matches: &ArgMatches) -> Result<tiny_bench::BenchmarkConfig> {
    let mut benchmark_cfg = tiny_bench::BenchmarkConfig::default();

    if let Some(measurement_time) = matches.get_one::<String>("measurement_time") {
        let duration: u64 = measurement_time
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'measurement-time' to seconds: {:?}", e))?;
        benchmark_cfg.measurement_time = Duration::from_secs(duration);
    }
    if let Some(num_resamples) = matches.get_one::<String>("num_resamples") {
        let num: usize = num_resamples
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'num-resamples' to number: {:?}", e))?;
        benchmark_cfg.num_resamples = num;
    }
    if let Some(num_samples) = matches.get_one::<String>("num_samples") {
        let num: usize = num_samples
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'num-samples' to number: {:?}", e))?;
        benchmark_cfg.num_samples = num;
    }
    if let Some(warm_up_time) = matches.get_one::<String>("warm_up_time") {
        let duration: u64 = warm_up_time
            .parse()
            .map_err(|e| anyhow!("Cannot convert 'warm-up-time' to seconds: {:?}", e))?;
        benchmark_cfg.warm_up_time = Duration::from_secs(duration);
    }
    benchmark_cfg.dump_results_to_disk = matches.contains_id("dump_results_to_disk");

    Ok(benchmark_cfg)
}
