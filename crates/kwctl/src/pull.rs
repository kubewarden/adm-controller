use std::time::Duration;

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use policy_evaluator::policy_fetcher::{
    PullDestination, fetch_policy, policy::Policy, sources::Sources,
};

pub(crate) async fn pull(
    uri: &str,
    sources: Option<&Sources>,
    destination: PullDestination,
    enable_http_policies: bool,
) -> Result<Policy> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .expect("cannot set spinner template"),
    );
    pb.set_message(format!("Pulling policy from {}", uri));
    pb.enable_steady_tick(Duration::from_millis(100));

    let result = fetch_policy(uri, destination, sources, enable_http_policies)
        .await
        .map_err(anyhow::Error::new);

    match &result {
        Ok(_) => pb.finish_with_message(format!("Successfully pulled policy from {}", uri)),
        Err(e) => pb.finish_with_message(format!("Failed to pull policy: {}", e)),
    }

    result
}
