use std::path::PathBuf;

use kube::Client;
use lazy_static::lazy_static;
use policy_evaluator::{
    callback_handler::CallbackHandlerBuilder,
    callback_requests::CallbackRequest,
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicyEvaluator, PolicyExecutionMode},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
};
use policy_fetcher::{PullDestination, policy::Policy, sources::Sources};
use tokio::sync::{mpsc, oneshot};

lazy_static! {
    pub(crate) static ref CONTEXT_AWARE_POLICY_FILE: String = format!(
        "file://{}",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("annotated-policy.wasm")
            .to_str()
            .expect("failed to convert path into str")
    );
}

pub(crate) async fn fetch_policy(policy_uri: &str, tempdir: PathBuf) -> Policy {
    policy_evaluator::policy_fetcher::fetch_policy(
        policy_uri,
        PullDestination::LocalFile(tempdir),
        None,
        false,
    )
    .await
    .expect("cannot fetch policy")
}

pub(crate) fn build_policy_evaluator(
    execution_mode: PolicyExecutionMode,
    policy: &Policy,
    eval_ctx: &EvaluationContext,
) -> PolicyEvaluator {
    let mut policy_evaluator_builder = PolicyEvaluatorBuilder::new()
        .execution_mode(execution_mode)
        .policy_file(&policy.local_path)
        .expect("cannot read policy file")
        .enable_wasmtime_cache();

    if let Some(deadline) = eval_ctx.epoch_deadline {
        policy_evaluator_builder =
            policy_evaluator_builder.enable_epoch_interruptions(deadline, deadline);
    }

    let policy_evaluator_pre = policy_evaluator_builder
        .build_pre()
        .expect("cannot build policy evaluator pre");

    policy_evaluator_pre
        .rehydrate(eval_ctx)
        .expect("cannot rehydrate policy evaluator")
}

pub(crate) fn load_request_data(request_file_name: &str) -> Vec<u8> {
    let request_file_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(request_file_name);
    std::fs::read(request_file_path).expect("cannot read request file")
}

pub(crate) async fn setup_callback_handler(
    client: Option<Client>,
    sources: Option<Sources>,
) -> (oneshot::Sender<()>, mpsc::Sender<CallbackRequest>) {
    let (callback_handler_shutdown_channel_tx, callback_handler_shutdown_channel_rx) =
        oneshot::channel();
    let mut callback_builder = CallbackHandlerBuilder::new(callback_handler_shutdown_channel_rx);
    if let Some(client) = client {
        callback_builder = callback_builder.kube_client(client);
    }
    if let Some(sources) = sources {
        callback_builder = callback_builder.registry_config(Some(sources));
    }
    let mut callback_handler = callback_builder
        .build()
        .await
        .expect("cannot build callback handler");
    let callback_handler_channel = callback_handler.sender_channel();
    tokio::spawn(async move {
        callback_handler.loop_eval().await;
    });
    (
        callback_handler_shutdown_channel_tx,
        callback_handler_channel,
    )
}
