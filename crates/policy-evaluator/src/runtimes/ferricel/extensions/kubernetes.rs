use std::sync::Arc;

use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{call_host, parse_field_masks, str_field},
};

pub(crate) fn get_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let api_version = str_field(builder_map, "apiVersion")?;
    let kind = str_field(builder_map, "kind")?;
    let name = str_field(builder_map, "name")?;
    let namespace = builder_map["namespace"].as_str().map(str::to_owned);
    let field_masks = parse_field_masks(builder_map);

    call_host(
        eval_ctx,
        "kubernetes",
        "get_resource",
        CallbackRequestType::KubernetesGetResource {
            api_version,
            kind,
            name,
            namespace,
            disable_cache: false,
            field_masks,
        },
    )
}

pub(crate) fn list_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let api_version = str_field(builder_map, "apiVersion")?;
    let kind = str_field(builder_map, "kind")?;
    let label_selector = builder_map["labelSelector"].as_str().map(str::to_owned);
    let field_selector = builder_map["fieldSelector"].as_str().map(str::to_owned);
    let field_masks = parse_field_masks(builder_map);

    let (operation, request_type) = if let Some(namespace) = builder_map["namespace"].as_str() {
        (
            "list_resources_by_namespace",
            CallbackRequestType::KubernetesListResourceNamespace {
                api_version,
                kind,
                namespace: namespace.to_owned(),
                label_selector,
                field_selector,
                field_masks,
            },
        )
    } else {
        (
            "list_resources_all",
            CallbackRequestType::KubernetesListResourceAll {
                api_version,
                kind,
                label_selector,
                field_selector,
                field_masks,
            },
        )
    };

    call_host(eval_ctx, "kubernetes", operation, request_type)
}
