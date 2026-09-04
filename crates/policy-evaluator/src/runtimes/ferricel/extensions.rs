mod crypto;
mod helpers;
mod kubernetes;
mod net;
mod oci;
mod sigstore;

use std::{collections::BTreeSet, sync::Arc};

use ferricel_core::{
    compiler::vap::{kw_k8s_get_extension, kw_k8s_list_extension},
    runtime::Extensions,
};
use ferricel_types::extensions::{BuilderChainDecl, ExtensionDecl, UsedExtension};

use crate::evaluation_context::EvaluationContext;

// ─── Compile-time declarations (used by kwctl to configure the ferricel compiler) ─────

/// All `BuilderChainDecl`s that must be registered on the ferricel compiler
/// when compiling a VAP policy that may use Kubewarden host capabilities.
///
/// Note: `kw.k8s` is auto-registered by ferricel-core's `compile_vap_from_policy`
/// and must NOT be included here.
pub fn compiler_builder_chains() -> Vec<BuilderChainDecl> {
    vec![oci::chain(), crypto::chain(), sigstore::chain()]
}

/// All `ExtensionDecl`s that must be registered on the ferricel compiler
/// (flat extensions, not covered by builder chains).
pub fn compiler_extension_decls() -> Vec<ExtensionDecl> {
    vec![
        net::lookup_host_extension(),
        oci::manifest_extension(),
        oci::manifest_digest_extension(),
        oci::manifest_config_extension(),
        crypto::verify_extension(),
        crypto::is_trusted_extension(),
        crypto::reason_extension(),
        sigstore::pub_key_verify_extension(),
        sigstore::keyless_verify_extension(),
        sigstore::keyless_prefix_verify_extension(),
        sigstore::github_actions_verify_extension(),
        sigstore::certificate_verify_extension(),
        sigstore::digest_extension(),
    ]
}

// ─── Runtime extensions map ───────────────────────────────────────────────────

/// Extract the first element (the builder map) from a guest-supplied
/// argument list.
///
/// The wasm host-call trampoline rejects a call whose `args.len()` doesn't match
/// the registered `ExtensionDecl::num_args` *before* invoking the closure, so
/// every handler here can already trust that `args` has exactly one element.
/// This helper is a defense-in-depth guard, not the primary line of defense:
/// it protects against a decl/handler mismatch introduced by a future edit
/// (e.g. a handler added with the wrong `num_args`) and against the closures
/// being invoked directly, as the unit tests below do. Every builder handler
/// must go through this helper instead of indexing `args[0]` directly, so
/// that a missing argument turns into a controlled `Err` rather than a host
/// panic in either case.
fn builder_arg<'a>(
    args: &'a [serde_json::Value],
    name: &str,
) -> Result<&'a serde_json::Value, String> {
    args.first()
        .ok_or_else(|| format!("{name}: expected a builder map argument, got none"))
}

/// Build the [`Extensions`] registry that is passed to `EnginePre::rehydrate`
/// for every ferricel policy evaluation.
///
/// Every handler is always registered. Handlers that require a callback
/// channel return an error if `eval_ctx.callback_channel` is `None` rather
/// than being omitted from the registry. This way CEL expressions that call
/// those functions receive a clear error message instead of an "extension not
/// found" error from the wasm runtime.
///
/// Every registration pairs the handler with the same [`ExtensionDecl`] used
/// to configure the compiler (see [`compiler_extension_decls`] and
/// [`kw_k8s_get_extension`]/[`kw_k8s_list_extension`]), so the compile-time
/// and runtime argument counts can never drift apart. Rembmer, `ferricel-core`
/// enforces `args.len() == decl.num_args` for every guest call before it
/// reaches these closures.
///
/// Every handler that performs a host call routes through
/// [`crate::runtimes::callback::host_callback_typed`] -- the single
/// authorization gate for the callback channel, which waPC/Wasi policies also
/// reach via their `host_callback` adapter. This enforces both the
/// host-capability allow list (`eval_ctx.host_capabilities`) and, for
/// `kw.k8s.get`/`kw.k8s.list`, the Kubernetes resource allow list
/// (`eval_ctx.ctx_aware_resources_allow_list`), so a ferricel policy can never
/// use a host capability or read a Kubernetes resource that its
/// `EvaluationContext` denies.
///
/// An `Err(String)` returned by any handler becomes a CEL runtime error at
/// the call site (unless absorbed by `||`/`&&`). A CEL runtime error inside
/// a VAP `matchCondition` or `validation` always fails the evaluation.
pub(crate) fn build_extensions(eval_ctx: &EvaluationContext) -> Extensions {
    let mut m = Extensions::new();

    // ── kw.k8s ────────────────────────────────────────────────────────────────
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            kw_k8s_get_extension(),
            move |args: Vec<serde_json::Value>| {
                kubernetes::get_handler(&ctx, builder_arg(&args, "kw.k8s.get")?)
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            kw_k8s_list_extension(),
            move |args: Vec<serde_json::Value>| {
                kubernetes::list_handler(&ctx, builder_arg(&args, "kw.k8s.list")?)
            },
        );
    }

    // ── kw.oci ────────────────────────────────────────────────────────────────
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            oci::manifest_extension(),
            move |args: Vec<serde_json::Value>| {
                oci::manifest_handler(&ctx, builder_arg(&args, "kw.oci.manifest")?)
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            oci::manifest_digest_extension(),
            move |args: Vec<serde_json::Value>| {
                oci::manifest_digest_handler(&ctx, builder_arg(&args, "kw.oci.manifestDigest")?)
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            oci::manifest_config_extension(),
            move |args: Vec<serde_json::Value>| {
                oci::manifest_config_handler(&ctx, builder_arg(&args, "kw.oci.manifestConfig")?)
            },
        );
    }

    // ── kw.net ────────────────────────────────────────────────────────────────
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            net::lookup_host_extension(),
            move |args: Vec<serde_json::Value>| net::lookup_host_handler(&ctx, &args),
        );
    }

    // ── kw.crypto ─────────────────────────────────────────────────────────────
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            crypto::verify_extension(),
            move |args: Vec<serde_json::Value>| {
                crypto::verify_handler(&ctx, builder_arg(&args, "kw.crypto.verify")?)
            },
        );
    }
    // Shared accessor: reads "trusted" (crypto) or "is_trusted" (sigstore).
    m.register(
        crypto::is_trusted_extension(),
        |args: Vec<serde_json::Value>| crypto::is_trusted_handler(&args),
    );
    m.register(
        crypto::reason_extension(),
        |args: Vec<serde_json::Value>| crypto::reason_handler(&args),
    );

    // ── kw.sigstore ───────────────────────────────────────────────────────────
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            sigstore::pub_key_verify_extension(),
            move |args: Vec<serde_json::Value>| {
                sigstore::pub_key_verify_handler(
                    &ctx,
                    builder_arg(&args, "kw.sigstore.pubKeyVerify")?,
                )
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            sigstore::keyless_verify_extension(),
            move |args: Vec<serde_json::Value>| {
                sigstore::keyless_verify_handler(
                    &ctx,
                    builder_arg(&args, "kw.sigstore.keylessVerify")?,
                )
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            sigstore::keyless_prefix_verify_extension(),
            move |args: Vec<serde_json::Value>| {
                sigstore::keyless_prefix_verify_handler(
                    &ctx,
                    builder_arg(&args, "kw.sigstore.keylessPrefixVerify")?,
                )
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            sigstore::github_actions_verify_extension(),
            move |args: Vec<serde_json::Value>| {
                sigstore::github_actions_verify_handler(
                    &ctx,
                    builder_arg(&args, "kw.sigstore.githubActionsVerify")?,
                )
            },
        );
    }
    {
        let ctx = Arc::new(eval_ctx.clone());
        m.register(
            sigstore::certificate_verify_extension(),
            move |args: Vec<serde_json::Value>| {
                sigstore::certificate_verify_handler(
                    &ctx,
                    builder_arg(&args, "kw.sigstore.certificateVerify")?,
                )
            },
        );
    }
    // Sigstore-only accessor: reads "digest" from the VerificationResponse.
    m.register(
        sigstore::digest_extension(),
        |args: Vec<serde_json::Value>| sigstore::digest_handler(&args),
    );

    m
}

// ─── Host-capability mapping ──────────────────────────────────────────────────

/// Map the host extensions a compiled ferricel module may call (as reported by
/// [`ferricel_core::extensions_used`]) to the Kubewarden host-capability path
/// strings used in policy metadata (`hostCapabilities`).
///
/// Non-namespaced in-wasm accessors (`isTrusted`, `reason`, `digest`) map to
/// nothing. Any unrecognized extension is skipped and a `tracing::warn!` is
/// emitted so that drift between registered extensions and this mapping is
/// visible in logs.
///
/// `kw.k8s/list` maps to *both* `kubernetes/list_resources_by_namespace` and
/// `kubernetes/list_resources_all` because the runtime chooses between the two
/// variants at evaluation time based on whether a namespace is present in the
/// builder map.
pub fn host_capabilities(used: &[UsedExtension]) -> BTreeSet<String> {
    let mut caps = BTreeSet::new();
    for ext in used {
        match (ext.namespace.as_deref(), ext.function.as_str()) {
            // kw.k8s
            (Some("kw.k8s"), "get") => {
                caps.insert("kubernetes/get_resource".to_string());
            }
            (Some("kw.k8s"), "list") => {
                // Both variants are possible; the namespace field in the
                // accumulated builder map selects between them at runtime.
                caps.insert("kubernetes/list_resources_by_namespace".to_string());
                caps.insert("kubernetes/list_resources_all".to_string());
            }
            // kw.oci
            (Some("kw.oci"), "manifest") => {
                caps.insert("oci/v1/oci_manifest".to_string());
            }
            (Some("kw.oci"), "manifestDigest") => {
                caps.insert("oci/v1/manifest_digest".to_string());
            }
            (Some("kw.oci"), "manifestConfig") => {
                caps.insert("oci/v1/oci_manifest_config".to_string());
            }
            // kw.net
            (Some("kw.net"), "lookupHost") => {
                caps.insert("net/v1/dns_lookup_host".to_string());
            }
            // kw.crypto
            (Some("kw.crypto"), "verify") => {
                caps.insert("crypto/v1/is_certificate_trusted".to_string());
            }
            // kw.sigstore — all five verify variants route through oci/v2/verify
            (Some("kw.sigstore"), "pubKeyVerify")
            | (Some("kw.sigstore"), "keylessVerify")
            | (Some("kw.sigstore"), "keylessPrefixVerify")
            | (Some("kw.sigstore"), "githubActionsVerify")
            | (Some("kw.sigstore"), "certificateVerify") => {
                caps.insert("oci/v2/verify".to_string());
            }
            // In-wasm accessors — no host call, no capability needed.
            (None, "isTrusted") | (None, "reason") | (None, "digest") => {}
            // Unknown / future extension — skip but make drift visible.
            (ns, func) => {
                tracing::warn!(
                    namespace = ns.unwrap_or("(none)"),
                    function = func,
                    "ferricel host extension has no known Kubewarden host-capability \
                     mapping; omitting from policy metadata hostCapabilities"
                );
            }
        }
    }
    caps
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn ext(namespace: Option<&str>, function: &str) -> UsedExtension {
        UsedExtension {
            namespace: namespace.map(str::to_owned),
            function: function.to_owned(),
        }
    }

    // ── single-extension → single-capability mapping (rstest table) ───────────

    #[rstest]
    // kw.k8s
    #[case(Some("kw.k8s"), "get", "kubernetes/get_resource")]
    // kw.oci
    #[case(Some("kw.oci"), "manifest", "oci/v1/oci_manifest")]
    #[case(Some("kw.oci"), "manifestDigest", "oci/v1/manifest_digest")]
    #[case(Some("kw.oci"), "manifestConfig", "oci/v1/oci_manifest_config")]
    // kw.net
    #[case(Some("kw.net"), "lookupHost", "net/v1/dns_lookup_host")]
    // kw.crypto
    #[case(Some("kw.crypto"), "verify", "crypto/v1/is_certificate_trusted")]
    // kw.sigstore — all five verify variants map to oci/v2/verify
    #[case(Some("kw.sigstore"), "pubKeyVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "keylessVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "keylessPrefixVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "githubActionsVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "certificateVerify", "oci/v2/verify")]
    fn single_extension_maps_to_expected_capability(
        #[case] namespace: Option<&str>,
        #[case] function: &str,
        #[case] expected_cap: &str,
    ) {
        let caps = host_capabilities(&[ext(namespace, function)]);
        assert_eq!(caps, BTreeSet::from([expected_cap.to_string()]));
    }

    // ── kw.k8s/list → two capabilities ───────────────────────────────────────

    #[test]
    fn kw_k8s_list_maps_to_both_list_variants() {
        let caps = host_capabilities(&[ext(Some("kw.k8s"), "list")]);
        assert_eq!(
            caps,
            BTreeSet::from([
                "kubernetes/list_resources_by_namespace".to_string(),
                "kubernetes/list_resources_all".to_string(),
            ])
        );
    }

    // ── sigstore deduplication ────────────────────────────────────────────────

    #[test]
    fn sigstore_deduplicates_oci_v2_verify() {
        // Multiple sigstore verify variants in one module → single "oci/v2/verify"
        let caps = host_capabilities(&[
            ext(Some("kw.sigstore"), "pubKeyVerify"),
            ext(Some("kw.sigstore"), "keylessVerify"),
        ]);
        assert_eq!(caps, BTreeSet::from(["oci/v2/verify".to_string()]));
    }

    // ── accessor extensions produce no capabilities ───────────────────────────

    #[test]
    fn accessors_produce_no_capabilities() {
        let caps = host_capabilities(&[
            ext(None, "isTrusted"),
            ext(None, "reason"),
            ext(None, "digest"),
        ]);
        assert!(caps.is_empty());
    }

    // ── unknown extension → empty + warn (no panic) ───────────────────────────

    #[test]
    fn unknown_extension_is_skipped_without_panic() {
        let caps = host_capabilities(&[ext(Some("kw.unknown"), "future_fn")]);
        assert!(caps.is_empty());
    }

    // ── empty input ───────────────────────────────────────────────────────────

    #[test]
    fn empty_used_list_produces_empty_capabilities() {
        let caps = host_capabilities(&[]);
        assert!(caps.is_empty());
    }

    // ── drift guard: every namespaced handler in build_extensions has a mapping ─

    #[test]
    fn all_namespaced_handlers_have_a_capability_mapping() {
        // Every ExtensionKey with Some(namespace) that is registered in
        // build_extensions should produce at least one capability path.
        // This test will fail if a new namespaced extension is added to
        // build_extensions without a corresponding entry in host_capabilities().
        let namespaced_handlers: Vec<(&str, &str)> = vec![
            ("kw.k8s", "get"),
            ("kw.k8s", "list"),
            ("kw.oci", "manifest"),
            ("kw.oci", "manifestDigest"),
            ("kw.oci", "manifestConfig"),
            ("kw.net", "lookupHost"),
            ("kw.crypto", "verify"),
            ("kw.sigstore", "pubKeyVerify"),
            ("kw.sigstore", "keylessVerify"),
            ("kw.sigstore", "keylessPrefixVerify"),
            ("kw.sigstore", "githubActionsVerify"),
            ("kw.sigstore", "certificateVerify"),
        ];
        for (ns, func) in namespaced_handlers {
            let caps = host_capabilities(&[ext(Some(ns), func)]);
            assert!(
                !caps.is_empty(),
                "namespaced extension {ns}/{func} has no host-capability mapping"
            );
        }
    }

    // ── untrusted-guest arity guard ────────────────────────────────────────────

    #[test]
    fn every_registered_extension_rejects_empty_args_without_panicking() {
        // Ferricel-core rejects a call whose argument count doesn't
        // match the registered `ExtensionDecl::num_args` before it ever
        // reaches the closure, but this is a defense-in-depth test for the
        // closures themselves (see `builder_arg`'s doc comment): it protects
        // against a decl/handler mismatch and against the closures being
        // invoked directly, as done here.
        let exts = build_extensions(&EvaluationContext::default());
        let decls: Vec<ExtensionDecl> = exts.decls().cloned().collect();
        assert!(
            !decls.is_empty(),
            "expected at least one registered extension"
        );
        for decl in decls {
            let key =
                ferricel_core::ExtensionKey::new(decl.namespace.clone(), decl.function.clone());
            let ext = exts.get(&key).unwrap_or_else(|| {
                panic!("decl {decl:?} not found in its own Extensions registry")
            });
            let result = (ext.implementation)(vec![]);
            assert!(
                result.is_err(),
                "extension {decl:?} did not return Err when called with empty args"
            );
        }
    }

    // ── compile-time / runtime decl drift guard ────────────────────────────────

    #[test]
    fn runtime_decls_match_compiler_decls() {
        // The runtime `Extensions` registry built by `build_extensions` must
        // declare exactly the same `ExtensionDecl`s (namespace, function,
        // calling style, and -- crucially -- `num_args`) that the compiler is
        // configured with. Otherwise ferricel-core's runtime arity check
        // (`args.len() == decl.num_args`) could silently diverge from what
        // the compiler emitted, defeating the type-checking the compiler
        // performs at each CEL call site.
        //
        // `kw.k8s.get`/`kw.k8s.list` are not in `compiler_extension_decls`
        // because the *compiler* auto-registers the `kw.k8s` builder chain
        // (see `compiler_builder_chains`'s doc comment); we compare against
        // their own decl constructors instead.
        let runtime_decls: BTreeSet<ExtensionDecl> =
            build_extensions(&EvaluationContext::default())
                .decls()
                .cloned()
                .collect();

        let mut expected: BTreeSet<ExtensionDecl> =
            compiler_extension_decls().into_iter().collect();
        expected.insert(kw_k8s_get_extension());
        expected.insert(kw_k8s_list_extension());

        assert_eq!(runtime_decls, expected);
    }

    // ── every builder-handler decl expects at least one argument ───────────────

    #[test]
    fn every_registered_decl_has_at_least_one_arg() {
        // Every handler registered in `build_extensions` reads `args[0]` (via
        // `builder_arg` or, for `kw.net.lookupHost`/`isTrusted`/`reason`/
        // `digest`, via `.first()` directly). If a future decl were
        // registered with `num_args: 0`, ferricel-core's arity check would
        // let a zero-arg call reach the closure and `builder_arg` would then
        // (correctly) reject it -- but the decl itself would be wrong. This
        // test catches that class of mistake independently of arity
        // enforcement.
        for decl in build_extensions(&EvaluationContext::default()).decls() {
            assert!(
                decl.num_args >= 1,
                "decl {decl:?} declares num_args=0 but its handler expects an argument"
            );
        }
    }
}
