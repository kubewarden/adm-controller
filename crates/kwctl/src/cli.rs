use std::path::PathBuf;

use clap::{
    Arg, ArgAction, ArgGroup, Command, builder::PossibleValuesParser, crate_authors,
    crate_description, crate_name, crate_version, value_parser,
};
use lazy_static::lazy_static;

pub(crate) mod bench;
pub(crate) mod run;

lazy_static! {
    static ref VERSION_AND_BUILTINS: String = {
        format!(
            r#"{}

Use the `info` command to display system information.
"#,
            crate_version!(),
        )
    };
}

static RUN_AND_BENCH_COMMON_LONG_ABOUT: &str = color_print::cstr!(
    r#"The policy can be specified in the following ways:
- <i>URI</i>: e.g., `registry://ghcr.io/kubewarden/policies/psp-policy:latest` or `https://example.com/kubewarden/policies/main/psp-policy/psp-policy.wasm`
- <i>SHA prefix</i>: e.g., `c3b80a10f9c3` (requires the policy to be already pulled)
- <i>Local WASM file</i>: e.g., `file://home/tux/new-policy/psp-policy.wasm`
- <i>Local YAML file</i>: e.g., `file://home/tux/cluster-admission-policy.yaml` (contains declarations of Kubewarden Custom Resources like `ClusterAdmissionPolicy`, `AdmissionPolicy`, etc.)

<strong><u>Default Behavior</u></strong>:
If the schema is omitted, `file://` is assumed, rooted in the current directory.

<strong><u>Notes on Kubewarden Custom Resources</u></strong>:
- Flags `--request-path`, `--settings-path`, and `--settings-json` are ignored; settings are read from the Custom Resource definition.
- The `--execution-mode` flag applies to all policies in the YAML file.
- The `--raw` flag cannot be used, as Kubewarden's Custom Resources do not support `raw` policies.

Only the following attributes of the Custom Resource Definition (CRD) are evaluated:
- Policy module
- Policy settings
- Context-aware resources the policy can access

Other fields, such as `rules`, `matchConditions`, `objectSelector`, and `namespaceSelector`, are ignored.

A YAML file may contain multiple Custom Resource declarations. In this case, `kwctl` evaluates
each policy in the file using the same request during each evaluation.
"#
);

static PROXY_ENV_VARS_COMMON_LONG_ABOUT: &str = r#"It respects standard proxy environment variables when downloading policies:
- HTTP_PROXY or http_proxy: proxy server for HTTP requests
- HTTPS_PROXY or https_proxy: proxy server for HTTPS requests
- NO_PROXY or no_proxy: comma-separated list of hosts to exclude from proxying"#;

// Minimum set of flags required to pull a policy from a registry
fn pull_shared_flags() -> Vec<Arg> {
    vec![
        Arg::new("docker-config-json-path")
            .long("docker-config-json-path")
            .value_name("DOCKER_CONFIG")
            .help("Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details"),
        Arg::new("sources-path")
            .long("sources-path")
            .value_name("PATH")
            .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        Arg::new("verification-config-path")
            .long("verification-config-path")
            .value_name("PATH")
            .help("YAML file holding verification config information (signatures, public keys...)"),
        Arg::new("verification-key")
            .short('k')
            .long("verification-key")
            .action(ArgAction::Append)
            .number_of_values(1)
            .value_name("PATH")
            .help("Path to key used to verify the policy. Can be repeated multiple times"),
        Arg::new("verification-annotation")
            .short('a')
            .long("verification-annotation")
            .action(ArgAction::Append)
            .number_of_values(1)
            .value_name("KEY=VALUE")
            .help("Annotation in key=value format. Can be repeated multiple times"),
        Arg::new("cert-email")
            .long("cert-email")
            .number_of_values(1)
            .value_name("VALUE")
            .help("Expected email in Fulcio certificate"),
        Arg::new("cert-oidc-issuer")
            .long("cert-oidc-issuer")
            .number_of_values(1)
            .value_name("VALUE")
            .help("Expected OIDC issuer in Fulcio certificates"),
        Arg::new("github-owner")
            .long("github-owner")
            .number_of_values(1)
            .value_name("VALUE")
            .help("GitHub owner expected in the certificates generated in CD pipelines"),
        Arg::new("github-repo")
            .long("github-repo")
            .number_of_values(1)
            .value_name("VALUE")
            .help("GitHub repository expected in the certificates generated in CD pipelines"),
       Arg::new("sigstore-trust-config")
           .long("sigstore-trust-config")
           .value_parser(value_parser!(PathBuf))
           .value_name("PATH")
           .help("JSON-formatted file conforming to the ClientTrustConfig message in the Sigstore protobuf specs. This file configures the entire Sigstore instance state, including the URIs used to access the CA and artifact transparency services as well as the cryptographic root of trust itself"),
    ]
}

fn subcommand_pull() -> Command {
    let mut args = pull_shared_flags();
    args.extend_from_slice(&[Arg::new("output-path")
        .short('o')
        .long("output-path")
        .value_name("PATH")
        .help("Output file. If not provided will be downloaded to the Kubewarden store")]);
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("uri")
            .required(true)
            .index(1)
            .help("Policy URI. Supported schemes: registry://, https://, file://"),
    );

    Command::new("pull")
        .about("Pulls a Kubewarden policy from a given URI")
        .after_long_help(PROXY_ENV_VARS_COMMON_LONG_ABOUT.to_string())
        .args(args)
}

fn subcommand_verify() -> Command {
    let mut args = vec![
        Arg::new("docker-config-json-path")
            .long("docker-config-json-path")
            .value_name("PATH")
            .help("Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details"),
        Arg::new("sources-path")
            .long("sources-path")
            .value_name("PATH")
            .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        Arg::new("verification-config-path")
            .long("verification-config-path")
            .value_name("PATH")
            .help("YAML file holding verification config information (signatures, public keys...)"),
        Arg::new("verification-key")
            .short('k')
            .long("verification-key")
            .action(ArgAction::Append)
            .number_of_values(1)
            .value_name("PATH")
            .help("Path to key used to verify the policy. Can be repeated multiple times"),
        Arg::new("verification-annotation")
            .short('a')
            .long("verification-annotation")
            .action(ArgAction::Append)
            .number_of_values(1)
            .value_name("KEY=VALUE")
            .help("Annotation in key=value format. Can be repeated multiple times"),
        Arg::new("cert-email")
            .long("cert-email")
            .number_of_values(1)
            .value_name("VALUE")
            .help("Expected email in Fulcio certificate"),
        Arg::new("cert-oidc-issuer")
            .long("cert-oidc-issuer")
            .number_of_values(1)
            .value_name("VALUE")
            .help("Expected OIDC issuer in Fulcio certificates"),
        Arg::new("github-owner")
            .long("github-owner")
            .number_of_values(1)
            .value_name("VALUE")
            .help("GitHub owner expected in the certificates generated in CD pipelines"),
        Arg::new("github-repo")
            .long("github-repo")
            .number_of_values(1)
            .value_name("VALUE")
            .help("GitHub repository expected in the certificates generated in CD pipelines"),
       Arg::new("sigstore-trust-config")
           .long("sigstore-trust-config")
           .value_parser(value_parser!(PathBuf))
           .value_name("PATH")
           .help("JSON-formatted file conforming to the ClientTrustConfig message in the Sigstore protobuf specs. This file configures the entire Sigstore instance state, including the URIs used to access the CA and artifact transparency services as well as the cryptographic root of trust itself"),
    ];
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("uri")
            .required(true)
            .index(1)
            .help("Policy URI. Supported schemes: registry://"),
    );

    Command::new("verify")
        .about("Verify a Kubewarden policy from a given URI using Sigstore")
        .after_long_help(PROXY_ENV_VARS_COMMON_LONG_ABOUT.to_string())
        .args(args)
}

fn subcommand_push() -> Command {
    let mut args = vec![
        Arg::new("docker-config-json-path")
            .long("docker-config-json-path")
            .value_name("PATH")
            .help("Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details"),
        Arg::new("sources-path")
            .long("sources-path")
            .value_name("PATH")
            .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        Arg::new("force")
            .short('f')
            .long("force")
            .help("Push also a policy that is not annotated"),
        Arg::new("output")
            .long("output")
            .short('o')
            .value_name("PATH")
            .value_parser(PossibleValuesParser::new(["text", "json"]))
            .default_value("text")
            .help("Output format"),
    ];
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("policy")
            .required(true)
            .index(1)
            .help("Policy to push. Can be the path to a local file, a policy URI or the SHA prefix of a policy in the store."),
    );
    args.push(
        Arg::new("uri")
            .required(true)
            .index(2)
            .help("Policy URI. Supported schemes: registry://"),
    );

    Command::new("push")
        .about("Pushes a Kubewarden policy to an OCI registry")
        .after_long_help(
            format!(
            r#"The annotations found inside of policy's metadata are going to be part of the OCI manifest.
The multi-line annotations are skipped because they are not compatible with the OCI specification.
The 'io.kubewarden.policy.source' annotation is propagated as 'org.opencontainers.image.source' to allow tools like
renovatebot to detect policy updates.

{}"#,
            PROXY_ENV_VARS_COMMON_LONG_ABOUT
        ))
        .args(args)
}

fn run_args() -> Vec<Arg> {
    vec![
       Arg::new("docker-config-json-path")
           .long("docker-config-json-path")
           .value_name("PATH")
           .help("Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details"),
       Arg::new("sources-path")
           .long("sources-path")
           .value_name("PATH")
           .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
       Arg::new("verification-config-path")
           .long("verification-config-path")
           .value_name("PATH")
           .help("YAML file holding verification config information (signatures, public keys...)"),
       Arg::new("request-path")
           .long("request-path")
           .short('r')
           .value_name("PATH")
           .required(true)
           .help("File containing the Kubernetes admission request object in JSON format"),
       Arg::new("settings-path")
           .long("settings-path")
           .short('s')
           .value_name("PATH")
           .help("File containing the settings for this policy"),
       Arg::new("settings-json")
           .long("settings-json")
           .value_name("VALUE")
           .help("JSON string containing the settings for this policy"),
       Arg::new("verification-key")
           .short('k')
           .long("verification-key")
           .action(ArgAction::Append)
           .number_of_values(1)
           .value_name("PATH")
           .help("Path to key used to verify the policy. Can be repeated multiple times"),
       Arg::new("verification-annotation")
           .short('a')
           .long("verification-annotation")
           .action(ArgAction::Append)
           .number_of_values(1)
           .value_name("KEY=VALUE")
           .help("Annotation in key=value format. Can be repeated multiple times"),
       Arg::new("cert-email")
           .long("cert-email")
           .number_of_values(1)
           .value_name("VALUE")
           .help("Expected email in Fulcio certificate"),
       Arg::new("cert-oidc-issuer")
           .long("cert-oidc-issuer")
           .number_of_values(1)
           .value_name("VALUE")
           .help("Expected OIDC issuer in Fulcio certificates"),
       Arg::new("github-owner")
           .long("github-owner")
           .number_of_values(1)
           .value_name("VALUE")
           .help("GitHub owner expected in the certificates generated in CD pipelines"),
       Arg::new("github-repo")
           .long("github-repo")
           .number_of_values(1)
           .value_name("VALUE")
           .help("GitHub repository expected in the certificates generated in CD pipelines"),
       Arg::new("execution-mode")
           .long("execution-mode")
           .short('e')
           .value_name("MODE")
           .value_parser(PossibleValuesParser::new(["opa","gatekeeper", "kubewarden", "wasi"]))
           .help("The runtime to use to execute this policy"),
       Arg::new("raw")
               .long("raw")
               .num_args(0)
               .default_value("false")
               .help("Validate a raw request"),
       Arg::new("disable-wasmtime-cache")
           .long("disable-wasmtime-cache")
           .num_args(0)
           .help("Turn off usage of wasmtime cache"),
       Arg::new("allow-context-aware")
           .long("allow-context-aware")
           .num_args(0)
           .help("Grant access to the Kubernetes resources defined inside of the policy's `contextAwareResources` section. Warning: review the list of resources carefully to avoid abuses. Disabled by default"),
       Arg::new("record-host-capabilities-interactions")
           .long("record-host-capabilities-interactions")
           .value_name("FILE")
           .long_help(r#"Record all the policy and host capabilities
communications to the given file.
Useful to be combined later with '--replay-host-capabilities-interactions' flag"#),
       Arg::new("replay-host-capabilities-interactions")
           .long("replay-host-capabilities-interactions")
           .value_name("FILE")
           .long_help(r#"During policy and host capabilities exchanges
the host replays back the answers found inside of the provided file.
This is useful to test policies in a reproducible way, given no external
interactions with OCI registries, DNS, Kubernetes are performed."#),
       Arg::new("sigstore-trust-config")
            .long("sigstore-trust-config")
            .value_parser(value_parser!(PathBuf))
            .value_name("PATH")
            .help("JSON-formatted file conforming to the ClientTrustConfig message in the Sigstore protobuf specs. This file configures the entire Sigstore instance state, including the URIs used to access the CA and artifact transparency services as well as the cryptographic root of trust itself"),
        Arg::new("allowed-host-capabilities")
            .long("allowed-host-capabilities")
            .num_args(0..)
            .default_values(["*"])
            .help("Host capabilities the policy is allowed to use. Use '*' to allow all. Can be repeated multiple times. Examples: 'oci/*', 'net/v1/dns_lookup_host'"),
     ]
}

fn subcommand_run() -> Command {
    let mut args = run_args();
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("uri_or_sha_prefix_or_yaml_file")
            .required(true)
            .index(1)
            .help("Policy URI, SHA prefix or YAML file containing Kubewarden policy resources. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory.")
    );

    Command::new("run")
        .about("Runs a Kubewarden policy from a given URI")
        .long_about(format!(
            r#"Run one or more Kubewarden policies locally.

{}"#,
            RUN_AND_BENCH_COMMON_LONG_ABOUT
        ))
        .after_long_help(PROXY_ENV_VARS_COMMON_LONG_ABOUT.to_string())
        .args(args)
        .group(
            // these flags cannot be used at the same time
            ArgGroup::new("host-capabilities-proxy").args([
                "record-host-capabilities-interactions",
                "replay-host-capabilities-interactions",
            ]),
        )
}

fn subcommand_annotate() -> Command {
    let mut args = vec![
        Arg::new("metadata-path")
            .long("metadata-path")
            .short('m')
            .required(true)
            .value_name("PATH")
            .help("File containing the metadata"),
        Arg::new("usage-path")
            .long("usage-path")
            .short('u')
            .value_name("PATH")
            .help("File containing the usage information of the policy"),
        Arg::new("output-path")
            .long("output-path")
            .short('o')
            .required(true)
            .value_name("PATH")
            .help("Output file"),
    ];
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("wasm-path")
            .required(true)
            .index(1)
            .help("Path to WebAssembly module to be annotated"),
    );

    Command::new("annotate")
        .about("Add Kubewarden metadata to a WebAssembly module")
        .args(args)
}

fn subcommand_inspect() -> Command {
    let mut args = vec![
        Arg::new("output")
            .long("output")
            .short('o')
            .value_name("FORMAT")
            .value_parser(PossibleValuesParser::new(["yaml"]))
            .help("Output format"),
        Arg::new("sources-path")
            .long("sources-path")
            .value_name("PATH")
            .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        Arg::new("docker-config-json-path")
            .long("docker-config-json-path")
            .value_name("PATH")
            .help("Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details"),
        Arg::new("show-signatures")
            .long("show-signatures")
            .num_args(0)
            .help("Show sigstore signatures"),
    ];
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("uri_or_sha_prefix")
            .required(true)
            .index(1)
            .help("Policy URI or SHA prefix. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory."),
    );

    Command::new("inspect")
        .about("Inspect Kubewarden policy")
        .args(args)
}

fn subcommand_scaffold() -> Command {
    let mut artifacthub_args = vec![
        Arg::new("metadata-path")
            .long("metadata-path")
            .short('m')
            .value_name("PATH")
            .help("File containing the metadata of the policy"),
        Arg::new("version")
            .long("version")
            .short('v')
            .number_of_values(1)
            .value_name("VALUE")
            .help("Semver version of the policy"),
        Arg::new("questions-path")
            .long("questions-path")
            .short('q')
            .value_name("PATH")
            .help("File containing the questions-ui content of the policy"),
        Arg::new("output")
            .long("output")
            .short('o')
            .value_name("FILE")
            .help("Path where the artifact-pkg.yml file will be stored"),
    ];
    artifacthub_args.sort_by(|a, b| a.get_id().cmp(b.get_id()));

    let mut manifest_args = vec![
        Arg::new("settings-path")
            .long("settings-path")
            .short('s')
            .value_name("PATH")
            .help("File containing the settings for this policy"),
        Arg::new("settings-json")
            .long("settings-json")
            .value_name("VALUE")
            .help("JSON string containing the settings for this policy")
            .conflicts_with("settings-path"),
        Arg::new("type")
            .long("type")
            .short('t')
            .required(true)
            .value_name("VALUE")
            .value_parser(PossibleValuesParser::new(["ClusterAdmissionPolicy", "AdmissionPolicy"]))
            .help("Kubewarden Custom Resource type"),
        Arg::new("title")
            .long("title")
            .value_name("VALUE")
            .help("Policy title"),
        Arg::new("allow-context-aware")
            .long("allow-context-aware")
            .num_args(0)
            .help("Uses the policy metadata to define which Kubernetes resources can be accessed by the policy. Warning: review the list of resources carefully to avoid abuses. Disabled by default"),
    ];
    // When scaffolding the manifest of a missing policy, we can pull it from a registry
    manifest_args.extend_from_slice(&pull_shared_flags());
    manifest_args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    manifest_args.push(
        Arg::new("uri_or_sha_prefix")
            .required(true)
            .index(1)
            .help("Policy URI or SHA prefix. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory."),
    );

    let mut vap_args = vec![
        Arg::new("cel-policy")
            .long("cel-policy")
            .value_name("URI")
            .default_value("ghcr.io/kubewarden/policies/cel-policy:latest")
            .help("The CEL policy module to use"),
        Arg::new("policy")
            .long("policy")
            .short('p')
            .required(true)
            .value_name("VALIDATING-ADMISSION-POLICY.yaml")
            .help("The file containing the ValidatingAdmissionPolicy definition"),
        Arg::new("binding")
            .long("binding")
            .short('b')
            .required(true)
            .value_name("VALIDATING-ADMISSION-POLICY-BINDING.yaml")
            .help("The file containing the ValidatingAdmissionPolicyBinding definition"),
    ];
    vap_args.sort_by(|a, b| a.get_id().cmp(b.get_id()));

    let mut admission_request_args = vec![
        Arg::new("operation")
            .long("operation")
            .short('o')
            .required(true)
            .value_name("TYPE")
            .value_parser(PossibleValuesParser::new(["CREATE"])) //TODO: add UPDATE and DELETE
            .help("Kubewarden Custom Resource type"),
        Arg::new("object")
            .long("object")
            .value_name("PATH")
            .help("The file containing the new object being admitted"),
        Arg::new("old-object")
            .long("old-object")
            .value_name("PATH")
            .help("The file containing the existing object"),
    ];
    admission_request_args.sort_by(|a, b| a.get_id().cmp(b.get_id()));

    let mut subcommands = vec![
        Command::new("verification-config")
            .about("Output a default Sigstore verification configuration file"),
        Command::new("artifacthub")
            .about("Output an artifacthub-pkg.yml file from a metadata.yml file")
            .args(artifacthub_args),
        Command::new("manifest")
            .about("Output a Kubernetes resource manifest")
            .args(manifest_args),
        Command::new("vap")
            .about("Convert a Kubernetes `ValidatingAdmissionPolicy` into a Kubewarden `ClusterAdmissionPolicy`")
            .args(vap_args),
        Command::new("admission-request")
            .about("Scaffold an AdmissionRequest object")
            .args(admission_request_args),
    ];
    subcommands.sort_by(|a, b| a.get_name().cmp(b.get_name()));

    Command::new("scaffold")
        .about("Scaffold a Kubernetes resource or configuration file")
        .subcommand_required(true)
        .subcommands(subcommands)
}

fn subcommand_digest() -> Command {
    let mut args = vec![
        Arg::new("sources-path")
            .long("sources-path")
            .value_name("PATH")
            .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),
        Arg::new("docker-config-json-path")
            .long("docker-config-json-path")
            .value_name("PATH")
            .help("Path to a directory containing the Docker 'config.json' file. Can be used to indicate registry authentication details"),

    ];
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(Arg::new("uri").required(true).index(1).help("Policy URI"));

    Command::new("digest")
        .about("Fetch digest from the OCI manifest of a policy")
        .args(args)
}

fn subcommand_bench() -> Command {
    let mut args = vec![
        Arg::new("measurement_time")
            .long("measurement-time")
            .number_of_values(1)
            .value_name("SECONDS")
            .help("How long the bench 'should' run, num_samples is prioritized so benching will take longer to be able to collect num_samples if the code to be benched is slower than this time limit allowed"),
        Arg::new("num_resamples")
            .long("num-resamples")
            .number_of_values(1)
            .value_name("NUM")
            .help("How many resamples should be done"),
        Arg::new("num_samples")
            .long("num-samples")
            .number_of_values(1)
            .value_name("NUM")
            .help("How many resamples should be done. Recommended at least 50, above 100 doesn't seem to yield a significantly different result"),
        Arg::new("warm_up_time")
            .long("warm-up-time")
            .number_of_values(1)
            .value_name("SECONDS")
            .help("How long the bench should warm up"),
        Arg::new("dump_results_to_disk")
            .long("dump-results-to-disk")
            .help("Puts results in target/tiny-bench/label/.. if target can be found. used for comparing previous runs"),
    ];
    let mut run_args = run_args();
    args.append(&mut run_args);
    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));
    args.push(
        Arg::new("uri_or_sha_prefix_or_yaml_file")
            .required(true)
            .index(1)
            .help("Policy URI, SHA prefix or YAML file containing Kubewarden policy resources. Supported schemes: registry://, https://, file://. If schema is omitted, file:// is assumed, rooted on the current directory.")
    );

    Command::new("bench")
        .about("Benchmarks a Kubewarden policy")
        .long_about(format!(
            r#"Benchmarks a Kubewarden policy.

{}"#,
            RUN_AND_BENCH_COMMON_LONG_ABOUT
        ))
        .args(args)
        .group(
            // these flags cannot be used at the same time
            ArgGroup::new("host-capabilities-proxy").args([
                "record-host-capabilities-interactions",
                "replay-host-capabilities-interactions",
            ]),
        )
}

fn subcommand_save() -> Command {
    Command::new("save")
        .about("save policies to a tar.gz file")
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .required(true)
                .value_name("FILE")
                .help("path where the file will be stored"),
        )
        .arg(
            Arg::new("policies")
                .num_args(1..)
                .required(true)
                .help("list of policies to save"),
        )
}

fn subcommand_docs() -> Command {
    Command::new("docs")
        .about("Generates documentation for kwctl commands. The output format is determined by the file extension: .md for Markdown, AsciiDoc otherwise")
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .required(true)
                .value_name("FILE")
                .help("path where the documentation file will be stored"),
        )
}

pub fn build_cli() -> Command {
    let mut subcommands = vec![
        Command::new("policies").about("Lists all downloaded policies"),
        Command::new("info").about("Display system information"),
        Command::new("rm")
            .about("Removes a Kubewarden policy from the store")
            .arg(
                Arg::new("uri_or_sha_prefix")
                    .required(true)
                    .index(1)
                    .help("Policy URI or SHA prefix"),
            ),
        Command::new("completions")
            .about("Generate shell completions")
            .arg(
                Arg::new("shell")
                    .long("shell")
                    .short('s')
                    .value_name("VALUE")
                    .required(true)
                    .value_parser(PossibleValuesParser::new([
                        "bash",
                        "elvish",
                        "fish",
                        "powershell",
                        "zsh",
                    ]))
                    .help("Shell type"),
            ),
        Command::new("load")
            .about("load policies from a tar.gz file")
            .arg(
                Arg::new("input")
                    .long("input")
                    .required(true)
                    .help("load policies from tarball"),
            ),
        subcommand_pull(),
        subcommand_verify(),
        subcommand_push(),
        subcommand_run(),
        subcommand_annotate(),
        subcommand_inspect(),
        subcommand_scaffold(),
        subcommand_digest(),
        subcommand_bench(),
        subcommand_save(),
        subcommand_docs(),
    ];
    subcommands.sort_by(|a, b| a.get_name().cmp(b.get_name()));

    Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .num_args(0)
                .help("Increase verbosity"),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .num_args(0)
                .help("Disable colorful output"),
        )
        .subcommands(subcommands)
        .long_version(VERSION_AND_BUILTINS.as_str())
        .subcommand_required(true)
        .arg_required_else_help(true)
}
