use clap::builder::PossibleValue;
use clap::{Arg, ArgAction, Command, crate_authors, crate_description, crate_name, crate_version};
use itertools::Itertools;
use lazy_static::lazy_static;
use policy_evaluator::burrego;

lazy_static! {
    static ref VERSION_AND_BUILTINS: String = {
        let builtins: String = burrego::get_builtins()
            .keys()
            .sorted()
            .map(|builtin| format!("  - {builtin}"))
            .join("\n");

        format!(
            "{}\n\nOpen Policy Agent/Gatekeeper implemented builtins:\n{}",
            crate_version!(),
            builtins,
        )
    };
}

pub(crate) fn build_cli() -> Command {
    let mut args = vec![
        Arg::new("log-level")
            .long("log-level")
            .value_name("LOG_LEVEL")
            .env("KUBEWARDEN_LOG_LEVEL")
            .default_value("info")
            .value_parser([
                PossibleValue::new("trace"),
                PossibleValue::new("debug"),
                PossibleValue::new("info"),
                PossibleValue::new("warn"),
                PossibleValue::new("error"),
            ])
            .help("Log level"),

        Arg::new("log-fmt")
            .long("log-fmt")
            .value_name("LOG_FMT")
            .env("KUBEWARDEN_LOG_FMT")
            .default_value("text")
            .value_parser([
                PossibleValue::new("text"),
                PossibleValue::new("json"),
                PossibleValue::new("otlp"),
            ])
            .help("Log output format"),

        Arg::new("log-no-color")
            .long("log-no-color")
            .env("NO_COLOR")
            .action(ArgAction::SetTrue)
            .help("Disable colored output for logs"),

        Arg::new("address")
            .long("addr")
            .value_name("BIND_ADDRESS")
            .default_value("0.0.0.0")
            .env("KUBEWARDEN_BIND_ADDRESS")
            .help("Bind against ADDRESS"),

        Arg::new("port")
            .long("port")
            .value_name("PORT")
            .default_value("3000")
            .env("KUBEWARDEN_PORT")
            .help("Listen on PORT"),

        Arg::new("readiness-probe-port")
            .long("readiness-probe-port")
            .value_name("READINESS_PROBE_PORT")
            .default_value("8081")
            .env("KUBEWARDEN_READINESS_PROBE_PORT")
            .help("Expose readiness endpoint on READINESS_PROBE_PORT"),

        Arg::new("workers")
            .long("workers")
            .value_name("WORKERS_NUMBER")
            .env("KUBEWARDEN_WORKERS")
            .help("Number of worker threads to create"),

        Arg::new("cert-file")
            .long("cert-file")
            .value_name("CERT_FILE")
            .env("KUBEWARDEN_CERT_FILE")
            .value_parser(clap::builder::PathBufValueParser::new())
            .help("Path to an X.509 certificate file for HTTPS"),

        Arg::new("key-file")
            .long("key-file")
            .value_name("KEY_FILE")
            .env("KUBEWARDEN_KEY_FILE")
            .value_parser(clap::builder::PathBufValueParser::new())
            .help("Path to an X.509 private key file for HTTPS"),

        Arg::new("client-ca-file")
            .long("client-ca-file")
            .value_delimiter(',')
            .value_name("CLIENT_CA_FILE")
            .env("KUBEWARDEN_CLIENT_CA_FILE")
            .value_parser(clap::builder::PathBufValueParser::new())
            .help("Path to an CA certificate file that issued the client certificate. Required to enable mTLS"),

        Arg::new("policies")
            .long("policies")
            .value_name("POLICIES_FILE")
            .env("KUBEWARDEN_POLICIES")
            .default_value("policies.yml")
            .help("YAML file holding the policies to be loaded and their settings"),

        Arg::new("policies-download-dir")
            .long("policies-download-dir")
            .value_name("POLICIES_DOWNLOAD_DIR")
            .default_value(".")
            .env("KUBEWARDEN_POLICIES_DOWNLOAD_DIR")
            .help("Download path for the policies"),

        Arg::new("sigstore-cache-dir")
            .long("sigstore-cache-dir")
            .value_name("SIGSTORE_CACHE_DIR")
            .default_value("sigstore-data")
            .env("KUBEWARDEN_SIGSTORE_CACHE_DIR")
            .help("Directory used to cache sigstore data"),

        Arg::new("sigstore-trust-config")
            .long("sigstore-trust-config")
            .value_name("SIGSTORE_TRUST_CONFIG_PATH")
            .env("KUBEWARDEN_SIGSTORE_TRUST_CONFIG_PATH")
            .value_parser(clap::builder::PathBufValueParser::new())
            .help("Path to a JSON Sigstore ClientTrustConfig file"),

        Arg::new("sources-path")
            .long("sources-path")
            .value_name("SOURCES_PATH")
            .env("KUBEWARDEN_SOURCES_PATH")
            .help("YAML file holding source information (https, registry insecure hosts, custom CA's...)"),

        Arg::new("verification-path")
            .long("verification-path")
            .value_name("VERIFICATION_CONFIG_PATH")
            .env("KUBEWARDEN_VERIFICATION_CONFIG_PATH")
            .help("YAML file holding verification information (URIs, keys, annotations...)"),

        Arg::new("docker-config-json-path")
            .long("docker-config-json-path")
            .value_name("DOCKER_CONFIG")
            .env("KUBEWARDEN_DOCKER_CONFIG_JSON_PATH")
            .help("Path to a Docker config.json-like path. Can be used to indicate registry authentication details"),

        Arg::new("enable-metrics")
            .long("enable-metrics")
            .env("KUBEWARDEN_ENABLE_METRICS")
            .action(ArgAction::SetTrue)
            .help("Enable metrics"),

        Arg::new("always-accept-admission-reviews-on-namespace")
            .long("always-accept-admission-reviews-on-namespace")
            .value_name("NAMESPACE")
            .env("KUBEWARDEN_ALWAYS_ACCEPT_ADMISSION_REVIEWS_ON_NAMESPACE")
            .required(false)
            .help("Always accept AdmissionReviews that target the given namespace"),

        Arg::new("disable-timeout-protection")
            .long("disable-timeout-protection")
            .action(ArgAction::SetTrue)
            .env("KUBEWARDEN_DISABLE_TIMEOUT_PROTECTION")
            .help("Disable policy timeout protection"),

        Arg::new("policy-timeout")
            .long("policy-timeout")
            .env("KUBEWARDEN_POLICY_TIMEOUT")
            .value_name("MAXIMUM_EXECUTION_TIME_SECONDS")
            .default_value("2")
            .help("Interrupt policy evaluation after the given time"),

        Arg::new("daemon")
            .long("daemon")
            .env("KUBEWARDEN_DAEMON")
            .action(ArgAction::SetTrue)
            .help("If set, runs policy-server in detached mode as a daemon"),

        Arg::new("daemon-pid-file")
            .long("daemon-pid-file")
            .env("KUBEWARDEN_DAEMON_PID_FILE")
            .default_value("policy-server.pid")
            .help("Path to the PID file, used only when running in daemon mode"),

        Arg::new("daemon-stdout-file")
            .long("daemon-stdout-file")
            .env("KUBEWARDEN_DAEMON_STDOUT_FILE")
            .required(false)
            .help("Path to the file holding stdout, used only when running in daemon mode"),

        Arg::new("daemon-stderr-file")
            .long("daemon-stderr-file")
            .env("KUBEWARDEN_DAEMON_STDERR_FILE")
            .required(false)
            .help("Path to the file holding stderr, used only when running in daemon mode"),

        Arg::new("ignore-kubernetes-connection-failure")
            .long("ignore-kubernetes-connection-failure")
            .env("KUBEWARDEN_IGNORE_KUBERNETES_CONNECTION_FAILURE")
            .action(ArgAction::SetTrue)
            .help("Do not exit with an error if the Kubernetes connection fails. This will cause context-aware policies to break when there's no connection with Kubernetes."),

        Arg::new("enable-pprof")
            .long("enable-pprof")
            .env("KUBEWARDEN_ENABLE_PPROF")
            .action(ArgAction::SetTrue)
            .help("Enable pprof profiling"),

        Arg::new("continue-on-errors")
            .long("continue-on-errors")
            .env("KUBEWARDEN_CONTINUE_ON_ERRORS")
            .action(ArgAction::SetTrue)
            .hide(true),
    ];

    args.sort_by(|a, b| a.get_id().cmp(b.get_id()));

    Command::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .about(crate_description!())
        .long_version(VERSION_AND_BUILTINS.as_str())
        .args(args)
        .subcommand(
            Command::new("docs")
                .about("Generates documentation for policy-server commands. The output format is determined by the file extension: .md for Markdown, AsciiDoc otherwise")
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .required(true)
                        .value_name("FILE")
                        .help("path where the documentation file will be stored"),
                ),
        )
}
