mod cli;

use std::fs;
use std::io::prelude::*;

use ::tracing::info;
use anyhow::Result;
use anyhow::anyhow;
use clap::ArgMatches;
use policy_server::PolicyServer;
use policy_server::metrics::setup_metrics;
use policy_server::tracing::setup_tracing;
use rustls::crypto::aws_lc_rs::default_provider;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    if matches.subcommand_name() == Some("docs") {
        return run_docs_subcommand(matches.subcommand_matches("docs"));
    }

    let config = policy_server::config::Config::from_args(&matches)?;

    let tracer_provider = setup_tracing(&config.log_level, &config.log_fmt, config.log_no_color)?;

    // This is necessary to ensure that we are using proper initializing the crypto provider.
    // Without this initialization step, depending on which cli flags policy server has, the
    // kubernetes client is initialized before the crypto provider causing a crash. In other
    // scenarios the client is initialized after other dependencies which set the provider for us.
    // Therefore, the following install_default() call ensure that we will have always a crypto
    // provider initialized before any operation may require it.
    if let Err(e) = default_provider().install_default() {
        tracing::warn!("Failed to install rustls crypto provider: {:?}", e);
    }

    if config.metrics_enabled {
        setup_metrics()?;
    };

    if config.daemon {
        info!("Running instance as a daemon");

        let mut daemonize = daemonize::Daemonize::new().pid_file(&config.daemon_pid_file);
        if let Some(stdout_file) = config.daemon_stdout_file.clone() {
            let file = fs::File::create(stdout_file)
                .map_err(|e| anyhow!("Cannot create file for daemon stdout: {}", e))?;
            daemonize = daemonize.stdout(file);
        }
        if let Some(stderr_file) = config.daemon_stderr_file.clone() {
            let file = fs::File::create(stderr_file)
                .map_err(|e| anyhow!("Cannot create file for daemon stderr: {}", e))?;
            daemonize = daemonize.stderr(file);
        }

        daemonize
            .start()
            .map_err(|e| anyhow!("Cannot daemonize: {}", e))?;

        info!("Detached from shell, now running in background.");
    }

    let api_server = PolicyServer::new_from_config(config).await?;
    api_server.run().await?;

    if let Some(trace_provider) = tracer_provider {
        trace_provider.shutdown()?;
    }

    Ok(())
}

/// Handle the docs subcommand and generates documentation for the CLI
fn run_docs_subcommand(matches: Option<&ArgMatches>) -> Result<()> {
    if let Some(matches) = matches {
        let output = matches.get_one::<String>("output").unwrap();
        let mut file = std::fs::File::create(output)
            .map_err(|e| anyhow!("cannot create file {}: {}", output, e))?;
        let docs_content = if output.ends_with(".md") {
            clap_documentation::help_markdown_command(&cli::build_cli())
        } else {
            clap_documentation::help_asciidoc_command(&cli::build_cli())
        };
        file.write_all(docs_content.as_bytes())
            .map_err(|e| anyhow!("cannot write to file {}: {}", output, e))?;
    }
    Ok(())
}
