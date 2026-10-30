mod cli;

use anyhow::{Context, bail};
use clap::Parser;
use ironwrit_gateway::Upstream;
use ironwrit_token::AllowAll;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command, LogCommand};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    tracing::debug!(command = ?cli.command, "parsed command");

    match cli.command {
        Command::Keygen { .. } => not_yet("keygen", 3),
        Command::Mint { .. } => not_yet("mint", 3),
        Command::Attenuate { .. } => not_yet("attenuate", 3),
        Command::Inspect { .. } => not_yet("inspect", 3),
        Command::Run {
            token, upstream, ..
        } => run(token, &upstream),
        Command::Log { command, .. } => match command {
            LogCommand::Show => not_yet("log show", 4),
            LogCommand::Verify { .. } => not_yet("log verify", 4),
            LogCommand::Prove { .. } => not_yet("log prove", 4),
            LogCommand::Consistency { .. } => not_yet("log consistency", 4),
        },
    }
}

fn run(token: Option<String>, upstream: &[String]) -> anyhow::Result<()> {
    // Fail closed: never accept a token we can't enforce yet.
    if token.is_some() {
        bail!(
            "token enforcement is not implemented yet (see docs/ROADMAP.md, phase 3);              unset --token/IRONWRIT_TOKEN to run in pass-through mode"
        );
    }
    tracing::warn!("no token given: running in pass-through mode, all tool calls are allowed");

    let runtime = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    let result = runtime.block_on(async {
        let upstream = Upstream::spawn(upstream)?;
        ironwrit_gateway::serve_stdio(AllowAll, upstream).await
    });
    // Stdin reads block a runtime thread that may never return; don't wait for it.
    runtime.shutdown_background();
    Ok(result?)
}

/// Logs go to stderr: in `run` mode stdout carries the MCP protocol stream.
fn init_tracing(verbose: u8) {
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn not_yet(command: &str, phase: u8) -> anyhow::Result<()> {
    bail!("`ironwrit {command}` is not implemented yet (see docs/ROADMAP.md, phase {phase})")
}
