mod cli;
mod log;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use clap::Parser;
use ironwrit_gateway::Upstream;
use ironwrit_ledger::{HeadPolicy, Ledger};
use ironwrit_token::{AllowAll, BiscuitPolicy, CallPolicy, Config, FactExtractor};
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command, LogCommand};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    tracing::debug!(command = ?cli.command, "parsed command");

    match cli.command {
        Command::Keygen { out, force } => keygen(&out, force),
        Command::Mint {
            key,
            policy,
            params,
            paths,
            ttl,
            out,
        } => mint(&key, &policy, params, &paths, ttl, out.as_deref()),
        Command::Attenuate {
            token,
            checks,
            ttl,
            out,
        } => attenuate(&token, &checks, ttl, out.as_deref()),
        Command::Inspect { token, public_key } => inspect(&token, public_key.as_deref()),
        Command::Run {
            token,
            root_pub,
            config,
            ledger,
            gateway_key,
            head_every,
            head_interval,
            upstream,
        } => {
            let heads = HeadPolicy {
                every: head_every,
                interval: head_interval,
            };
            let protected = protected_paths(&[&ledger, &gateway_key, &root_pub, &config])?;
            let ledger = || open_ledger(&ledger, &gateway_key, heads);
            run(token, &root_pub, &config, protected, ledger, &upstream)
        }
        Command::Log { db, command } => match command {
            LogCommand::Show => log::show(&db),
            LogCommand::Verify { public_key } => log::verify(&db, &public_key),
            LogCommand::Prove { seq, public_key } => log::prove(&db, seq, public_key.as_deref()),
            LogCommand::Consistency {
                old,
                new,
                public_key,
            } => log::consistency(&db, old, new, public_key.as_deref()),
        },
    }
}

fn keygen(out: &Path, force: bool) -> anyhow::Result<()> {
    let keypair = ironwrit_token::generate_keypair();
    let (key, public) = ironwrit_token::write_keypair(&keypair, out, force)?;
    eprintln!("wrote {key} (keep this secret) and {public}");
    Ok(())
}

fn mint(
    key: &Path,
    policy: &Path,
    mut params: Vec<(String, String)>,
    paths: &[(String, String)],
    ttl: Option<Duration>,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let root = ironwrit_token::read_private_key(key)?;
    let policy = std::fs::read_to_string(policy)
        .with_context(|| format!("failed to read {}", policy.display()))?;
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    for (name, path) in paths {
        let canonical = ironwrit_token::canon::canonical_path(path, &cwd)
            .with_context(|| format!("--path {name}={path}"))?;
        params.push((name.clone(), canonical));
    }
    let token = ironwrit_token::mint_with_params(&policy, &params, &root, ttl)?;
    write_token(&token, out)
}

fn attenuate(
    token: &Path,
    checks: &[String],
    ttl: Option<Duration>,
    out: Option<&Path>,
) -> anyhow::Result<()> {
    let token = ironwrit_token::attenuate(&read_token(token)?, checks, ttl)?;
    write_token(&token, out)
}

fn inspect(token: &Path, public_key: Option<&Path>) -> anyhow::Result<()> {
    let root = public_key
        .map(ironwrit_token::read_public_key)
        .transpose()?;
    let info = ironwrit_token::inspect(&read_token(token)?, root.as_ref())?;

    match public_key {
        Some(path) => println!("signature: valid for {}", path.display()),
        None => println!("signature: not verified (pass --pub to check it)"),
    }
    match info.expires {
        None => println!("expires:   never"),
        Some(at) => {
            let when = humantime::format_rfc3339_seconds(at);
            match at.duration_since(SystemTime::now()) {
                Ok(left) => {
                    let left = Duration::from_secs(left.as_secs());
                    println!(
                        "expires:   {when} (in {})",
                        humantime::format_duration(left)
                    );
                }
                Err(_) => println!("expires:   {when} (EXPIRED)"),
            }
        }
    }
    for (i, block) in info.blocks.iter().enumerate() {
        let label = if i == 0 { " (authority)" } else { "" };
        println!("\nblock {i}{label}:");
        for line in block.lines() {
            println!("  {line}");
        }
    }
    Ok(())
}

/// Open the ledger, creating the gateway key on first use.
fn open_ledger(path: &Path, key_path: &Path, heads: HeadPolicy) -> anyhow::Result<Arc<Ledger>> {
    if !key_path.exists() {
        if key_path.extension().is_none_or(|ext| ext != "key") {
            bail!(
                "{} not found (create one with `ironwrit keygen --out <prefix>`)",
                key_path.display()
            );
        }
        let keypair = ironwrit_token::generate_keypair();
        let (key, public) =
            ironwrit_token::write_keypair(&keypair, &key_path.with_extension(""), false)?;
        tracing::warn!("created gateway key {key}; verify the ledger with {public}");
    }
    let key = ironwrit_ledger::read_signing_key(key_path)?;
    let ledger = Ledger::open(path, key, heads)
        .with_context(|| format!("failed to open ledger {}", path.display()))?;
    Ok(Arc::new(ledger))
}

/// Files an agent must never read or replace: keys, ledger and config.
fn protected_paths(files: &[&Path]) -> anyhow::Result<Vec<String>> {
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    let mut paths = Vec::new();
    for file in files {
        let name = file.to_string_lossy();
        let variants = [
            file.to_path_buf(),
            file.with_extension("key"),
            file.with_extension("pub"),
            format!("{name}-wal").into(),
            format!("{name}-shm").into(),
            format!("{name}-journal").into(),
        ];
        for variant in variants {
            let variant = variant.to_string_lossy();
            paths.push(ironwrit_token::canon::canonical_path(&variant, &cwd)?);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn run(
    token: Option<String>,
    root_pub: &Path,
    config: &Path,
    protected: Vec<String>,
    ledger: impl FnOnce() -> anyhow::Result<Arc<Ledger>>,
    upstream: &[String],
) -> anyhow::Result<()> {
    let Some(token) = token else {
        tracing::warn!("no token given: running in pass-through mode, all tool calls are allowed");
        return serve(AllowAll, ledger()?, upstream);
    };
    let root = ironwrit_token::read_public_key(root_pub)
        .context("a root public key is needed to verify the token (see --root-pub)")?;
    let token = ironwrit_token::parse_token(&token, &root)?;
    // Without extractors, argument checks would have no facts to look at.
    let config = Config::load(config)
        .context("an extractor config is needed to enforce a token (see --config)")?;
    let base_dir = std::env::current_dir().context("failed to read current directory")?;
    let extractor = FactExtractor::new(config, &base_dir).protect(protected);
    let policy = BiscuitPolicy::new(token, extractor);
    tracing::info!("enforcing capability token");
    serve(policy, ledger()?, upstream)
}

fn serve(policy: impl CallPolicy, ledger: Arc<Ledger>, upstream: &[String]) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("failed to start async runtime")?;
    let result = runtime.block_on(async {
        let upstream = Upstream::spawn(upstream)?;
        ironwrit_gateway::serve_stdio(policy, ledger, upstream).await
    });
    // Stdin reads block a runtime thread that may never return; don't wait for it.
    runtime.shutdown_background();
    Ok(result?)
}

/// Read a token from a file, or from stdin if the path is `-`.
fn read_token(path: &Path) -> anyhow::Result<String> {
    let mut token = String::new();
    if path == Path::new("-") {
        std::io::stdin().read_to_string(&mut token)?;
    } else {
        token = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
    }
    Ok(token.trim().to_owned())
}

fn write_token(token: &str, out: Option<&Path>) -> anyhow::Result<()> {
    match out {
        Some(path) => std::fs::write(path, format!("{token}\n"))
            .with_context(|| format!("failed to write {}", PathBuf::from(path).display())),
        None => {
            println!("{token}");
            Ok(())
        }
    }
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
