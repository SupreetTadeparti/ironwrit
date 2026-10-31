use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

/// A cryptographic seatbelt for AI agents.
///
/// Ironwrit proxies MCP tool calls, allows only what a capability token
/// permits, and records every decision in a tamper-evident log.
#[derive(Debug, Parser)]
#[command(name = "ironwrit", version, about, long_about)]
pub struct Cli {
    /// Increase log verbosity (-v info, -vv debug, -vvv trace). RUST_LOG overrides this.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate an Ed25519 root keypair for minting tokens.
    Keygen {
        /// Output path prefix; writes <OUT>.key and <OUT>.pub.
        #[arg(long, default_value = "root")]
        out: PathBuf,

        /// Overwrite existing key files.
        #[arg(long)]
        force: bool,
    },

    /// Mint a new capability token from a Datalog policy.
    ///
    /// The policy grants tools with `right("<tool>")` facts and constrains
    /// arguments with checks, e.g.
    /// `reject if path($p), !$p.starts_with("/srv/docs/")`.
    Mint {
        /// Root private key created by `ironwrit keygen`.
        #[arg(long, default_value = "root.key")]
        key: PathBuf,

        /// Datalog policy file describing what the token allows.
        #[arg(long)]
        policy: PathBuf,

        /// Expire the token after this long, e.g. `8h` or `30m`.
        #[arg(long, value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,

        /// Where to write the token (stdout if omitted).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Narrow an existing token by appending checks. Never widens it.
    ///
    /// Needs no key: anyone holding a token can attenuate it.
    Attenuate {
        /// Token file to attenuate (`-` for stdin).
        token: PathBuf,

        /// Datalog check to add, e.g. 'check if tool("read_file")'. Repeatable.
        #[arg(long = "check")]
        checks: Vec<String>,

        /// Expire the new token after this long, e.g. `10m`.
        #[arg(long, value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,

        /// Where to write the new token (stdout if omitted).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },

    /// Print a token's blocks, checks and expiry.
    Inspect {
        /// Token file to inspect (`-` for stdin).
        token: PathBuf,

        /// Root public key; if given, the token's signatures are verified.
        #[arg(long = "pub")]
        public_key: Option<PathBuf>,
    },

    /// Run an upstream MCP server behind the gateway.
    ///
    /// Example: ironwrit run --token <TOKEN> -- npx @modelcontextprotocol/server-filesystem ./docs
    Run {
        /// Capability token (base64) for this session. Without one, every call
        /// is allowed (pass-through mode).
        #[arg(long, env = "IRONWRIT_TOKEN", hide_env_values = true)]
        token: Option<String>,

        /// Root public key that tokens must be signed with.
        #[arg(long, env = "IRONWRIT_ROOT_PUB", default_value = "root.pub")]
        root_pub: PathBuf,

        /// Extractor config mapping tool arguments to facts.
        #[arg(long, env = "IRONWRIT_CONFIG", default_value = "ironwrit.toml")]
        config: PathBuf,

        /// Ledger database to append decisions to.
        #[arg(long, default_value = "ironwrit.db")]
        ledger: PathBuf,

        /// Upstream MCP server command and its arguments.
        #[arg(last = true, required = true, value_name = "UPSTREAM")]
        upstream: Vec<String>,
    },

    /// Inspect and verify the action log.
    Log {
        /// Ledger database.
        #[arg(long, default_value = "ironwrit.db", global = true)]
        db: PathBuf,

        #[command(subcommand)]
        command: LogCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum LogCommand {
    /// List recorded tool calls and decisions.
    Show,

    /// Check every signature and the Merkle tree against the gateway public key.
    Verify {
        /// Gateway public key.
        #[arg(long = "pub")]
        public_key: PathBuf,
    },

    /// Produce an inclusion proof that entry SEQ is in the log.
    Prove { seq: u64 },

    /// Produce a consistency proof that tree size OLD is a prefix of tree size NEW.
    Consistency { old: u64, new: u64 },
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn run_collects_upstream_after_double_dash() {
        let cli = Cli::parse_from(["ironwrit", "run", "--", "npx", "server", "./docs"]);
        let Command::Run { upstream, .. } = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(upstream, ["npx", "server", "./docs"]);
    }
}
