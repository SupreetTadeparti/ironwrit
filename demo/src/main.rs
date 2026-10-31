//! Pieces for the prompt-injection demo; see demo/README.md.
//!
//! - `ironwrit-demo server`: one MCP server with `read_file`, `list_directory`,
//!   `fetch` and `send_email`, all fake and local to the working directory.
//! - `ironwrit-demo agent`: a scripted agent that does whatever the pages it
//!   reads tell it to, which is the worst case for an LLM.

mod agent;
mod server;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ironwrit-demo")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the mock tools over stdio.
    ///
    /// Files resolve against the working directory, `fetch` serves
    /// `web/<host>.html`, and `send_email` appends to `out/outbox.jsonl`.
    Server,

    /// Run the gullible agent against an MCP server command.
    Agent {
        /// The page to summarize.
        #[arg(long, default_value = "https://news.example.test/")]
        url: String,

        /// Name shown in the agent's output.
        #[arg(long, default_value = "agent")]
        name: String,

        /// MCP server command and its arguments.
        #[arg(last = true, required = true)]
        server: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async {
        match cli.command {
            Command::Server => server::serve().await,
            Command::Agent { url, name, server } => agent::run(&name, &url, &server).await,
        }
    });
    // Stdin reads block a runtime thread that may never return.
    runtime.shutdown_background();
    result
}
