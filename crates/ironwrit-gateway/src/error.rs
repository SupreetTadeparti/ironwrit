/// Errors raised while proxying between the agent and the upstream server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The upstream command could not be found or started.
    #[error("failed to start upstream `{command}`: {source}")]
    Spawn {
        command: String,
        source: std::io::Error,
    },

    /// The upstream MCP server failed to start or returned a protocol error.
    #[error("upstream server: {0}")]
    Upstream(String),

    /// The ledger could not be written.
    #[error(transparent)]
    Ledger(#[from] ironwrit_ledger::Error),

    /// The agent disconnected or failed the MCP handshake.
    #[error("agent connection: {0}")]
    Agent(String),
}

pub type Result<T> = std::result::Result<T, Error>;
