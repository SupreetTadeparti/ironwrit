/// Errors raised while proxying between the agent and the upstream server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The upstream MCP server failed to start or returned a protocol error.
    #[error("upstream server: {0}")]
    Upstream(String),
}

pub type Result<T> = std::result::Result<T, Error>;
