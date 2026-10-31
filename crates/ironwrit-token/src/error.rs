/// Errors raised while parsing, minting or authorizing tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The token bytes could not be decoded or its signature chain is invalid.
    #[error("malformed token: {0}")]
    Malformed(String),

    /// A key file could not be read or written.
    #[error("key: {0}")]
    Key(String),

    /// A Datalog policy or check failed to parse.
    #[error("invalid datalog: {0}")]
    Datalog(String),

    /// The extractor config (`ironwrit.toml`) is invalid.
    #[error("config: {0}")]
    Config(String),

    /// A tool argument could not be turned into facts, e.g. an unresolvable path.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The token is valid but does not permit the requested call.
    #[error("denied: {0}")]
    Denied(String),
}

pub type Result<T> = std::result::Result<T, Error>;
