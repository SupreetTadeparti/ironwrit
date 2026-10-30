/// Errors raised while parsing, minting or authorizing tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The token bytes could not be decoded or its signature chain is invalid.
    #[error("malformed token: {0}")]
    Malformed(String),

    /// The token is valid but does not permit the requested call.
    #[error("denied: {0}")]
    Denied(String),
}

pub type Result<T> = std::result::Result<T, Error>;
