/// Errors raised while appending to or reading the ledger.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("ledger database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("invalid key: {0}")]
    Key(String),

    /// The stored log doesn't match its signatures or tree heads.
    #[error("ledger failed verification: {0}")]
    Integrity(String),

    #[error("{0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, Error>;
