/// Errors raised while appending to or verifying the ledger.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Verification found an entry that does not match its signature or tree.
    #[error("integrity check failed at entry {seq}: {reason}")]
    Integrity { seq: u64, reason: String },
}

pub type Result<T> = std::result::Result<T, Error>;
