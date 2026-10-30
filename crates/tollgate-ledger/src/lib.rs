//! Tamper-evident action log for Tollgate.
//!
//! Stores signed entries in an RFC 6962 Merkle tree and produces inclusion and
//! consistency proofs. Implemented in Phase 4.

mod error;

pub use error::{Error, Result};
