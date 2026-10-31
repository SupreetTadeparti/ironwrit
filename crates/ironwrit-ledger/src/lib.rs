//! Tamper-evident action log for Ironwrit.
//!
//! Every gateway decision becomes a signed [`LedgerEntry`] stored in SQLite.
//! Entries are the leaves of an RFC 6962 Merkle tree; periodic signed
//! [`TreeHead`]s commit to the tree, and inclusion and consistency proofs
//! show that an entry is in the log and that the log only ever grew.

mod entry;
mod error;
mod keys;
pub mod merkle;
mod store;
mod verify;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
pub use entry::{Decision, Hash, LedgerEntry, MAX_FIELD, Record, TreeHead, hash_json};
pub use error::{Error, Result};
pub use keys::{read_signing_key, read_verifying_key};
pub use store::{ConsistencyProof, HeadPolicy, InclusionProof, Ledger, Log};
pub use verify::{Location, Problem, Report};
