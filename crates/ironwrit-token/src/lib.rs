//! Capability tokens for Ironwrit.
//!
//! Mints, attenuates and authorizes Biscuit tokens that scope which tool calls
//! an agent may make. Token support lands in Phase 3; for now this crate holds
//! the [`CallPolicy`] hook the gateway checks every call against.

mod error;
mod policy;

pub use error::{Error, Result};
pub use policy::{AllowAll, CallPolicy, Decision, ToolCall};
