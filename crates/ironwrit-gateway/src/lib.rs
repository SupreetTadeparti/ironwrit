//! MCP proxy that enforces capability tokens on every tool call.
//!
//! Sits between an agent and an upstream MCP server over stdio. Implemented in
//! Phase 2.

mod error;

pub use error::{Error, Result};
