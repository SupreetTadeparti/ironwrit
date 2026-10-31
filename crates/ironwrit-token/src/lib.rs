//! Capability tokens for Ironwrit.
//!
//! Mints, attenuates and authorizes Biscuit tokens that scope which tool calls
//! an agent may make. See [`authorize`] for the contract between tokens and
//! the gateway, and [`extract`] for the facts each call produces.

pub mod authorize;
pub mod canon;
mod error;
pub mod extract;
mod policy;
mod token;

pub use authorize::BiscuitPolicy;
pub use error::{Error, Result};
pub use extract::{Config, FactExtractor};
pub use policy::{AllowAll, CallPolicy, Decision, ToolCall};
pub use token::{
    Inspection, attenuate, generate_keypair, inspect, mint, mint_with_params, parse_token,
    read_private_key, read_public_key, write_keypair,
};
