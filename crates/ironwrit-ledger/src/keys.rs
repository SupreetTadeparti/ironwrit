//! Gateway keys, in the same PEM formats `ironwrit keygen` writes.

use std::path::Path;

use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{Error, Result};

/// Read a PKCS#8 PEM Ed25519 private key.
pub fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| Error::Key(format!("{}: {e}", path.display())))?;
    SigningKey::from_pkcs8_pem(&pem).map_err(|e| Error::Key(format!("{}: {e}", path.display())))
}

/// Read an SPKI PEM Ed25519 public key.
pub fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| Error::Key(format!("{}: {e}", path.display())))?;
    VerifyingKey::from_public_key_pem(&pem)
        .map_err(|e| Error::Key(format!("{}: {e}", path.display())))
}
