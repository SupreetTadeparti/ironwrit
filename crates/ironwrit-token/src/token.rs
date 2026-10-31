//! Key management and the token lifecycle: mint, attenuate, inspect.

use std::path::Path;
use std::time::{Duration, SystemTime};

use biscuit_auth::builder::Check;
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PublicKey, UnverifiedBiscuit};

use crate::{Error, Result};

/// Generate a new Ed25519 root keypair.
pub fn generate_keypair() -> KeyPair {
    KeyPair::new()
}

/// Write `<prefix>.key` (PKCS#8 PEM, owner-only on Unix) and `<prefix>.pub`.
/// Refuses to overwrite existing files unless `force` is set.
pub fn write_keypair(keypair: &KeyPair, prefix: &Path, force: bool) -> Result<(String, String)> {
    let key_path = format!("{}.key", prefix.display());
    let pub_path = format!("{}.pub", prefix.display());
    if !force {
        for path in [&key_path, &pub_path] {
            if Path::new(path).exists() {
                return Err(Error::Key(format!(
                    "{path} already exists (use --force to overwrite)"
                )));
            }
        }
    }
    let private = keypair
        .to_private_key_pem()
        .map_err(|e| Error::Key(e.to_string()))?;
    let public = keypair
        .public()
        .to_pem()
        .map_err(|e| Error::Key(e.to_string()))?;
    write_private(Path::new(&key_path), private.as_bytes())?;
    std::fs::write(&pub_path, public)?;
    Ok((key_path, pub_path))
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

pub fn read_private_key(path: &Path) -> Result<KeyPair> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| Error::Key(format!("{}: {e}", path.display())))?;
    KeyPair::from_private_key_pem(&pem).map_err(|e| Error::Key(format!("{}: {e}", path.display())))
}

pub fn read_public_key(path: &Path) -> Result<PublicKey> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| Error::Key(format!("{}: {e}", path.display())))?;
    PublicKey::from_pem(&pem).map_err(|e| Error::Key(format!("{}: {e}", path.display())))
}

/// Mint a token whose authority block is the Datalog `policy`, optionally
/// expiring after `ttl`. Returns the token as base64.
pub fn mint(policy: &str, root: &KeyPair, ttl: Option<Duration>) -> Result<String> {
    let mut builder = Biscuit::builder()
        .code(policy)
        .map_err(|e| Error::Datalog(e.to_string()))?;
    if let Some(ttl) = ttl {
        builder = builder
            .check(expiry_check(ttl)?)
            .map_err(|e| Error::Datalog(e.to_string()))?;
    }
    let token = builder
        .build(root)
        .map_err(|e| Error::Malformed(e.to_string()))?;
    token
        .to_base64()
        .map_err(|e| Error::Malformed(e.to_string()))
}

/// Append a block of `checks` (and an optional expiry) to `token`.
///
/// Needs no key: Biscuit attenuation is offline. Only checks are accepted,
/// since facts or rules in a later block can't grant anything anyway and
/// would only confuse readers.
pub fn attenuate(token: &str, checks: &[String], ttl: Option<Duration>) -> Result<String> {
    if checks.is_empty() && ttl.is_none() {
        return Err(Error::Datalog(
            "nothing to add: give at least one check or a ttl".into(),
        ));
    }
    let token = parse_unverified(token)?;
    let mut block = BlockBuilder::new();
    for source in checks {
        let check: Check = source
            .trim()
            .trim_end_matches(';')
            .parse()
            .map_err(|e| Error::Datalog(format!("{source:?}: {e:?}")))?;
        block = block
            .check(check)
            .map_err(|e| Error::Datalog(e.to_string()))?;
    }
    if let Some(ttl) = ttl {
        block = block
            .check(expiry_check(ttl)?)
            .map_err(|e| Error::Datalog(e.to_string()))?;
    }
    let token = token
        .append(block)
        .map_err(|e| Error::Malformed(e.to_string()))?;
    token
        .to_base64()
        .map_err(|e| Error::Malformed(e.to_string()))
}

fn expiry_check(ttl: Duration) -> Result<Check> {
    let expires = SystemTime::now() + ttl;
    let source = format!(
        "check if time($time), $time <= {}",
        humantime::format_rfc3339_seconds(expires)
    );
    source.parse().map_err(|e| Error::Datalog(format!("{e:?}")))
}

/// Decode and verify a token against the root public key.
pub fn parse_token(token: &str, root: &PublicKey) -> Result<Biscuit> {
    Biscuit::from_base64(token.trim(), *root).map_err(|e| Error::Malformed(e.to_string()))
}

fn parse_unverified(token: &str) -> Result<UnverifiedBiscuit> {
    UnverifiedBiscuit::from_base64(token.trim()).map_err(|e| Error::Malformed(e.to_string()))
}

/// A human-readable summary of a token.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// Datalog source of each block; block 0 is the authority block.
    pub blocks: Vec<String>,
    /// Earliest expiry found in any `time` check, if any.
    pub expires: Option<SystemTime>,
    /// Whether the signature chain was checked against a root key.
    pub verified: bool,
}

/// Summarize `token`. If `root` is given, the signatures are verified first.
pub fn inspect(token: &str, root: Option<&PublicKey>) -> Result<Inspection> {
    let unverified = parse_unverified(token)?;
    let blocks = (0..unverified.block_count())
        .map(|i| {
            unverified
                .print_block_source(i)
                .map_err(|e| Error::Malformed(e.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(root) = root {
        parse_token(token, root)?;
    }
    let expires = blocks
        .iter()
        .flat_map(|block| block.lines())
        .filter(|line| line.contains("time("))
        .filter_map(earliest_date)
        .min();
    Ok(Inspection {
        blocks,
        expires,
        verified: root.is_some(),
    })
}

fn earliest_date(line: &str) -> Option<SystemTime> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == ':'))
        .filter_map(|word| humantime::parse_rfc3339(word).ok())
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"right("read_file");"#;

    #[test]
    fn keypair_round_trips_through_files() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("root");
        let keypair = generate_keypair();
        let (key, public) = write_keypair(&keypair, &prefix, false).unwrap();

        assert_eq!(
            read_public_key(Path::new(&public)).unwrap(),
            keypair.public()
        );
        let token = mint(POLICY, &read_private_key(Path::new(&key)).unwrap(), None).unwrap();
        parse_token(&token, &keypair.public()).unwrap();
    }

    #[test]
    fn keygen_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("root");
        write_keypair(&generate_keypair(), &prefix, false).unwrap();
        assert!(write_keypair(&generate_keypair(), &prefix, false).is_err());
        write_keypair(&generate_keypair(), &prefix, true).unwrap();
    }

    #[test]
    fn tokens_from_another_root_are_rejected() {
        let token = mint(POLICY, &generate_keypair(), None).unwrap();
        assert!(parse_token(&token, &generate_keypair().public()).is_err());
    }

    #[test]
    fn invalid_policies_are_rejected() {
        assert!(mint("right(", &generate_keypair(), None).is_err());
    }

    #[test]
    fn attenuate_adds_a_block_without_the_root_key() {
        let root = generate_keypair();
        let token = mint(POLICY, &root, None).unwrap();
        let narrowed = attenuate(&token, &[r#"check if tool("read_file")"#.into()], None).unwrap();

        let info = inspect(&narrowed, Some(&root.public())).unwrap();
        assert_eq!(info.blocks.len(), 2);
        assert!(info.blocks[1].contains(r#"check if tool("read_file")"#));
    }

    #[test]
    fn attenuate_only_accepts_checks() {
        let token = mint(POLICY, &generate_keypair(), None).unwrap();
        assert!(attenuate(&token, &[r#"right("send_email")"#.into()], None).is_err());
        assert!(attenuate(&token, &[], None).is_err());
    }

    #[test]
    fn inspect_reports_the_earliest_expiry() {
        let root = generate_keypair();
        let token = mint(POLICY, &root, Some(Duration::from_secs(3600))).unwrap();
        let token = attenuate(&token, &[], Some(Duration::from_secs(60))).unwrap();
        let expires = inspect(&token, None).unwrap().expires.expect("no expiry");
        let left = expires.duration_since(SystemTime::now()).unwrap();
        assert!(left <= Duration::from_secs(60), "{left:?}");
    }

    #[test]
    fn inspect_without_key_is_unverified() {
        let token = mint(POLICY, &generate_keypair(), None).unwrap();
        let info = inspect(&token, None).unwrap();
        assert!(!info.verified);
        assert_eq!(info.expires, None);
    }
}
