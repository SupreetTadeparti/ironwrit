//! Ledger entries, their canonical encoding, and signed tree heads.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A SHA-256 digest.
pub type Hash = [u8; 32];

/// Encoding version written as the first byte of every entry.
const ENTRY_VERSION: u8 = 1;
/// Signature domains, so an entry signature can never pass as a tree head's.
const ENTRY_DOMAIN: &[u8] = b"ironwrit-entry-v1\0";
const HEAD_DOMAIN: &[u8] = b"ironwrit-tree-head-v1\0";
/// Longest string field an entry may hold, in bytes.
pub const MAX_FIELD: usize = 64 * 1024;

/// What the gateway did with a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// The call was allowed. Written *before* it is forwarded upstream.
    Allow,
    /// The call was denied and never forwarded.
    Deny,
    /// An allowed call finished; `call_seq` points at its `Allow` entry.
    Completed,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Completed => "completed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Decision::Allow),
            "deny" => Some(Decision::Deny),
            "completed" => Some(Decision::Completed),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Decision::Allow => 0,
            Decision::Deny => 1,
            Decision::Completed => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Decision::Allow),
            1 => Some(Decision::Deny),
            2 => Some(Decision::Completed),
            _ => None,
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the gateway asks the ledger to record. The ledger assigns `seq` and `ts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub token_id: String,
    pub tool: String,
    pub args_hash: Hash,
    pub decision: Decision,
    pub reason: String,
    pub result_hash: Option<Hash>,
    pub call_seq: Option<u64>,
}

/// One row of the log. Its canonical encoding is the Merkle leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Position in the log, starting at 0. Also the Merkle leaf index.
    pub seq: u64,
    /// Milliseconds since the Unix epoch. Never decreases along the log.
    pub ts: u64,
    /// Which token authorized the call (`none` in pass-through mode).
    pub token_id: String,
    pub tool: String,
    /// SHA-256 of the canonical JSON arguments. The arguments themselves are
    /// never stored.
    pub args_hash: Hash,
    pub decision: Decision,
    /// Why a call was denied, or how a completed call ended.
    pub reason: String,
    /// SHA-256 of the canonical JSON result, for completed calls that returned one.
    pub result_hash: Option<Hash>,
    /// For `Completed` entries, the `Allow` entry they complete.
    pub call_seq: Option<u64>,
}

impl LedgerEntry {
    pub(crate) fn new(seq: u64, ts: u64, record: Record) -> Self {
        Self {
            seq,
            ts,
            token_id: record.token_id,
            tool: record.tool,
            args_hash: record.args_hash,
            decision: record.decision,
            reason: record.reason,
            result_hash: record.result_hash,
            call_seq: record.call_seq,
        }
    }

    /// Structural rules every entry must follow.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("token_id", &self.token_id),
            ("tool", &self.tool),
            ("reason", &self.reason),
        ] {
            if value.len() > MAX_FIELD {
                return Err(format!("{name} is longer than {MAX_FIELD} bytes"));
            }
        }
        match (self.decision, self.call_seq) {
            (Decision::Completed, None) => Err("completed entry without call_seq".into()),
            (Decision::Completed, Some(call)) if call >= self.seq => {
                Err(format!("completes entry {call}, which comes after it"))
            }
            (Decision::Allow | Decision::Deny, Some(_)) => {
                Err(format!("{} entry with call_seq", self.decision))
            }
            (Decision::Allow | Decision::Deny, None) if self.result_hash.is_some() => {
                Err(format!("{} entry with result_hash", self.decision))
            }
            _ => Ok(()),
        }
    }

    /// The canonical byte encoding: what gets signed and hashed into the tree.
    ///
    /// ```text
    /// u8 version | u64 seq | u64 ts | str token_id | str tool | [32] args_hash
    /// | u8 decision | str reason | opt [32] result_hash | opt u64 call_seq
    /// ```
    /// Integers are big-endian, `str` is a u32 length then UTF-8 bytes, and
    /// `opt` is a 0/1 byte followed by the value when 1.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.tool.len() + self.reason.len());
        out.push(ENTRY_VERSION);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        put_str(&mut out, &self.token_id);
        put_str(&mut out, &self.tool);
        out.extend_from_slice(&self.args_hash);
        out.push(self.decision.code());
        put_str(&mut out, &self.reason);
        match &self.result_hash {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(hash);
            }
            None => out.push(0),
        }
        match self.call_seq {
            Some(seq) => {
                out.push(1);
                out.extend_from_slice(&seq.to_be_bytes());
            }
            None => out.push(0),
        }
        out
    }

    /// Strict inverse of [`encode`](Self::encode): rejects anything that
    /// wouldn't re-encode to exactly the same bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != ENTRY_VERSION {
            return Err(format!("unknown entry version {version}"));
        }
        let entry = LedgerEntry {
            seq: r.u64()?,
            ts: r.u64()?,
            token_id: r.str()?,
            tool: r.str()?,
            args_hash: r.hash()?,
            decision: {
                let code = r.u8()?;
                Decision::from_code(code).ok_or_else(|| format!("unknown decision {code}"))?
            },
            reason: r.str()?,
            result_hash: if r.flag()? { Some(r.hash()?) } else { None },
            call_seq: if r.flag()? { Some(r.u64()?) } else { None },
        };
        if !r.0.is_empty() {
            return Err(format!("{} trailing bytes", r.0.len()));
        }
        entry.validate()?;
        Ok(entry)
    }

    pub fn sign(&self, key: &SigningKey) -> Signature {
        key.sign(&signed_message(ENTRY_DOMAIN, &self.encode()))
    }

    pub fn verify(&self, key: &VerifyingKey, signature: &Signature) -> bool {
        key.verify(&signed_message(ENTRY_DOMAIN, &self.encode()), signature)
            .is_ok()
    }

    /// RFC 6962 leaf hash of this entry.
    pub fn leaf_hash(&self) -> Hash {
        crate::merkle::leaf_hash(&self.encode())
    }
}

/// A signed commitment to the first `size` entries of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    pub size: u64,
    pub ts: u64,
    pub root: Hash,
    pub signature: Signature,
}

impl TreeHead {
    pub(crate) fn sign(size: u64, ts: u64, root: Hash, key: &SigningKey) -> Self {
        let signature = key.sign(&Self::message(size, ts, &root));
        Self {
            size,
            ts,
            root,
            signature,
        }
    }

    pub fn verify(&self, key: &VerifyingKey) -> bool {
        key.verify(
            &Self::message(self.size, self.ts, &self.root),
            &self.signature,
        )
        .is_ok()
    }

    fn message(size: u64, ts: u64, root: &Hash) -> Vec<u8> {
        let mut body = Vec::with_capacity(48);
        body.extend_from_slice(&size.to_be_bytes());
        body.extend_from_slice(&ts.to_be_bytes());
        body.extend_from_slice(root);
        signed_message(HEAD_DOMAIN, &body)
    }
}

fn signed_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    [domain, body].concat()
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // `validate` caps every string at MAX_FIELD, far below u32::MAX.
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.0.len() < n {
            return Err("truncated entry".into());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| "bad u64")?))
    }

    fn hash(&mut self) -> Result<Hash, String> {
        self.take(32)?.try_into().map_err(|_| "bad hash".into())
    }

    fn flag(&mut self) -> Result<bool, String> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(format!("bad option flag {other}")),
        }
    }

    fn str(&mut self) -> Result<String, String> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| "bad length")?);
        if len as usize > MAX_FIELD {
            return Err("string field too long".into());
        }
        let bytes = self.take(len as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| "string is not UTF-8".into())
    }
}

/// SHA-256 of `value` as canonical JSON: object keys sorted, no whitespace.
///
/// Used for `args_hash` and `result_hash`, so anyone holding the original
/// arguments can check them against the log without the log storing them.
pub fn hash_json(value: &Value) -> Hash {
    let mut out = String::new();
    write_canonical(value, &mut out);
    Sha256::digest(out.as_bytes()).into()
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    pub(crate) fn sample(seq: u64) -> LedgerEntry {
        LedgerEntry {
            seq,
            ts: 1_700_000_000_000 + seq,
            token_id: "tok".into(),
            tool: "read_file".into(),
            args_hash: [7; 32],
            decision: Decision::Deny,
            reason: "check failed: ünïcode".into(),
            result_hash: None,
            call_seq: None,
        }
    }

    #[test]
    fn encoding_round_trips() {
        let mut entry = sample(3);
        assert_eq!(LedgerEntry::decode(&entry.encode()).unwrap(), entry);
        entry.decision = Decision::Completed;
        entry.result_hash = Some([9; 32]);
        entry.call_seq = Some(2);
        assert_eq!(LedgerEntry::decode(&entry.encode()).unwrap(), entry);
    }

    #[test]
    fn decode_is_strict() {
        let bytes = sample(1).encode();
        assert!(LedgerEntry::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(LedgerEntry::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        let mut bad_version = bytes.clone();
        bad_version[0] = 2;
        assert!(LedgerEntry::decode(&bad_version).is_err());
        let mut bad_flag = bytes.clone();
        let flag = bad_flag.len() - 2;
        bad_flag[flag] = 2;
        assert!(LedgerEntry::decode(&bad_flag).is_err());
    }

    #[test]
    fn invalid_shapes_are_rejected() {
        let mut entry = sample(5);
        entry.call_seq = Some(1);
        assert!(entry.validate().is_err());
        entry.decision = Decision::Completed;
        entry.call_seq = Some(5);
        assert!(entry.validate().is_err());
        entry.call_seq = None;
        assert!(entry.validate().is_err());
    }

    #[test]
    fn signatures_cover_every_field() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let entry = sample(4);
        let signature = entry.sign(&key);
        assert!(entry.verify(&key.verifying_key(), &signature));

        let mut changed = entry.clone();
        changed.reason.push('!');
        assert!(!changed.verify(&key.verifying_key(), &signature));
        let mut changed = entry;
        changed.seq = 5;
        assert!(!changed.verify(&key.verifying_key(), &signature));
    }

    #[test]
    fn entry_signatures_are_not_tree_head_signatures() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let head = TreeHead::sign(1, 2, [3; 32], &key);
        assert!(head.verify(&key.verifying_key()));
        let entry = sample(0);
        assert!(!entry.verify(&key.verifying_key(), &head.signature));
    }

    #[test]
    fn json_hash_ignores_key_order() {
        let a = json!({"b": 1, "a": {"y": [1, "x"], "x": null}});
        let b: Value = serde_json::from_str(r#"{"a":{"x":null,"y":[1,"x"]},"b":1}"#).unwrap();
        assert_eq!(hash_json(&a), hash_json(&b));
        assert_ne!(hash_json(&a), hash_json(&json!({"b": 2})));
    }
}
