//! SQLite storage: an append-only `entries` table and signed `tree_heads`.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, params};

use crate::entry::{Decision, Hash, LedgerEntry, Record, TreeHead};
use crate::verify::{self, Report};
use crate::{Error, Result, merkle};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
    seq         INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    token_id    TEXT NOT NULL,
    tool        TEXT NOT NULL,
    args_hash   BLOB NOT NULL,
    decision    TEXT NOT NULL,
    reason      TEXT NOT NULL,
    result_hash BLOB,
    call_seq    INTEGER,
    signature   BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS tree_heads (
    size      INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    root      BLOB NOT NULL,
    signature BLOB NOT NULL
) STRICT;

-- Guards against accidents, not attackers: anyone with the file can drop
-- these, which is what signatures and `verify` are for.
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries
    BEGIN SELECT RAISE(ABORT, 'the ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
    BEGIN SELECT RAISE(ABORT, 'the ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tree_heads_no_update BEFORE UPDATE ON tree_heads
    BEGIN SELECT RAISE(ABORT, 'the ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS tree_heads_no_delete BEFORE DELETE ON tree_heads
    BEGIN SELECT RAISE(ABORT, 'the ledger is append-only'); END;
";

/// When to sign a new tree head.
#[derive(Debug, Clone, Copy)]
pub struct HeadPolicy {
    /// After this many new entries (0 disables).
    pub every: u64,
    /// After this long, if there are new entries. The gateway runs the timer.
    pub interval: Duration,
}

impl Default for HeadPolicy {
    fn default() -> Self {
        Self {
            every: 64,
            interval: Duration::from_secs(30),
        }
    }
}

/// The writable log. Shared by every call in a gateway session.
pub struct Ledger {
    inner: Mutex<Inner>,
    heads: HeadPolicy,
}

struct Inner {
    conn: Connection,
    key: SigningKey,
    leaves: Vec<Hash>,
    last_ts: u64,
    /// Size of the newest signed tree head.
    head_size: u64,
}

impl Ledger {
    /// Open (or create) the ledger at `path`.
    ///
    /// An existing log is fully verified with `key` first: the gateway won't
    /// extend a log it can't vouch for.
    pub fn open(path: &Path, key: SigningKey, heads: HeadPolicy) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn, key, heads)
    }

    /// A ledger that lives only as long as this value. For tests.
    pub fn open_in_memory(key: SigningKey, heads: HeadPolicy) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, key, heads)
    }

    fn init(conn: Connection, key: SigningKey, heads: HeadPolicy) -> Result<Self> {
        // Every append must survive a crash before the call is forwarded.
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(SCHEMA)?;
        let report = verify::verify(&conn, &key.verifying_key())?;
        if let Some(problem) = report.problems.first() {
            let more = match report.problems.len() - 1 {
                0 => String::new(),
                n => format!(" (and {n} more)"),
            };
            return Err(Error::Integrity(format!(
                "{problem}{more}; refusing to append to it (check it with `ironwrit log verify`)"
            )));
        }
        let inner = Inner {
            conn,
            key,
            leaves: report.leaves(),
            last_ts: report.last_ts,
            head_size: report.latest_head.as_ref().map_or(0, |h| h.size),
        };
        Ok(Self {
            inner: Mutex::new(inner),
            heads,
        })
    }

    pub fn head_policy(&self) -> HeadPolicy {
        self.heads
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.lock().key.verifying_key()
    }

    /// Number of entries in the log.
    pub fn size(&self) -> u64 {
        self.lock().leaves.len() as u64
    }

    /// Sign, store and return the next entry. Nothing is written on error.
    pub fn append(&self, record: Record) -> Result<LedgerEntry> {
        let mut inner = self.lock();
        let seq = inner.leaves.len() as u64;
        let ts = now_ms().max(inner.last_ts);
        let entry = LedgerEntry::new(seq, ts, record);
        entry.validate().map_err(Error::InvalidArgument)?;
        let signature = entry.sign(&inner.key);
        inner.conn.execute(
            "INSERT INTO entries (seq, ts, token_id, tool, args_hash, decision, reason,
                                  result_hash, call_seq, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                to_sql_int(entry.seq)?,
                to_sql_int(entry.ts)?,
                entry.token_id,
                entry.tool,
                entry.args_hash.as_slice(),
                entry.decision.as_str(),
                entry.reason,
                entry.result_hash.as_ref().map(|h| h.as_slice()),
                entry.call_seq.map(to_sql_int).transpose()?,
                signature.to_bytes().as_slice(),
            ],
        )?;
        inner.leaves.push(entry.leaf_hash());
        inner.last_ts = ts;

        if self.heads.every > 0 && inner.leaves.len() as u64 - inner.head_size >= self.heads.every {
            // The entry is already durable; a missing head only delays coverage.
            if let Err(e) = inner.sign_head() {
                tracing::warn!(error = %e, "failed to sign tree head");
            }
        }
        Ok(entry)
    }

    /// Sign a tree head over every entry so far, unless the newest head
    /// already covers them all.
    pub fn sign_head(&self) -> Result<Option<TreeHead>> {
        self.lock().sign_head()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic mid-append leaves nothing half-written (one INSERT), so the
        // state is still usable.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Inner {
    fn sign_head(&mut self) -> Result<Option<TreeHead>> {
        let size = self.leaves.len() as u64;
        if size == self.head_size {
            return Ok(None);
        }
        let ts = now_ms().max(self.last_ts);
        let head = TreeHead::sign(size, ts, merkle::root(&self.leaves), &self.key);
        self.conn.execute(
            "INSERT INTO tree_heads (size, ts, root, signature) VALUES (?1, ?2, ?3, ?4)",
            params![
                to_sql_int(head.size)?,
                to_sql_int(head.ts)?,
                head.root.as_slice(),
                head.signature.to_bytes().as_slice(),
            ],
        )?;
        self.head_size = size;
        self.last_ts = ts;
        Ok(Some(head))
    }
}

/// A read-only view of a ledger file, for `ironwrit log`.
pub struct Log {
    conn: Connection,
}

impl Log {
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::InvalidArgument(format!(
                "{}: no such ledger",
                path.display()
            )));
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        Ok(Self { conn })
    }

    /// Check every entry, every tree head, and their agreement.
    pub fn verify(&self, key: &VerifyingKey) -> Result<Report> {
        verify::verify(&self.conn, key)
    }

    /// All entries in order. Fails on rows that don't decode; `verify`
    /// reports those individually.
    pub fn entries(&self) -> Result<Vec<LedgerEntry>> {
        verify::read_entries(&self.conn)?
            .into_iter()
            .map(|row| {
                let label = row.seq_label();
                row.parsed
                    .map(|(entry, _)| entry)
                    .map_err(|e| Error::Integrity(format!("entry {label}: {e}")))
            })
            .collect()
    }

    /// All tree heads, oldest first.
    pub fn heads(&self) -> Result<Vec<TreeHead>> {
        verify::read_heads(&self.conn)?
            .into_iter()
            .map(|row| row.map_err(Error::Integrity))
            .collect()
    }

    /// Prove that entry `seq` is in the tree committed to by the newest head.
    pub fn prove(&self, seq: u64) -> Result<InclusionProof> {
        let leaves = self.leaves()?;
        let head = self
            .heads()?
            .pop()
            .filter(|head| head.size > seq)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "entry {seq} is not covered by a signed tree head yet"
                ))
            })?;
        let size = usize::try_from(head.size).unwrap_or(usize::MAX);
        let tree = leaves.get(..size).ok_or_else(|| missing(head.size))?;
        check_root(&head, tree)?;
        let index = usize::try_from(seq).unwrap_or(usize::MAX);
        let path = merkle::inclusion_proof(tree, index).ok_or_else(|| missing(head.size))?;
        let entry = self
            .entries()?
            .into_iter()
            .nth(index)
            .ok_or_else(|| missing(head.size))?;
        Ok(InclusionProof {
            leaf_hash: tree[index],
            entry,
            head,
            path,
        })
    }

    /// Prove that the tree of the first `old` entries is a prefix of the
    /// tree of the first `new` entries.
    pub fn consistency(&self, old: u64, new: u64) -> Result<ConsistencyProof> {
        if old == 0 || old > new {
            return Err(Error::InvalidArgument(
                "need 0 < OLD <= NEW tree sizes".into(),
            ));
        }
        let leaves = self.leaves()?;
        let new_len = usize::try_from(new).unwrap_or(usize::MAX);
        let tree = leaves.get(..new_len).ok_or_else(|| {
            Error::InvalidArgument(format!("the log has only {} entries", leaves.len()))
        })?;
        let old_len = old as usize;
        let heads = self.heads()?;
        let head_at = |size: u64| heads.iter().find(|h| h.size == size).cloned();
        let (old_head, new_head) = (head_at(old), head_at(new));
        for head in old_head.iter().chain(&new_head) {
            check_root(head, &tree[..head.size as usize])?;
        }
        let path = merkle::consistency_proof(tree, old_len)
            .ok_or_else(|| Error::InvalidArgument("bad tree sizes".into()))?;
        Ok(ConsistencyProof {
            old_size: old,
            old_root: merkle::root(&tree[..old_len]),
            new_size: new,
            new_root: merkle::root(tree),
            path,
            old_head,
            new_head,
        })
    }

    fn leaves(&self) -> Result<Vec<Hash>> {
        Ok(self.entries()?.iter().map(LedgerEntry::leaf_hash).collect())
    }
}

fn missing(size: u64) -> Error {
    Error::Integrity(format!(
        "the tree head at size {size} covers missing entries; run `ironwrit log verify`"
    ))
}

fn check_root(head: &TreeHead, tree: &[Hash]) -> Result<()> {
    if merkle::root(tree) == head.root {
        Ok(())
    } else {
        Err(Error::Integrity(format!(
            "entries don't match the tree head at size {}; run `ironwrit log verify`",
            head.size
        )))
    }
}

/// Entry `entry` is leaf `entry.seq` of the tree that `head` signs.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub entry: LedgerEntry,
    pub leaf_hash: Hash,
    pub head: TreeHead,
    pub path: Vec<Hash>,
}

impl InclusionProof {
    /// Check the proof on its own: needs only the gateway public key.
    pub fn verify(&self, key: &VerifyingKey) -> bool {
        self.head.verify(key)
            && self.entry.leaf_hash() == self.leaf_hash
            && merkle::verify_inclusion(
                &self.leaf_hash,
                self.entry.seq,
                self.head.size,
                &self.path,
                &self.head.root,
            )
    }
}

/// The tree of size `old_size` is a prefix of the tree of size `new_size`.
#[derive(Debug, Clone)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub old_root: Hash,
    pub new_size: u64,
    pub new_root: Hash,
    pub path: Vec<Hash>,
    /// Signed heads at those sizes, if the gateway signed one there.
    pub old_head: Option<TreeHead>,
    pub new_head: Option<TreeHead>,
}

impl ConsistencyProof {
    /// Check the proof, and any heads it carries, against the gateway key.
    pub fn verify(&self, key: &VerifyingKey) -> bool {
        let head_ok = |head: &Option<TreeHead>, size, root| {
            head.as_ref()
                .is_none_or(|h| h.size == size && h.root == root && h.verify(key))
        };
        head_ok(&self.old_head, self.old_size, self.old_root)
            && head_ok(&self.new_head, self.new_size, self.new_root)
            && merkle::verify_consistency(
                self.old_size,
                self.new_size,
                &self.old_root,
                &self.new_root,
                &self.path,
            )
    }
}

/// Convert a stored row back into an entry, or say what's wrong with it.
pub(crate) fn entry_from_row(
    values: &[Value],
) -> std::result::Result<(LedgerEntry, ed25519_dalek::Signature), String> {
    let [
        seq,
        ts,
        token_id,
        tool,
        args_hash,
        decision,
        reason,
        result_hash,
        call_seq,
        signature,
    ] = values
    else {
        return Err("wrong number of columns".into());
    };
    let decision = text(decision, "decision")?;
    let entry = LedgerEntry {
        seq: int(seq, "seq")?,
        ts: int(ts, "ts")?,
        token_id: text(token_id, "token_id")?,
        tool: text(tool, "tool")?,
        args_hash: hash(args_hash, "args_hash")?,
        decision: Decision::parse(&decision)
            .ok_or_else(|| format!("unknown decision {decision:?}"))?,
        reason: text(reason, "reason")?,
        result_hash: match result_hash {
            Value::Null => None,
            other => Some(hash(other, "result_hash")?),
        },
        call_seq: match call_seq {
            Value::Null => None,
            other => Some(int(other, "call_seq")?),
        },
    };
    entry.validate()?;
    Ok((entry, signature_from(signature)?))
}

pub(crate) fn head_from_row(values: &[Value]) -> std::result::Result<TreeHead, String> {
    let [size, ts, root, signature] = values else {
        return Err("wrong number of columns".into());
    };
    Ok(TreeHead {
        size: int(size, "size")?,
        ts: int(ts, "ts")?,
        root: hash(root, "root")?,
        signature: signature_from(signature)?,
    })
}

pub(crate) fn int(value: &Value, name: &str) -> std::result::Result<u64, String> {
    match value {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| format!("{name} is negative")),
        _ => Err(format!("{name} is not an integer")),
    }
}

fn text(value: &Value, name: &str) -> std::result::Result<String, String> {
    match value {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(format!("{name} is not text")),
    }
}

fn hash(value: &Value, name: &str) -> std::result::Result<Hash, String> {
    match value {
        Value::Blob(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| format!("{name} is not 32 bytes")),
        _ => Err(format!("{name} is not a blob")),
    }
}

fn signature_from(value: &Value) -> std::result::Result<ed25519_dalek::Signature, String> {
    match value {
        Value::Blob(b) => {
            ed25519_dalek::Signature::from_slice(b).map_err(|_| "signature is not 64 bytes".into())
        }
        _ => Err("signature is not a blob".into()),
    }
}

fn to_sql_int(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| Error::InvalidArgument(format!("{n} is too large to store")))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
