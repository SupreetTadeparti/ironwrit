//! Full-log verification: what `ironwrit log verify` runs, and what the
//! gateway runs before it appends to an existing log.

use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::Connection;
use rusqlite::types::Value;

use crate::entry::{Decision, Hash, LedgerEntry, TreeHead};
use crate::store::{entry_from_row, head_from_row, int};
use crate::{Result, merkle};

/// Where a problem was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Entry(u64),
    /// The tree head with this size.
    Head(u64),
}

/// One thing wrong with the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub at: Location,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.at {
            Location::Entry(seq) => write!(f, "entry {seq}: {}", self.message),
            Location::Head(size) => write!(f, "tree head at size {size}: {}", self.message),
        }
    }
}

/// The outcome of verifying a log.
#[derive(Debug, Clone)]
pub struct Report {
    /// Number of entries the log should have (one past the highest seq seen).
    pub entries: u64,
    pub heads: u64,
    /// Newest tree head whose signature and root check out.
    pub latest_head: Option<TreeHead>,
    /// Empty if the log is intact.
    pub problems: Vec<Problem>,
    pub(crate) last_ts: u64,
    leaves: Vec<Option<Hash>>,
}

impl Report {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }

    /// Entries after the newest valid head. Normal after a crash, but nothing
    /// commits to them yet, so they could be truncated undetectably.
    pub fn uncovered(&self) -> u64 {
        self.entries - self.latest_head.as_ref().map_or(0, |h| h.size)
    }

    /// Leaf hashes of an intact log.
    pub(crate) fn leaves(&self) -> Vec<Hash> {
        self.leaves.iter().map(|l| l.unwrap_or_default()).collect()
    }
}

pub(crate) struct EntryRow {
    /// The `seq` column, if it was a non-negative integer.
    pub seq: Option<u64>,
    rowid: i64,
    pub parsed: std::result::Result<(LedgerEntry, Signature), String>,
}

impl EntryRow {
    pub fn seq_label(&self) -> String {
        self.seq
            .map_or_else(|| format!("at rowid {}", self.rowid), |s| s.to_string())
    }
}

pub(crate) fn read_entries(conn: &Connection) -> Result<Vec<EntryRow>> {
    let mut stmt = conn.prepare(
        "SELECT rowid, seq, ts, token_id, tool, args_hash, decision, reason, result_hash,
                call_seq, signature
         FROM entries ORDER BY seq",
    )?;
    let rows = stmt.query_map([], |row| {
        let rowid: i64 = row.get(0)?;
        let values = (1..=10)
            .map(|i| row.get::<_, Value>(i))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(EntryRow {
            seq: int(&values[0], "seq").ok(),
            rowid,
            parsed: entry_from_row(&values),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn read_heads(conn: &Connection) -> Result<Vec<std::result::Result<TreeHead, String>>> {
    let mut stmt =
        conn.prepare("SELECT size, ts, root, signature FROM tree_heads ORDER BY size")?;
    let rows = stmt.query_map([], |row| {
        let values = (0..4)
            .map(|i| row.get::<_, Value>(i))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(head_from_row(&values))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn verify(conn: &Connection, key: &VerifyingKey) -> Result<Report> {
    let mut problems = Vec::new();
    let mut entry_problem = |seq: u64, message: String| {
        problems.push(Problem {
            at: Location::Entry(seq),
            message,
        });
    };

    let mut leaves: Vec<Option<Hash>> = Vec::new();
    let mut last_ts = 0;
    // Allowed calls not yet completed, keyed by seq.
    let mut open_calls: HashMap<u64, LedgerEntry> = HashMap::new();

    for row in read_entries(conn)? {
        let Some(seq) = row.seq else {
            let next = leaves.len() as u64;
            entry_problem(next, format!("row {} has an invalid seq", row.rowid));
            continue;
        };
        let expected = leaves.len() as u64;
        if seq > expected {
            let message = if seq == expected + 1 {
                "entry is missing (deleted?)".to_owned()
            } else {
                format!("entries {expected}..={} are missing (deleted?)", seq - 1)
            };
            entry_problem(expected, message);
            leaves.resize(seq as usize, None);
        }

        let (entry, signature) = match row.parsed {
            Ok(parsed) => parsed,
            Err(message) => {
                entry_problem(seq, format!("malformed: {message}"));
                leaves.push(None);
                continue;
            }
        };
        if !entry.verify(key, &signature) {
            entry_problem(
                seq,
                "signature doesn't match: the entry was modified, moved, or not written by this gateway".into(),
            );
        }
        if entry.ts < last_ts {
            entry_problem(seq, "timestamp goes backwards (entries reordered?)".into());
        }
        last_ts = last_ts.max(entry.ts);
        match entry.decision {
            Decision::Allow => {
                open_calls.insert(seq, entry.clone());
            }
            Decision::Deny => {}
            Decision::Completed => {
                let call = entry.call_seq.unwrap_or_default();
                match open_calls.remove(&call) {
                    Some(allowed)
                        if allowed.tool == entry.tool
                            && allowed.args_hash == entry.args_hash
                            && allowed.token_id == entry.token_id => {}
                    Some(_) => {
                        entry_problem(seq, format!("doesn't match the call at entry {call}"))
                    }
                    None => entry_problem(
                        seq,
                        format!("completes entry {call}, which isn't an open allowed call"),
                    ),
                }
            }
        }
        leaves.push(Some(entry.leaf_hash()));
    }

    let entries = leaves.len() as u64;
    let mut heads = 0;
    let mut latest_head: Option<TreeHead> = None;
    let mut truncated = false;
    for head in read_heads(conn)? {
        heads += 1;
        let head = match head {
            Ok(head) => head,
            Err(message) => {
                problems.push(Problem {
                    at: Location::Head(heads),
                    message: format!("malformed: {message}"),
                });
                continue;
            }
        };
        let head_problem = |message: String| Problem {
            at: Location::Head(head.size),
            message,
        };
        if !head.verify(key) {
            problems.push(head_problem(
                "signature doesn't match: the tree head was modified or forged".into(),
            ));
            continue;
        }
        if head.size > entries {
            // Every later head covers the same missing entries; say it once.
            if std::mem::replace(&mut truncated, true) {
                continue;
            }
            problems.push(Problem {
                at: Location::Entry(entries),
                message: format!(
                    "entries {entries}..={} are missing: the tree head at size {} covers them (log truncated?)",
                    head.size - 1,
                    head.size
                ),
            });
            continue;
        }
        if let Some(prev) = &latest_head
            && head.ts < prev.ts
        {
            problems.push(head_problem("timestamp goes backwards".into()));
        }
        // Gaps and malformed entries were already reported above.
        let tree: Option<Vec<Hash>> = leaves[..head.size as usize].iter().copied().collect();
        if let Some(tree) = tree {
            if merkle::root(&tree) != head.root {
                problems.push(head_problem(format!(
                    "root doesn't match entries 0..={}",
                    head.size.saturating_sub(1)
                )));
                continue;
            }
            latest_head = Some(head);
        }
    }

    Ok(Report {
        entries,
        heads,
        latest_head,
        problems,
        last_ts,
        leaves,
    })
}
