//! `ironwrit log`: read, verify and prove things about a ledger file.

use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use ironwrit_ledger::{Decision, Hash, LedgerEntry, Log, TreeHead};
use serde_json::{Value, json};

pub fn show(db: &Path) -> anyhow::Result<()> {
    let log = Log::open(db)?;
    let entries = log.entries()?;
    let heads = log.heads()?;

    println!(
        "{:>5}  {:<24}  {:<9}  {:<10}  {:<20}  details",
        "seq", "time", "decision", "token", "tool"
    );
    for entry in &entries {
        let details = match (entry.decision, entry.call_seq) {
            (Decision::Completed, Some(call)) => format!("#{call} {}", entry.reason),
            _ => entry.reason.clone(),
        };
        println!(
            "{:>5}  {:<24}  {:<9}  {:<10}  {:<20}  {details}",
            entry.seq,
            time(entry.ts),
            entry.decision.as_str(),
            short(&entry.token_id),
            entry.tool,
        );
    }
    let covered = heads.last().map_or(0, |h| h.size);
    println!(
        "\n{} entries, {} signed tree heads (newest covers {covered})",
        entries.len(),
        heads.len()
    );
    Ok(())
}

pub fn verify(db: &Path, public_key: &Path) -> anyhow::Result<()> {
    let key = ironwrit_ledger::read_verifying_key(public_key)?;
    let report = Log::open(db)?.verify(&key)?;

    for problem in &report.problems {
        eprintln!("error: {problem}");
    }
    if !report.is_ok() {
        bail!(
            "{} failed verification: {} problem(s) found",
            db.display(),
            report.problems.len()
        );
    }
    println!(
        "ok: {} entries and {} tree heads verified against {}",
        report.entries,
        report.heads,
        public_key.display()
    );
    if let Some(head) = &report.latest_head {
        println!(
            "newest tree head: size {}, root {}, signed {}",
            head.size,
            hex::encode(head.root),
            time(head.ts)
        );
    }
    if report.uncovered() > 0 {
        eprintln!(
            "warning: the last {} entries are not covered by a signed tree head yet \
             (normal while the gateway runs, or after it was killed)",
            report.uncovered()
        );
    }
    Ok(())
}

pub fn prove(db: &Path, seq: u64, public_key: Option<&Path>) -> anyhow::Result<()> {
    let proof = Log::open(db)?.prove(seq)?;
    if let Some(path) = public_key {
        let key = ironwrit_ledger::read_verifying_key(path)?;
        if !proof.verify(&key) {
            bail!("the proof does not verify against {}", path.display());
        }
        eprintln!("proof verified against {}", path.display());
    }
    print_json(&json!({
        "entry": entry_json(&proof.entry),
        "leaf_hash": hex::encode(proof.leaf_hash),
        "tree_head": head_json(&proof.head),
        "path": hashes(&proof.path),
    }))
}

pub fn consistency(db: &Path, old: u64, new: u64, public_key: Option<&Path>) -> anyhow::Result<()> {
    let proof = Log::open(db)?.consistency(old, new)?;
    if let Some(path) = public_key {
        let key = ironwrit_ledger::read_verifying_key(path)?;
        if !proof.verify(&key) {
            bail!("the proof does not verify against {}", path.display());
        }
        eprintln!("proof verified against {}", path.display());
    }
    if proof.old_head.is_none() || proof.new_head.is_none() {
        eprintln!(
            "note: no signed tree head at one of these sizes; the roots are computed, not signed"
        );
    }
    print_json(&json!({
        "old": {"size": proof.old_size, "root": hex::encode(proof.old_root),
                "tree_head": proof.old_head.as_ref().map(head_json)},
        "new": {"size": proof.new_size, "root": hex::encode(proof.new_root),
                "tree_head": proof.new_head.as_ref().map(head_json)},
        "path": hashes(&proof.path),
    }))
}

fn entry_json(entry: &LedgerEntry) -> Value {
    json!({
        "seq": entry.seq,
        "ts": entry.ts,
        "token_id": entry.token_id,
        "tool": entry.tool,
        "args_hash": hex::encode(entry.args_hash),
        "decision": entry.decision.as_str(),
        "reason": entry.reason,
        "result_hash": entry.result_hash.map(hex::encode),
        "call_seq": entry.call_seq,
    })
}

fn head_json(head: &TreeHead) -> Value {
    json!({
        "size": head.size,
        "ts": head.ts,
        "root": hex::encode(head.root),
        "signature": hex::encode(head.signature.to_bytes()),
    })
}

fn hashes(path: &[Hash]) -> Vec<String> {
    path.iter().map(hex::encode).collect()
}

fn print_json(value: &Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn time(ms: u64) -> String {
    let at = SystemTime::UNIX_EPOCH + Duration::from_millis(ms);
    humantime::format_rfc3339_millis(at).to_string()
}

/// Token ids are long; the first few characters are enough to tell them apart.
fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}
