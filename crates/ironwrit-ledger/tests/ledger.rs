//! Storage, proofs, and tamper detection against a real SQLite file.

use std::path::{Path, PathBuf};

use ironwrit_ledger::{Decision, HeadPolicy, Ledger, Location, Log, Record, SigningKey, hash_json};
use rusqlite::Connection;
use serde_json::json;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn record(tool: &str, decision: Decision, call_seq: Option<u64>) -> Record {
    Record {
        token_id: "tok".into(),
        tool: tool.into(),
        args_hash: hash_json(&json!({"path": tool})),
        decision,
        reason: match decision {
            Decision::Deny => "tool is not granted".into(),
            Decision::Completed => "ok".into(),
            Decision::Allow => String::new(),
        },
        result_hash: call_seq.map(|_| hash_json(&json!("result"))),
        call_seq,
    }
}

/// A closed log of 10 entries with tree heads at sizes 4, 8 and 10:
/// allow/completed pairs at even seqs, and denials at 4..=5 and 9.
fn sample_log(dir: &Path) -> PathBuf {
    let path = dir.join("ironwrit.db");
    let heads = HeadPolicy {
        every: 4,
        ..HeadPolicy::default()
    };
    let ledger = Ledger::open(&path, key(), heads).unwrap();
    for seq in 0..10u64 {
        let rec = match seq {
            4 | 5 | 9 => record("send_email", Decision::Deny, None),
            s if s % 2 == 0 => record("read_file", Decision::Allow, None),
            s => record("read_file", Decision::Completed, Some(s - 1)),
        };
        assert_eq!(ledger.append(rec).unwrap().seq, seq);
    }
    ledger.sign_head().unwrap().expect("a new head");
    path
}

/// Open the file the way an attacker would: no triggers in the way.
fn tamper(path: &Path, sql: &str) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER entries_no_update; DROP TRIGGER entries_no_delete;
         DROP TRIGGER tree_heads_no_update; DROP TRIGGER tree_heads_no_delete;",
    )
    .unwrap();
    conn.execute_batch(sql).unwrap();
}

fn problems(path: &Path) -> Vec<Location> {
    let report = Log::open(path)
        .unwrap()
        .verify(&key().verifying_key())
        .unwrap();
    report.problems.iter().map(|p| p.at).collect()
}

#[test]
fn intact_log_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let log = Log::open(&path).unwrap();
    let report = log.verify(&key().verifying_key()).unwrap();
    assert!(report.is_ok(), "{:?}", report.problems);
    assert_eq!(report.entries, 10);
    assert_eq!(report.heads, 3);
    assert_eq!(report.uncovered(), 0);
    let sizes: Vec<u64> = log.heads().unwrap().iter().map(|h| h.size).collect();
    assert_eq!(sizes, [4, 8, 10]);
}

#[test]
fn reopening_continues_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let ledger = Ledger::open(&path, key(), HeadPolicy::default()).unwrap();
    assert_eq!(ledger.size(), 10);
    assert!(ledger.sign_head().unwrap().is_none(), "nothing new to sign");
    let entry = ledger.append(record("x", Decision::Deny, None)).unwrap();
    assert_eq!(entry.seq, 10);
    ledger.sign_head().unwrap().unwrap();
    drop(ledger);
    assert!(problems(&path).is_empty());
}

#[test]
fn gateway_refuses_to_extend_a_log_it_did_not_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let other = SigningKey::from_bytes(&[7; 32]);
    let err = Ledger::open(&path, other, HeadPolicy::default())
        .err()
        .expect("opened with the wrong key");
    assert!(err.to_string().contains("refusing to append"), "{err}");
}

#[test]
fn gateway_refuses_to_extend_a_tampered_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    tamper(
        &path,
        "UPDATE entries SET reason = 'nothing to see' WHERE seq = 4;",
    );
    assert!(Ledger::open(&path, key(), HeadPolicy::default()).is_err());
}

#[test]
fn triggers_block_accidental_edits() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let conn = Connection::open(&path).unwrap();
    assert!(conn.execute("UPDATE entries SET reason = 'x'", []).is_err());
    assert!(conn.execute("DELETE FROM entries", []).is_err());
    assert!(conn.execute("DELETE FROM tree_heads", []).is_err());
}

#[test]
fn every_entry_has_a_valid_inclusion_proof() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let log = Log::open(&path).unwrap();
    let public = key().verifying_key();
    for seq in 0..10 {
        let proof = log.prove(seq).unwrap();
        assert_eq!(proof.entry.seq, seq);
        assert_eq!(proof.head.size, 10);
        assert!(proof.verify(&public), "entry {seq}");

        let mut forged = proof.clone();
        forged.entry.reason = "edited".into();
        forged.leaf_hash = forged.entry.leaf_hash();
        assert!(!forged.verify(&public));
    }
    assert!(log.prove(10).is_err());
}

#[test]
fn consistency_proofs_link_tree_heads() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let log = Log::open(&path).unwrap();
    let public = key().verifying_key();
    for (old, new) in [(4, 8), (4, 10), (8, 10), (1, 10), (3, 7), (10, 10)] {
        let proof = log.consistency(old, new).unwrap();
        assert!(proof.verify(&public), "{old} -> {new}");
    }
    let proof = log.consistency(4, 10).unwrap();
    assert!(proof.old_head.is_some() && proof.new_head.is_some());
    let mut bad = proof;
    bad.old_root[0] ^= 1;
    assert!(!bad.verify(&public));
    assert!(log.consistency(0, 4).is_err());
    assert!(log.consistency(4, 11).is_err());
}

#[test]
fn edited_entries_are_named() {
    for column in [
        "reason = 'nothing to see'",
        "tool = 'read_file'",
        "decision = 'allow'",
        "args_hash = zeroblob(32)",
        "ts = ts + 1",
        "token_id = 'other'",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = sample_log(dir.path());
        tamper(
            &path,
            &format!("UPDATE entries SET {column} WHERE seq = 5;"),
        );
        let found = problems(&path);
        assert!(found.contains(&Location::Entry(5)), "{column}: {found:?}");
    }
}

#[test]
fn malformed_rows_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    tamper(&path, "UPDATE entries SET signature = x'00' WHERE seq = 2;");
    assert!(problems(&path).contains(&Location::Entry(2)));
}

#[test]
fn deleted_entries_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    tamper(&path, "DELETE FROM entries WHERE seq = 4;");
    let found = problems(&path);
    assert_eq!(found.first(), Some(&Location::Entry(4)), "{found:?}");
}

#[test]
fn reordered_entries_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    tamper(
        &path,
        "UPDATE entries SET seq = -1 WHERE seq = 2;
         UPDATE entries SET seq = 2 WHERE seq = 6;
         UPDATE entries SET seq = 6 WHERE seq = -1;",
    );
    let found = problems(&path);
    assert!(found.contains(&Location::Entry(2)), "{found:?}");
    assert!(found.contains(&Location::Entry(6)), "{found:?}");
}

#[test]
fn truncated_entries_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    tamper(&path, "DELETE FROM entries WHERE seq >= 7;");
    assert_eq!(problems(&path), [Location::Entry(7)]);
}

#[test]
fn tampered_tree_heads_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    tamper(
        &path,
        "UPDATE tree_heads SET root = zeroblob(32) WHERE size = 8;",
    );
    assert_eq!(problems(&path), [Location::Head(8)]);
}

#[test]
fn forged_entries_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    // Someone else's key can't add to the log.
    let forged = dir.path().join("forged.db");
    let other = Ledger::open(
        &forged,
        SigningKey::from_bytes(&[7; 32]),
        HeadPolicy::default(),
    )
    .unwrap();
    for _ in 0..=10 {
        other
            .append(record("send_email", Decision::Deny, None))
            .unwrap();
    }
    drop(other);
    tamper(
        &path,
        &format!(
            "ATTACH '{}' AS f; INSERT INTO entries SELECT * FROM f.entries WHERE seq = 10;",
            forged.display().to_string().replace('\'', "''")
        ),
    );
    assert_eq!(problems(&path), [Location::Entry(10)]);
}

#[test]
fn completions_must_match_their_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ironwrit.db");
    let ledger = Ledger::open(&path, key(), HeadPolicy::default()).unwrap();
    ledger
        .append(record("read_file", Decision::Allow, None))
        .unwrap();
    // Completes a different call than the one at seq 0.
    let mut rec = record("write_file", Decision::Completed, Some(0));
    rec.reason = "ok".into();
    ledger.append(rec).unwrap();
    drop(ledger);
    assert_eq!(problems(&path), [Location::Entry(1)]);
}

/// The one change a lone verifier can't see: dropping the newest entries
/// *and* every tree head that covers them. A saved head catches it.
#[test]
fn rollback_needs_a_saved_tree_head() {
    let dir = tempfile::tempdir().unwrap();
    let path = sample_log(dir.path());
    let saved = Log::open(&path).unwrap().heads().unwrap().pop().unwrap();
    tamper(
        &path,
        "DELETE FROM entries WHERE seq >= 8; DELETE FROM tree_heads WHERE size > 8;",
    );
    let log = Log::open(&path).unwrap();
    assert!(problems(&path).is_empty());
    assert!(log.consistency(8, saved.size).is_err());
}
