use std::path::Path;
use std::process::{Command, Output};

fn ironwrit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ironwrit"))
        .args(args)
        .output()
        .expect("failed to run ironwrit binary")
}

#[test]
fn help_lists_all_subcommands() {
    let out = ironwrit(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for cmd in ["keygen", "mint", "attenuate", "inspect", "run", "log"] {
        assert!(stdout.contains(cmd), "--help is missing `{cmd}`:\n{stdout}");
    }
}

#[test]
fn version_matches_crate() {
    let out = ironwrit(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        format!("ironwrit {}", env!("CARGO_PKG_VERSION"))
    );
}

/// Run ironwrit in `dir`, with no token or key settings inherited.
fn ironwrit_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ironwrit"))
        .args(args)
        .current_dir(dir)
        .env_remove("IRONWRIT_TOKEN")
        .env_remove("IRONWRIT_ROOT_PUB")
        .env_remove("IRONWRIT_CONFIG")
        .env_remove("IRONWRIT_LEDGER")
        .env_remove("IRONWRIT_GATEWAY_KEY")
        .output()
        .expect("failed to run ironwrit binary")
}

fn assert_ok(out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "stderr was:
{stderr}"
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn assert_fails_with(out: &Output, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "expected failure");
    assert!(
        stderr.contains(needle),
        "stderr was:
{stderr}"
    );
}

#[test]
fn keygen_mint_attenuate_inspect() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("policy.dl"),
        "right(\"read_file\");
",
    )
    .unwrap();

    assert_ok(&ironwrit_in(d, &["keygen"]));
    assert!(d.join("root.key").exists() && d.join("root.pub").exists());
    assert_fails_with(&ironwrit_in(d, &["keygen"]), "already exists");

    assert_ok(&ironwrit_in(
        d,
        &[
            "mint",
            "--policy",
            "policy.dl",
            "--ttl",
            "1h",
            "-o",
            "token",
        ],
    ));
    let narrowed = assert_ok(&ironwrit_in(
        d,
        &["attenuate", "token", "--check", "check if op(\"read\")"],
    ));
    std::fs::write(d.join("narrowed"), narrowed).unwrap();

    let report = assert_ok(&ironwrit_in(
        d,
        &["inspect", "narrowed", "--pub", "root.pub"],
    ));
    assert!(report.contains("signature: valid"), "{report}");
    assert!(report.contains("(in 59m"), "{report}");
    assert!(report.contains("right(\"read_file\")"), "{report}");
    assert!(
        report.contains(
            "block 1:
  check if op(\"read\")"
        ),
        "{report}"
    );
}

#[test]
fn inspect_rejects_tokens_from_another_root() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("policy.dl"),
        "right(\"read_file\");
",
    )
    .unwrap();
    assert_ok(&ironwrit_in(d, &["keygen", "--out", "a"]));
    assert_ok(&ironwrit_in(d, &["keygen", "--out", "b"]));
    assert_ok(&ironwrit_in(
        d,
        &[
            "mint",
            "--key",
            "a.key",
            "--policy",
            "policy.dl",
            "-o",
            "token",
        ],
    ));
    assert_fails_with(
        &ironwrit_in(d, &["inspect", "token", "--pub", "b.pub"]),
        "malformed token",
    );
}

#[test]
fn run_refuses_forged_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert_ok(&ironwrit_in(d, &["keygen"]));
    assert_fails_with(
        &ironwrit_in(d, &["run", "--token", "not-a-token", "--", "anything"]),
        "malformed token",
    );
}

#[test]
fn run_with_token_requires_config() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("policy.dl"),
        "right(\"read_file\");
",
    )
    .unwrap();
    assert_ok(&ironwrit_in(d, &["keygen"]));
    let token = assert_ok(&ironwrit_in(d, &["mint", "--policy", "policy.dl"]));
    assert_fails_with(
        &ironwrit_in(d, &["run", "--token", token.trim(), "--", "anything"]),
        "extractor config is needed",
    );
}

#[test]
fn run_reports_missing_upstream_command() {
    let dir = tempfile::tempdir().unwrap();
    assert_fails_with(
        &ironwrit_in(dir.path(), &["run", "--", "ironwrit-no-such-command-12345"]),
        "failed to start upstream",
    );
}

#[test]
fn run_creates_a_gateway_key_on_first_use() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    ironwrit_in(d, &["run", "--", "ironwrit-no-such-command-12345"]);
    assert!(d.join("gateway.key").exists());
    assert!(d.join("gateway.pub").exists());
    assert!(d.join("ironwrit.db").exists());
}

#[test]
fn forged_tokens_leave_no_files_behind() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    assert_ok(&ironwrit_in(d, &["keygen"]));
    ironwrit_in(d, &["run", "--token", "not-a-token", "--", "anything"]);
    assert!(!d.join("gateway.key").exists());
    assert!(!d.join("ironwrit.db").exists());
}

#[test]
fn run_refuses_a_tampered_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    sample_ledger(d);
    tamper(d, "UPDATE entries SET reason = 'fine' WHERE seq = 2;");
    assert_fails_with(
        &ironwrit_in(d, &["run", "--", "anything"]),
        "refusing to append",
    );
}

/// gateway.key/.pub plus a closed ironwrit.db holding 4 entries.
fn sample_ledger(dir: &Path) {
    use ironwrit_ledger::{Decision, HeadPolicy, Ledger, Record};
    assert_ok(&ironwrit_in(dir, &["keygen", "--out", "gateway"]));
    let key = ironwrit_ledger::read_signing_key(&dir.join("gateway.key")).unwrap();
    let ledger = Ledger::open(&dir.join("ironwrit.db"), key, HeadPolicy::default()).unwrap();
    let record = |tool: &str, decision, reason: &str, call_seq: Option<u64>| Record {
        token_id: "0123456789abcdef".into(),
        tool: tool.into(),
        args_hash: [1; 32],
        decision,
        reason: reason.into(),
        result_hash: call_seq.map(|_| [2; 32]),
        call_seq,
    };
    ledger
        .append(record("read_file", Decision::Allow, "", None))
        .unwrap();
    ledger
        .append(record("read_file", Decision::Completed, "ok", Some(0)))
        .unwrap();
    ledger
        .append(record("send_email", Decision::Deny, "not granted", None))
        .unwrap();
    ledger.sign_head().unwrap();
    ledger
        .append(record("fetch", Decision::Deny, "check failed", None))
        .unwrap();
    ledger.sign_head().unwrap();
}

fn tamper(dir: &Path, sql: &str) {
    let conn = rusqlite::Connection::open(dir.join("ironwrit.db")).unwrap();
    conn.execute_batch("DROP TRIGGER entries_no_update; DROP TRIGGER entries_no_delete;")
        .unwrap();
    conn.execute_batch(sql).unwrap();
}

#[test]
fn log_show_lists_decisions() {
    let dir = tempfile::tempdir().unwrap();
    sample_ledger(dir.path());
    let out = assert_ok(&ironwrit_in(dir.path(), &["log", "show"]));
    assert!(out.contains("send_email"), "{out}");
    assert!(out.contains("#0 ok"), "{out}");
    assert!(out.contains("01234567 "), "{out}");
    assert!(
        out.contains("4 entries, 2 signed tree heads (newest covers 4)"),
        "{out}"
    );
}

#[test]
fn log_verify_accepts_an_intact_log() {
    let dir = tempfile::tempdir().unwrap();
    sample_ledger(dir.path());
    let out = assert_ok(&ironwrit_in(dir.path(), &["log", "verify"]));
    assert!(out.contains("ok: 4 entries and 2 tree heads"), "{out}");
}

#[test]
fn log_verify_names_the_tampered_entry() {
    let dir = tempfile::tempdir().unwrap();
    sample_ledger(dir.path());
    tamper(
        dir.path(),
        "UPDATE entries SET decision = 'allow' WHERE seq = 2;",
    );
    assert_fails_with(
        &ironwrit_in(dir.path(), &["log", "verify", "--pub", "gateway.pub"]),
        "error: entry 2: signature doesn't match",
    );
}

#[test]
fn log_verify_rejects_the_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    sample_ledger(dir.path());
    assert_ok(&ironwrit_in(dir.path(), &["keygen", "--out", "other"]));
    assert_fails_with(
        &ironwrit_in(dir.path(), &["log", "verify", "--pub", "other.pub"]),
        "failed verification",
    );
}

#[test]
fn log_prove_and_consistency_print_checked_proofs() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    sample_ledger(d);

    let out = assert_ok(&ironwrit_in(
        d,
        &["log", "prove", "2", "--pub", "gateway.pub"],
    ));
    let proof: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(proof["entry"]["tool"], "send_email");
    assert_eq!(proof["tree_head"]["size"], 4);
    assert_eq!(proof["path"].as_array().unwrap().len(), 2);

    let out = assert_ok(&ironwrit_in(
        d,
        &["log", "consistency", "3", "4", "--pub", "gateway.pub"],
    ));
    let proof: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(proof["old"]["size"], 3);
    assert!(proof["old"]["tree_head"].is_object());

    assert_fails_with(&ironwrit_in(d, &["log", "prove", "9"]), "not covered");
}
