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

#[test]
fn unimplemented_commands_fail_with_roadmap_hint() {
    let out = ironwrit(&["log", "show"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not implemented yet"),
        "stderr was:\n{stderr}"
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
    let out = ironwrit(&["run", "--", "ironwrit-no-such-command-12345"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("failed to start upstream"),
        "stderr was:\n{stderr}"
    );
}
