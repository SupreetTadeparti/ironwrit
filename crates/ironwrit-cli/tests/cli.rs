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

#[test]
fn run_refuses_tokens_until_they_are_enforced() {
    let out = Command::new(env!("CARGO_BIN_EXE_ironwrit"))
        .args(["run", "--token", "abc", "--", "anything"])
        .env_remove("IRONWRIT_TOKEN")
        .output()
        .expect("failed to run ironwrit binary");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("token enforcement is not implemented yet"),
        "stderr was:\n{stderr}"
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
