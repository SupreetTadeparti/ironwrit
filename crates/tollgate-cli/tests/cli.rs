use std::process::{Command, Output};

fn tollgate(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tollgate"))
        .args(args)
        .output()
        .expect("failed to run tollgate binary")
}

#[test]
fn help_lists_all_subcommands() {
    let out = tollgate(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for cmd in ["keygen", "mint", "attenuate", "inspect", "run", "log"] {
        assert!(stdout.contains(cmd), "--help is missing `{cmd}`:\n{stdout}");
    }
}

#[test]
fn version_matches_crate() {
    let out = tollgate(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        format!("tollgate {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unimplemented_commands_fail_with_roadmap_hint() {
    let out = tollgate(&["log", "show"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not implemented yet"),
        "stderr was:\n{stderr}"
    );
}
