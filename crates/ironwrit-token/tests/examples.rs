//! Every policy in examples/policies mints, and behaves as its comments say.

use std::path::{Path, PathBuf};

use biscuit_auth::KeyPair;
use ironwrit_token::canon::canonical_path;
use ironwrit_token::{BiscuitPolicy, CallPolicy, Config, FactExtractor, ToolCall};
use serde_json::{Value, json};

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policies")
}

struct Fixture {
    dir: tempfile::TempDir,
    root: KeyPair,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["repo/src", "repo/tests", "repo/.git", "docs"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        Self {
            dir,
            root: ironwrit_token::generate_keypair(),
        }
    }

    /// Mint `name`; `--path`-style params are canonicalized, `domain` isn't.
    fn policy(&self, name: &str, params: &[(&str, &str)]) -> BiscuitPolicy {
        let source = std::fs::read_to_string(examples().join(name)).unwrap();
        let params: Vec<(String, String)> = params
            .iter()
            .map(|&(k, v)| {
                let value = if k == "domain" {
                    v.to_owned()
                } else {
                    canonical_path(v, self.dir.path()).unwrap()
                };
                (k.to_owned(), value)
            })
            .collect();
        let token = ironwrit_token::mint_with_params(&source, &params, &self.root, None)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let token = ironwrit_token::parse_token(&token, &self.root.public()).unwrap();
        let config = Config::load(&examples().join("../../ironwrit.toml")).unwrap();
        BiscuitPolicy::new(token, FactExtractor::new(config, self.dir.path()))
    }
}

fn allows(policy: &BiscuitPolicy, tool: &str, args: Value) -> bool {
    let call = ToolCall::new(tool, args.as_object().cloned().unwrap_or_default());
    policy.check(&call).is_allowed()
}

#[test]
fn every_example_mints() {
    let f = Fixture::new();
    let params = [
        ("docs", "docs"),
        ("repo", "repo"),
        ("domain", "example.com"),
    ];
    let mut minted = 0;
    for entry in std::fs::read_dir(examples()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "dl") {
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let source = std::fs::read_to_string(&path).unwrap();
            let used: Vec<_> = params
                .iter()
                .copied()
                .filter(|(k, _)| source.contains(&format!("{{{k}}}")))
                .collect();
            f.policy(&name, &used);
            minted += 1;
        }
    }
    assert!(minted >= 4);
}

#[test]
fn read_only_docs() {
    let f = Fixture::new();
    let p = f.policy("read-only-docs.dl", &[("docs", "docs")]);
    assert!(allows(&p, "read_text_file", json!({"path": "docs/a.md"})));
    assert!(allows(&p, "list_directory", json!({"path": "docs"})));
    assert!(!allows(&p, "read_text_file", json!({"path": "docs/../x"})));
    assert!(!allows(
        &p,
        "read_text_file",
        json!({"path": "docs-old/a.md"})
    ));
    assert!(!allows(&p, "write_file", json!({"path": "docs/a.md"})));
}

#[test]
fn code_assistant() {
    let f = Fixture::new();
    let p = f.policy("code-assistant.dl", &[("repo", "repo")]);
    assert!(allows(
        &p,
        "read_text_file",
        json!({"path": "repo/README.md"})
    ));
    assert!(allows(
        &p,
        "write_file",
        json!({"path": "repo/src/main.rs"})
    ));
    assert!(allows(&p, "edit_file", json!({"path": "repo/tests/a.rs"})));
    assert!(!allows(
        &p,
        "write_file",
        json!({"path": "repo/Cargo.toml"})
    ));
    assert!(!allows(
        &p,
        "read_text_file",
        json!({"path": "repo/.git/config"})
    ));
    assert!(!allows(
        &p,
        "read_text_file",
        json!({"path": "repo/src/.env"})
    ));
    assert!(!allows(
        &p,
        "move_file",
        json!({"source": "repo/src/a", "destination": "repo/src/b"})
    ));
}

#[test]
fn web_research() {
    let f = Fixture::new();
    let p = f.policy("web-research.dl", &[]);
    assert!(allows(&p, "fetch", json!({"url": "https://docs.rs/serde"})));
    assert!(allows(
        &p,
        "fetch",
        json!({"url": "https://DOCS.RS./serde"})
    ));
    assert!(!allows(&p, "fetch", json!({"url": "http://docs.rs/serde"})));
    assert!(!allows(
        &p,
        "fetch",
        json!({"url": "https://docs.rs:8443/"})
    ));
    assert!(!allows(
        &p,
        "fetch",
        json!({"url": "https://docs.rs.evil.test/"})
    ));
}

#[test]
fn email_team_only() {
    let f = Fixture::new();
    let p = f.policy("email-team-only.dl", &[("domain", "example.com")]);
    assert!(allows(
        &p,
        "send_email",
        json!({"to": "Ann <ann@Example.com>"})
    ));
    assert!(!allows(
        &p,
        "send_email",
        json!({"to": "ann@example.com", "bcc": ["x@evil.test"]})
    ));
    assert!(!allows(
        &p,
        "send_email",
        json!({"to": "ann@example.com.evil.test"})
    ));
}
