//! Property: whatever block is appended, an attenuated token never allows a
//! call (or lists a tool) that its parent doesn't.

use std::path::Path;
use std::sync::OnceLock;

use biscuit_auth::{Biscuit, BlockBuilder, KeyPair};
use ironwrit_token::canon::canonical_path;
use ironwrit_token::{BiscuitPolicy, CallPolicy, Config, FactExtractor, ToolCall};
use proptest::prelude::*;
use serde_json::{Value, json};

const CONFIG: &str = r#"
    [tools.read_file]
    extract = "fs"
    op = "read"
    args = ["path"]

    [tools.write_file]
    extract = "fs"
    op = "write"
    args = ["path"]

    [tools.fetch]
    extract = "url"
    args = ["url"]

    [tools.send_email]
    extract = "email"
    args = ["to"]
"#;

const TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "fetch",
    "send_email",
    "delete_everything",
];

struct Fixture {
    dir: tempfile::TempDir,
    root: KeyPair,
    docs: String,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/a.txt"), "a").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "s").unwrap();
        let docs = canonical_path("docs", dir.path()).unwrap();
        Fixture {
            dir,
            root: KeyPair::new(),
            docs,
        }
    })
}

fn policy(token: Biscuit, dir: &Path) -> BiscuitPolicy {
    BiscuitPolicy::new(
        token,
        FactExtractor::new(Config::parse(CONFIG).unwrap(), dir),
    )
}

/// Parent tokens: some rights, optionally confined to `docs/`.
fn parent_source() -> impl Strategy<Value = String> {
    (
        proptest::sample::subsequence(TOOLS.to_vec(), 0..=TOOLS.len()),
        any::<bool>(),
    )
        .prop_map(|(rights, confine)| {
            let mut source: String = rights
                .iter()
                .map(|t| format!("right(\"{t}\");\n"))
                .collect();
            if confine {
                source.push_str("reject if path($p), !$p.starts_with(\"{docs}/\");\n");
            }
            source
        })
}

/// Attenuation blocks: real checks mixed with facts and rules that try to
/// grant more than the parent did.
fn block_statement() -> impl Strategy<Value = String> {
    let tool = proptest::sample::select(TOOLS.to_vec());
    prop_oneof![
        tool.clone()
            .prop_map(|t| format!("check if tool(\"{t}\");")),
        Just("check if op(\"read\");".to_owned()),
        Just("reject if op(\"write\");".to_owned()),
        Just("reject if url_host($h), !$h.ends_with(\".example.test\");".to_owned()),
        Just("check if time($t), $t <= 2999-01-01T00:00:00Z;".to_owned()),
        Just("check if time($t), $t <= 2000-01-01T00:00:00Z;".to_owned()),
        tool.clone().prop_map(|t| format!("right(\"{t}\");")),
        tool.prop_map(|t| format!("right(\"{t}\") <- tool(\"{t}\");")),
        Just("right($t) <- tool($t);".to_owned()),
        Just("path(\"{docs}/a.txt\");".to_owned()),
        Just("op(\"read\");".to_owned()),
    ]
}

fn call() -> impl Strategy<Value = ToolCall> {
    let tool = proptest::sample::select(TOOLS.to_vec());
    let args = prop_oneof![
        Just(json!({"path": "docs/a.txt"})),
        Just(json!({"path": "docs/../secret.txt"})),
        Just(json!({"path": "secret.txt"})),
        Just(json!({"url": "https://news.example.test/"})),
        Just(json!({"url": "https://evil.test/"})),
        Just(json!({"to": "attacker@evil.test"})),
        Just(json!({})),
    ];
    (tool, args).prop_map(|(tool, args): (&str, Value)| {
        ToolCall::new(tool, args.as_object().cloned().unwrap_or_default())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn attenuated_token_is_a_subset_of_its_parent(
        parent in parent_source(),
        blocks in proptest::collection::vec(proptest::collection::vec(block_statement(), 1..4), 1..3),
        calls in proptest::collection::vec(call(), 1..8),
    ) {
        let f = fixture();
        let parent_token = Biscuit::builder()
            .code(parent.replace("{docs}", &f.docs))
            .unwrap()
            .build(&f.root)
            .unwrap();
        let mut child_token = parent_token.clone();
        for block in &blocks {
            let source = block.join("\n").replace("{docs}", &f.docs);
            child_token = child_token.append(BlockBuilder::new().code(source).unwrap()).unwrap();
        }
        let parent_policy = policy(parent_token, f.dir.path());
        let child_policy = policy(child_token, f.dir.path());

        for call in &calls {
            if child_policy.check(call).is_allowed() {
                prop_assert!(
                    parent_policy.check(call).is_allowed(),
                    "child allowed {call:?} but parent denied it"
                );
            }
        }
        for tool in TOOLS {
            if child_policy.could_permit(tool) {
                prop_assert!(parent_policy.could_permit(tool), "child lists {tool}, parent doesn't");
            }
        }
    }
}

/// The Phase 3 "done when": a token scoped to `read_file` under `docs/`.
#[test]
fn read_docs_token_cannot_escape() {
    let f = fixture();
    let token = Biscuit::builder()
        .code(format!(
            "right(\"read_file\");\nreject if path($p), !$p.starts_with(\"{}/\");",
            f.docs
        ))
        .unwrap()
        .build(&f.root)
        .unwrap();
    let policy = policy(token, f.dir.path());
    let check = |tool: &str, args: Value| {
        policy
            .check(&ToolCall::new(
                tool,
                args.as_object().cloned().unwrap_or_default(),
            ))
            .is_allowed()
    };

    assert!(check("read_file", json!({"path": "docs/a.txt"})));
    assert!(!check("read_file", json!({"path": "docs/../secret.txt"})));
    assert!(!check(
        "write_file",
        json!({"path": "docs/a.txt", "content": "x"})
    ));
    assert!(!check("send_email", json!({"to": "attacker@evil.test"})));
}

#[test]
fn shipped_config_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ironwrit.toml");
    Config::load(&path).unwrap();
}
