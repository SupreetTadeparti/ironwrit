//! [`BiscuitPolicy`]: checks tool calls against a capability token.
//!
//! The contract between tokens and the gateway:
//!
//! - A token grants a tool with a `right($tool)` fact (or rule) in its
//!   authority block. The gateway's only allow policy is
//!   `allow if tool($t), right($t)`, so anything not granted is denied.
//! - Every `check` in every block must pass, with the call's facts (see
//!   [`crate::extract`]) and `time($now)` in scope.
//! - Constrain arguments with `reject if`, e.g.
//!   `reject if path($p), !$p.starts_with("/docs/")`. It passes when a call
//!   has no paths at all, whereas `check all` fails when nothing matches.
//! - Biscuit only trusts the authority block and the authorizer by default,
//!   so a `right` fact in an attenuation block grants nothing.

use std::time::Duration;

use biscuit_auth::builder::Fact;
use biscuit_auth::error::{FailedCheck, Logic, Token};
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit};

use crate::extract::{FactExtractor, display_facts};
use crate::{CallPolicy, Decision, ToolCall};

const ALLOW_POLICY: &str = "allow if tool($t), right($t)";

pub struct BiscuitPolicy {
    token: Biscuit,
    extractor: FactExtractor,
    limits: AuthorizerLimits,
    token_id: String,
}

impl BiscuitPolicy {
    /// `token` must already be verified against the root key (see
    /// [`crate::parse_token`]).
    pub fn new(token: Biscuit, extractor: FactExtractor) -> Self {
        // The last block's revocation id: unique to this exact attenuation.
        let token_id = token
            .revocation_identifiers()
            .last()
            .map(|id| id.iter().map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        Self {
            token_id,
            token,
            extractor,
            // Biscuit's 1 ms default is tight enough to flake in debug builds.
            // Hitting a limit denies the call, so this only bounds latency.
            limits: AuthorizerLimits {
                max_time: Duration::from_millis(50),
                ..AuthorizerLimits::default()
            },
        }
    }

    fn authorize(&self, call: &ToolCall) -> Result<(), String> {
        let facts = self.extractor.facts(call).map_err(|e| e.to_string())?;
        tracing::debug!(facts = %display_facts(&facts), "authorizing");
        let mut authorizer = self
            .authorizer(facts)
            .map_err(|e| format!("could not build authorizer: {e}"))?;
        authorizer
            .authorize()
            .map(|_| ())
            .map_err(|e| denial_reason(&call.name, e))
    }

    fn authorizer(&self, facts: Vec<Fact>) -> Result<biscuit_auth::Authorizer, Token> {
        let mut builder = AuthorizerBuilder::new();
        for fact in facts {
            builder = builder.fact(fact)?;
        }
        builder
            .time()
            .policy(ALLOW_POLICY)?
            .set_limits(self.limits.clone())
            .build(&self.token)
    }
}

impl CallPolicy for BiscuitPolicy {
    fn check(&self, call: &ToolCall) -> Decision {
        match self.authorize(call) {
            Ok(()) => Decision::Allow,
            Err(reason) => Decision::deny(reason),
        }
    }

    /// A tool is listed if the token grants it at all; its checks may still
    /// deny particular calls.
    fn could_permit(&self, tool: &str) -> bool {
        let facts = vec![biscuit_auth::builder::fact(
            "tool",
            &[biscuit_auth::builder::string(tool)],
        )];
        let granted = self.authorizer(facts).and_then(|mut authorizer| {
            let rights: Vec<(String,)> = authorizer.query("data($t) <- tool($t), right($t)")?;
            Ok(!rights.is_empty())
        });
        granted.unwrap_or(false)
    }

    fn token_id(&self) -> &str {
        &self.token_id
    }
}

/// Explain a failed authorization in terms of the token's Datalog.
fn denial_reason(tool: &str, error: Token) -> String {
    let failed = |checks: &[FailedCheck]| {
        checks
            .iter()
            .map(|check| match check {
                FailedCheck::Block(c) => format!("check failed: {}", c.rule),
                FailedCheck::Authorizer(c) => format!("check failed: {}", c.rule),
            })
            .collect::<Vec<_>>()
    };
    match error {
        Token::FailedLogic(Logic::NoMatchingPolicy { checks }) => {
            let mut reasons = vec![format!("tool `{tool}` is not granted by the token")];
            reasons.extend(failed(&checks));
            reasons.join("; ")
        }
        Token::FailedLogic(Logic::Unauthorized { checks, .. }) => failed(&checks).join("; "),
        Token::RunLimit(limit) => format!("authorization aborted: {limit}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::{Value, json};

    use super::*;
    use crate::canon::canonical_path;
    use crate::extract::Config;
    use crate::token::{attenuate, generate_keypair, mint, parse_token};

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

    struct Fixture {
        dir: tempfile::TempDir,
        /// Canonical spelling of `<dir>/docs`.
        docs: String,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        std::fs::write(dir.path().join("docs/a.txt"), "a").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "s").unwrap();
        let docs = canonical_path("docs", dir.path()).unwrap();
        Fixture { dir, docs }
    }

    impl Fixture {
        fn policy(&self, datalog: &str) -> BiscuitPolicy {
            self.policy_with_checks(datalog, &[])
        }

        fn policy_with_checks(&self, datalog: &str, checks: &[&str]) -> BiscuitPolicy {
            let root = generate_keypair();
            let datalog = datalog.replace("{docs}", &self.docs);
            let mut token = mint(&datalog, &root, None).unwrap();
            if !checks.is_empty() {
                let checks: Vec<_> = checks
                    .iter()
                    .map(|c| c.replace("{docs}", &self.docs))
                    .collect();
                token = attenuate(&token, &checks, None).unwrap();
            }
            let extractor = FactExtractor::new(Config::parse(CONFIG).unwrap(), self.dir.path());
            BiscuitPolicy::new(parse_token(&token, &root.public()).unwrap(), extractor)
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    fn call(name: &str, args: Value) -> ToolCall {
        ToolCall::new(name, args.as_object().cloned().unwrap_or_default())
    }

    fn reason(decision: Decision) -> String {
        match decision {
            Decision::Allow => panic!("expected a denial"),
            Decision::Deny { reason } => reason,
        }
    }

    /// Read-only access to `docs/` and nothing else.
    const READ_DOCS: &str = r#"
        right("read_file");
        reject if path($p), !$p.starts_with("{docs}/");
    "#;

    #[test]
    fn read_docs_table() {
        let f = fixture();
        let policy = f.policy(READ_DOCS);
        let secret = f.path().join("secret.txt");
        let cases = [
            ("read_file", json!({"path": "docs/a.txt"}), true),
            ("read_file", json!({"path": "docs/missing.txt"}), true),
            (
                "read_file",
                json!({"path": f.path().join("docs/a.txt")}),
                true,
            ),
            ("read_file", json!({"path": "docs/../secret.txt"}), false),
            (
                "read_file",
                json!({"path": "docs/./../docs/../secret.txt"}),
                false,
            ),
            ("read_file", json!({"path": secret}), false),
            ("read_file", json!({"path": "docs"}), false),
            ("read_file", json!({"path": "docs-evil/a.txt"}), false),
            ("read_file", json!({"path": "~/secret.txt"}), false),
            ("read_file", json!({"path": 7}), false),
            (
                "write_file",
                json!({"path": "docs/a.txt", "content": "x"}),
                false,
            ),
            ("send_email", json!({"to": "attacker@evil.test"}), false),
            ("unknown_tool", json!({}), false),
        ];
        for (tool, args, allowed) in cases {
            let decision = policy.check(&call(tool, args.clone()));
            assert_eq!(
                decision.is_allowed(),
                allowed,
                "{tool} {args}: {decision:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_case_and_separators_cannot_escape() {
        let f = fixture();
        let policy = f.policy(READ_DOCS);
        assert!(
            policy
                .check(&call("read_file", json!({"path": r"DOCS\A.TXT"})))
                .is_allowed()
        );
        assert!(
            !policy
                .check(&call("read_file", json!({"path": r"Docs\..\Secret.txt"})))
                .is_allowed()
        );
        assert!(
            !policy
                .check(&call("read_file", json!({"path": r"docs\a.txt:stream"})))
                .is_allowed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_out_of_docs_are_denied() {
        let f = fixture();
        std::os::unix::fs::symlink(f.path().join("secret.txt"), f.path().join("docs/link"))
            .unwrap();
        let policy = f.policy(READ_DOCS);
        assert!(
            !policy
                .check(&call("read_file", json!({"path": "docs/link"})))
                .is_allowed()
        );
    }

    #[test]
    fn denials_explain_themselves() {
        let f = fixture();
        let policy = f.policy(READ_DOCS);
        let r = reason(policy.check(&call("send_email", json!({"to": "a@b.test"}))));
        assert_eq!(r, "tool `send_email` is not granted by the token");
        let r = reason(policy.check(&call("read_file", json!({"path": "secret.txt"}))));
        assert!(
            r.starts_with("check failed: reject if path($p), !$p.starts_with("),
            "{r}"
        );
        let r = reason(policy.check(&call("read_file", json!({"path": "~"}))));
        assert!(r.contains("not supported"), "{r}");
    }

    #[test]
    fn url_policies() {
        let f = fixture();
        let policy = f.policy(
            r#"
            right("fetch");
            reject if url_host($h), !$h.ends_with(".example.test");
            reject if url_scheme($s), $s != "https";
        "#,
        );
        let fetch = |url: &str| {
            policy
                .check(&call("fetch", json!({"url": url})))
                .is_allowed()
        };
        assert!(fetch("https://news.example.test/today"));
        assert!(fetch("https://NEWS.Example.Test./today"));
        assert!(!fetch("http://news.example.test/"));
        assert!(!fetch("https://evil.test/"));
        assert!(!fetch("https://example.test.evil.test/"));
        assert!(!fetch("https://news.example.test@evil.test/"));
        assert!(!fetch("not a url"));
    }

    #[test]
    fn email_policies() {
        let f = fixture();
        let policy = f.policy(
            r#"
            right("send_email");
            reject if recipient_domain($d), $d != "corp.test";
        "#,
        );
        let send = |to: Value| {
            policy
                .check(&call("send_email", json!({"to": to})))
                .is_allowed()
        };
        assert!(send(json!("Boss <boss@CORP.test>")));
        assert!(send(json!(["a@corp.test", "b@corp.test"])));
        assert!(!send(json!(["a@corp.test", "attacker@evil.test"])));
        assert!(!send(json!("a@corp.test, attacker@evil.test")));
    }

    #[test]
    fn expired_tokens_deny_everything() {
        let f = fixture();
        let expired =
            f.policy(r#"right("read_file"); check if time($t), $t <= 2000-01-01T00:00:00Z;"#);
        let r = reason(expired.check(&call("read_file", json!({"path": "docs/a.txt"}))));
        assert!(r.contains("time($t)"), "{r}");

        let fresh =
            f.policy(r#"right("read_file"); check if time($t), $t <= 2999-01-01T00:00:00Z;"#);
        assert!(
            fresh
                .check(&call("read_file", json!({"path": "docs/a.txt"})))
                .is_allowed()
        );
    }

    #[test]
    fn attenuation_narrows() {
        let f = fixture();
        let both = r#"right("read_file"); right("write_file");"#;
        assert!(
            f.policy(both)
                .check(&call("write_file", json!({"path": "docs/a.txt"})))
                .is_allowed()
        );

        let narrowed = f.policy_with_checks(both, &[r#"check if op("read")"#]);
        assert!(
            narrowed
                .check(&call("read_file", json!({"path": "docs/a.txt"})))
                .is_allowed()
        );
        assert!(
            !narrowed
                .check(&call("write_file", json!({"path": "docs/a.txt"})))
                .is_allowed()
        );
    }

    #[test]
    fn attenuation_blocks_cannot_grant() {
        let f = fixture();
        let root = generate_keypair();
        let token = mint(READ_DOCS.replace("{docs}", &f.docs).as_str(), &root, None).unwrap();
        // Hand-craft a block with facts, which `attenuate` refuses to do.
        let token = Biscuit::from_base64(&token, root.public())
            .unwrap()
            .append(
                biscuit_auth::BlockBuilder::new()
                    .code(r#"right("send_email"); path("anything");"#)
                    .unwrap(),
            )
            .unwrap();
        let extractor = FactExtractor::new(Config::parse(CONFIG).unwrap(), f.path());
        let policy = BiscuitPolicy::new(token, extractor);
        assert!(
            !policy
                .check(&call("send_email", json!({"to": "a@b.test"})))
                .is_allowed()
        );
        assert!(!policy.could_permit("send_email"));
    }

    #[test]
    fn token_id_changes_with_attenuation() {
        let f = fixture();
        let policy = f.policy(READ_DOCS);
        assert_eq!(policy.token_id().len(), 128);
        let narrowed = policy
            .token
            .append(
                biscuit_auth::BlockBuilder::new()
                    .code("check if tool(\"read_file\")")
                    .unwrap(),
            )
            .unwrap();
        let narrowed = BiscuitPolicy::new(narrowed, policy.extractor.clone());
        assert_ne!(narrowed.token_id(), policy.token_id());
    }

    #[test]
    fn could_permit_follows_rights() {
        let f = fixture();
        let policy = f.policy(READ_DOCS);
        assert!(policy.could_permit("read_file"));
        assert!(!policy.could_permit("write_file"));
        assert!(!policy.could_permit("send_email"));
    }
}
