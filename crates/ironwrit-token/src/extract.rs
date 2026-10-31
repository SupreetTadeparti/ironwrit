//! Turn a [`ToolCall`] into Datalog facts, driven by `ironwrit.toml`.
//!
//! Every call yields `tool($name)`. Tools listed in the config also yield:
//!
//! | extractor | facts |
//! |-----------|-------|
//! | `fs`      | `op("read" \| "write")`, `path($canonical)` per path |
//! | `url`     | `url_scheme`, `url_host`, `url_port`, `url_path` per URL |
//! | `email`   | `recipient($address)`, `recipient_domain($domain)` per recipient |
//!
//! Facts are built from typed terms, never by formatting Datalog source, so
//! arguments can't inject rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use biscuit_auth::builder::{Fact, fact, int, string};
use serde::Deserialize;
use serde_json::Value;

use crate::canon::{canonical_email, canonical_path, canonical_url};
use crate::{Error, Result, ToolCall};

/// Per-tool extractor config, usually loaded from `ironwrit.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    tools: BTreeMap<String, Extractor>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "extract", rename_all = "lowercase", deny_unknown_fields)]
enum Extractor {
    /// Filesystem access. `args` name the arguments that hold paths.
    Fs { op: FsOp, args: Vec<String> },
    /// Network access. `args` name the arguments that hold URLs.
    Url { args: Vec<String> },
    /// Outgoing mail. `args` name the arguments that hold recipients.
    Email { args: Vec<String> },
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FsOp {
    Read,
    Write,
}

impl FsOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl Config {
    pub fn parse(source: &str) -> Result<Self> {
        toml::from_str(source).map_err(|e| Error::Config(e.to_string()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        Self::parse(&source).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }
}

/// Builds facts for tool calls. Relative paths resolve against `base_dir`,
/// which should be the upstream server's working directory.
#[derive(Debug, Clone)]
pub struct FactExtractor {
    config: Config,
    base_dir: PathBuf,
}

impl FactExtractor {
    pub fn new(config: Config, base_dir: impl Into<PathBuf>) -> Self {
        Self {
            config,
            base_dir: base_dir.into(),
        }
    }

    pub fn facts(&self, call: &ToolCall) -> Result<Vec<Fact>> {
        let mut facts = vec![fact("tool", &[string(&call.name)])];
        let Some(extractor) = self.config.tools.get(&call.name) else {
            return Ok(facts);
        };
        match extractor {
            Extractor::Fs { op, args } => {
                facts.push(fact("op", &[string(op.as_str())]));
                for value in values(call, args)? {
                    let path = canonical_path(value, &self.base_dir)?;
                    facts.push(fact("path", &[string(&path)]));
                }
            }
            Extractor::Url { args } => {
                for value in values(call, args)? {
                    let url = canonical_url(value)?;
                    facts.push(fact("url_scheme", &[string(&url.scheme)]));
                    facts.push(fact("url_host", &[string(&url.host)]));
                    facts.push(fact("url_port", &[int(i64::from(url.port))]));
                    facts.push(fact("url_path", &[string(&url.path)]));
                }
            }
            Extractor::Email { args } => {
                for value in values(call, args)? {
                    let email = canonical_email(value)?;
                    facts.push(fact("recipient", &[string(&email.address)]));
                    facts.push(fact("recipient_domain", &[string(&email.domain)]));
                }
            }
        }
        Ok(facts)
    }
}

/// The string values of the named arguments. Each may be a string or an array
/// of strings; missing arguments are skipped, anything else is an error.
fn values<'a>(call: &'a ToolCall, args: &[String]) -> Result<Vec<&'a str>> {
    let mut out = Vec::new();
    for name in args {
        let wrong_type = || {
            Error::InvalidArgument(format!(
                "`{name}` of `{}` must be a string or an array of strings",
                call.name
            ))
        };
        match call.arguments.get(name) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => out.push(s.as_str()),
            Some(Value::Array(items)) => {
                for item in items {
                    out.push(item.as_str().ok_or_else(wrong_type)?);
                }
            }
            Some(_) => return Err(wrong_type()),
        }
    }
    Ok(out)
}

/// Render facts as Datalog, for logs and error messages.
pub fn display_facts(facts: &[Fact]) -> String {
    facts
        .iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CONFIG: &str = r#"
        [tools.read_file]
        extract = "fs"
        op = "read"
        args = ["path"]

        [tools.read_multiple_files]
        extract = "fs"
        op = "read"
        args = ["paths"]

        [tools.fetch]
        extract = "url"
        args = ["url"]

        [tools.send_email]
        extract = "email"
        args = ["to", "cc"]
    "#;

    fn call(name: &str, args: Value) -> ToolCall {
        ToolCall::new(name, args.as_object().cloned().unwrap_or_default())
    }

    fn extract(name: &str, args: Value) -> Result<String> {
        let dir = std::env::temp_dir();
        let extractor = FactExtractor::new(Config::parse(CONFIG).unwrap(), dir);
        extractor
            .facts(&call(name, args))
            .map(|f| display_facts(&f))
    }

    #[test]
    fn unknown_tools_only_get_a_tool_fact() {
        assert_eq!(
            extract("whatever", json!({"path": "/x"})).unwrap(),
            r#"tool("whatever")"#
        );
    }

    #[test]
    fn fs_tools_get_op_and_paths() {
        let facts = extract("read_multiple_files", json!({"paths": ["a", "b"]})).unwrap();
        assert!(facts.starts_with(r#"tool("read_multiple_files"), op("read"), path("#));
        assert_eq!(facts.matches("path(").count(), 2);
    }

    #[test]
    fn url_tools_get_url_parts() {
        let facts = extract("fetch", json!({"url": "https://News.Example.test/x"})).unwrap();
        assert_eq!(
            facts,
            r#"tool("fetch"), url_scheme("https"), url_host("news.example.test"), url_port(443), url_path("/x")"#
        );
    }

    #[test]
    fn email_tools_get_one_fact_per_recipient() {
        let facts = extract(
            "send_email",
            json!({"to": ["a@x.test", "B@Y.test"], "cc": "c@z.test"}),
        )
        .unwrap();
        assert_eq!(facts.matches("recipient(").count(), 3);
        assert!(facts.contains(r#"recipient("b@y.test")"#));
        assert!(facts.contains(r#"recipient_domain("z.test")"#));
    }

    #[test]
    fn missing_optional_args_are_skipped() {
        let facts = extract("send_email", json!({"to": "a@x.test"})).unwrap();
        assert_eq!(facts.matches("recipient(").count(), 1);
    }

    #[test]
    fn wrong_argument_types_are_errors() {
        assert!(extract("read_file", json!({"path": 42})).is_err());
        assert!(extract("read_multiple_files", json!({"paths": ["a", 1]})).is_err());
        assert!(extract("send_email", json!({"to": {"addr": "a@x.test"}})).is_err());
    }

    #[test]
    fn hostile_strings_stay_inside_their_term() {
        let extractor = FactExtractor::new(Config::parse(CONFIG).unwrap(), std::env::temp_dir());
        let hostile = call(
            "fetch",
            json!({"url": "https://x.test/\"), right(\"send_email"}),
        );
        // One URL means exactly four url facts after `tool`; nothing was injected.
        assert_eq!(extractor.facts(&hostile).unwrap().len(), 5);
    }

    #[test]
    fn config_typos_are_rejected() {
        for bad in [
            "[tools.x]\nextract = \"fs\"\nop = \"read\"\nargz = [\"path\"]",
            "[tools.x]\nextract = \"fs\"\nop = \"delete\"\nargs = []",
            "[tools.x]\nextract = \"ftp\"\nargs = []",
            "[tool.x]\nextract = \"url\"\nargs = []",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject:\n{bad}");
        }
    }
}
