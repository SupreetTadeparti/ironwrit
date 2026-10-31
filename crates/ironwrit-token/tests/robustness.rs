//! Stable-toolchain versions of the fuzz targets in `fuzz/`: arbitrary input
//! must never panic, and canonical forms must be fixed points.
//! Raise PROPTEST_CASES for a longer run.

use std::sync::OnceLock;

use ironwrit_token::canon::{canonical_email, canonical_path, canonical_url};
use ironwrit_token::{Config, FactExtractor, ToolCall};
use proptest::prelude::*;
use serde_json::Value;

fn base() -> &'static std::path::Path {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("docs/sub")).unwrap();
        std::fs::write(dir.path().join("docs/a.txt"), "a").unwrap();
        dir
    })
    .path()
}

/// Path-ish strings: separators, dots, drive letters, colons, `~`, `%`, unicode.
fn path_like() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        Just("/".to_owned()),
        Just("\\".to_owned()),
        Just("..".to_owned()),
        Just(".".to_owned()),
        Just("docs".to_owned()),
        Just("a.txt".to_owned()),
        Just("C:".to_owned()),
        Just(":".to_owned()),
        Just("~".to_owned()),
        Just("%2e".to_owned()),
        Just(" ".to_owned()),
        Just("\u{0130}".to_owned()),
        "[a-zA-Z0-9_.-]{1,6}",
        any::<String>(),
    ];
    proptest::collection::vec(piece, 0..8).prop_map(|parts| parts.concat())
}

fn url_like() -> impl Strategy<Value = String> {
    let scheme = prop_oneof![Just("https://"), Just("http://"), Just("file://"), Just("")];
    let host = prop_oneof![
        Just("news.example.test".to_owned()),
        Just("EXAMPLE.test.".to_owned()),
        Just("xn--bcher-kva.example".to_owned()),
        Just("bücher.example".to_owned()),
        Just("127.0.0.1".to_owned()),
        Just("[::1]".to_owned()),
        Just("user:pw@host".to_owned()),
        "[a-z0-9.-]{0,12}",
    ];
    let rest = proptest::collection::vec(
        prop_oneof![
            Just("/".to_owned()),
            Just("%2f".to_owned()),
            Just("%2e%2e".to_owned()),
            Just("%5c".to_owned()),
            Just("%00".to_owned()),
            Just("..".to_owned()),
            Just(":8080".to_owned()),
            Just("?q=1".to_owned()),
            Just("#frag".to_owned()),
            "[a-z0-9]{1,4}",
            any::<String>(),
        ],
        0..6,
    )
    .prop_map(|parts| parts.concat());
    (scheme, host, rest).prop_map(|(s, h, r)| format!("{s}{h}{r}"))
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        path_like().prop_map(Value::String),
        url_like().prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z]{1,4}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// `PROPTEST_CASES` overrides the default, for long runs.
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(2048)))]

    #[test]
    fn canonical_paths_are_fixed_points(input in path_like()) {
        if let Ok(once) = canonical_path(&input, base()) {
            let twice = canonical_path(&once, base());
            prop_assert_eq!(twice.as_deref().ok(), Some(once.as_str()), "input {:?}", input);
        }
    }

    #[test]
    fn canonical_urls_are_fixed_points(input in url_like()) {
        if let Ok(url) = canonical_url(&input) {
            let host = if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.clone() };
            let rebuilt = format!("{}://{}:{}{}", url.scheme, host, url.port, url.path);
            // Re-encoding the decoded path can legitimately fail (e.g. `%`), but
            // must never produce something different.
            if let Ok(again) = canonical_url(&rebuilt) {
                prop_assert_eq!(&again.host, &url.host);
                prop_assert_eq!(again.port, url.port);
            }
        }
    }

    #[test]
    fn emails_never_panic(input in any::<String>()) {
        let _ = canonical_email(&input);
    }

    #[test]
    fn extractors_never_panic(args in proptest::collection::btree_map(
        prop_oneof![Just("path".to_owned()), Just("url".to_owned()), Just("to".to_owned()), "[a-z]{1,3}"],
        json_value(),
        0..4,
    )) {
        let config = Config::parse(r#"
            [tools.read_file]
            extract = "fs"
            op = "read"
            args = ["path"]
            [tools.fetch]
            extract = "url"
            args = ["url"]
            [tools.send_email]
            extract = "email"
            args = ["to"]
        "#).unwrap();
        let extractor = FactExtractor::new(config, base());
        let args: serde_json::Map<String, Value> = args.into_iter().collect();
        for tool in ["read_file", "fetch", "send_email", "other"] {
            let _ = extractor.facts(&ToolCall::new(tool, args.clone()));
        }
    }
}
