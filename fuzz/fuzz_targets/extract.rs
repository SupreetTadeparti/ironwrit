//! Arbitrary JSON arguments must never panic the fact extractors.
#![no_main]

use std::sync::OnceLock;

use ironwrit_token::{Config, FactExtractor, ToolCall};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fn extractor() -> &'static FactExtractor {
    static EXTRACTOR: OnceLock<FactExtractor> = OnceLock::new();
    EXTRACTOR.get_or_init(|| {
        let config = Config::parse(include_str!("../../ironwrit.toml")).unwrap();
        FactExtractor::new(config, std::env::temp_dir())
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(Value::Object(args)) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    for tool in ["read_file", "read_multiple_files", "move_file", "fetch", "send_email", "x"] {
        let _ = extractor().facts(&ToolCall::new(tool, args.clone()));
    }
});
