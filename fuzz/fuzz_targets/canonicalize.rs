//! Canonical forms must never panic and must be fixed points.
#![no_main]

use ironwrit_token::canon::{canonical_email, canonical_path, canonical_url};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let base = std::env::temp_dir();
    if let Ok(once) = canonical_path(input, &base) {
        let twice = canonical_path(&once, &base);
        assert_eq!(twice.as_deref().ok(), Some(once.as_str()), "input {input:?}");
    }
    if let Ok(url) = canonical_url(input) {
        let host = if url.host.contains(':') {
            format!("[{}]", url.host)
        } else {
            url.host.clone()
        };
        if let Ok(again) = canonical_url(&format!("{}://{host}:{}/", url.scheme, url.port)) {
            assert_eq!(again.host, url.host, "input {input:?}");
            assert_eq!(again.port, url.port, "input {input:?}");
        }
    }
    let _ = canonical_email(input);
});
