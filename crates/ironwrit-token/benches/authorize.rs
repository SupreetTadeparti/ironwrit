//! Authorization latency for a realistic token: rights, path/URL/email
//! checks, an attenuation block and an expiry.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use ironwrit_token::canon::canonical_path;
use ironwrit_token::{BiscuitPolicy, CallPolicy, Config, FactExtractor, ToolCall};
use serde_json::{Value, json};

const CONFIG: &str = r#"
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
"#;

fn call(tool: &str, args: Value) -> ToolCall {
    ToolCall::new(tool, args.as_object().cloned().unwrap_or_default())
}

fn bench(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("docs")).unwrap();
    std::fs::write(dir.path().join("docs/a.txt"), "a").unwrap();
    let docs = canonical_path("docs", dir.path()).unwrap();

    let root = ironwrit_token::generate_keypair();
    let policy = format!(
        r#"right("read_file"); right("fetch"); right("send_email");
        reject if path($p), $p != "{docs}", !$p.starts_with("{docs}/");
        reject if url_host($h), !$h.ends_with(".example.test");
        reject if recipient_domain($d), $d != "example.test";"#
    );
    let token = ironwrit_token::mint(&policy, &root, Some(Duration::from_secs(3600))).unwrap();
    let token = ironwrit_token::attenuate(
        &token,
        &[r#"check if tool($t), ["read_file", "fetch"].contains($t)"#.into()],
        Some(Duration::from_secs(600)),
    )
    .unwrap();
    let token = ironwrit_token::parse_token(&token, &root.public()).unwrap();
    let extractor = FactExtractor::new(Config::parse(CONFIG).unwrap(), dir.path());
    let policy = BiscuitPolicy::new(token, extractor.clone());

    let allowed = call("read_file", json!({"path": "docs/a.txt"}));
    let traversal = call("read_file", json!({"path": "docs/../secret.txt"}));
    let fetch = call("fetch", json!({"url": "https://news.example.test/a?b=c"}));
    let ungranted = call("delete_everything", json!({}));
    assert!(policy.check(&allowed).is_allowed());
    assert!(!policy.check(&traversal).is_allowed());

    let mut group = c.benchmark_group("authorize");
    group.bench_function("read_file allowed", |b| {
        b.iter(|| policy.check(black_box(&allowed)))
    });
    group.bench_function("read_file traversal denied", |b| {
        b.iter(|| policy.check(black_box(&traversal)))
    });
    group.bench_function("fetch allowed", |b| {
        b.iter(|| policy.check(black_box(&fetch)))
    });
    group.bench_function("ungranted tool denied", |b| {
        b.iter(|| policy.check(black_box(&ungranted)))
    });
    group.bench_function("could_permit", |b| {
        b.iter(|| policy.could_permit(black_box("fetch")))
    });
    group.finish();

    c.bench_function("extract facts (read_file)", |b| {
        b.iter(|| extractor.facts(black_box(&allowed)).unwrap())
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
