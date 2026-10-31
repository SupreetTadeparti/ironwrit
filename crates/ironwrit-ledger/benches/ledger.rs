//! Ledger append throughput, and the cost of tree hashing and proofs.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ironwrit_ledger::{Decision, HeadPolicy, Ledger, Record, SigningKey, merkle};

fn record() -> Record {
    Record {
        token_id: "a".repeat(128),
        tool: "read_file".into(),
        args_hash: [1; 32],
        decision: Decision::Deny,
        reason: "check failed: reject if path($p), !$p.starts_with(\"/srv/docs/\")".into(),
        result_hash: None,
        call_seq: None,
    }
}

fn bench(c: &mut Criterion) {
    let key = SigningKey::from_bytes(&[9; 32]);
    let heads = HeadPolicy::default();

    let mut group = c.benchmark_group("append");
    group.throughput(Throughput::Elements(1));
    let memory = Ledger::open_in_memory(key.clone(), heads).unwrap();
    group.bench_function("in memory", |b| b.iter(|| memory.append(record()).unwrap()));
    let dir = tempfile::tempdir().unwrap();
    let file = Ledger::open(&dir.path().join("bench.db"), key.clone(), heads).unwrap();
    // Each append is a durable (fsync'd) SQLite transaction.
    group.bench_function("SQLite file, synchronous=FULL", |b| {
        b.iter(|| file.append(record()).unwrap())
    });
    group.finish();

    let leaves: Vec<_> = (0u32..10_000)
        .map(|i| merkle::leaf_hash(&i.to_be_bytes()))
        .collect();
    let root = merkle::root(&leaves);
    let mut group = c.benchmark_group("merkle (10k leaves)");
    group.bench_function("root", |b| b.iter(|| merkle::root(black_box(&leaves))));
    group.bench_function("inclusion proof", |b| {
        b.iter(|| merkle::inclusion_proof(black_box(&leaves), 4321).unwrap())
    });
    let proof = merkle::inclusion_proof(&leaves, 4321).unwrap();
    group.bench_function("verify inclusion", |b| {
        b.iter(|| merkle::verify_inclusion(&leaves[4321], 4321, 10_000, black_box(&proof), &root))
    });
    group.bench_function("consistency proof", |b| {
        b.iter(|| merkle::consistency_proof(black_box(&leaves), 6000).unwrap())
    });
    group.finish();

    // Built once: criterion calls the closure for every sample.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.db");
    {
        let ledger = Ledger::open(&path, key.clone(), heads).unwrap();
        for _ in 0..10_000 {
            ledger.append(record()).unwrap();
        }
        ledger.sign_head().unwrap();
    }
    let mut group = c.benchmark_group("startup");
    group.sample_size(10);
    group.bench_function("open + verify 10k-entry ledger", |b| {
        b.iter(|| Ledger::open(&path, key.clone(), heads).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
