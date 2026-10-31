# Benchmarks

Machine: Intel Core i5-1235U laptop, Windows 11, NVMe SSD, rustc 1.99.1, `cargo bench`
(release profile). Reproduce with:

```sh
cargo bench -p ironwrit-token -p ironwrit-ledger --bench authorize --bench ledger
```

## Authorization (goal: < 1 ms)

A realistic token: three rights; path, URL and recipient checks; an attenuation
block; and two expiry checks.

| Call | Mean |
|------|------|
| `fetch` allowed (URL parse + checks) | 171 µs |
| ungranted tool denied | 171 µs |
| `read_file` allowed (path canonicalized against the filesystem) | 251 µs |
| `read_file` with `docs/../secret.txt` denied | 783 µs |
| `could_permit` (per tool in `tools/list`) | 138 µs |

Most of the time goes to Biscuit's authorizer and, for paths, to filesystem
lookups (symlink resolution), which are slower on Windows. The denied
traversal also builds the denial reason. Everything is under 1 ms.

## Ledger

| Operation | Mean | Notes |
|-----------|------|-------|
| append, SQLite file (`synchronous=FULL`) | 5.9 ms | ~170 entries/s. One fsync per entry, so durability dominates. |
| append, in memory | 160 µs | Signing, encoding and the periodic tree head |
| Merkle root, 10k leaves | 1.27 ms | |
| inclusion or consistency proof, 10k leaves | 1.27 ms | Recomputes subtree roots |
| verify inclusion proof | 1.8 µs | |
| open + verify a 10k-entry ledger (startup) | ~1 s | Every signature and tree head checked; noisy (0.7–1.4 s) |

An allowed call writes two durable entries, `allow` before forwarding and
`completed` after, so on this machine the ledger adds about 12 ms per allowed
call and 6 ms per denied one. That's small next to a typical tool call, but it
is the main cost. Batching fsyncs, or `synchronous=NORMAL` with WAL, would trade
some crash durability for throughput. Tree hashing is O(n) for each head and
proof; an incremental tree (a compact range) would make it O(log n) for large
logs.
