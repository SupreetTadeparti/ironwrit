# Ironwrit Roadmap

Ironwrit is a Rust MCP proxy that sits between an AI agent and its tool servers. It:

1. Only allows tool calls permitted by a signed, attenuable capability token (Biscuit).
2. Writes every decision to a signed, Merkle-tree log with inclusion and consistency proofs.
3. Contains prompt injection: no model output can widen what the token allows.

## Architecture

```
ironwrit/
  Cargo.toml                 # workspace
  crates/
    ironwrit-token/          # mint, attenuate, authorize(ToolCall) -> Decision
    ironwrit-ledger/         # signed entries, RFC 6962 Merkle tree, proofs, SQLite
    ironwrit-gateway/        # MCP proxy (rmcp): agent <-> gateway <-> upstream
    ironwrit-cli/            # `ironwrit` binary
  demo/                      # mock fs/fetch/email MCP servers + poisoned page
  docs/                      # ROADMAP.md, DESIGN.md, THREAT_MODEL.md
  ironwrit.toml              # per-tool fact-extractor config
```

**Flow:** agent `tools/call` → extract facts → Biscuit authorizer → forward if allowed → append signed ledger entry → return the result or a denial error.

**Principles**
- Fail closed: any error means the call is denied.
- Canonicalize paths and URLs before authorizing.
- Store hashes of arguments and results in the log, never the raw secrets.
- Use vetted crypto crates (`biscuit-auth`, `ed25519-dalek`, `sha2`). Never write your own primitives.

## Phase 1: Project scaffold (Week 1)
- [x] 1.1 `git init`, `.gitignore`, `README.md` stub, MIT/Apache-2.0 license
- [x] 1.2 Cargo workspace with 4 crates; `ironwrit-cli` depends on the others
- [x] 1.3 `ironwrit --version` and `ironwrit --help` via a `clap` subcommand skeleton (`keygen`, `mint`, `attenuate`, `inspect`, `run`, `log`)
- [x] 1.4 Error types per crate (`thiserror`) and `tracing` setup
- [x] 1.5 GitHub Actions CI: `cargo fmt --check`, `clippy -D warnings`, `test`
- **Done when:** CI is green and `ironwrit --help` lists all subcommands

## Phase 2: Pass-through MCP proxy (Weeks 2–3)
- [x] 2.1 `ironwrit run -- <cmd> [args]` spawns the upstream MCP server as a child process over stdio
- [x] 2.2 Gateway acts as an MCP server to the agent (rmcp stdio) and as an MCP client to the upstream
- [x] 2.3 Relay `initialize` (merge capabilities), `tools/list`, `tools/call`
- [x] 2.4 Interception hook: `trait CallPolicy { fn check(&self, call: &ToolCall) -> Decision }`, starting with `AllowAll`
- [x] 2.5 Structured `tracing` log per call (tool, args, latency, decision)
- [x] 2.6 Integration test: a mock upstream server in `tests/`, asserting round-trips
- [ ] 2.7 Manual test: Claude Code → ironwrit → `@modelcontextprotocol/server-filesystem`
- **Done when:** Claude Code behaves the same with or without ironwrit in the path

## Phase 3: Capability tokens (Weeks 4–6)
- [x] 3.1 `ironwrit keygen` writes an Ed25519 root keypair (`root.key`, `root.pub`)
- [x] 3.2 `ironwrit mint --policy <file.dl>` creates a Biscuit token from a Datalog policy file
- [x] 3.3 `ironwrit attenuate <token> --check '<datalog>'` appends a narrowing block
- [x] 3.4 `ironwrit inspect <token>` pretty-prints blocks, checks and expiry
- [x] 3.5 `ToolCall` → facts: `tool($name)`, plus extractors from `ironwrit.toml`:
  - fs: `path($canonical)`, `op("read"|"write")`
  - fetch: `url_scheme`, `url_host`, `url_port`, `url_path`
  - email: `recipient`, `recipient_domain` (one per recipient)
- [x] 3.6 Canonicalization module: resolve `..` and symlinks, normalize separators and case (Windows!), percent-decode, IDN → punycode
- [x] 3.7 `BiscuitPolicy: CallPolicy`: authorizer with a `time()` fact and `allow if` rules; deny by default
- [x] 3.8 Gateway loads the token from `--token`/`IRONWRIT_TOKEN` and filters `tools/list` down to tools the token could permit
- [x] 3.9 A denial comes back as an MCP tool error with a clear reason (`"denied: path outside /docs"`)
- [x] 3.10 Tests: allow/deny table tests, traversal attacks, expiry, and a property test that an attenuated token ⊆ its parent
- **Done when:** a token scoped to `read_file` + `/docs/**` can't read `/docs/../secret.txt`, write files, or call `send_email`

## Phase 4: Tamper-evident ledger (Weeks 7–8)
- [x] 4.1 `LedgerEntry {seq, ts, token_id, tool, args_hash, decision, reason, result_hash, call_seq}` with canonical serialization (allowed calls write `allow` before forwarding and `completed` after)
- [x] 4.2 Gateway Ed25519 key; every entry is signed
- [x] 4.3 RFC 6962 Merkle tree: leaf hash `H(0x00‖d)`, node hash `H(0x01‖l‖r)`; tested against the RFC vectors
- [x] 4.4 Inclusion proof (entry `i` is in a tree of size `n`) and consistency proof (tree `m` is a prefix of tree `n`): generate and verify
- [x] 4.5 SQLite storage (`rusqlite`): `entries` and `tree_heads` tables; append-only API
- [x] 4.6 Signed Tree Head every N entries or T seconds, and on shutdown
- [x] 4.7 Gateway appends on every decision (allowed **and** denied); if the ledger write fails, the call is denied
- [x] 4.8 CLI: `log show`, `log verify --pub gateway.pub`, `log prove <seq>`, `log consistency <old> <new>`
- [x] 4.9 Tamper tests: edit, delete, reorder or truncate rows → `verify` names the bad entry
- **Done when:** a verifier with only the public key and the DB file detects any modification

## Phase 5: Injection demo (Week 9)
- [x] 5.1 Mock tools in `demo/`: `fetch` (serves `web/news.example.test.html`), `send_email` (records "sent" mail), and a filesystem over `demo/docs/` + `demo/secrets/`. One server, since the gateway proxies a single upstream; plus a scripted gullible agent
- [x] 5.2 Policy: `fetch` only `*.example.test`, `read_file` only `demo/docs/**`, no `send_email`
- [x] 5.3 Scenario: "Summarize https://news.example.test", where the page tells the agent to email the secrets to `attacker@evil.test`
- [x] 5.4 `demo/run.sh` / `run.ps1`: run A without ironwrit (the exfiltration gets recorded), run B with ironwrit (denied, and the ledger proves it)
- [x] 5.5 Sub-agent demo: attenuate the token for a "summarizer" sub-agent that only gets fetch access
- [ ] 5.6 Record an asciinema/GIF for the README (the README shows a text transcript for now)
- **Done when:** anyone can reproduce both runs in under 5 minutes

## Phase 6: Hardening (Week 10)
- [x] 6.1 `cargo-fuzz` targets: canonicalization, fact extractors, ledger entry decoding (`fuzz/`, run weekly in CI for 1 hour; stable proptest versions in `tests/robustness.rs`)
- [x] 6.2 `criterion` benchmarks: authorize latency (goal < 1 ms), ledger append throughput (results in `docs/BENCHMARKS.md`)
- [x] 6.3 `cargo audit` + `cargo deny` in CI
- [x] 6.4 `docs/THREAT_MODEL.md`: assets, attackers, trust boundaries, non-goals (e.g. a compromised gateway host, bugs in upstream servers)
- [x] 6.5 Fix findings and add a regression test for each:
  - canonicalization errors echoed argument values into denial reasons (and so the ledger)
  - an agent with file access could read or replace the gateway's keys, ledger or config
  - Windows: non-final path components ending in a space or dot weren't a fixed point
  - `https://0..` canonicalized to host `0`, which re-parses as `0.0.0.0`
- **Done when:** 1 hour of fuzzing finds nothing new, and benchmarks are published

## Phase 7: Polish and release (Week 11)
- [x] 7.1 README: the problem, demo GIF, quickstart, architecture diagram, and a comparison to prior art (Biscuit, Macaroons, Tenuo, CT logs)
- [x] 7.2 `docs/DESIGN.md`: token format, fact schema, ledger format, proof algorithms
- [x] 7.3 Example policies in `examples/policies/`
- [ ] 7.4 Tag `v0.1.0` and publish GitHub release binaries (Windows/Linux/macOS) (`.github/workflows/release.yml` builds them when the tag is pushed)
- [ ] 7.5 Blog post or writeup, linked from the README and your portfolio (draft in `docs/WRITEUP.md`)

## Stretch goals (after v0.1)
- Multiple upstream servers behind one gateway (namespaced tools)
- Streamable HTTP transport with `Authorization: Bearer` tokens
- A `ironwrit.delegate` meta-tool so agents can attenuate tokens for sub-agents in-band
- Revocation list and short-lived tokens
- A web viewer for the ledger that verifies proofs in the browser (WASM)
