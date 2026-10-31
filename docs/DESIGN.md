# Design

```
agent ──tools/call──▶ ironwrit ─────────────────────────────▶ upstream MCP server
                        │ 1. extract facts (ironwrit.toml)
                        │ 2. Biscuit authorizer: token + facts + time
                        │ 3. append signed ledger entry ── deny ──▶ error to agent
                        │ 4. forward, then append a "completed" entry
```

| Crate | Job |
|-------|-----|
| `ironwrit-token` | Keys; minting, attenuating and inspecting tokens; fact extraction; canonicalization; `BiscuitPolicy` |
| `ironwrit-ledger` | Entry encoding and signing; RFC 6962 tree; proofs; SQLite storage; verification |
| `ironwrit-gateway` | The MCP relay (rmcp): agent-facing server, upstream-facing client |
| `ironwrit-cli` | The `ironwrit` binary |

## Gateway

- **Startup:** the gateway spawns the upstream server, but doesn't start the
  MCP handshake with it until the agent sends `initialize`. It then forwards
  the agent's client info and capabilities upstream, and answers with the
  upstream's server info, capabilities and instructions.
- **Protocol versions:** capped at the newest version that still uses
  `initialize` (2025-11-25), because the relay needs server-to-client requests:
  roots, sampling and elicitation.
- **Relaying:** everything except `tools/call` passes straight through.
  `tools/list` drops tools the token never grants.
- **Session end:** either side disconnecting ends the session. The upstream's
  stdin is then closed, the process is reaped (killed after 3 s), and a final
  tree head is signed.

## Tokens

Tokens are standard [Biscuit](https://www.biscuitsec.org/) v3 tokens, with
Ed25519 keys stored as PKCS#8 / SPKI PEM files.

- **Authority block** (written by `ironwrit mint`): `right("<tool>")` facts
  plus checks. A `--ttl` adds
  `check if time($time), $time <= <RFC 3339>`.
- **Attenuation blocks** (`ironwrit attenuate`): checks only, plus an optional
  expiry. No key is needed. Attenuation can only narrow a token: facts in later
  blocks aren't trusted, so they can't grant anything.
- **Parameters:** `{name}` placeholders are bound when the token is minted.
  `--param` binds a string, and `--path` binds a canonical path. Values go in
  as typed terms, never as Datalog source.

The authorizer adds the call's facts and `time(now)`, then a single policy:

```datalog
allow if tool($t), right($t);
```

Every check in every block must pass as well. The authorizer runs within
Biscuit's limits, with a 50 ms time cap, and hitting a limit denies the call.
The token id recorded in the ledger is the hex revocation id of the token's
last block, so each attenuation gets a distinct id.

## Facts

| Extractor | Facts per value |
|-----------|-----------------|
| (every call) | `tool($name)` |
| `fs` | `op("read"\|"write")`, `path($canonical)` |
| `url` | `url_scheme($s)`, `url_host($h)`, `url_port($int)`, `url_path($decoded)` |
| `email` | `recipient($address)`, `recipient_domain($punycode)` |

How it works:
- `ironwrit.toml` maps each tool to an extractor and lists the arguments that
  hold the values.
- Each listed argument may be a string or an array of strings; missing or
  `null` arguments are skipped.
- An argument of any other type, or a value that won't canonicalize, denies
  the call.
- Unknown keys in the config are an error.

**Canonical paths** are built in four steps:
1. Make the path absolute against the working directory, then resolve `..`
   lexically.
2. Follow symlinks along the longest prefix that exists; missing trailing
   components are kept, so new files can be authorized.
3. On Unix, also resolve `..` the way the kernel does, and reject the path if
   the two answers differ.
4. Output with `/` separators. On Windows, lowercase it and drop the `\\?\`
   prefix.

[THREAT_MODEL.md](THREAT_MODEL.md#canonicalization) lists the inputs that are
rejected outright.

**Protected paths:** the gateway's key files, root public key, config and
ledger files (with their `-wal`/`-shm`/`-journal` siblings) are refused as
`fs` arguments, whatever the token says. Writing to any directory above them
is refused too.

## Ledger

### Entry

```
LedgerEntry { seq, ts, token_id, tool, args_hash, decision, reason, result_hash, call_seq }
```

- **decision** is one of:
  - `deny`: the call was never forwarded.
  - `allow`: written *before* the call is forwarded. If that write fails, the
    call is denied.
  - `completed`: written when the result arrives. `call_seq` points at the
    matching `allow` entry. `reason` is `ok`, `tool_error` or
    `relay_error: ...`, and `result_hash` is set when there was a result. If
    this write fails, the result is withheld from the agent.
- **args_hash / result_hash** are SHA-256 hashes of canonical JSON (object
  keys sorted, no whitespace). The values themselves are never stored.
- **ts** is in Unix milliseconds and never goes backwards along the log.

Canonical encoding, version 1 (integers are big-endian):

```
u8  version = 1
u64 seq
u64 ts
str token_id          str = u32 length + UTF-8 bytes (≤ 64 KiB)
str tool
[32] args_hash
u8  decision          0 allow, 1 deny, 2 completed
str reason
opt [32] result_hash  opt = 0x00, or 0x01 followed by the value
opt u64 call_seq
```

Decoding is strict: anything that wouldn't re-encode to exactly the same
bytes is rejected. The encoding serves two purposes:
- Each entry is signed with the gateway key as
  `Ed25519("ironwrit-entry-v1\0" ‖ encoding)`.
- The encoding is the entry's Merkle leaf data.

### Tree and tree heads

[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) hashing, with SHA-256:

```
leaf  = SHA-256(0x00 ‖ encoding)
node  = SHA-256(0x01 ‖ left ‖ right)
MTH() = SHA-256("")
MTH(D[n]) = node(MTH(D[0:k]), MTH(D[k:n]))   where k is the largest power of two < n
```

A signed tree head commits to the first `size` entries:
`Ed25519("ironwrit-tree-head-v1\0" ‖ u64 size ‖ u64 ts ‖ root)`. The domain
prefixes keep an entry signature from ever passing as a tree head signature.
The gateway signs a head:
- after every 64 new entries (`--head-every`),
- every 30 s while there are new entries (`--head-interval`),
- and on shutdown.

The code is tested against the reference vectors from the Certificate
Transparency implementation.

### Proofs

| Proof | Generation | Verification |
|-------|-----------|--------------|
| Inclusion: entry `i` is in the tree of size `n` | `PATH(m, D[n])`, RFC 6962 §2.1.1 | RFC 9162 §2.1.3.2 |
| Consistency: tree `m` is a prefix of tree `n` | `PROOF(m, D[n])`, RFC 6962 §2.1.2 | RFC 9162 §2.1.4.2 |

`ironwrit log prove` prints a self-contained inclusion proof against the newest
signed head: the entry, its leaf hash, the audit path, and the signed head.
`ironwrit log consistency` prints the two roots, the path, and the signed
heads at those sizes, if there are any. Both commands check the proof first
when `--pub` is given.

An inclusion proof checks a leaf against a root, and a tree size only means
something together with its root. So a proof is trusted only against a
*signed* tree head, which binds the two.

### Storage

SQLite, in WAL mode with `synchronous=FULL`, so each append is durable before
the call it records is forwarded. There are two `STRICT` tables:
- `entries`: one column per field, plus the signature,
- `tree_heads`: `size`, `ts`, `root`, `signature`.

Triggers block `UPDATE` and `DELETE` on both. They guard against accidents,
not attackers; that's what signatures are for.

On startup, the gateway verifies the whole existing log with its own key, and
refuses to append to a log that doesn't verify.

### Verification

`ironwrit log verify --pub gateway.pub` reports every problem it finds, each
with its location:

- a gap in `seq`: entries deleted,
- a row that doesn't decode: malformed,
- a bad entry signature: edited, moved or forged,
- a timestamp that goes backwards: reordered,
- a `completed` entry that doesn't match an open `allow` with the same
  tool, arguments and token,
- a bad tree head signature,
- a tree head larger than the log: truncated,
- a tree head root that doesn't match the entries.

It also reports entries not yet covered by a signed head. Detecting a rollback
of both entries *and* heads needs a tree head saved earlier (see the threat
model).

## Testing

| What | Where |
|------|-------|
| RFC 6962 vectors, every proof for trees up to 40 leaves | `ironwrit-ledger/src/merkle.rs` |
| Tamper tests: edit, delete, reorder, truncate, forge, bad heads | `ironwrit-ledger/tests/ledger.rs` |
| Attenuated token ⊆ parent (property test) | `ironwrit-token/tests/attenuation.rs` |
| Canonical forms are fixed points; extractors and decoders never panic | `*/tests/robustness.rs`, `fuzz/` |
| Relay round-trips, filtering, ledger recording, ledger failure denies | `ironwrit-gateway/tests/proxy.rs` |
| Example policies behave as documented | `ironwrit-token/tests/examples.rs` |
| The injection demo, end to end | `demo/run.sh` (CI) |
