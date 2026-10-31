# Threat model

Ironwrit sits between an AI agent and an MCP tool server. It assumes the
agent's output can be hostile at any moment, and makes two promises:

1. **Containment:** a tool call goes through only if a signed capability token
   permits it. Nothing the model says can widen the token.
2. **Accountability:** every decision, allowed or denied, is recorded in a
   signed, append-only Merkle log. Someone holding only the gateway's public
   key can check that the log is intact.

## Assets

| Asset | Why it matters |
|-------|----------------|
| What the tools can reach: files, network, mailboxes, APIs | The thing an attacker actually wants |
| The root signing key (`root.key`) | Whoever holds it can mint any token |
| The gateway signing key (`gateway.key`) | Whoever holds it can forge a whole log |
| The ledger (`ironwrit.db`) | The evidence of what the agent did |
| Secrets inside arguments and results | Must not leak into the log |

## Trust boundaries

```
 untrusted                  trusted                     trusted code, untrusted output
┌──────────────┐  stdio  ┌──────────────────┐  stdio  ┌──────────────────┐
│ agent / LLM  │ ──────▶ │ ironwrit gateway │ ──────▶ │ upstream MCP     │ ──▶ files, web, mail
│ + everything │ ◀────── │ token + ledger   │ ◀────── │ server           │
│ it has read  │         └──────────────────┘         └──────────────────┘
└──────────────┘                  ▲
                         token issuer (root.key), operator
```

- **Trusted:** the token issuer, the operator who starts the gateway, the
  gateway binary, and the OS account it runs under.
- **Untrusted:** the model, every token it emits, and anything it has read:
  web pages, files, emails, and tool results, including tool descriptions.
- **Upstream servers** are trusted to do what they're told, and nothing more.
  The gateway decides *whether* a call happens; the server decides *what it
  means*. When the two read an argument differently, there's a gap (see
  [Canonicalization](#canonicalization)).

## Attackers and what stops them

### A1. Prompt injection through content

A poisoned page, file or email tells the agent to read secrets and send them
somewhere. This is the main case, and [demo/](../demo/README.md) reproduces it.

- **Default deny:** only `right("<tool>")` grants a tool, and checks constrain
  its arguments. Tools the token never grants are hidden from `tools/list`.
  Hiding them is only a courtesy; every call is still checked.
- **Fail closed:** any of these denies the call:
  - an extraction or canonicalization error,
  - an unparseable argument,
  - hitting an authorizer limit,
  - a ledger write failure.
- **Evidence:** the denied attempt is logged, with a reason that names the
  failed check.

### A2. A sub-agent trying to widen its token

Biscuit attenuation only appends blocks. The authorizer trusts facts from the
authority block and from itself, so rules or facts in a later block can't grant
rights. A property test checks that an attenuated token never allows a call, or
lists a tool, that its parent didn't. That test includes blocks that try to
re-grant rights.

### A3. Token theft

Tokens are bearer credentials: anyone holding one can use it until it expires.
To limit the damage:
- mint short-lived tokens (`--ttl`),
- attenuate before handing a token to a sub-agent,
- pass tokens in an environment variable, not on a command line other users
  can see.

There's no revocation list yet (it's on the stretch list). Tenuo-style holder
binding (proof of possession) would also close this gap.

### A4. The agent attacking the gateway's own files

A common setup serves the current directory (`server-filesystem .`), which is
often where `root.key`, `gateway.key`, `ironwrit.toml` and the ledger live.
Whatever the token grants, the gateway refuses file arguments that:
- read or write those files, or their `.key`/`.pub`/`-wal`/`-shm`/`-journal`
  siblings, or
- write, move or delete a directory above them.

This guards only the tool path. An agent with a shell, or any process running
as the same OS user, can read the keys directly, which is out of scope. In
production, keep keys and the ledger outside every directory an upstream
server can reach.

### A5. Tampering with the log afterwards

Someone with write access to the DB file, but not to `gateway.key`, edits rows
to hide what happened. `ironwrit log verify` checks every signature, sequence
number, timestamp, completion link and tree head, and names the bad entry
when it finds:
- an edited field,
- a forged or moved entry,
- a deleted entry,
- swapped rows,
- a truncation that a signed tree head still covers.

**Limit:** if someone removes the newest entries *and* every tree head that
covers them, what's left is a valid, shorter log. Only a verifier who saved an
earlier tree head can tell, using `ironwrit log consistency`. Rolling the log
back is undetectable by anyone who never saw it longer, as in Certificate
Transparency. Publish or copy tree heads somewhere the attacker can't reach
(stretch goal: a witness).

Entries written after the newest tree head aren't committed to by anything
yet. `verify` reports how many there are. The gateway signs a head every 64
entries, every 30 seconds and on shutdown, so if it's killed, at most that
window is exposed.

### A6. A malicious or buggy upstream server

Out of scope for enforcement: once a call is allowed, the server can do
whatever its code does. Its results are untrusted input to the agent, and are
exactly how A1 starts.

## Canonicalization

Checks compare canonical strings, so the canonical form must be the one the
server will act on.

- **Paths** are absolute, with `..` resolved and symlinks followed, using `/`
  separators, and lowercased on Windows. Rejected outright:
  - ambiguous forms: `~`, NUL, device and verbatim paths, alternate data
    streams, symlink-then-`..`,
  - and on Windows, non-final components that end in a space or dot.

  Known gaps:
  - **TOCTOU:** the gateway resolves symlinks when it checks. If a symlink is
    swapped before the server opens the path, the server follows the new
    target. Don't grant write access to directories whose symlinks an
    attacker can create, which includes granting `write_file` plus a symlink
    tool.
  - **Hard links** are just names. A hard link inside `docs/` that points at a
    secret passes a `docs/` prefix check.
  - **Case-insensitive filesystems** other than Windows (default macOS, casefold
    directories on Linux): `/x/SECRET` and `/x/secret` are the same file but
    different strings. Prefix *allow* rules fail closed. *Deny* rules
    (`reject if path("/x/secret")`) can be bypassed, so write allow lists.
  - **Unicode normalization:** macOS treats NFC and NFD names as one file.
    Same advice: use allow-list prefixes.
  - **Relative paths** are resolved against the gateway's working directory,
    which the upstream inherits. A server that resolves them against its own
    root instead (or expands `~`, which the gateway refuses) reads them
    differently.
- **URLs** are parsed the WHATWG way.
  - Normalized: hosts go to punycode and lowercase, with one trailing dot
    removed; default ports are filled in.
  - Rejected: credentials, empty host labels, and paths that decode to `.`,
    `..`, `\` or NUL.
  - Gap: a server that parses URLs differently (not WHATWG) can disagree with
    the gateway on odd inputs.
- **Email** addresses are lowercased and their domain is converted to
  punycode. Lists in one string are rejected; pass recipients as an array.
- **JSON:** the gateway forwards its own parsed copy of the arguments.
  Duplicate keys are collapsed before the policy sees them, so the server
  can't read a different value than the one that was checked.

The canonicalization and extraction code is fuzzed, and a property test checks
that canonical forms are fixed points. That's how the Windows trailing-space
and `https://0..` cases were found.

## Policy pitfalls

- **Arguments the config doesn't list are invisible.** A tool missing from
  `ironwrit.toml`, or a path argument left out of `args`, produces no `path`
  facts, so `reject if path(...)` never fires. Grant only tools you have
  extractors for, and list every argument that names a resource.
- **Use `reject if`, not `check all`,** to constrain arguments: `check all`
  fails when a call has no matching facts, so it would deny every other tool.
- **Allowed channels can still carry data out.** If `fetch` to `*.example.test`
  is allowed and an attacker controls a subdomain, the agent can put secrets
  in the URL. Ironwrit limits *which* actions run, not what data flows through
  them.

## What the log reveals

- Arguments and results are stored only as SHA-256 hashes of canonical JSON.
  - Anyone holding the original arguments can confirm them against the log.
  - Hashes of low-entropy arguments (a recipient, a short path) can be guessed
    by brute force.
- Tool names, timestamps, token ids and denial reasons are stored in
  plaintext.
  - Reasons quote the token's own rules and name the bad argument, but never
    its value: a URL can carry an API key. That was a bug, fixed with a
    regression test.
  - Error messages from upstream relays are stored as they arrive.

## Non-goals

- A compromised gateway host or OS account (it can read the keys and the token).
- Bugs or malice in upstream servers, and what they do with allowed calls.
- Data-flow tracking, and inspecting or filtering tool results for injections.
- Availability: a hostile agent can make many calls, and each is logged.
- Pass-through mode (no token) enforces nothing. It only logs.
