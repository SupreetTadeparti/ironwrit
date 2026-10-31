# ironwrit

ironwrit is a proxy you put in front of an MCP server. It checks every tool
call against a capability token ([Biscuit](https://www.biscuitsec.org/)) and
writes each decision to a signed, append-only log.

The idea: if an agent reads a web page that tells it to email your API keys
somewhere, the call gets blocked because the token never allowed it, and you
have a record of the attempt.

It's an early v0.1. See [docs/ROADMAP.md](docs/ROADMAP.md) for what's done and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what it doesn't cover.

## Try the demo

```sh
./demo/run.sh            # or: powershell -File demo\run.ps1
```

This runs a scripted agent against a page with a hidden prompt injection,
once without ironwrit (the fake secrets get "emailed") and once with it (both
calls are denied). Details in [demo/README.md](demo/README.md).

## Usage

Build it:

```sh
cargo install --path crates/ironwrit-cli
```

Make a key and a token. A policy is Biscuit Datalog: `right(...)` grants a
tool and `reject if` limits its arguments.

```datalog
// policy.dl
right("read_text_file");
right("list_directory");
reject if path($p), $p != {docs}, !$p.starts_with({docs} + "/");
```

```sh
ironwrit keygen
ironwrit mint --policy policy.dl --path docs=./docs --ttl 8h -o task.token
ironwrit inspect task.token --pub root.pub
```

Run an MCP server behind it, here with Claude Code:

```sh
claude mcp add docs -- ironwrit run --token "$(cat task.token)" \
  -- npx -y @modelcontextprotocol/server-filesystem ./docs
```

Afterwards, look at the log:

```sh
ironwrit log show
ironwrit log verify --pub gateway.pub
ironwrit log prove 3 --pub gateway.pub
```

You can narrow a token for a sub-agent without the root key:

```sh
ironwrit attenuate task.token --check 'check if tool("read_text_file")' --ttl 10m -o sub.token
```

A few notes:

- `ironwrit.toml` says which tool arguments are paths, URLs or email
  addresses. Arguments it doesn't know about can't be checked.
- On first run, `ironwrit run` creates `gateway.key`, `gateway.pub` and
  `ironwrit.db`. Keep keys out of directories the MCP server can reach.
- Without `--token`, everything is allowed and only logged.

More example policies are in [examples/policies](examples/policies).

## How it works

Each tool call's arguments are canonicalized (paths, URLs, email addresses)
and turned into Datalog facts, then checked against the token. Allowed calls
are logged before they're forwarded, so if the log write fails the call
doesn't happen.

The log is a Merkle tree in the style of Certificate Transparency
(RFC 6962), stored in SQLite. Entries hold hashes of arguments and results,
not the values themselves. `ironwrit log verify` catches edited, deleted or
reordered entries.

There's more in [docs/DESIGN.md](docs/DESIGN.md) and benchmark numbers in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Development

```sh
cargo test --workspace
cargo bench -p ironwrit-token -p ironwrit-ledger --bench authorize --bench ledger
cargo +nightly fuzz run canonicalize
```

## License

MIT or Apache-2.0, at your option.
