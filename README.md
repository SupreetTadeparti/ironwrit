# Ironwrit

**A cryptographic seatbelt for AI agents.**

Ironwrit is an MCP proxy that sits between an AI agent and its tool servers.
Every tool call must be permitted by a signed, attenuable capability token, and
every decision is recorded in a tamper-evident Merkle log.

- **Scoped capability tokens:** each task gets a token that allows only specific
  actions, like "read files in `/docs`, call the weather API, nothing else".
  Tokens can be narrowed for sub-agents but never widened.
- **Tamper-evident action log:** every call is signed and appended to an
  RFC 6962 Merkle tree, so you can prove exactly what the agent did.
- **Injection containment:** if a poisoned web page tells the agent to email
  your secrets somewhere, the gateway blocks it because the token never
  allowed it.

> Status: early development. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Building

```sh
cargo build
cargo run -p ironwrit-cli -- --help
```

## Running

Put `ironwrit run --` in front of any stdio MCP server command. For example,
with Claude Code:

```sh
claude mcp add fs -- ironwrit run -- npx -y @modelcontextprotocol/server-filesystem ./docs
```

Without a token the gateway runs in pass-through mode: every call is allowed
and logged. Use `-v` (or `RUST_LOG=info`) to see one log line per tool call on
stderr.

## Capability tokens

Write a Datalog policy. `right(...)` grants a tool; `reject if` rules constrain
its arguments. Paths are canonical: absolute, symlinks resolved, `/`
separators, and lowercase on Windows (`c:/work/docs`).

```datalog
// policy.dl: read-only access to one folder
right("read_text_file");
right("list_directory");
reject if path($p), !$p.starts_with("/home/me/docs/"), $p != "/home/me/docs";
```

Then create a key, mint a token and run with it:

```sh
ironwrit keygen                                   # root.key + root.pub
ironwrit mint --policy policy.dl --ttl 8h -o task.token
ironwrit inspect task.token --pub root.pub
ironwrit run --token "$(cat task.token)" -- npx -y @modelcontextprotocol/server-filesystem /home/me/docs
```

Anyone holding a token can narrow it for a sub-agent, without the root key:

```sh
ironwrit attenuate task.token --check 'check if tool("read_text_file")' --ttl 10m -o sub.token
```

Tools the token never grants are hidden from `tools/list`, and denied calls
come back as tool errors that name the failed check. `ironwrit.toml` decides
which arguments become facts (`path`, `url_host`, `recipient`, ...); the
default covers `server-filesystem` and the demo servers.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
