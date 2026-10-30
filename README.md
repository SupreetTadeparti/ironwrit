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

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
