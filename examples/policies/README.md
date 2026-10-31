# Example policies

| Policy | Grants | Parameters |
|--------|--------|------------|
| [read-only-docs.dl](read-only-docs.dl) | `server-filesystem` read tools, inside one folder | `--path docs=<dir>` |
| [code-assistant.dl](code-assistant.dl) | Read a repo; write only under `src/` and `tests/`; never `.git/` or `.env` | `--path repo=<dir>` |
| [web-research.dl](web-research.dl) | `fetch` from an allowlist of hosts, HTTPS only | none |
| [email-team-only.dl](email-team-only.dl) | `send_email` to one domain, checked for every recipient | `--param domain=<domain>` |

Each file says how to mint it. `crates/ironwrit-token/tests/examples.rs` checks
that every policy here mints and behaves as its comments say.

Narrow any of them further for a sub-agent, without the root key:

```sh
ironwrit attenuate task.token --check 'check if tool($t), ["read_text_file", "list_directory"].contains($t)' --ttl 10m
ironwrit attenuate task.token --check 'reject if op("write")'
```

Write allow lists (`reject if ... !$p.starts_with(...)`) rather than deny
lists. Deny lists can be bypassed on case-insensitive filesystems; see
[docs/THREAT_MODEL.md](../../docs/THREAT_MODEL.md#canonicalization).
