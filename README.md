<div align="center">

# 🦮 Leash

**A local runtime security layer for autonomous coding agents.**

Know what your coding agent sent, and where it tried to push your code — before either one leaves the building.

[English](README.md) · [简体中文](README.zh-CN.md)

[![CI](https://github.com/wang110696/Leash/actions/workflows/ci.yml/badge.svg)](https://github.com/wang110696/Leash/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](go.mod)
[![Status](https://img.shields.io/badge/status-v0.1%20alpha-orange)](ARCHITECTURE.md)

</div>

---

## Why

Autonomous coding agents (Claude Code, Codex CLI, Cursor, and the like) now have shell, filesystem, and network access by default. That's what makes them useful — and it's also a blind spot: nobody's watching what they actually *send*, and nobody's watching what they *push*.

Most local proxy tools stop at "HTTP requests." That's not enough. **Most enterprise git remotes are SSH, not HTTPS — an HTTP(S) proxy never sees a `git push` at all.** If an agent decides to push your repository history somewhere it shouldn't, a plain egress proxy has nothing to say about it.

Leash covers both planes with one tool, running entirely on your machine:

- **Egress Sensor** — a local MITM proxy that inspects outbound HTTP(S) traffic for secrets and `.env`-shaped payloads, and blocks them before they leave.
- **Git Sensor** — a session-scoped `git` shim that gates `push` against the set of remotes your repo actually had when the session started. Push to anywhere else, and it's blocked *before real git is even invoked* — no network attempt, no exposure.

## Quick look

```console
$ leash run -- codex
leash: session 6f91b6cf started, proxy on 127.0.0.1:57826, known remotes: [github.com/you/your-repo]

# agent tries to exfiltrate a .env file over HTTPS
leash: BLOCK network POST example.com ([dotenv_pattern])

# agent tries to push to a repo that wasn't there when the session started
leash: BLOCK git push to github.com/attacker/stolen-repo: not in this session's known-remote snapshot [github.com/you/your-repo]

leash: session 6f91b6cf ended — allow=12 warn=0 block=2
```

Nothing here is simulated — this is what the tool actually prints when it catches something.

## Install

```bash
go install github.com/wang110696/Leash/cmd/leash@latest
```

Or build from source:

```bash
git clone git@github.com:wang110696/Leash.git
cd Leash
go build -o leash ./cmd/leash
```

## Usage

```bash
leash run -- codex
```

That's it. `leash run` wraps the launch of your agent: it starts a session-scoped MITM proxy, generates a local CA, installs a session-scoped `git` shim on `PATH`, snapshots your repo's current remotes as the trusted baseline, and then execs your agent with all of that wired in through environment variables. When the agent exits, the session ends and every temporary artifact — the shim symlink, the session directory — is cleaned up.

Every decision (allow/warn/block) is recorded to a local SQLite database at `~/.leash/events.db`, with secrets and raw request bodies deliberately **not** stored — only matched rule names and normalized remote identities.

## v0.1 scope — read this before you trust it

Leash is honest about what it does and doesn't cover, on purpose. Security tools that oversell their guarantees are worse than none at all.

| | Covered |
|---|---|
| Platform | macOS only |
| Harness | Codex CLI (`leash run -- codex`) |
| Network | HTTP/1.1 + HTTPS CONNECT, **request** inspection only — no response inspection, no WebSocket special-casing |
| Git | `git push <remote>` or `git push <url>` explicitly — bare `git push` relying on implicit upstream resolution is blocked as unresolved, not guessed at |
| Policy | Fixed, high-confidence rules in code — no YAML policy engine yet (v0.2) |
| CA trust | Environment variables only (`CODEX_CA_CERTIFICATE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`) — **the OS trust store is never touched** |

**Fail-closed by design**: if Leash's own proxy or git shim can't make a decision — a crash, a store failure, an unreadable baseline — the security-sensitive action (an outbound request, a push) is blocked, not silently allowed through. Leash may fail, but it will never fail silently and let traffic bypass unnoticed.

Full architecture, threat model, and the reasoning behind every one of these scope decisions — including the results of a security review that closed six confirmed bypasses before this was published — are in [ARCHITECTURE.md](ARCHITECTURE.md).

## Roadmap

- **v0.2** — process-level visibility (what did the agent actually execute?), YAML policy, a second harness
- **v0.3** — a local dashboard: timeline, diff viewer, session replay
- **v0.4** — an OS-enforced mode where the agent can no longer route around the sensors at all
- **v0.5+** — tamper-evident audit trail, compliance export

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, including what's deliberately *not* being built yet and why.

## Contributing

Issues and PRs welcome. If you're going to propose a scope change, read section 0 of [ARCHITECTURE.md](ARCHITECTURE.md) first — v0.1's narrow scope is a deliberate, reviewed decision, not an oversight.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
