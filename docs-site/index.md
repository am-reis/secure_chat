---
layout: default
title: Secure Messaging Protocol
---

# Secure Messaging Protocol

Transport-agnostic PQXDH + Double Ratchet secure messaging protocol core.

**⚠️ Pre-audit — see [Security](SECURITY.md).** This has not undergone a
third-party security audit. Don't use it to protect real communications
yet.

```
npm install secure-messaging-protocol
```

## Getting started

- [Getting Started](docs/getting-started.md) — a minimal two-party chat, in ~10 minutes
- [Integration Guide](docs/integration-guide.md) — persistence, transport, error handling, and what this library does *not* do for you
- [Project README](README.md) — full status, design decisions, structure

## Protocol specification

- [Protocol Specification](docs/spec.md) — the full phase-by-phase spec this implementation follows
- [Git Workflow](docs/git-workflow.md) — branching, versioning, release process
- [Multi-Device (Future)](docs/multi-device-future.md) — deferred design notes, grounded in Signal's Sesame algorithm and WhatsApp's per-device-key model

## Security

- [Security Overview](SECURITY.md) — audit status, design principles
- [Security Invariants](docs/security-invariants.md) — every invariant mapped to what enforces it and what proves it
- [Threat Model](docs/audit/threat-model.md)
- [Cryptographic Design](docs/audit/cryptographic-design.md)
- [Protocol State Machine](docs/audit/protocol-state-machine.md)
- [Wire Format Specification](docs/audit/wire-format.md)
- [Key Lifecycle Specification](docs/audit/key-lifecycle.md)
- [Persistence Specification](docs/audit/persistence-spec.md)
- [Test Vector Suite](docs/audit/test-vector-suite.md)
- [Dependency Inventory](docs/audit/dependency-inventory.md)

## Project

- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE) (Apache-2.0)
- [GitHub repository](https://github.com/am-reis/secure_chat)
- [npm package](https://www.npmjs.com/package/secure-messaging-protocol)
