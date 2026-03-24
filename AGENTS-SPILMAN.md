Don't make any changes to git, unless the user explicitly directs you to

# Agent Context for Spilman Channels

This document provides context for AI coding assistants working on this codebase.

## Project Summary

This workspace contains **Spilman-style unidirectional payment channels** for Cashu ecash. The core Rust implementation and bindings now live under `spilman-standalone/`, while the root `cdk` crate remains only as upstream reference code during the migration.

**Primary demos:**
- **CashuTube** (`web/blossom-server/`) - Video streaming (51 tests)
- **Rust ASCII Art** (`spilman-standalone/examples/rust-ascii-art/`) - Native Rust server using `ConfigurableHost`
- **TypeScript ASCII Art** (`spilman-standalone/examples/ts-ascii-art/`) - Node.js server using `ConfigurableSpilman`
- **Python ASCII Art** (`spilman-standalone/examples/python-ascii-art/`) - Python server using `ConfigurableSpilman`
- **Go ASCII Art** (`spilman-standalone/examples/go-ascii-art/`) - Go server using `ConfigurableSpilman`

**Integration tests:** `spilman-standalone/crates/cdk-spilman-server-integration-tests/` - Rust test client testing all servers.

## Key Directories

| Path | Purpose |
|------|---------|
| `spilman-standalone/crates/cdk-spilman/` | Core Rust implementation |
| `spilman-standalone/crates/cdk-spilman-interop-tests/` | Upstream `cdk` interoperability coverage |
| `spilman-standalone/crates/cdk-spilman-server-integration-tests/` | Multi-server test suite |
| `spilman-standalone/crates/cdk-wasm/` | WASM bindings |
| `spilman-standalone/integration-kits/` | Framework-specific kits (Express, etc.) |
| `spilman-standalone/examples/` | Demo implementations |

## Running Commands

```bash
# Run standalone unit/interop suite
make test-standalone

# Run full standalone suite (includes live mint integration)
make test-standalone-all

# Run server integration tests
make test-server-ts
make test-server-rust
make test-server-python
make test-server-go
```

## Documentation Index

| Topic | Document |
|-------|----------|
| Protocol & Design | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Integration Guide | [INTEGRATION.md](INTEGRATION.md) |
| Demo API & Specs | [CASHUTUBE.md](CASHUTUBE.md) |
| Contributor Guide | [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) |

## Active TODOs

- use the errorcodes.md
- [Client-side Opening] prefer swapping into an active keyset even if input is stale.
- P2BK: Include ephemeral key and signature in witness.
- In-memory cache for funding tokens.
- Server logic to transition 'Closing' to 'Closed' on startup if swap succeeded.
- Receiver proofs: Include blinded signature and ephemeral key for non-P2BK compatibility.

## Conventions

- **Default mint:** `http://localhost:3338`
- **Pricing:** Always use `pricing_scale` and snake_case `variables`.
- **API:** Clean snake_case responses (no camelCase aliases).
