Don't make any changes to git, unless the user explicitly directs you to

# Agent Context for Spilman Channels

This document provides context for AI coding assistants working on this codebase.

## Project Summary

This is an extension of CDK that adds **Spilman-style unidirectional payment channels** for Cashu ecash. The core protocol is in Rust with bindings for WASM (TypeScript), Python, and Go.

**Primary demos:**
- **CashuTube** (`web/blossom-server/`) - Video streaming (47 tests)
- **Rust ASCII Art** (`examples/rust-ascii-art/`) - Native Rust server using `ConfigurableHost`
- **TypeScript ASCII Art** (`examples/ts-ascii-art/`) - Node.js server using `ConfigurableSpilman`
- **Python ASCII Art** (`examples/python-ascii-art/`) - Python server using `ConfigurableSpilman`
- **Go ASCII Art** (`examples/go-ascii-art/`) - Go server using `ConfigurableSpilman`

**Integration tests:** `crates/cdk-spilman-server-integration-tests/` - Rust test client testing all servers.

## Key Directories

| Path | Purpose |
|------|---------|
| `crates/cdk/src/spilman/` | Core Rust implementation |
| `crates/cdk-spilman-server-integration-tests/` | Multi-server test suite |
| `crates/cdk-wasm/` | WASM bindings |
| `integration-kits/` | Framework-specific kits (Express, etc.) |
| `examples/` | Demo implementations |

## Running Commands

```bash
# Start CDK mint
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# Run Spilman unit tests
cargo test -p cdk spilman

# Build WASM
make build-wasm

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
