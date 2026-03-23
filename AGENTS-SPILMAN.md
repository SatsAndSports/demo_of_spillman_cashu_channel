Don't make any changes to git, unless the user explicitly directs you to

# Agent Context for Spilman Channels

This document provides context for AI coding assistants working on this codebase.

## Project Summary

This workspace contains **Spilman-style unidirectional payment channels** for Cashu ecash. The core Rust implementation lives in the standalone `crates/cdk-spilman/` crate, with bindings for WASM (TypeScript), Python, and Go. The `cdk` crate keeps only wallet interop tests for the standalone library.

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
| `crates/cdk-spilman/` | Core Rust implementation |
| `crates/cdk/src/spilman/tests.rs` | `cdk` wallet interoperability coverage |
| `crates/cdk-spilman-server-integration-tests/` | Multi-server test suite |
| `crates/cdk-wasm/` | WASM bindings |
| `integration-kits/` | Framework-specific kits (Express, etc.) |
| `examples/` | Demo implementations |

## Running Commands

```bash
# Start CDK mint
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# Run standalone Spilman unit tests
cargo test -p cdk-spilman --features configurable-host

# Run `cdk` wallet interop tests against `cdk-spilman`
cargo test -p cdk spilman_tests

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
