# AGENTS.md - Spilman / Standalone-First Root

This repo now has two roles:

- `spilman-standalone/` is the canonical home of Spilman code, bindings, demos, shared test harnesses, and the standalone test mint.
- the root `cdk/` workspace is a temporary upstream-reference subset slated for removal once the standalone workspace fully replaces it.

`web/blossom-server/` is a nested git repo that consumes standalone-managed WASM and TS kit assets.

## Remaining Root Crates

Only these root crates remain while root removal is in progress:

- `cashu`
- `cdk`
- `cdk-common`
- `cdk-axum`
- `cdk-fake-wallet`
- `cdk-http-client`
- `cdk-mintd`
- `cdk-signatory`
- `cdk-sql-common`
- `cdk-sqlite`

If a task appears to require removed crates or old fork-local Spilman code, prefer `spilman-standalone/` instead.

## Common Commands

```bash
# Standalone test mint
cargo build -p cdk-spilman-test-mint --manifest-path spilman-standalone/Cargo.toml

# Auto-spawn mint for a command
spilman-standalone/scripts/run_with_mint.sh <command...>

# Legacy root subset sanity check
cargo check -p cdk-mintd --locked

# Standalone suites
make test-standalone
make test-standalone-all

# Common delegated top-level targets
make test-unit-spilman
make test-blossom
make test-blossom-nutmix

# WASM / kit sync
make build-wasm
make build-blossom-wasm

# Lint / format
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Important Paths

| Path | Purpose |
|---|---|
| `spilman-standalone/crates/cdk-spilman/` | Canonical Rust Spilman implementation |
| `spilman-standalone/crates/cdk-spilman-test-mint/` | Standalone fakewallet+sqlite test mint |
| `spilman-standalone/crates/cdk-spilman-interop-tests/` | Upstream `cdk` interoperability tests |
| `spilman-standalone/crates/cdk-spilman-server-integration-tests/` | Shared multi-server harness |
| `spilman-standalone/crates/cdk-wasm/` | WASM bindings |
| `spilman-standalone/integration-kits/` | Python / Go / TS integration kits |
| `spilman-standalone/examples/` | Demo servers |
| `crates/cdk-mintd/` | Legacy root mint subset pending removal |
| `web/blossom-server/` | Nested repo for CashuTube / blossom tests |

## Mint Infrastructure

- Prefer `MINT_URL` when an external mint is available.
- Otherwise, standalone flows auto-build and spawn `cdk-spilman-test-mintd`.
- The standalone test mint is intentionally minimal: `fakewallet` + in-memory sqlite + mint/swap coverage.
- The root `cdk-mintd` subset is now legacy cleanup material and should not be the default choice for new work.

## Rust Workspace Conventions

- edition 2021, MSRV 1.85.0, toolchain pinned to 1.93.0
- no `unsafe`
- no `.unwrap()` in non-test code
- prefer `Self` over repeating the type name in impls
- prefer bounds in `where` clauses instead of inline generic bounds
- use full-path tracing macros (`tracing::info!`, not imported macros)
- prefer `.to_string()` / `.to_owned()` over `.into()` / `String::from()`
- use `match` when both branches contain logic
- use `mod x;` in separate files; only inline test/bench modules
- import `core::fmt` / `std::fmt` module, not individual items

## Project Notes

- root `cdk` no longer carries Spilman-specific code
- root duplicate crates for Spilman/bindings/demos were removed
- blossom tests run through `web/blossom-server/Makefile` and expect standalone-managed assets
- if you need live-mint integration for standalone tests, start with `spilman-standalone/scripts/run_with_mint.sh`
- active tests should use the standalone test mint, not the root `cdk-mintd` path

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`.

## Useful Docs

| Document | Path |
|---|---|
| Contributor guide | `SPILMAN_DEVELOPMENT.md` |
| Integration guide | `INTEGRATION.md` |
| Architecture notes | `ARCHITECTURE.md` |
