# Agent Context for Spilman Channels

This document provides context for AI coding assistants working on this codebase.

## Project Summary

This is an extension of CDK that adds **Spilman-style unidirectional payment channels** for Cashu ecash. The core protocol is in Rust with bindings for WASM (TypeScript), Python, and Go.

**Primary demos:**
- **CashuTube** (`web/blossom-server/`) - Pay-per-segment video streaming (41 tests)
- **TypeScript ASCII Art** (`examples/ts-ascii-art/`) - Reference implementation with full test suite (33 tests)
- **Python ASCII Art** (`examples/python-ascii-art/`) - Multi-language proof-of-concept
- **Go ASCII Art** (`examples/go-ascii-art/`) - Multi-language proof-of-concept

## Baseline Commits (for diffing)

To see all Spilman channel changes, compare ('git diff') against these pre-channel commits:
- **CDK repo:** 'origin/main'
- **Blossom-server repo:** 'origin/master' in the ./web/blossom-server folder


## Key Directories

| Path | Purpose |
|------|---------|
| `crates/cdk/src/spilman/` | Core Rust implementation |
| `crates/cdk-wasm/` | WASM bindings for browser/Node.js |
| `crates/cdk-spilman-python/` | PyO3 bindings |
| `crates/cdk-spilman-go/` | CGO bindings |
| `web/blossom-server/` (different git repo) | CashuTube (TypeScript server + HTML player) |
| `examples/python-ascii-art/` | Python demo |
| `examples/go-ascii-art/` | Go demo |
| `examples/ts-ascii-art/` | TypeScript demo |
| `dev-mint/` | CDK mint development config |

## Key Files by Topic

### Protocol Implementation
- `spilman/params.rs` - `ChannelParameters`, channel ID, P2BK blinding
- `spilman/bridge.rs` - `SpilmanBridge`, `SpilmanHost` trait
- `spilman/balance_update.rs` - Balance updates and Schnorr signatures
- `spilman/deterministic.rs` - Deterministic blinded output generation
- `spilman/sender_and_receiver.rs` - `verify_valid_channel`, DLEQ verification

### CashuTube Server
- `web/blossom-server/src/api/fetch.ts` - Payment validation, 402 responses
- `web/blossom-server/src/api/bridge-hooks.ts` - `SpilmanHost` implementation
- `web/blossom-server/src/api/stores.ts` - Channel state stores
- `web/blossom-server/src/api/channel.ts` - `/channel/params` endpoint

### CashuTube Player
- `web/blossom-server/public/index.html` - Video player with payment headers

### Tests
- `crates/cdk/src/spilman/tests.rs` - Rust integration tests
- `web/blossom-server/tests/*.test.ts` - CashuTube tests (41 tests: blobs, channels, minting, payment, validation, closing)
- `examples/ts-ascii-art/tests/*.test.ts` - ASCII Art tests (33 tests: channels, minting, payment, validation, closing)

## Running Commands

```bash
# Start CDK mint (for testing)
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# Run Spilman tests
cargo test -p cdk spilman

# Clippy checks (must pass)
cargo clippy -p cdk -p cdk-wasm -p cdk-spilman-python -p cdk-spilman-go -- -D warnings

# Build WASM (uses sentinel-based dependency tracking - instant when nothing changed)
make wasm-dev

# Run tests (automatically builds WASM if needed, copies to consumers)
make test-blossom-cdk      # Blossom server tests with CDK mint
make test-ts-ascii-cdk     # TypeScript ASCII Art tests with CDK mint

# TypeScript checks
cd web/blossom-server && npx tsc --noEmit

# Run TypeScript ASCII demo (requires mint at localhost:3338)
cd examples/ts-ascii-art && npm install && npm run server  # In one terminal
cd examples/ts-ascii-art && npm run client -- Hello World  # In another terminal
```

### WASM Build Details

The `make wasm-dev` target uses **sentinel-based dependency tracking**:
- Only rebuilds if Rust source files (`crates/cdk/src/**/*.rs`, `crates/cdk-wasm/src/**/*.rs`), `Cargo.toml`, or `Cargo.lock` changed
- Instant (~0.02s) when nothing changed, ~3-6s when rebuild needed
- Test targets (`test-blossom-*`, `test-ts-ascii-*`) automatically depend on WASM build
- Blossom server gets WASM copied (separate git repo); ts-ascii-art uses symlink

## Documentation Index

For detailed information, see:

| Topic | Document |
|-------|----------|
| Payment construction, signing, verification (the NUT) | [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) |
| Protocol design, P2BK privacy, bridge architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| CashuTube API, data stores, HLS encoding | [CASHUTUBE.md](CASHUTUBE.md) |
| Development setup, running mints, testing | [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) |
| Completed features history | [SPILMAN_CHANGELOG.md](SPILMAN_CHANGELOG.md) |

## Active TODOs

### Protocol
- Keyset rotation issue: deactivated keysets removed from cache break existing channels
- Two-stage channel closing in SpilmanBridge (see ARCHITECTURE.md "Future Work")

### Player
- Remember volume preference in localStorage

### Lower Priority
- Python/Go demos: Add client-initiated closing (currently server-only CLI close). TS is the reference for this.

## Conventions

- **Line endings:** LF (Unix), not CRLF
- **Default mint:** `http://localhost:3338`
- **Blossom server:** Port 3000 (dev), Port 3099 (tests)
- **Keyset IDs (dev mint):** sat=`001b6c716bf42c7e`, msat=`00ffedc2dbb87212`, usd=`00818d176a78e7f0`

## Quick Reference: SpilmanHost Trait

The bridge delegates policy (pricing policy and data-storage policy) to the host via these hooks:

```rust
trait SpilmanHost {
    fn receiver_key_is_acceptable(&self, pubkey: &str) -> bool;
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset: &str) -> bool;
    fn get_amount_due(&self, channel_id: &str, context: Option<&str>) -> u64;
    fn record_payment(&self, channel_id: &str, balance: u64, sig: &str, context: &str);
    fn get_funding(&self, channel_id: &str) -> Option<(params, proofs, secret, keyset_info)>;
    fn save_funding(&self, channel_id: &str, ...);
    fn is_closed(&self, channel_id: &str) -> bool;
    fn get_channel_policy(&self) -> ChannelPolicy;
    fn now_seconds(&self) -> u64;
    fn get_keyset_info(&self, mint: &str, keyset_id: &str) -> Option<KeysetInfo>;
}
```

## Quick Reference: Payment Header

Clients send `X-Cashu-Channel` header with each request. The header value is **base64-encoded JSON**:

```javascript
// Client-side encoding
const payment = {
  channel_id: "hex_string",
  balance: 150,
  signature: "schnorr_sig_hex",
  params: { ... },           // Optional, cached by server
  funding_proofs: [ ... ]    // Optional, cached by server
};
headers["X-Cashu-Channel"] = btoa(JSON.stringify(payment));  // Browser
// or: base64.b64encode(json.dumps(payment).encode()).decode()  # Python
// or: base64.StdEncoding.EncodeToString(jsonBytes)  // Go
```

Server responds with confirmation header on 200 OK (plain JSON, not base64):

```json
{
  "channel_id": "...",
  "balance": 150,
  "amount_due": 145,
  "capacity": 1000,
  "size": 524288
}
```

Or returns 402 (Payment Required), 400 (Bad Request), etc. on errors. See [CASHUTUBE.md](CASHUTUBE.md) for full error codes.
