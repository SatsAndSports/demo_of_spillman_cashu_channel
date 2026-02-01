# Agent Context for Spilman Channels

This document provides context for AI coding assistants working on this codebase.

## Project Summary

This is an extension of CDK that adds **Spilman-style unidirectional payment channels** for Cashu ecash. The core protocol is in Rust with bindings for WASM (TypeScript), Python, and Go.

**Primary demos:**
- **CashuTube** (`web/blossom-server/`) - Pay-per-segment video streaming (41 tests)
- **Rust ASCII Art** (`crates/cdk-ascii-art/`) - Native Rust server using core `cdk` library
- **TypeScript ASCII Art** (`examples/ts-ascii-art/`) - Reference TypeScript server
- **Python ASCII Art** (`examples/python-ascii-art/`) - Multi-language proof-of-concept
- **Go ASCII Art** (`examples/go-ascii-art/`) - Multi-language proof-of-concept

**Server integration tests:** `crates/cdk-spilman-server-integration-tests/` - Rust test client that tests all four server implementations (52 tests)

## Baseline Commits (for diffing)

To see all Spilman channel changes, compare ('git diff') against these pre-channel commits:
- **CDK repo:** 'origin/main'
- **Blossom-server repo:** 'origin/master' in the ./web/blossom-server folder


## Key Directories

| Path | Purpose |
|------|---------|
| `crates/cdk/src/spilman/` | Core Rust implementation |
| `crates/cdk-ascii-art/` | Rust ASCII Art server (native, uses core `cdk`) |
| `crates/cdk-spilman-server-integration-tests/` | Rust test client for all servers |
| `crates/cdk-wasm/` | WASM bindings for browser/Node.js |
| `crates/cdk-spilman-python/` | PyO3 bindings |
| `crates/cdk-spilman-go/` | CGO bindings |
| `web/blossom-server/` (different git repo) | CashuTube (TypeScript server + HTML player) |
| `examples/python-ascii-art/` | Python demo |
| `examples/go-ascii-art/` | Go demo |
| `examples/ts-ascii-art/` | TypeScript demo |
| `dev-mint/` | CDK mint development config |
| `containers/` | Podman dev environment (Dockerfile, mint config) |

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
- `web/blossom-server/src/api/channel.ts` - `/channel/params`, cooperative close, unilateral close endpoints

### CashuTube Player
- `web/blossom-server/public/index.html` - Video player with payment headers

### Tests
- `crates/cdk/src/spilman/tests.rs` - Rust unit/integration tests
- `crates/cdk-spilman-server-integration-tests/tests/integration.rs` - Server integration tests (Rust client testing all servers)
- `web/blossom-server/tests/*.test.ts` - CashuTube tests (41 tests)

## Running Commands

```bash
# Start CDK mint (for testing)
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# Run Spilman tests
cargo test -p cdk spilman

# Clippy checks (must pass)
cargo clippy -p cdk -p cdk-wasm -p cdk-spilman-python -p cdk-spilman-go -p cdk-spilman-server-integration-tests -- -D warnings

# Build WASM (uses sentinel-based dependency tracking - instant when nothing changed)
make wasm-dev

# Run server integration tests
make test-ts-cdkmintd        # Test TypeScript server
make test-rust-cdkmintd      # Test Rust server
make test-python-cdkmintd    # Test Python server
make test-go-cdkmintd        # Test Go server
make test-servers-cdkmintd   # Test all servers

# Run blossom tests
make test-blossom-cdkmintd

# Run all tests
make test-all-cdkmintd

# Orphan process management (servers/mints left running after interrupted tests)
make list-orphans              # Show orphaned processes
make kill-orphans              # Kill them all

# Containerized testing (no local Rust required - Podman or Docker)
# Default is Podman; use CONTAINER_ENGINE=docker for Docker
make build-devenv                       # Build the dev container image
make test-rust-only-containerized       # Build + run Rust integration tests in containers
make test-rust-only-containerized CONTAINER_ENGINE=docker  # Use Docker instead
make clean-containers                   # Remove containers, volumes, image
# Note: Uses host networking on ports 33380 (mint) and 50080 (server)

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


### Tests not yet ported from TS to Rust (follow up soon)
When we migrated from TS tests to Rust integration tests, 3 tests were skipped:
1. **`closes unused channel and verifies sender can derive secret keys for returned proofs`** - Tests client-side key derivation from returned proofs. Requires WASM function `get_sender_blinded_secret_key_for_stage2_output()`. Should be a native Rust test in `cdk::spilman::tests`.
2. **`retries cooperative close with refreshed keysets when first swap fails`** - Tests keyset refresh retry logic by mocking a `SpilmanHost` that returns stale keysets first. Requires direct `SpilmanBridge` instantiation with custom host.
3. **`retries unilateral close with refreshed keysets when first swap fails`** - Same as above for unilateral close path.

These test bridge internals rather than the HTTP API, so they belong as native Rust unit tests in `cdk::spilman::tests`, not integration tests.

### Other TODOs
- stop using blossom server in the tests
- maybe stop sending funding+params in the header, now that we have the /channel/register endpoint?
- video player should stop sending funding+params, and should use the register endpoint after any 4xx
- scale back the demos, they're not really needed as we now have so many tests
- how about maximum_amount? is it still being enforced? we need the policy to include it

### Protocol
- Keyset rotation issue: deactivated keysets removed from cache break existing channels (High Priority)

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
    fn get_balance_and_signature_for_unilateral_exit(&self, channel_id: &str) -> Option<(u64, String)>;
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;
    fn refresh_active_keysets(&self, mint: &str) -> Result<(), String>;
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
    fn mark_channel_closed(&self, channel_id: &str, locktime: u64, balance: u64,
        receiver_proofs_json: &str, sender_proofs_json: &str,
        receiver_sum: u64, sender_sum: u64) -> Result<(), String>;
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
