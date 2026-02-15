# Agent Context for Spilman Channels

This document provides context for AI coding assistants working on this codebase.

## Project Summary

This is an extension of CDK that adds **Spilman-style unidirectional payment channels** for Cashu ecash. The core protocol is in Rust with bindings for WASM (TypeScript), Python, and Go.

**Primary demos:**
- **CashuTube** (`web/blossom-server/`) - Pay-per-segment video streaming (47 tests)
- **Rust ASCII Art** (`examples/rust-ascii-art/`) - Native Rust server using `ConfigurableHost` with YAML config
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
| `examples/rust-ascii-art/` | Rust ASCII Art server (native, uses core `cdk`) |
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
- `spilman/bridge.rs` - `SpilmanBridge`, `SpilmanHost` trait (server-side)
- `spilman/client_bridge.rs` - `SpilmanClientBridge`, `SpilmanClientHost` trait (client-side)
- `spilman/bindings.rs` - FFI-friendly wrapper functions (compute_channel_from_token, create_funding_swap, etc.)
- `spilman/balance_update.rs` - Balance updates and Schnorr signatures
- `spilman/deterministic.rs` - Deterministic blinded output generation
- `spilman/sender_and_receiver.rs` - `verify_valid_channel`, DLEQ verification
- `spilman/configurable_host.rs` - `ConfigurableHost`, YAML-configurable `SpilmanHost` implementation (feature-gated: `configurable-host`)

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
- `web/blossom-server/tests/*.test.ts` - CashuTube tests (47 tests)

## Running Commands

```bash
# Start CDK mint (for testing)
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# Run Spilman tests
cargo test -p cdk spilman

# Clippy checks (must pass)
cargo clippy -p cdk -p cdk-wasm -p cdk-spilman-python -p cdk-spilman-go -p cdk-spilman-server-integration-tests -- -D warnings

# Build WASM (uses sentinel-based dependency tracking - instant when nothing changed)
make build-wasm

# Run server integration tests (52-test Rust client suite)
make test-server-ts          # Test TypeScript server
make test-server-rust        # Test Rust server
make test-server-python      # Test Python server
make test-server-go          # Test Go server
make test-server-all         # Test all servers

# Run blossom tests (requires web/blossom-server repo)
make test-blossom

# Run all tests
make test-all                # Does NOT require blossom-server repo
make test-all-with-blossom   # Includes blossom tests (requires blossom-server repo)

# Orphan process management (servers/mints left running after interrupted tests)
make list-orphans            # Show orphaned processes
make kill-orphans            # Kill them all

# Containerized testing (no local Rust required - Podman or Docker)
# Default is Podman; use CONTAINER_ENGINE=docker for Docker
make build-devenv            # Build the dev container image
make test-containerized      # Build + run Rust integration tests in containers
make test-containerized CONTAINER_ENGINE=docker  # Use Docker instead
make clean-containers        # Remove containers, volumes, image
# Note: Uses host networking on ports 33380 (mint) and 50080 (server)

# TypeScript checks
cd web/blossom-server && npx tsc --noEmit

# Run TypeScript ASCII demo (requires mint at localhost:3338)
cd examples/ts-ascii-art && npm install && npm run server  # In one terminal
cd examples/ts-ascii-art && npm run client -- Hello World  # In another terminal
```

### WASM Build Details

The `make build-wasm` target uses **sentinel-based dependency tracking**:
- Only rebuilds if Rust source files (`crates/cdk/src/**/*.rs`, `crates/cdk-wasm/src/**/*.rs`), `Cargo.toml`, or `Cargo.lock` changed
- Instant (~0.02s) when nothing changed, ~3-6s when rebuild needed
- Blossom server gets WASM copied (separate git repo); examples/ts-ascii-art uses symlink

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

- the function that swaps an input token into a funding should prefer to swap into an active keyset

### Closing
- it would be nice if the 'receiver_proofs_json' included the receiver's blinded signature, (and the p2pk_e?), to make it easy for non-P2BK wallets to accept them.

### Cleanup
- Scale back the demos, they're not really needed as we now have so many tests

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

The bridge delegates policy (pricing policy and data-storage policy) and cryptographic operations to the host via these hooks. The bridge never holds or sees the server's secret key.

```rust
trait SpilmanHost<C = String> {
    // Policy
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool;
    fn get_amount_due(&self, channel_id: &str, context: Option<&C>) -> u64;
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy>;
    fn now_seconds(&self) -> u64;

    // Storage: funding and payments
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;
    fn save_funding(&self, channel_id: &str, funding: ChannelFunding, initial_payment: PaymentProof);
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &C);
    fn get_balance_and_signature_for_unilateral_exit(&self, channel_id: &str) -> Option<PaymentProof>;

    // Channel state (returns Open/Closing/Closed)
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;
    fn mark_channel_closing(&self, channel_id: &str, locktime: u64, payment: PaymentProof) -> Result<(), String>;
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String>;

    // Keyset cache
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;

    // Cryptographic operations (host owns the secret key)
    fn compute_channel_secret(&self, charlie_pubkey_hex: &str, alice_pubkey_hex: &str) -> Result<String, String>;
    fn sign_with_tweaked_key(&self, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String>;
}

trait SpilmanNetworking {
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

#[async_trait]
trait SpilmanAsyncNetworking {
    async fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}
```

A ready-to-use implementation is provided: `ConfigurableHost` (feature-gated behind `configurable-host`) reads pricing and policy from YAML and tracks usage via named variables with linear pricing. See `spilman/configurable_host.rs` and the Rust ASCII Art server for a working example.

See [INTEGRATION.md](INTEGRATION.md) for full method signatures and documentation.

## Quick Reference: SpilmanClientHost Trait

The client-side bridge delegates key management and storage to the host via these hooks:

```rust
trait SpilmanClientHost {
    // Mint communication
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
    
    // Channel storage
    fn save_channel(&self, channel_id: &str, channel_json: &str, channel_secret_hex: &str);
    fn get_channel(&self, channel_id: &str) -> Option<ChannelData>;
    fn list_channel_ids(&self) -> Vec<String>;
    fn delete_channel(&self, channel_id: &str);
    
    // Key operations (bridge never sees the secret key)
    fn sign_with_tweaked_key(&self, signer_pubkey_hex: &str, message_hex: &str, tweak_scalar_hex: &str) -> Result<String, String>;
    fn compute_channel_secret(&self, alice_pubkey_hex: &str, charlie_pubkey_hex: &str) -> Result<String, String>;
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
