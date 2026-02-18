# Spilman Channels Changelog

This document tracks the completed features and improvements for the Spilman Channels implementation.

## Completed Features (Feb 17, 2026)

### Rust Networking Batteries

Introduced a "batteries-included" networking module for Rust integrators to eliminate repetitive mint-communication boilerplate.

- **New Feature Flag**: `configurable-host-reqwest` (implies `configurable-host` + `reqwest`).
- **`ReqwestNetworking`**: A production-ready `SpilmanAsyncNetworking` implementation using `reqwest`.
- **`host.initialize_keysets()`**: A new async method on `ConfigurableHost` that fetches and caches keysets from all configured mints at startup.
- **`fetch_and_cache_keysets`**: Shared utility for re-populating the host cache from a mint.
- **Example Cleanup**: Deleted 171 lines of hand-rolled networking code from `examples/rust-ascii-art`, replacing it with the library provided battery.

### Storage Improvements

- **Lazy Funding Cache**: Added a write-once, in-memory cache to `SqliteStorage` for `ChannelFunding` lookups. This eliminates redundant JSON deserialization and disk reads for static channel parameters.
- **Async Method Safety**: Changed `ConfigurableHost::set_keyset` to return `Result<(), String>`, and updated 30+ call sites in tests and examples to handle or unwrap the result.
- **Makefile Integration**: Updated `test-unit-spilman` to include the `configurable-host` feature by default.

## Completed Features (Feb 15, 2026)

### SQLite Persistence for ConfigurableHost

Added pluggable storage to `ConfigurableHost` via an internal `SpilmanStorage` trait,
with two backends: `MemoryStorage` (default, identical to previous behavior) and
`SqliteStorage` for file-backed persistence.

- **`SpilmanStorage` trait**: 15-method interface covering funding, balance, usage, channel
  state, and keyset cache. All methods are synchronous (`Send + Sync`).
- **`MemoryStorage`**: Refactored from the previous `Stores` struct; implements the trait
  with the same `RwLock<HashMap>` approach.
- **`SqliteStorage`**: Uses `rusqlite` (bundled SQLite) with `Mutex<Connection>`.
  Three tables: `spilman_channels` (funding, balance, state, closing/closed JSON),
  `spilman_usage` (normalized: one row per variable with atomic `count = count + delta`
  via `INSERT ... ON CONFLICT DO UPDATE`), and `spilman_keysets` (keyset entry JSON).
- **YAML config**: New optional `storage` section (`type: memory` or `type: sqlite` +
  `path`). Defaults to memory when omitted; existing configs are unchanged.
- **Constructor**: `ConfigurableHost::new()` reads `config.storage` to select the backend.
  `ConfigurableHost::with_storage()` accepts a custom `Arc<dyn SpilmanStorage>`.
- **`rusqlite` dependency**: Added as optional, gated behind `configurable-host` feature.
- **16 new tests** (76 total spilman tests): 3 for `StorageConfig` YAML parsing, 13 for
  `SqliteStorage` (funding roundtrip, monotonic balance, usage increments, full channel
  lifecycle, keyset cache, file persistence across connections).

### Typed Per-Unit Channel Policy

Replaced the JSON-based `get_channel_policy() -> String` with a typed, per-unit method:
`get_channel_policy(unit: &str) -> Option<ChannelPolicy>`. The new `ChannelPolicy` struct
has three fields: `min_expiry_in_seconds`, `min_capacity`, and `max_amount_per_output: Option<u64>`.

- **Eliminated**: `BridgeServerConfig` and `UnitPricing` deserialization structs, all JSON
  serialization/deserialization round-trips for the policy.
- **All FFI bindings updated**: WASM (returns JS object or null), Python (returns tuple or None),
  Go (uses out-pointers + return code, new `ChannelPolicy` Go struct).
- **All examples and tests updated** across Rust, TypeScript, Python, and Go.

### ConfigurableHost Improvements

- **Keyset cache uses typed keys**: `(String, Id)` instead of `(String, String)`;
  `KeysetCacheEntry.unit` is `CurrencyUnit` instead of `String`. Parsing happens once
  at the boundary; internal lookups are type-safe with no string conversions.
- **`get_balance()` returns `Option<PaymentProof>`** instead of `Option<(u64, String)>`.
- **`get_usage()` returns `Option<UsageMap>`** (public type alias) instead of raw `Option<HashMap<String, u64>>`.
- **`UsageMap` type alias made public** for use in return types and downstream code.
- **`mark_channel_closed` ordering fix**: inserts into `closed` store before removing from
  `closing` store, so `get_channel_state` never briefly reports a closing channel as `Open`.

## Completed Features (Feb 14, 2026)

### ConfigurableHost: YAML-Driven SpilmanHost Implementation

Added `ConfigurableHost`, a generic, ready-to-use implementation of the `SpilmanHost` trait that eliminates the need to write custom host implementations for common use cases.

- **Named usage variables**: Pricing is defined in terms of named monotonic integer counters (e.g., `"requests"`, `"bytes"`, `"chars"`) with per-unit linear pricing. The amount due is computed as `sum(accumulated[var] * price_per_unit[var])`.
- **YAML configuration**: All pricing, mints, and expiry settings are defined in a YAML file. Example:
  ```yaml
  mints:
    "http://localhost:3338": [sat]
  min_expiry_seconds: 3600
  pricing:
    sat:
      min_capacity: 10
      variables:
        chars: 1
        requests: 5
  ```
- **Feature-gated**: Behind `configurable-host` Cargo feature flag, using `serde_yml` (the `serde_yaml` replacement).
- **In-memory storage**: Thread-safe `RwLock<HashMap>` stores behind `Arc`; cheap `Clone` for sharing between bridge and route handlers.
- **Public accessors**: `get_balance()`, `get_usage()`, `get_funding_data()`, `get_closed_data()`, `get_mints_units_keysets()`, `get_active_units()` for use in route handlers.
- **Context JSON**: Request context uses variable names as keys (e.g., `{"chars": 12, "requests": 1}`), directly matching the YAML config.
- **30 unit tests + 1 clone-shares-state test** in `configurable_host.rs`.
- **Rust ASCII Art server converted**: Replaced custom `AsciiArtHost` (deleted `host.rs`, `stores.rs`) with `ConfigurableHost` + `config.yaml`. New `networking.rs` provides `SpilmanAsyncNetworking`. All 54 integration tests pass.

### Bridge Modernization: Sync/Async Split + Typed Funding
- **Networking split**: `SpilmanHost` no longer owns mint IO. New traits `SpilmanNetworking` (sync) and `SpilmanAsyncNetworking` (async) isolate swap calls and keyset refresh.
- **Typed funding/payment**: Replaced long JSON parameter lists with `ChannelFunding` and `PaymentProof` structs.
- **Generic context**: `SpilmanHost<C = String>` allows passing a native request context instead of forced JSON strings.
- **FFI alignment**: Updated WASM, Python, and Go bindings + demos to the new signatures.
- **Close retry fix**: Ensured keyset-refresh retries finalize with the retried preparation data (prevents DLEQ mismatch).
- **Blossom parity**: Restored missing-field error strings expected by CashuTube tests.

## Completed Features (Feb 13, 2026)

### Full Retry Close Tests
- Added end-to-end tests for the close-swap retry path (swap rejected by mint due to stale keyset, refresh, retry with new keyset, mint accepts).
- **Rust tests** (`crates/cdk/src/spilman/tests.rs`): `test_cooperative_close_full_retry_with_real_mint` and `test_unilateral_close_full_retry_with_real_mint` -- use an in-process mint with keyset rotation and a lying host.
- **TypeScript/WASM test** (`examples/ts-ascii-art/tests/retry-close.test.ts`): Exercises the WASM async retry path with a real mint and a lying host that reports a fake keyset.

### All Demos Consolidated Under examples/
- **TypeScript**: Moved from `crates/cdk-wasm/examples/ascii-art/` to `examples/ts-ascii-art/`.
- **Python**: Moved from `crates/cdk-spilman-python/examples/ascii-art/` to `examples/python-ascii-art/`.
- **Go**: Moved from `crates/cdk-spilman-go/examples/ascii-art/` to `examples/go-ascii-art/`.
- All four demos now live under `examples/` with consistent naming: `rust-ascii-art`, `ts-ascii-art`, `python-ascii-art`, `go-ascii-art`.

## Completed Features (Feb 11, 2026)

### Standardized Keyset Fetching and Mockability
Refactored all four host implementations (Rust, TypeScript, Go, Python) to use a consistent, test-friendly pattern for retrieving keyset information from mints. This ensures that network-heavy logic is easily mockable in unit tests without changing the core `SpilmanHost` trait.

- **Standalone Helpers**: Implemented `fetchAllKeysetsFromMint` (or equivalent) as a standalone function or mockable package variable in all languages.
- **In-Place Cache Updates**: Updated `blossom-server` and other reference hosts to perform in-place updates of existing keyset entries. This ensures that any bridge instances holding references to keyset objects immediately see `active` status changes.
- **Persistent Keyset Strategy**: Standardized the "retain missing keysets" strategy across all languages. During a refresh, keysets that are no longer returned by the mint are kept in the local cache to ensure existing channels using those keysets remain valid until they are closed.
- **Verification**: All four server implementations now pass the full 54-test integration suite, and `blossom-server` passes its 49-test suite.

### Bug Fixes
- **Blossom Keyset Cache**: Fixed a bug where `refreshKeysetsForMint` incorrectly dropped existing keysets or failed to update the `active` status of cached entries.
- **TypeScript Mocking**: Implemented a self-import pattern in `channel.ts` to enable proper `vi.spyOn` mocking of internal function calls during Vitest runs.

## Completed Features (Feb 5-9, 2026)

### Secret Key Removal from Server Bridge (SpilmanBridge)

Redesigned the `SpilmanBridge` (server-side) so it **never holds or sees the server's secret key**, mirroring the client-side redesign. The host (application layer) owns the key and provides callbacks for operations that need it.

- Added `compute_channel_secret(charlie_pubkey_hex, alice_pubkey_hex) -> Result<String, String>` to `SpilmanHost` trait — called during `validate_and_save_new_channel` for ECDH
- Added `sign_with_tweaked_key(signer_pubkey_hex, message_hex, tweak_scalar_hex) -> Result<String, String>` to `SpilmanHost` trait — called during cooperative/unilateral close for signing the swap request
- Added `derive_receiver_blinding_scalar_for_stage1()` to `ChannelParameters` — exposes the receiver's P2BK tweak scalar for host signing
- Removed `server_secret_key: Option<SecretKey>` from `SpilmanBridge` — constructor is now `new(host)` (infallible, keyless)
- Removed `SpilmanChannelReceiver` entirely — replaced by host-delegated signing
- All FFI layers updated: WASM (`JsSpilmanHost` extern), Go (`SpilmanHostCallbacks` struct + CGO exports), Python (`PySpilmanHost`)
- All 10+ host implementations updated to own the secret key and delegate to `compute_channel_secret_from_hex` / `sign_with_tweaked_key_util`
- Fixed Go `#[repr(C)]` struct field ordering mismatch between `gateway.c` / `bridge.go` CGO header and Rust `lib.rs`
- Fixed pre-existing Rust integration test failure: added missing `funding_token_amount` field to params JSON

### Client-Side Bridge: SpilmanClientBridge

Added a full client-side bridge (`SpilmanClientBridge` + `SpilmanClientHost` trait) mirroring the server-side `SpilmanBridge` / `SpilmanHost` pattern. The client bridge orchestrates channel creation from tokens, payment signing, and HTTP header construction.

- **Go implementation first** (`cdk-spilman-go`), then **Python** (`cdk-spilman-python`), both with full integration tests
- **Core Rust API** (`client_bridge.rs`): `open_channel_from_token`, `sign_balance_update`, `build_payment_header`, `get_channel_info`, `list_channels`, `remove_channel`
- **`compute_channel_from_token` binding**: Parses a cashuA/cashuB token and computes channel parameters + funding swap in one step
- **`create_funding_swap` binding**: Creates the mint swap request for funding, with deterministic 2-of-2 locked outputs
- **`complete_funding_swap` binding**: Processes the mint's swap response, unblinding signatures and verifying DLEQ proofs
- **Code de-duplication**: `MintProofsFromMint` and `BuildCashuAToken` utility functions lifted from per-language test code into core Rust bindings, shared across Go and Python

### Secret Key Removal from Client Bridge (Stages 1-2)

Redesigned the `SpilmanClientBridge` so it **never holds or sees Alice's secret key**. The host (application layer) owns the key and provides callbacks for operations that need it.

**Stage 1: `sign_with_tweaked_key` callback**
- Added `sign_with_tweaked_key(signer_pubkey_hex, message_hex, tweak_scalar_hex) -> Result<String, String>` to `SpilmanClientHost` trait
- New binding functions: `sign_with_tweaked_key_util()` (convenience for hosts holding raw keys), `create_unsigned_balance_update()`, `attach_signature_to_balance_update()`
- Added `derive_sender_blinding_scalar_for_stage1()` public method on `ChannelParameters`

**Stage 2: Full secret removal**
- Added `compute_channel_secret(alice_pubkey_hex, charlie_pubkey_hex) -> Result<String, String>` to `SpilmanClientHost` trait
- Bridge constructor `new(host)` takes no key parameter (infallible, no longer returns `Result`)
- `open_channel_from_token()` takes `alice_pubkey_hex` per channel, enabling different keys per channel
- Removed `alice_secret_hex`, `alice_pubkey_hex` fields and accessors from bridge struct
- `ChannelData` struct separates channel JSON from channel secret for flexible host storage
- `StoredChannel` includes per-channel `alice_pubkey_hex`
- All FFI layers (Go, Python) and all tests updated

### Protocol Changes

- **Rename `shared_secret` to `channel_secret`**: Consistent naming across all code, docs, and FFI bindings
- **Channel ID includes channel_secret**: Restored the channel secret hash in the channel ID derivation (it had been accidentally removed). The channel_id is `SHA256(mint|unit|capacity|funding_token_amount|keyset_id|input_fee_ppk|maximum_amount|setup_timestamp|alice_pubkey|charlie_pubkey|locktime|sender_nonce|channel_secret_hex)`
- **`funding_token_amount` as explicit parameter**: No longer deterministically computed from capacity. Now an explicit field in `ChannelParameters`, with `compute_funding_token_amount()` utility for computing the minimum needed for a given capacity
- **Configurable mint fees in tests**: Dev mint now uses `input_fee_ppk=400`; all tests adjusted for non-zero fees

### Package Restructuring

- **Go package tidied** (`cdk-spilman-go`): Separate `spilman/` package directory, platform-specific CGO files, `packaged/` directory for pre-built libs, full README
- **TypeScript ASCII Art moved** to `crates/cdk-wasm/examples/ascii-art/` (from `examples/ts-ascii-art/`)
- **Python venv simplified**: Single `.venv` at the top of the Python subproject
- **Rust ASCII Art**: Added integration tests (`examples/rust-ascii-art/tests/integration.rs`)

## Completed Features (Feb 3, 2026)

### Atomic Funding with Initial Payment Proof
- **`save_funding` now includes initial balance/signature**: Extended the `SpilmanHost::save_funding` method across all language bindings (Rust, WASM, Python, Go) to accept `initial_balance: u64` and `initial_signature: &str` parameters. This enables servers to atomically store the first payment proof together with funding data, ensuring no payment is lost if the server restarts between funding and the first payment.

### Idiomatic Error Handling for Channel Close Methods
- **`mark_channel_closing` and `mark_channel_closed` now use native error handling**: Changed from returning `{error: string} | undefined` objects to language-native error mechanisms:
  - **TypeScript/WASM**: Now throws `Error` on failure (uses wasm-bindgen `catch` attribute)
  - **Python**: Raises exception on failure (already idiomatic, documented)
  - **Go**: Returns non-nil `error` on failure (already idiomatic)
  - **Rust**: Returns `Result<(), String>` (already idiomatic)
- **Defensive "already closed" checks**: All five server implementations (CashuTube, TS ASCII Art, Rust ASCII Art, Python ASCII Art, Go ASCII Art) now check channel state before marking closing/closed and return appropriate errors if the channel is already closed.

### Bug Fixes
- **BigInt serialization fix**: Fixed WASM BigInt → JSON serialization issue in TypeScript servers. WASM passes `u64` values as JavaScript `BigInt`, but `JSON.stringify()` cannot serialize BigInt. Added explicit `Number()` conversions at the WASM boundary in `bridge-hooks.ts` and `crates/cdk-wasm/examples/ascii-art/src/server.ts`.

### Video Player: Register-Only Channel Setup
- **Removed header fallback for channel params/funding**: The video player no longer sends `params` and `funding_proofs` in the `X-Cashu-Channel` header. This avoids HTTP header size limits (~16KB) that could be exceeded with large funding tokens.
- **Re-register on 4xx**: On any 4xx response (including 402), the player now calls `POST /channel/register` to re-register the channel with the server (fire-and-forget). HLS.js's built-in retry handles segment recovery.
- **Removed `confirmedChannels` tracking**: The Set tracking server-confirmed channels is no longer needed since params are never sent in headers.

## Completed Features (Feb 2, 2026)

### Bridge API Refactoring
- **Typed return values**: Core bridge methods (`process_payment`, `fund_channel`, `validate_payment`) now return typed result structs instead of JSON strings with `{success: true/false}` format.
- **Exception-based errors**: Errors are returned as exceptions/error returns in each language binding (WASM throws, Python raises `RuntimeError`, Go returns `error`).
- **New types**: `PaymentSuccess`, `PaymentValidationResult`, `FundChannelResult` (all without redundant `success` field).
- **Removed types**: `PaymentResponse`, `BridgeStatus`, `error_with_extra` helper.
- **Hybrid API**: Close methods (`executeCooperativeClose`, `executeUnilateralClose`) still return JSON strings with `{success: true/false}` for backward compatibility.
- **All servers updated**: TypeScript, Python, Go ASCII Art servers updated to use new API pattern.
- **All tests pass**: 52 integration tests pass for all four server implementations (Rust, TS, Python, Go), plus 47 Blossom tests.

## Completed Features (Jan 31, 2026)

### Containerized Testing Improvements
- **VPS/Cloud Environment Support**: Containerized tests now use host networking (`--network=host`) to work on VPS and cloud environments where bridge networking may be restricted (OpenVZ, LXC, Njalla, etc.).
- **Fixed High Ports**: Services use ports 33380 (mint) and 50080 (server) to avoid conflicts with existing services.
- **Port Availability Checking**: Makefile checks that required ports are free before starting tests, with clear error messages if ports are in use.
- **Dual Container Engine Support**: Makefile now supports both Podman and Docker via configurable `CONTAINER_ENGINE` variable (default: Podman).
- **Docker Support**: Full Docker support added alongside Podman. Use `make test-rust-only-containerized CONTAINER_ENGINE=docker` to run with Docker.

### User-Only Rust Installation
- **Documented user-only Rust setup**: Added instructions for installing Rust as a regular user in restricted environments like RaspiBlitz, avoiding conflicts with system-wide Rust installations.

### Multi-Architecture Container Support
- **ARM64 support**: Changed base image from `rust:1.92-slim-bookworm` (x86_64 only) to `debian:bookworm-slim` with Rust installed via rustup. Now works on x86_64 and ARM64 cloud environments.
- **Native recommendation for Pi**: Documented that containerized tests are not supported on Raspiblitz due to cgroup restrictions; native tests are the recommended approach for Raspberry Pi.
- **Devenv image renamed**: `docker-compose.yml` renamed to `docker-compose.spilman.yml` for clarity.

## Completed Features (Jan 29, 2026)

### Rust Integration Test Suite (`cdk-spilman-server-integration-tests`)
- **Migrated TS tests to Rust**: Replaced the TypeScript test suite with a comprehensive Rust integration test crate (52 tests).
- **Tests all four server implementations**: TypeScript, Rust, Python, and Go servers all pass the same test suite.
- **Parallel test execution**: Tests run in parallel using `tokio::sync::OnceCell` for thread-safe lazy initialization of shared mint/server processes.
- **New Makefile targets**: `test-server-ts`, `test-server-rust`, `test-server-python`, `test-server-go`, `test-server-all`.
- **Orphan process management**: Added `make list-orphans` and `make kill-orphans` to handle servers/mints left running after interrupted tests.
- **Clean test output**: Disabled doc-tests and lib unit tests (no tests there) to show only the 52 integration tests.

### Test Coverage (52 tests)
- `channel_params` (4 tests) - Receiver pubkey, pricing, keysets, min expiry
- `channel_status` (1 test) - 404 for unknown channel
- `channel_register` (6 tests) - Registration, idempotency, validation
- `minting` (1 test) - Funding token with deterministic outputs
- `verification` (3 tests) - DLEQ and keyset tampering detection
- `payment` (6 tests) - Payment flow, sat/msat/usd units
- `validation` (12 tests) - Signatures, balances, DLEQ, locktime, headers
- `status` (2 tests) - Status before/after payment
- `closing` (12 tests) - Cooperative close, idempotency, error cases
- `unilateral_closing` (7 tests) - Server-initiated close, overpayment

### Tests Not Ported (to follow up)
Three tests require direct bridge access (not HTTP API) and will be added as native Rust unit tests:
1. Sender key derivation from returned proofs
2. Cooperative close keyset refresh retry
3. Unilateral close keyset refresh retry

## Completed Features (Late Jan 2026)

### Rust ASCII Art Server (`rust-ascii-art`)
- **Native Rust implementation**: New crate implementing a Spilman channel payment server using the core `cdk` library directly (no WASM or FFI).
- **Full SpilmanHost implementation**: `AsciiArtHost` struct with all required callbacks for pricing, storage, keyset caching, and mint interaction.
- **Axum HTTP server**: Endpoints for `/channel/params`, `/channel/register`, `/ascii`, `/channel/:id/status`, `/channel/:id/close`, `/channel/:id/unilateral-close`.
- **In-memory stores**: Thread-safe (`RwLock<HashMap>`) storage for channel funding, balances, usage, closed channels, and keyset cache.
- **Async mint interaction**: `call_mint_swap_async()` for swap requests during channel close (avoids `reqwest::blocking` in tokio runtime).
- **Full test coverage**: Passes all 52 tests from the Rust integration test suite via `make test-server-rust`.
- **Added to CI**: Included in `make test-all` and `scripts/docker-test.sh`.

### Hash Input Normalization
- **Normalized all hash-based derivations to pipe-delimited text**: All 5 protocol-critical derivations now use consistent string interpolation instead of raw integer bytes or platform-dependent `usize`.
- **Derivations affected**: Channel ID, shared blinding scalars, per-output blinding scalars, deterministic nonces, and deterministic blinding factors.
- **Improved cross-platform consistency**: Ensures identical behavior between WASM (wasm32) and native (x86_64) implementations regardless of integer endianness or pointer size.

### Multi-Unit and msat Coverage
- **Added msat payment tests**: Verified high-precision payments (msat unit) work correctly across the full channel lifecycle.
- **Fixed `mintFundedChannel` unit bug**: The TS test helper now correctly respects the requested unit when minting tokens.
- **Discovered HTTP transport constraints**: High-capacity channels with small output amounts generate many proofs (~150+), which can exceed the 16KB limit for the `X-Cashu-Channel` header in Node.js/Express.

### Cleanup and Fixes
- **Removed legacy `mint` field fallbacks**: Python and Go clients now exclusively use the `mints_units_keysets` field for parameter discovery.
- **Fixed Python server scoping bug**: Resolved `UnboundLocalError` in the `/ascii` handler where `payment_info` was accessed before assignment.

## Completed Features (Previous)

### Protocol, Bridge, and Bindings

#### Dynamic Multi-Unit Pricing and `mints_units_keysets`
- **All three servers (TS, Python, Go) dynamically discover and advertise supported units**: `/channel/params` now returns `pricing` filtered to only units with active mint keysets, and `mints_units_keysets` (replacing the old `mint` field) mapping `{mint_url: {unit: [keyset_id, ...]}}`.
- **`ALL_PRICING` constant with dynamic filtering**: Each server defines a superset of pricing (sat, msat, usd) and filters at request time via `getActivePricing()` / `get_active_pricing()` so keyset rotation is reflected immediately.
- **Clients derive mint URL from `mints_units_keysets`**: Python and Go clients extract the mint URL from the new field.
- **Test suite updated**: Channel params tests assert `mints_units_keysets` structure and all-unit pricing for all servers.

#### Cross-Platform Bug Fixes
- **Fixed `usize` platform-dependent bug** in `params.rs`: `index.to_le_bytes()` produced 4 bytes on WASM (wasm32) but 8 bytes on native x86_64 (PyO3/CGo), causing deterministic output derivation to differ between WASM clients and native servers. Fixed by casting to `u64` before `to_le_bytes()` in `derive_blinding_scalar_for_output()` and `create_deterministic_output_with_blinding()`.
- **Fixed Python server `json.loads` bug** in `server.py`: Cooperative close idempotent path called `json.loads()` on an already-parsed Python list (stored as parsed JSON in `mark_channel_closed`).
- **Fixed Go server error response format** in `main.go`: Error responses returned `{"error": ...}` instead of the bridge's structured `body` containing `reason`, `capacity`, `balance`, `locktime`, `min_capacity`, `min_expiry_in_seconds`, and `validation_errors` fields. Also added missing-header guard for empty `X-Cashu-Channel`.

#### Cross-Server Testing
- **Rust test suite validates all four servers**: The 52-test Rust integration suite validates TS, Rust, Python, and Go servers via `SERVER_TYPE` env var
- **Makefile targets**: `make test-server-ts`, `make test-server-rust`, `make test-server-python`, `make test-server-go` run the full test suite with ephemeral mints
- **All servers pass tests**: TS, Rust, Python, and Go all pass 52/52 tests

#### Core Protocol
- Channel ID computed and verified (WASM on both client and server)
- Real Schnorr signatures from Alice (sender)
- Signature verification on server (via WASM)
- DLEQ proof verification (detects tampered funding proofs)
- Keyset validation (only approved mints accepted)
- P2BK (Pay-to-Blinded-Key) privacy for funding tokens
- Separate blinding tweak for refund path (unlinkable to 2-of-2 path)
- Integration tests verifying blinded signatures accepted by mint
- Keyset ID validation (`InvalidKeysetId` check): Verifies keyset ID matches public keys using NUT-02 V1 derivation

#### Bridge Architecture
- Structured `BridgeError` system returning detailed metadata in 402 headers
- `SpilmanHost` hooks for early rejection of invalid receiver keys or unsupported mints
- Validation of empty signatures early in payment processing
- Comprehensive unit tests for `SpilmanBridge` acceptability hooks
- Atomic usage and payment proof updates via `recordPayment(context)`
- Simplified Bridge API: Removed redundant `keyset_info_json` from `process_payment` and `validate_and_prepare_cooperative_close`
- Automatic Closure Validation: `validate_and_prepare_cooperative_close` verifies balance matches `amount_due`
- Consolidated `unblind_and_verify_dleq`: Core logic in `bridge.rs`, thin wrappers in WASM and Python

#### Channel Operations
- Channel closure and settlement (server closes, submits swap to mint)
- Stage 1 unblinding with DLEQ verification
- Receiver proof P2PK pubkey verification (ensures proofs are locked to Charlie)
- Idempotent channel closing (same amount succeeds, different amount rejected)
- Closed channels reject further payments
- Unilateral channel closing: `get_balance_and_signature_for_unilateral_exit` host hook + `create_unilateral_close_data` bridge method
- Full settlement flow in Python and Go: create swap request -> POST to mint -> unblind + verify DLEQ -> store proofs

#### Unified Channel Closing
- Bridge-orchestrated closing: `executeCooperativeClose` / `executeUnilateralClose` across WASM, PyO3, CGO, and native Rust
- All five servers (CashuTube, TS ASCII Art, Rust ASCII Art, Python, Go) use identical closing patterns (call bridge, pass through result)
- CashuTube migrated from manual close flow to bridge-based `executeCooperativeClose`
- CashuTube gained `POST /channel/:id/unilateral-close` endpoint
- Stores updated to track `receiverSum` / `senderSum` separately (replacing `valueAfterStage1`)
- Idempotent close responses include `receiver_sum` and `sender_sum`
- BigInt-to-Number conversion at WASM hook boundary for numeric params
- Python/Go: Removed redundant store checks from close helpers (bridge handles internally)

#### Native Rust Server
- **Rust ASCII Art** (`examples/rust-ascii-art/`): Reference implementation using core `cdk` library directly
- Demonstrates `SpilmanHost` trait implementation in native Rust
- Pricing: sat=1/char, msat=1000/char, usd=1/char (matching other demo servers)

#### Language Bindings
- **Python demo** (`crates/cdk-spilman-python/examples/ascii-art/`): Pay-per-character ASCII art generator
- **PyO3 bindings** (`crates/cdk-spilman-python/`): SpilmanBridge + client functions for Python
- Python SpilmanHost implementation with all required callbacks
- Python server with keyset caching from mint at startup
- Python client displays BOLT11 invoice + QR code during funding
- **Go parity with Python**: Go implementation matches Python feature-for-feature
- **Go Parallel Demo** (`scripts/go-parallel-demo.sh`): Parallel testing for Go implementation
- CLI commands in Python and Go servers: `s` (stats), `c` (close all), `q` (quit), `Ctrl+\` (quick stats)

### CashuTube

#### Video Player
- Video player with HLS.js and quality selector
- Payment headers sent with each segment request
- Server caches channel params and funding proofs
- 402 responses with detailed error info
- Balance checking against usage (requests + megabytes)
- 200 response with payment confirmation header (channel_id, balance, amount_due, capacity, size)
- Client-side byte tracking with post-response correction
- Channel exhaustion handling (pauses video, shows toast, opens channel manager)

#### UI/UX
- YouTube-style side-by-side layout (video left, list right)
- Direct video linking via URL hash (#master_hash)
- Share button with URL copying
- Timestamp in URL (#hash&t=90 or #hash&t=1m30s)
- Play/pause action indicator (brief YouTube-style feedback)
- Tap sides to skip +/-10 seconds (mobile/desktop)
- Keyboard shortcuts (Space, arrows, M=mute, F=fullscreen)
- Manual orientation rotation button for mobile
- Video thumbnails in list (preview.jpg)
- Sprite animation on video card hover
- Sprite thumbnails on progress bar hover (desktop) / drag (mobile)
- Balance indicator overlay (shows balance / capacity)
- Responsive controls (volume slider hidden on narrow screens)
- Playback speed control (0.5x, 1x, 1.25x, 1.5x, 2x)
- Display video title when playing
- Remember playback position (resume where left off)
- Auto-play hash video after channel modal close
- Fixed race conditions in progress preview during video switches
- Bandwidth memory across videos and sessions
- Fast-start HLS settings (reduced buffer, player-size capping)
- Autoplay failure detection with persistent overlay hint
- Video quality preference persistence in localStorage
- Loading spinner while buffering and during initial load

#### Channel Management
- Multi-server/multi-unit support with (server, unit) dropdown
- Per-unit pricing (sat, usd, eur, etc.)
- Per-quality cost estimation displayed in video cards
- Channels stored in IndexedDB with alice_secret and server_url
- Channel list sorted by setup_timestamp (most recent first)
- Refresh button on open channels (sync request counts with server)
- `closing_amount_due` saved to IndexedDB on channel close
- Reset Identity button in channel modal (with confirmation)
- First-time user onboarding tooltips
- Channel status moved to header bar (clickable to manage channels)
- Balance display in video player clickable to manage channels
- Improved "Close" button feedback (dimmed card, immediate toast, blocked for active channel)
- Handle "unused" channel status (server 404 -> blue theme)
- Server pricing summary displayed in channel management modal
- Conditional header balance display (appears only when <10% capacity)
- Highlight low funds with red pill badge in header

#### Server Features
- Video registration and listing via Blossom
- HLS encoding tools with hash-based naming
- Adaptive quality encoding (matches source resolution)
- HDR to SDR conversion for browser compatibility
- View counting for videos
- Resolution and blob stats displayed in video list
- Per-unit minimum capacity enforcement
- Minimum expiry enforcement (server rejects channels with locktime too soon)
- Server logs every 402 response with full header JSON
- `msat` unit test coverage (20-payment loop test with channel close)
- Active viewers count in header (polls /channel/stats every 5 seconds)
- Resolved circular dependencies via `stores.ts` reorganization

#### PWA & Mobile
- PWA support (manifest.json, add-to-home-screen, service worker with update prompt)
- YouTube-style tap controls (double-tap sides = +/-10s skip, double-tap middle = pause/play)
- Touch scroll detection (prevents accidental pause/skip when scrolling on mobile)
- Overlay-gated controls with tap-unlock delay
- Simplified page scrolling (removed nested scroll containers)
- Dynamic sticky player positioning
- Centered video content with pillarboxing for non-16:9 videos
- Auto-scroll video into view when starting playback
- Version display toast on "active" viewers count label tap

#### Misc
- Comprehensive test suite for payment flow
- Improved client-side payment logging
- Fixed sprite animation sizing on video card hover
- Fixed wide-screen layout grid bug
- Added visual divider and padding above video list in narrow mode
- Display video title in bold above list in narrow mode
- Global OGP/Twitter meta tags for improved link previews
- Suppress "Select a video" placeholder content in portrait mode
- Improved action indicator centering using robust Inset + Auto-Margin CSS
- Thumbnail preloading when channel connects (in-view)
- Collapsible Log section at page bottom
- Proper modal to pay the minting invoice (QR code + copy button)
- Update list of alternative channels after creating a new channel
- Player sends funding params/token until server confirms understanding
