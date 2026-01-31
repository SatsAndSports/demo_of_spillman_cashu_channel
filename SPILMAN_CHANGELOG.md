# Spilman Channels Changelog

This document tracks the completed features and improvements for the Spilman Channels implementation.

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
- **Raspberry Pi / ARM support**: Changed base image from `rust:1.92-slim-bookworm` (x86_64 only) to `debian:bookworm-slim` with Rust installed via rustup. Now works on x86_64, ARM64, and ARM (Raspberry Pi).
- **Devenv image renamed**: `docker-compose.yml` renamed to `docker-compose.spilman.yml` for clarity.

## Completed Features (Jan 29, 2026)

### Rust Integration Test Suite (`cdk-spilman-server-integration-tests`)
- **Migrated TS tests to Rust**: Replaced the TypeScript test suite with a comprehensive Rust integration test crate (52 tests).
- **Tests all four server implementations**: TypeScript, Rust, Python, and Go servers all pass the same test suite.
- **Parallel test execution**: Tests run in parallel using `tokio::sync::OnceCell` for thread-safe lazy initialization of shared mint/server processes.
- **New Makefile targets**: `test-ts-cdkmintd`, `test-rust-cdkmintd`, `test-python-cdkmintd`, `test-go-cdkmintd`, `test-servers-cdkmintd`.
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

### Rust ASCII Art Server (`cdk-ascii-art`)
- **Native Rust implementation**: New crate implementing a Spilman channel payment server using the core `cdk` library directly (no WASM or FFI).
- **Full SpilmanHost implementation**: `AsciiArtHost` struct with all required callbacks for pricing, storage, keyset caching, and mint interaction.
- **Axum HTTP server**: Endpoints for `/channel/params`, `/channel/register`, `/ascii`, `/channel/:id/status`, `/channel/:id/close`, `/channel/:id/unilateral-close`.
- **In-memory stores**: Thread-safe (`RwLock<HashMap>`) storage for channel funding, balances, usage, closed channels, and keyset cache.
- **Async mint interaction**: `call_mint_swap_async()` for swap requests during channel close (avoids `reqwest::blocking` in tokio runtime).
- **Full test coverage**: Passes all 52 tests from the Rust integration test suite via `make test-rust-cdkmintd`.
- **Added to CI**: Included in `make test-all-cdkmintd` and `scripts/docker-test.sh`.

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

### Dynamic Multi-Unit Pricing and `mints_units_keysets`
- **All three servers (TS, Python, Go) dynamically discover and advertise supported units**: `/channel/params` now returns `pricing` filtered to only units with active mint keysets, and `mints_units_keysets` (replacing the old `mint` field) mapping `{mint_url: {unit: [keyset_id, ...]}}`.
- **`ALL_PRICING` constant with dynamic filtering**: Each server defines a superset of pricing (sat, msat, usd) and filters at request time via `getActivePricing()` / `get_active_pricing()` so keyset rotation is reflected immediately.
- **Clients derive mint URL from `mints_units_keysets`**: Python and Go clients extract the mint URL from the new field.
- **Test suite updated**: Channel params tests assert `mints_units_keysets` structure and all-unit pricing for all servers.

### Cross-Platform Bug Fixes
- **Fixed `usize` platform-dependent bug** in `params.rs`: `index.to_le_bytes()` produced 4 bytes on WASM (wasm32) but 8 bytes on native x86_64 (PyO3/CGo), causing deterministic output derivation to differ between WASM clients and native servers. Fixed by casting to `u64` before `to_le_bytes()` in `derive_blinding_scalar_for_output()` and `create_deterministic_output_with_blinding()`.
- **Fixed Python server `json.loads` bug** in `server.py`: Cooperative close idempotent path called `json.loads()` on an already-parsed Python list (stored as parsed JSON in `mark_channel_closed`).
- **Fixed Go server error response format** in `main.go`: Error responses returned `{"error": ...}` instead of the bridge's structured `body` containing `reason`, `capacity`, `balance`, `locktime`, `min_capacity`, `min_expiry_in_seconds`, and `validation_errors` fields. Also added missing-header guard for empty `X-Cashu-Channel`.

### Cross-Server Testing
- **Rust test suite validates all four servers**: The 52-test Rust integration suite validates TS, Rust, Python, and Go servers via `SERVER_TYPE` env var
- **Makefile targets**: `make test-ts-cdkmintd`, `make test-rust-cdkmintd`, `make test-python-cdkmintd`, `make test-go-cdkmintd` run the full test suite with ephemeral mints
- **All servers pass tests**: TS, Rust, Python, and Go all pass 52/52 tests

### Core Protocol
- Channel ID computed and verified (WASM on both client and server)
- Real Schnorr signatures from Alice (sender)
- Signature verification on server (via WASM)
- DLEQ proof verification (detects tampered funding proofs)
- Keyset validation (only approved mints accepted)
- P2BK (Pay-to-Blinded-Key) privacy for funding tokens
- Separate blinding tweak for refund path (unlinkable to 2-of-2 path)
- Integration tests verifying blinded signatures accepted by mint
- Keyset ID validation (`InvalidKeysetId` check): Verifies keyset ID matches public keys using NUT-02 V1 derivation

### Bridge Architecture
- Structured `BridgeError` system returning detailed metadata in 402 headers
- `SpilmanHost` hooks for early rejection of invalid receiver keys or unsupported mints
- Validation of empty signatures early in payment processing
- Comprehensive unit tests for `SpilmanBridge` acceptability hooks
- Atomic usage and payment proof updates via `recordPayment(context)`
- Simplified Bridge API: Removed redundant `keyset_info_json` from `process_payment` and `validate_and_prepare_cooperative_close`
- Automatic Closure Validation: `validate_and_prepare_cooperative_close` verifies balance matches `amount_due`
- Consolidated `unblind_and_verify_dleq`: Core logic in `bridge.rs`, thin wrappers in WASM and Python

### Channel Operations
- Channel closure and settlement (server closes, submits swap to mint)
- Stage 1 unblinding with DLEQ verification
- Receiver proof P2PK pubkey verification (ensures proofs are locked to Charlie)
- Idempotent channel closing (same amount succeeds, different amount rejected)
- Closed channels reject further payments
- Unilateral channel closing: `get_balance_and_signature_for_unilateral_exit` host hook + `create_unilateral_close_data` bridge method
- Full settlement flow in Python and Go: create swap request -> POST to mint -> unblind + verify DLEQ -> store proofs

### Unified Channel Closing
- Bridge-orchestrated closing: `executeCooperativeClose` / `executeUnilateralClose` across WASM, PyO3, CGO, and native Rust
- All five servers (CashuTube, TS ASCII Art, Rust ASCII Art, Python, Go) use identical closing patterns (call bridge, pass through result)
- CashuTube migrated from manual close flow to bridge-based `executeCooperativeClose`
- CashuTube gained `POST /channel/:id/unilateral-close` endpoint
- Stores updated to track `receiverSum` / `senderSum` separately (replacing `valueAfterStage1`)
- Idempotent close responses include `receiver_sum` and `sender_sum`
- BigInt-to-Number conversion at WASM hook boundary for numeric params
- Python/Go: Removed redundant store checks from close helpers (bridge handles internally)

### Native Rust Server
- **Rust ASCII Art** (`crates/cdk-ascii-art/`): Reference implementation using core `cdk` library directly
- Demonstrates `SpilmanHost` trait implementation in native Rust
- Pricing: sat=1/char, msat=1000/char, usd=1/char (matching other demo servers)

### Language Bindings
- **Python demo** (`examples/python-ascii-art/`): Pay-per-character ASCII art generator
- **PyO3 bindings** (`crates/cdk-spilman-python/`): SpilmanBridge + client functions for Python
- Python SpilmanHost implementation with all required callbacks
- Python server with keyset caching from mint at startup
- Python client displays BOLT11 invoice + QR code during funding
- **Go parity with Python**: Go implementation matches Python feature-for-feature
- **Go Parallel Demo** (`scripts/go-parallel-demo.sh`): Parallel testing for Go implementation
- CLI commands in Python and Go servers: `s` (stats), `c` (close all), `q` (quit), `Ctrl+\` (quick stats)

### CashuTube Video Player
- Video player with HLS.js and quality selector
- Payment headers sent with each segment request
- Server caches channel params and funding proofs
- 402 responses with detailed error info
- Balance checking against usage (requests + megabytes)
- 200 response with payment confirmation header (channel_id, balance, amount_due, capacity, size)
- Client-side byte tracking with post-response correction
- Channel exhaustion handling (pauses video, shows toast, opens channel manager)

### CashuTube UI/UX
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

### CashuTube Channel Management
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

### CashuTube Server Features
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

### CashuTube PWA & Mobile
- PWA support (manifest.json, add-to-home-screen, service worker with update prompt)
- YouTube-style tap controls (double-tap sides = +/-10s skip, double-tap middle = pause/play)
- Touch scroll detection (prevents accidental pause/skip when scrolling on mobile)
- Overlay-gated controls with tap-unlock delay
- Simplified page scrolling (removed nested scroll containers)
- Dynamic sticky player positioning
- Centered video content with pillarboxing for non-16:9 videos
- Auto-scroll video into view when starting playback
- Version display toast on "active" viewers count label tap

### CashuTube Misc
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
