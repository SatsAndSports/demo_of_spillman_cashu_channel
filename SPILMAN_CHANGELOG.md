# Spilman Channels Changelog

This document tracks the completed features and improvements for the Spilman Channels implementation.

## Completed Features

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
- Simplified Bridge API: Removed redundant `keyset_info_json` from `process_payment` and `create_close_data`
- Automatic Closure Validation: `create_close_data` verifies balance matches `amount_due`
- Consolidated `unblind_and_verify_dleq`: Core logic in `bridge.rs`, thin wrappers in WASM and Python

### Channel Operations
- Channel closure and settlement (server closes, submits swap to mint)
- Stage 1 unblinding with DLEQ verification
- Receiver proof P2PK pubkey verification (ensures proofs are locked to Charlie)
- Idempotent channel closing (same amount succeeds, different amount rejected)
- Closed channels reject further payments
- Unilateral channel closing: `get_balance_and_signature_for_unilateral_exit` host hook + `create_unilateral_close_data` bridge method
- Full settlement flow in Python and Go: create swap request -> POST to mint -> unblind + verify DLEQ -> store proofs

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
