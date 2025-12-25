# Cashu Development Kit (CDK) with Spilman Channels

## Project Overview

This is a fork/extension of CDK that adds Spilman-style unidirectional payment channels for Cashu ecash. The primary demo application is **CashuTube** - a pay-per-segment video streaming service built on Blossom (decentralized blob storage).

## Directory Structure

```
cdk/
├── crates/
│   ├── cdk/                        # Main Cashu library
│   │   └── src/spilman/            # Spilman channel implementation
│   ├── cdk-wasm/                   # WASM bindings (browser + Node.js)
│   └── cdk-py/                     # PyO3 bindings (Python, legacy)
└── web/
    ├── Makefile                    # WASM build targets
    ├── wasm-web/                   # Browser WASM output (--target web)
    ├── wasm-nodejs/                # Node.js WASM output (--target nodejs)
    └── blossom-server/             # Modified Blossom server + video player
        ├── src/
        │   ├── api/channel.ts      # GET /channel/params endpoint
        │   ├── api/videos.ts       # GET /videos (public listing)
        │   ├── api/fetch.ts        # Payment header logging + verification
        │   ├── admin-api/videos.ts # POST/DELETE /api/videos (admin)
        │   ├── wasm/               # Node.js WASM (copied from wasm-nodejs/)
        │   └── ...
        ├── public/
        │   ├── index.html          # Video player with payment headers
        │   └── wasm/               # Browser WASM (copied from wasm-web/)
        ├── tools/
        │   ├── hls-encode.sh       # Encode video to HLS with hash-based names
        │   ├── hls-upload.sh       # Upload HLS content to Blossom
        │   └── hls-publish.sh      # Combined encode + upload + register
        └── config.example.yml      # Example config with channel settings
```

## Spilman Channel Architecture

A Spilman channel is a unidirectional payment channel between:
- **Alice (sender)**: The video viewer/payer
- **Charlie (receiver)**: The video server

### Key Concepts

1. **2-of-2 Multisig Funding**: Channel is funded with tokens that require both Alice and Charlie to spend (with locktime refund for Alice)

2. **Deterministic Outputs**: Both parties can compute the same blinded outputs using a shared secret (ECDH), eliminating round trips

3. **Balance Updates**: Alice signs off-chain messages incrementing Charlie's balance

4. **Channel ID**: SHA256 hash of channel parameters (mint, pubkeys, locktime, nonce, etc.)

### Core Rust Files

- `spilman/params.rs` - ChannelParameters struct with channel ID derivation
- `spilman/keysets_and_amounts.rs` - Fee calculations, amount decomposition
- `spilman/deterministic.rs` - Deterministic output generation
- `spilman/balance_update.rs` - Balance update messages and signatures
- `spilman/sender_and_receiver.rs` - SpilmanChannelSender, SpilmanChannelReceiver
- `spilman/established_channel.rs` - EstablishedChannel state machine
- `spilman/bindings.rs` - FFI-friendly functions for WASM/PyO3

## CashuTube Video Streaming

### Architecture

```
┌─────────────────┐         ┌─────────────────┐
│  Browser        │         │  Blossom Server │
│  (player.html)  │         │  (Node.js)      │
├─────────────────┤         ├─────────────────┤
│ - HLS.js player │  HTTP   │ - Blob storage  │
│ - WASM (web)    │◄───────►│ - WASM (nodejs) │
│ - Payment HDR   │         │ - Channel API   │
│ - IndexedDB     │         │ - Video registry│
└─────────────────┘         └─────────────────┘
```

### Payment Flow

1. Player fetches `/channel/params` to get Charlie's pubkey
2. Player creates and funds a channel (stored in IndexedDB)
3. For each segment request, player adds `X-Cashu-Channel` header containing:
   - `channel_id` - identifies the channel
   - `balance` - current balance (increments each segment)
   - `signature` - Alice's Schnorr signature over the balance update
   - `params` - full channel parameters (only on first request)
   - `funding_proofs` - funding token proofs (only on first request)
4. Server caches params and funding proofs by channel_id
5. Server verifies channel_id matches computed value
6. Server verifies Alice's signature using WASM

### HLS.js xhrSetup Gotcha

**Important:** When using HLS.js `xhrSetup` to add custom headers, you must call `xhr.open()` before `xhr.setRequestHeader()`. The XHR starts in `UNSENT` state (readyState=0), and `setRequestHeader` only works after `open()` is called.

```javascript
xhrSetup: function(xhr, url) {
    if (xhr.readyState === XMLHttpRequest.UNSENT) {
        xhr.open('GET', url, true);
    }
    xhr.setRequestHeader('X-Custom-Header', 'value');
}
```

From the HLS.js docs: "xhr.open() should be called in xhrSetup if the callback modifies the XMLHttpRequest instance in ways that require it to be opened first."

See: https://github.com/video-dev/hls.js/blob/master/docs/API.md#xhrsetup

### HLS Encoding for Blossom

Blossom stores blobs by SHA256 hash (content-addressed). Our HLS tools create hash-based playlists:

```bash
# Encode video to multiple qualities with hash-based segment names
./tools/hls-encode.sh /path/to/video.mp4

# Upload to Blossom and register in video database
BLOSSOM_ADMIN_PASS=xxx ./tools/hls-upload.sh http://localhost:3000 "Video Title"

# Or do both in one step
BLOSSOM_ADMIN_PASS=xxx ./tools/hls-publish.sh http://localhost:3000 /path/to/video.mp4 "Video Title"
```

The encoder:
- Detects source height and only encodes qualities at or below it
- Supports non-standard resolutions (e.g., 500p source → 500p, 480p, 360p, 240p)
- Caps at 1080p for H.264 level 4.1 browser compatibility
- Converts 10-bit HDR sources to 8-bit SDR (yuv420p)
- Rewrites playlists to reference segments by SHA256 hash (no extensions)
- Creates `hashed/` directory with symlinks for easy Blossom upload
- Generates `preview.jpg` - best frame thumbnail for video list (280px wide)
- Generates `sprite.jpg` - sprite sheet for progress bar scrubbing (160x90 thumbs, 5s intervals)
- Generates `sprite-meta.json` - sprite sheet metadata (dimensions, interval, frame count)
- Outputs blob stats: count, total size, max blob size

### Server Configuration

Add to `config.yml`:

```yaml
channel:
  enabled: true
  secretKey: "your-64-char-hex-secret-key"  # Charlie's private key
  approvedMintsAndUnits:
    http://localhost:3338:
      - sat
  pricePerRequestPpk: 500   # Price per request in parts per thousand (0.5 sat)
  pricePerMegabytePpk: 1000 # Price per megabyte in parts per thousand (1 sat)
```

### Video Database Schema

```sql
CREATE TABLE videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  master_hash TEXT NOT NULL,
  duration INTEGER NOT NULL,
  uploaded INTEGER NOT NULL,
  description TEXT,        -- Optional description
  source TEXT,             -- Original source file path
  preview_hash TEXT,       -- SHA256 of preview.jpg thumbnail
  sprite_meta_hash TEXT,   -- SHA256 of sprite-meta.json
  views INTEGER DEFAULT 0, -- View counter
  width INTEGER,           -- Video width in pixels
  height INTEGER,          -- Video height in pixels
  blob_count INTEGER,      -- Number of blobs (segments + playlists + assets)
  total_size INTEGER,      -- Total size of all blobs in bytes
  max_blob_size INTEGER    -- Size of largest blob in bytes
)
```

### API Endpoints

**Public:**
- `GET /channel/params` - Returns receiver pubkey, pricing (ppk), approved mints/units/keysets
- `GET /videos` - List registered videos (includes preview_hash, sprite_meta_hash, width, height, blob stats)
- `GET /<sha256>` - Fetch blob (accepts X-Cashu-Channel header)

**Admin (basic auth):**
- `POST /api/videos` - Register video `{title, master_hash, duration, description?, source?, preview_hash?, sprite_meta_hash?, width?, height?, blob_count?, total_size?, max_blob_size?}`
- `DELETE /api/videos/:id` - Remove video by id

### Player URL Format

Videos can be directly linked using the master_hash in the URL fragment:
```
http://localhost:3000/#<master_hash>
http://localhost:3000/#<master_hash>&t=90      # Start at 90 seconds
http://localhost:3000/#<master_hash>&t=1m30s   # Start at 1:30
```
The player will load the video on page load. Share button provides easy URL copying with optional timestamp.

## Building WASM

```bash
cd web/

# Build browser WASM (--target web)
make wasm-web

# Build Node.js WASM (--target nodejs)
make wasm-nodejs

# Build both and copy to blossom-server
make wasm-to-blossom-server
```

After copying WASM, rebuild blossom-server:
```bash
cd blossom-server
npx pnpm build
npx pnpm start
```

## Running Tests

```bash
# All CDK tests
cargo test -p cdk

# Spilman-specific tests
cargo test -p cdk spilman

# Run the example
cargo run -p cdk --example spilman_channel
```

## Current Status

**Working:**
- ✅ Video player with HLS.js and quality selector
- ✅ Payment headers sent with each segment request
- ✅ Channel ID computed and verified (WASM on both client and server)
- ✅ Real Schnorr signatures from Alice
- ✅ Signature verification on server (via WASM)
- ✅ Server caches channel params and funding proofs
- ✅ Video registration and listing via Blossom
- ✅ HLS encoding tools with hash-based naming
- ✅ Adaptive quality encoding (matches source resolution)
- ✅ HDR to SDR conversion for browser compatibility
- ✅ Direct video linking via URL hash (#master_hash)
- ✅ Multi-server support with server selector dropdown
- ✅ Channels stored in IndexedDB with alice_secret and server_url
- ✅ View counting for videos
- ✅ Resolution and blob stats displayed in video list

**TODO - Payments:**
- ❌ Payment enforcement (402 responses for insufficient balance)
- ❌ Channel closure and settlement
- ❌ Server-side balance persistence (currently in-memory only)

**TODO - Player Improvements:**

*Completed:*
- ✅ Share button with URL copying
- ✅ Timestamp in URL (#hash&t=90 or #hash&t=1m30s)
- ✅ Play/pause action indicator (brief YouTube-style feedback)
- ✅ Tap sides to skip ±10 seconds (mobile/desktop)
- ✅ Keyboard shortcuts (Space, arrows, M=mute, F=fullscreen)
- ✅ Video thumbnails in list (preview.jpg)
- ✅ Sprite animation on video card hover (cycles through sprite frames)
- ✅ Sprite thumbnails on progress bar hover (desktop) / drag (mobile)
- ✅ Balance indicator overlay (shows balance / capacity)
- ✅ Responsive controls (volume hidden on narrow screens)

*High Priority:*
- ❌ Playback speed control (0.5x, 1x, 1.25x, 1.5x, 2x)
- ❌ Display video title when playing
- ❌ Highlight currently playing video in list
- ❌ Remember playback position (resume where left off)

*Medium Priority:*
- ❌ Remember preferences (volume, speed, quality) in localStorage
- ❌ Loop toggle
- ❌ Picture-in-picture button
- ❌ Video description panel (expandable)

*Lower Priority:*
- ❌ Search/filter video list
- ❌ Sort videos by date, title, duration
- ❌ Theater mode (wider video, darker background)
- ❌ Loading spinner while buffering
- ❌ Autoplay next video

## Notes

- Line endings: Use LF (Unix style), not CRLF
- The approved mint for testing is `http://localhost:3338`
- Blossom server runs on port 3000 by default
- Player available at `http://localhost:3000/`
