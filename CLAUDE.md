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
        │   ├── player.html         # Video player with payment headers
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
2. Player creates a channel (stored in IndexedDB)
3. For each segment request, player adds `X-Cashu-Channel` header containing:
   - `channel_id` - identifies the channel
   - `balance` - current balance (increments each segment)
   - `signature` - Schnorr signature (TODO: currently zeros)
   - `params` - full channel parameters
4. Server verifies channel_id matches computed value
5. Server verifies signature (TODO: not yet implemented)

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
- Creates 5 quality levels (1080p, 720p, 480p, 360p, 240p)
- Rewrites playlists to reference segments by SHA256 hash (no extensions)
- Creates `hashed/` directory with symlinks for easy Blossom upload

### Server Configuration

Add to `config.yml`:

```yaml
channel:
  enabled: true
  secretKey: "your-64-char-hex-secret-key"  # Charlie's private key
  approvedMints:
    - http://localhost:3338
  pricePerSegment: 1
```

### API Endpoints

**Public:**
- `GET /channel/params` - Returns receiver pubkey, approved mints, price
- `GET /videos` - List registered videos (title, master_hash, duration)
- `GET /<sha256>` - Fetch blob (accepts X-Cashu-Channel header)

**Admin (basic auth):**
- `POST /api/videos` - Register video `{title, master_hash, duration}`
- `DELETE /api/videos/:title` - Remove video

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
- ✅ Video registration and listing via Blossom
- ✅ HLS encoding tools with hash-based naming

**TODO:**
- ❌ Real Schnorr signatures (currently fake zeros)
- ❌ Signature verification on server
- ❌ Payment enforcement (402 responses)
- ❌ Actual channel funding with Cashu tokens
- ❌ Channel closure and settlement

## Notes

- Line endings: Use LF (Unix style), not CRLF
- The approved mint for testing is `http://localhost:3338`
- Blossom server runs on port 3000 by default
- Player available at `http://localhost:3000/player.html`
