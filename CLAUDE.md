# Cashu Development Kit (CDK) with Spilman Channels

## Baseline Commits (for diffing)

To see all Spilman channel changes, compare against these pre-channel commits:
- **CDK repo:** `4a505bae` (origin/main)
- **Blossom-server repo:** `5d84316`

Example: `git diff 4a505bae --stat` in cdk repo, `git diff 5d84316 --stat` in blossom-server.

## Project Overview

This is a fork/extension of CDK that adds Spilman-style unidirectional payment channels for Cashu ecash. The primary demo application is **CashuTube** - a pay-per-segment video streaming service built on Blossom (decentralized blob storage).

## Directory Structure

```
cdk/
├── crates/
│   ├── cdk/                        # Main Cashu library
│   │   ├── src/spilman/            # Spilman channel implementation
│   │   └── examples/spilman_channel/  # Example + test helpers
│   └── cdk-wasm/                   # WASM bindings (browser + Node.js)
└── web/
    ├── Makefile                    # WASM build targets
    ├── wasm-web/                   # Browser WASM output (--target web)
    ├── wasm-nodejs/                # Node.js WASM output (--target nodejs)
    └── blossom-server/             # Modified Blossom server + video player
        ├── src/
        │   ├── api/channel.ts      # GET /channel/params + keyset caching
        │   ├── api/videos.ts       # GET /videos (public listing)
        │   ├── api/fetch.ts        # Payment validation + 402 responses
        │   ├── admin-api/videos.ts # POST/DELETE /api/videos (admin)
        │   ├── wasm/               # Node.js WASM (copied from wasm-nodejs/)
        │   └── ...
        ├── public/
        │   ├── index.html          # Video player with payment headers
        │   ├── manifest.json       # PWA manifest (standalone mode)
        │   ├── icon.svg            # Vector logo (Cashu/Tu₿e)
        │   ├── icon-*.png          # App icons (192, 512, apple-touch)
        │   └── wasm/               # Browser WASM (copied from wasm-web/)
        ├── tools/
        │   ├── hls-encode.sh       # Encode video to HLS with hash-based names
        │   ├── hls-upload.sh       # Upload HLS content to Blossom
        │   └── hls-publish.sh      # Combined encode + upload + register
        ├── tests/
        │   ├── blobs.test.ts       # Basic blob operations
        │   ├── channel.test.ts     # Channel params endpoint
        │   ├── minting.test.ts     # Channel funding + DLEQ verification
        │   └── payment.test.ts     # Full payment flow tests
        └── config.example.yml      # Example config with channel settings
```

## Quick Start (Rust)

```bash
# Clone the repo:
git clone git@github.com:SatsAndSports/demo_of_spillman_cashu_channel.git
cd demo_of_spillman_cashu_channel

# Checkout the correct branch:
git checkout spilman.channel

# Run the Spilman-specific tests:
cargo test -p cdk spilman
```

### Where to Start Reading

The tests in `sender_and_receiver.rs`, starting with `test_full_flow`, are the best place to start to see the flow of a channel being opened, payments being made, and the channel being closed.

A typical test does the following:

1. Generate private and public keys for Alice (the sender) and Charlie (the receiver)
2. Set up the test mint and wallets, with configurable fee rate, and collect the KeysetInfo for the relevant keyset
3. Define all the channel parameters in `ChannelParameters`, including the ECDH _shared secret_. The `ChannelParameters` are identical for both parties
4. Alice creates the funding token (via a 'mint' or 'swap' operation)
5. The `SpilmanChannelSender` (for Alice) and `SpilmanChannelReceiver` (for Charlie) objects are set up, containing all the channel data and the relevant private key
6. Alice calls `sender.create_signed_balance_update(charlie_balance)` to create the `BalanceUpdateMessage` containing channel_id, new balance, and signature
7. Charlie calls `receiver.verify_sender_signature(&balance_update)` to reconstruct the commitment transaction and verify Alice's signature
8. Charlie adds his signature with `receiver.add_second_signature(&balance_update, swap_request)`
9. Charlie exits by swapping the funding token
10. The results are _unblinded_ using the deterministic blinding factors
11. The resulting 1-of-1 P2PK outputs are swapped for anyone-can-spend outputs and added to both wallets

### Running with Nutshell

The Blossom server requires a mint to be running.
Follow the exact instructions below to get a compatible mint; in particular with the right `SIG_ALL` support.

In a separate terminal, start a Nutshell mint:

```bash
git clone https://github.com/cashubtc/nutshell.git
cd nutshell

# Check out the tested version:
git checkout 1568e51  # Nutshell version 0.18.2

# Apply the SIG_ALL message update (https://github.com/cashubtc/nuts/pull/302):
sed -ire 's/\[p.secret for p in proofs\] + \[o.B_ for o in outputs\]/[p.secret + p.C for p in proofs] + [str(o.amount) + o.B_ for o in outputs]/' cashu/mint/conditions.py

# Build and run:
docker compose build mint
docker compose up mint
```

### Setting Up Blossom Server

First, clone and set up the blossom-server repo (from the cdk repo root):

```bash
cd web/
git clone git@github.com:SatsAndSports/blossom-server.git
cd blossom-server  # Now in a different git repo
git checkout spilman.channel
```

Build the WASM bindings and copy them to blossom-server:

```bash
(cd .. && make wasm-to-blossom-server)
```

Install dependencies and build:

```bash
npx pnpm install
npx pnpm build
```

### Running Blossom Server Tests

The blossom-server tests require a mint running at localhost:3338 (see "Running with Nutshell" above):

```bash
npm test
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

5. **DLEQ Verification**: Server verifies funding proofs include valid DLEQ proofs from the mint

### P2BK (Pay-to-Blinded-Key) Privacy

The channel uses **blinded pubkeys** in the funding token so the mint cannot correlate channels to real identities.

**Funding Token (2-of-2 multisig):**
- `data` field: Alice's **blinded** pubkey
- `pubkeys` tag: Charlie's **blinded** pubkey
- `refund_keys` tag: Alice's **refund blinded** pubkey (different tweak for unlinkability)
- All signatures use corresponding **blinded secret keys**

**Stage 1 Outputs (after channel close):**
- Receiver proofs: P2PK locked to Charlie's **blinded** pubkey (stage2 context)
- Sender proofs: P2PK locked to Alice's **blinded** pubkey (stage2 context)

**Blinding Derivation:**
```
r = SHA256("Cashu_Spilman_P2BK_v1" || channel_id || shared_secret || context || retry_counter)

If pubkey has even Y:  blinded_pubkey = raw_pubkey + r*G
If pubkey has odd Y:   blinded_pubkey = -raw_pubkey + r*G  (BIP-340 parity handling)

blinded_secret = raw_secret + r  (or -raw_secret + r for odd Y)
```

**Contexts:**
- `"sender_stage1"` - Alice's blinded key for 2-of-2 spending
- `"receiver_stage1"` - Charlie's blinded key for 2-of-2 spending
- `"sender_stage1_refund"` - Alice's refund key (different tweak, unlinkable to 2-of-2)
- `"sender_stage2"` - Alice's blinded key for stage 1 outputs (signs in stage 2)
- `"receiver_stage2"` - Charlie's blinded key for stage 1 outputs (signs in stage 2)

### Core Rust Files

- `spilman/params.rs` - ChannelParameters struct, channel ID derivation, P2BK blinded key derivation
- `spilman/keysets_and_amounts.rs` - Fee calculations, amount decomposition
- `spilman/deterministic.rs` - Deterministic output generation
- `spilman/balance_update.rs` - Balance update messages and signatures
- `spilman/sender_and_receiver.rs` - SpilmanChannelSender, SpilmanChannelReceiver
- `spilman/established_channel.rs` - EstablishedChannel state machine
- `spilman/bindings.rs` - FFI-friendly functions for WASM/PyO3
- `spilman/tests.rs` - Integration tests (2-of-2 spending, refund path with blinded keys against test mint)

### WASM Functions (cdk-wasm)

Key functions exported for browser and Node.js:

- `compute_shared_secret(my_secret_hex, their_pubkey_hex)` - ECDH shared secret
- `channel_parameters_get_channel_id(params_json, shared_secret_hex)` - Derive channel ID
- `create_funding_outputs(params_json, alice_secret_hex, keyset_info_json)` - Create blinded messages for funding
- `construct_proofs(signatures_json, secrets_with_blinding_json, keyset_info_json)` - Unblind mint signatures
- `verify_channel(params_json, shared_secret_hex, funding_proofs_json, keyset_info_json)` - Verify DLEQ proofs on funding proofs
- `verify_balance_update_signature(params_json, shared_secret_hex, funding_proofs_json, channel_id, balance, signature)` - Verify Alice's signature
- `spilman_channel_sender_create_signed_balance_update(params_json, keyset_info_json, alice_secret_hex, proofs_json, balance)` - Create signed balance update
- `create_close_swap_request(...)` - Server-side: create fully-signed swap request for channel closing. Returns `{swap_request, expected_total, secrets_with_blinding}`
- `unblind_and_verify_dleq(blind_signatures_json, secrets_with_blinding_json, params_json, keyset_info_json, shared_secret_hex, balance)` - Unblind stage 1 signatures, verify DLEQ proofs, verify receiver proofs are P2PK locked to Charlie's **blinded** pubkey (stage2 context). Returns `{receiver_proofs, sender_proofs, receiver_sum_after_stage1, sender_sum_after_stage1}`
- `get_sender_blinded_secret_key_for_stage2(params_json, keyset_info_json, alice_secret_hex)` - Get Alice's blinded secret key for signing stage 2 swaps
- `get_receiver_blinded_secret_key_for_stage2(params_json, keyset_info_json, charlie_secret_hex, shared_secret_hex)` - Get Charlie's blinded secret key for signing stage 2 swaps

## CashuTube Video Streaming

### Architecture

```
┌─────────────────┐         ┌─────────────────┐
│  Browser        │         │  Blossom Server │
│  (index.html)   │         │  (Node.js)      │
├─────────────────┤         ├─────────────────┤
│ - HLS.js player │  HTTP   │ - Blob storage  │
│ - WASM (web)    │◄───────►│ - WASM (nodejs) │
│ - Payment HDR   │         │ - Channel API   │
│ - IndexedDB     │         │ - Video registry│
│ - YouTube layout│         │                 │
└─────────────────┘         └─────────────────┘
```

**Layout:** YouTube-style side-by-side (video left ~70%, scrollable video list right 320px). Responsive: stacks vertically on mobile (≤900px).

### Payment Flow

1. Player fetches `/channel/params` to get Charlie's pubkey
2. Player creates and funds a channel (stored in IndexedDB)
3. For each segment request, player adds `X-Cashu-Channel` header containing:
   - `channel_id` - identifies the channel
   - `balance` - current balance (increments each segment)
   - `signature` - Alice's Schnorr signature over the balance update
   - `params` - full channel parameters (can be sent on any request, cached by server)
   - `funding_proofs` - funding token proofs with DLEQ (can be sent on any request, cached by server)
4. Server validates payment and returns 402 if invalid, or 200 with confirmation header

### Client-Side Payment Tracking

The player tracks actual bytes served to avoid overpayment:

1. **Pessimistic pre-payment**: Before each request, adds `globalMaxBlobSize` to tracked bytes
2. **Post-response correction**: After 200 response, subtracts overage using actual `size` from response header
3. **Balance calculation**: `balance = f(count, bytes)` using same pricing formula as server

**Channel Exhaustion:**
- When next payment would exceed capacity, `createPayment()` throws
- Video is paused automatically
- Red toast notification shown: "Channel exhausted - video paused"

### Server-Side Payment Validation

The server's `validatePayment()` function in `src/api/fetch.ts` performs these checks in order:

1. **Header parsing**: Parse JSON from `X-Cashu-Channel` header
2. **Required fields**: Check `channel_id` (string), `balance` (number, not NaN), `signature` (string)
3. **If params + funding_proofs provided**:
   - Verify server has a secret key configured
   - Compute shared secret via ECDH
   - Verify channel_id matches computed value from params
   - Check keyset is from an approved mint (cached at startup)
   - Run full channel verification (DLEQ proofs, keyset ID match) via WASM
   - Cache funding data in `channelFunding` store
4. **Look up cached funding** (from step 3 or previous request)
5. **Verify signature** using cached params and shared secret via WASM
6. **Check balance** covers usage:
   - Look up existing usage (blobs served, bytes served)
   - Compute amount due based on pricing (per-request + per-megabyte)
   - Return 402 if balance < amount_due

### Server-Side Data Stores (In-Memory)

Four separate stores for channel state:

1. **`channelFunding`** (immutable after insert):
   - `paramsJson` - serialized channel parameters
   - `fundingProofsJson` - serialized funding proofs
   - `sharedSecret` - ECDH shared secret (hex)
   - `secretKey` - server's secret key (for channel closure)
   - `keysetInfoJson` - serialized keyset info (for unblinding)

2. **`channelBalance`** (updated on each payment):
   - `balance` - highest balance seen
   - `signature` - signature for that balance (for channel closure)

3. **`channelUsage`** (updated after successful validation):
   - `blobsServed` - count of blobs served
   - `bytesServed` - total bytes served

4. **`channelClosed`** (set when channel is closed):
   - `locktime` - channel locktime (for future: allow reuse after expiry)
   - `closedAmount` - the balance at which channel was closed
   - `valueAfterStage1` - total value of stage 1 proofs

### Client-Side Data Stores

**IndexedDB** (`cashu_channels`, version 6):

| Store | Key | Schema |
|-------|-----|--------|
| `channels` | `channel_id` | `{ channel_id, sender_json, alice_secret, charlie_pubkey, server_url, mint, status, closing_amount_due? }` |
| `request_counts` | `channel_id` | `{ channel_id, count, bytes }` |
| `video_positions` | `master_hash` | `{ master_hash, position, timestamp }` |

**localStorage:**
- `cashu_alice_secret` - Alice's private key (hex)
- `cashutube_server_unit` - Last selected server + unit (JSON)

**In-Memory:**
- `channelRequestCounts` - Map<channel_id, {count, bytes}>
- `serverInfo` - Cached server params (fetched once on page load)
- `blobUrlCache` - Map<hash, objectURL>
- `channelsSentParams` - Set<channel_id> (tracks which channels have sent full params)

### 402 Payment Required Response

When payment validation fails, server returns:
- Status: 402
- Header: `X-Cashu-Channel: {"error": "...", "size": N, ...}`
- Body: `{"error": "Payment required", "reason": "...", ...}`

Error types:
- `missing` - no X-Cashu-Channel header
- `invalid JSON` - header not valid JSON
- `invalid or missing channel_id/balance/signature` - required field issues
- `server misconfigured` - no secret key configured
- `channel_id mismatch` - computed ID doesn't match provided
- `capacity too small` - channel capacity below server's minCapacity for that unit (includes `capacity` and `min_capacity`)
- `locktime too soon` - channel locktime doesn't leave enough time before expiry (includes `locktime`, `min_expiry_in_seconds`, `seconds_remaining`)
- `keyset not from approved mint` - keyset not cached at startup
- `channel validation failed` - DLEQ verification failed (includes `validation_errors`)
- `unknown channel` - no cached funding and no params/funding_proofs provided
- `invalid signature` - Alice's signature doesn't verify
- `insufficient balance` - balance < amount_due (includes `amount_due`)
- `unsupported unit` - no pricing configured for channel's unit
- `channel closed` - channel has already been closed, use a different channel

### 200 OK Response Header

On successful blob fetch, server returns confirmation header:
- Header: `X-Cashu-Channel: {"channel_id": "...", "balance": N, "amount_due": N, "capacity": N, "size": N}`

Fields:
- `channel_id` - the channel used
- `balance` - what client sent
- `amount_due` - what server actually charged
- `capacity` - channel capacity
- `size` - actual blob size in bytes (for client-side byte correction)

### Channel Closing Flow

When a client wants to close a channel, the server performs a "stage 1" swap with the mint:

```
Client                          Server                          Mint
   |                               |                               |
   |  POST /channel/:id/close      |                               |
   |  {balance, signature,         |                               |
   |   params?, funding_proofs?}   |                               |
   |------------------------------>|                               |
   |                               |                               |
   |                    1. Validate signature                      |
   |                    2. Verify balance === amount_due           |
   |                    3. Create swap request (WASM)              |
   |                       - 2-of-2 signed (Alice + Charlie)       |
   |                       - Outputs: P2PK to Charlie + Alice      |
   |                               |                               |
   |                               |  POST /v1/swap                |
   |                               |  {inputs: funding_proofs,     |
   |                               |   outputs: commitment_outputs}|
   |                               |------------------------------>|
   |                               |                               |
   |                               |  {signatures: blind_sigs}     |
   |                               |<------------------------------|
   |                               |                               |
   |                    4. Unblind signatures (WASM)               |
   |                    5. Verify DLEQ on all proofs               |
   |                    6. Verify receiver proofs P2PK             |
   |                       locked to Charlie's pubkey              |
   |                    7. Mark channel as closed                  |
   |                               |                               |
   |  {success, total_value}       |                               |
   |<------------------------------|                               |
```

**Stage 1 outputs:**
- **Receiver proofs (Charlie)**: P2PK locked to Charlie's blinded pubkey (stage2) - he can spend them with his blinded secret key
- **Sender proofs (Alice)**: P2PK locked to Alice's blinded pubkey (stage2) - her "change"

**Verifications performed:**
1. Alice's balance update signature is valid
2. Balance equals amount_due (exact match required)
3. DLEQ proofs valid on all unblinded proofs (mint actually signed them)
4. Receiver proofs are P2PK secrets with `data` = Charlie's **blinded** pubkey (stage2 context)
5. Receiver nominal sum matches `inverse_deterministic_value_after_fees(balance)`

**Idempotent closing:**
- If channel already closed with same amount → returns success with `already_closed: true`
- If channel already closed with different amount → returns 400 error
- Closed channels reject all further payments with "channel closed" error

**Future work (Stage 2):**
Charlie's proofs are P2PK-locked to his key. A stage 2 swap would convert them to anyone-can-spend proofs. Currently not implemented - Charlie can spend the P2PK proofs directly by signing.

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
- Outputs per-quality stats in `quality_stats.json` for cost estimation

### Server Configuration

Add to `config.yml`:

```yaml
channel:
  enabled: true
  secretKey: "your-64-char-hex-secret-key"  # Charlie's private key
  approvedMintsAndUnits:
    http://localhost:3338:
      - sat
      - usd
  # Per-unit pricing (ppk = parts per thousand)
  # cost = ceil((requests * perRequestPpk + megabytes * perMegabytePpk) / 1000)
  # Note: megabytes = bytes / 1,000,000 (not mebibytes)
  pricing:
    sat:
      perRequestPpk: 500    # 0.5 sats per request
      perMegabytePpk: 1000  # 1 sat per MB
      minCapacity: 100      # minimum channel capacity in sats
    usd:
      perRequestPpk: 100    # 0.1 cents per request
      perMegabytePpk: 200   # 0.2 cents per MB
      minCapacity: 10       # minimum channel capacity in cents
  # minimum locktime in seconds (1 hour = 3600)
  minExpiryInSeconds: 3600
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
  max_blob_size INTEGER,   -- Size of largest blob in bytes
  quality_stats TEXT       -- JSON with per-quality blob stats for cost estimation
)
```

### API Endpoints

**Public:**
- `GET /channel/params` - Returns receiver pubkey, pricing (ppk + minCapacity per unit), min_expiry_in_seconds, approved mints/units/keysets
- `GET /channel/:channel_id/status` - Returns channel status (capacity, balance, usage, amount_due, closed, closed_amount)
- `POST /channel/:channel_id/close` - Close channel and settle with mint
  - Body: `{ balance, signature, params?, funding_proofs? }`
  - Requires `balance === amount_due` (exact match)
  - Idempotent: same amount returns success with `already_closed: true`
  - Different amount on closed channel returns 400 error
  - Returns: `{ success, channel_id, total_value, already_closed }`
- `GET /videos` - List registered videos (includes preview_hash, sprite_meta_hash, width, height, blob stats)
- `GET /<sha256>` - Fetch blob (requires X-Cashu-Channel header if channel.enabled)
- `HEAD /<sha256>` - Check blob exists (no payment required)
- `GET /channel/stats?window=N` - Returns count of active channels in last N seconds (default 300)

**Admin (basic auth):**
- `POST /api/videos` - Register video `{title, master_hash, duration, description?, source?, preview_hash?, sprite_meta_hash?, width?, height?, blob_count?, total_size?, max_blob_size?, quality_stats?}`
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
# CDK Rust tests
cargo test -p cdk
cargo test -p cdk spilman  # Spilman-specific (includes mint integration tests for P2BK)

# Blossom server tests (requires mint at localhost:3338)
cd web/blossom-server
npm test                    # All tests
npm test -- tests/payment.test.ts  # Specific file
```

The test suite includes:
- **blobs.test.ts**: Upload, fetch (402), HEAD, 404 cases
- **channel.test.ts**: `/channel/params` endpoint
- **minting.test.ts**: Funding token creation, DLEQ verification, keyset tampering detection
- **payment.test.ts**: Full payment flow, 402→200 transition, tampered DLEQ rejection, capacity validation, locktime validation, channel closing, idempotent close, closed channel rejection

## Current Status

**Working:**
- ✅ Video player with HLS.js and quality selector
- ✅ Payment headers sent with each segment request
- ✅ Channel ID computed and verified (WASM on both client and server)
- ✅ Real Schnorr signatures from Alice
- ✅ Signature verification on server (via WASM)
- ✅ DLEQ proof verification (detects tampered funding proofs)
- ✅ Keyset validation (only approved mints accepted)
- ✅ Server caches channel params and funding proofs
- ✅ 402 responses with detailed error info
- ✅ Balance checking against usage (requests + megabytes)
- ✅ Video registration and listing via Blossom
- ✅ HLS encoding tools with hash-based naming
- ✅ Adaptive quality encoding (matches source resolution)
- ✅ HDR to SDR conversion for browser compatibility
- ✅ Direct video linking via URL hash (#master_hash)
- ✅ Multi-server/multi-unit support with (server, unit) dropdown
- ✅ Per-unit pricing (sat, usd, eur, etc.)
- ✅ Per-quality cost estimation displayed in video cards
- ✅ Channels stored in IndexedDB with alice_secret and server_url
- ✅ View counting for videos
- ✅ Resolution and blob stats displayed in video list
- ✅ Comprehensive test suite for payment flow
- ✅ Channel closure and settlement (server closes, submits swap to mint)
- ✅ Stage 1 unblinding with DLEQ verification
- ✅ Receiver proof P2PK pubkey verification (ensures proofs are locked to Charlie)
- ✅ Idempotent channel closing (same amount succeeds, different amount rejected)
- ✅ Closed channels reject further payments
- ✅ P2BK (Pay-to-Blinded-Key) privacy for funding tokens
- ✅ Separate blinding tweak for refund path (unlinkable to 2-of-2 path)
- ✅ Integration tests verifying blinded signatures accepted by mint
- ✅ 200 response with payment confirmation header (channel_id, balance, amount_due, capacity, size)
- ✅ Client-side byte tracking with post-response correction
- ✅ Channel exhaustion handling (pauses video, shows toast, opens channel manager)
- ✅ YouTube-style side-by-side layout (video left, list right)
- ✅ Per-unit minimum capacity enforcement (server rejects channels below minCapacity)
- ✅ Minimum expiry enforcement (server rejects channels with locktime too soon)
- ✅ Server logs every 402 response with full header JSON (`paymentError()` helper in `fetch.ts`)
- ✅ `msat` unit test coverage (20-payment loop test with channel close)
- ✅ Improved client-side payment logging: `[Payment] #N | X.X MB | bal: N/N unit | chan: abc123...`
- ✅ Fixed sprite animation sizing on video card hover (uses `spriteMeta.thumb_width/height`)
- ✅ Channel list sorted by setup_timestamp (most recent first)
- ✅ Refresh button on open channels (sync request counts with server)
- ✅ `closing_amount_due` saved to IndexedDB on channel close
- ✅ Reset Identity button in channel modal (with confirmation)
- ✅ First-time user onboarding tooltips
- ✅ Thumbnail preloading when channel connects (in-view)
- ✅ Active viewers count in header (polls /channel/stats every 5 seconds)
- ✅ YouTube-style tap controls (double-tap sides = ±10s skip, double-tap middle = pause/play, single tap only pauses when overlays already visible)
- ✅ Touch scroll detection (prevents accidental pause/skip when scrolling on mobile)
- ✅ Overlay-gated controls with tap-unlock delay (prevents hidden control taps on mobile)
- ✅ Simplified page scrolling (removed nested scroll containers and auto-scroll logic)
- ✅ Fixed wide-screen layout grid bug
- ✅ Video player sizing: max-height 562.5px (via CSS variable), flexible aspect ratio
- ✅ Dynamic sticky player positioning (Broad: fit bottom edge, Narrow: max 50% screen height)
- ✅ Centered video content with pillarboxing for non-16:9 videos
- ✅ PWA support (manifest.json, add-to-home-screen, Cashu/Tu₿e logo icons, service worker with update prompt)
- ✅ Collapsible Log section at page bottom (hidden by default, toggle in channel modal)
- ✅ Channel status moved to header bar (clickable to manage channels, shows server/id/balance)
- ✅ Balance display in video player clickable to manage channels (exits fullscreen if active)
- ✅ Consolidated management: "Manage Channels" button removed, integrated into status bar
- ✅ Improved "Close" button feedback (dimmed card, immediate toast, blocked for active channel)
- ✅ Auto-scroll video into view when starting playback (if not fully visible)
- ✅ Version display toast on "active" viewers count label tap
- ✅ Handle "unused" channel status ( server 404 -> blue theme)
- ✅ Server pricing summary displayed in channel management modal
- ✅ Conditional header balance display (appears only when <10% capacity and no alternatives remain)
- ✅ Highlight low funds with red pill badge in header
- ✅ Detect autoplay failure and show persistent controls hint until interaction
- ✅ Improved action indicator centering (flash triangle) using robust Inset + Auto-Margin CSS
- ✅ Removed redundant #play-overlay from video player DOM

**TODO - Payments:**
- ❌ Server-side token storage after close (Charlie should keep the proofs)
- ❌ Server-side balance persistence (currently in-memory only)
- ❌ Client-side top-up prompts (byte tracking works, needs UI)
- ✅ Proper modal to pay the minting invoice (QR code + copy button)
- ✅ Update list of alternative channels after creating a new channel
- ❌ **Keyset rotation issue**: When `initializeChannelKeysets()` refreshes, deactivated keysets are removed from cache. Existing channels using those keysets will fail validation even though the mint may still honor them. Possible solutions:
  - Keep old keysets in cache indefinitely (memory concerns?)
  - Only remove keysets that have no active channels using them
  - Store keyset info per-channel in `channelFunding` rather than global cache
  - Query mint on-demand for unknown keysets (adds latency)
- ❌ 'correct' the player's 200-payment by checking Content-Length, not our special header, as we want this to work in caching contexts too
- ❌ player to send the funding params and token on every request, until we get some confirmation from the server that it understands the channel, via the server's X-Cashu-Channel response. player to start sending it again when there is a 402

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
- ✅ Playback speed control (0.5x, 1x, 1.25x, 1.5x, 2x)
- ✅ Display video title when playing
- ✅ Remember playback position (resume where left off)
- ✅ Auto-play hash video after channel modal close (when placeholder visible)
- ✅ Fixed race conditions in progress preview during video switches
- ✅ Bandwidth memory across videos and sessions
- ✅ Fast-start HLS settings (reduced buffer, player-size capping)
- ✅ Autoplay failure detection with persistent overlay hint
- ✅ Robust centering for action indicator (flash icon) across mobile/desktop

*High Priority:*
- ❌ Highlight currently playing video in list
- ✅ different play/pause/top/click behaviour depending on whetether the 'player overlay' is visible
- ✅ get rid of the video popout, instead, ensure any below-video content isn't too big
- ✅ 'share' button looks much better
- ✅ un-fullscreen icon is ugly
- ❌ ?still getting the blank video while the sound is playing?
- ✅ refresh remembers the currently selected server
- ✅ Loading spinner while buffering and during initial load (layout-stable 16/9 box)


*Medium Priority:*
- ✅ Remember quality preference in localStorage
- ❌ Remember volume preference in localStorage
- ❌ Loop toggle
- ✅ Picture-in-picture (superseded by popout mini-player)
- ❌ Video description panel (expandable)
- ❌ Ctrl+Shift+M and mute?

*Lower Priority:*
- ✅ drop the volume controls on mobile (detected via coarse pointer)
- ✅ Version display toast on "active" viewers count label tap

## Notes

- Line endings: Use LF (Unix style), not CRLF
- The approved mint for testing is `http://localhost:3338`
- Blossom server runs on port 3000 by default
- Player available at `http://localhost:3000/`
- Makefile is at `web/Makefile` (in the 'web' subdirectory of main 'cdk' folder)
- Tests run on port 3099 with a separate test config
