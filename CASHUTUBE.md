# CashuTube

CashuTube is a pay-per-segment video streaming demo built on Spilman channels. It demonstrates how to monetize content delivery using Cashu ecash micropayments.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│  Browser        │         │  Blossom Server │
│  (index.html)   │         │  (Node.js)      │
├─────────────────┤         ├─────────────────┤
│ - HLS.js player │  HTTP   │ - Blob storage  │
│ - WASM (web)    │◄───────►│ - WASM (nodejs) │
│ - Payment HDR   │         │ - Channel API   │
│ - IndexedDB     │         │ - Video registry│
└─────────────────┘         └─────────────────┘
```

**Layout**: YouTube-style side-by-side (video left ~70%, scrollable video list right 320px). Responsive: stacks vertically on mobile (≤900px).

## Payment Flow

### 1. Channel Setup

```
Player                              Server
  |  GET /channel/params              |
  |---------------------------------->|
  |  {receiver_pubkey, pricing, ...}  |
  |<----------------------------------|
  |                                   |
  |  [Create channel via WASM]        |
  |  [Fund channel at mint]           |
  |  [Store in IndexedDB]             |
```

### 2. Segment Requests

For each HLS segment, the player adds an `X-Cashu-Channel` header:

```json
{
  "channel_id": "abc123...",
  "balance": 150,
  "signature": "schnorr_sig_hex",
  "params": { ... },           // Optional, cached by server
  "funding_proofs": [ ... ]    // Optional, cached by server
}
```

### 3. Server Validation

The server validates payments in order:

1. Parse JSON from `X-Cashu-Channel` header
2. Check required fields: `channel_id`, `balance`, `signature`
3. If `params` + `funding_proofs` provided:
   - Verify DLEQ proofs via WASM
   - Check keyset is from approved mint
   - Cache funding data
4. Look up cached funding
5. Verify Schnorr signature
6. Check `balance >= amount_due`
7. Record payment atomically

### 4. Pricing Formula

```
cost = ceil((requests * perRequestPpk + megabytes * perMegabytePpk) / 1000)
```

Where `megabytes = bytes / 1,000,000` (decimal, not binary).

## Server Configuration

Add to `config.yml`:

```yaml
channel:
  enabled: true
  secretKey: "your-64-char-hex-secret-key"  # Charlie's private key
  approvedMintsAndUnits:
    http://localhost:3338:
      - sat
      - usd
  pricing:
    sat:
      perRequestPpk: 500    # 0.5 sats per request
      perMegabytePpk: 1000  # 1 sat per MB
      minCapacity: 100      # minimum channel capacity
    usd:
      perRequestPpk: 100    # 0.1 cents per request
      perMegabytePpk: 200   # 0.2 cents per MB
      minCapacity: 10
  minExpiryInSeconds: 3600  # 1 hour minimum locktime
```

## API Endpoints

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /channel/params` | Returns receiver pubkey, pricing, approved mints/keysets |
| `GET /channel/:id/status` | Returns channel capacity, balance, usage, amount_due |
| `POST /channel/:id/close` | Close channel and settle with mint |
| `GET /channel/stats?window=N` | Count of active channels in last N seconds |
| `GET /videos` | List registered videos with metadata |
| `GET /<sha256>` | Fetch blob (requires payment header) |
| `HEAD /<sha256>` | Check blob exists (no payment required) |

### Admin Endpoints (Basic Auth)

| Endpoint | Description |
|----------|-------------|
| `POST /api/videos` | Register a video |
| `DELETE /api/videos/:id` | Remove a video |

### Video Registration

```json
POST /api/videos
{
  "title": "My Video",
  "master_hash": "abc123...",
  "duration": 300,
  "description": "Optional description",
  "preview_hash": "def456...",
  "sprite_meta_hash": "ghi789...",
  "width": 1920,
  "height": 1080,
  "blob_count": 150,
  "total_size": 52428800,
  "max_blob_size": 2097152,
  "quality_stats": "{...}"
}
```

## Response Headers

### 402 Payment Required

```json
{
  "error": "insufficient balance",
  "amount_due": 150,
  "size": 524288
}
```

Error types:
- `missing` - no X-Cashu-Channel header
- `invalid JSON` - malformed header
- `channel_id mismatch` - computed ID doesn't match
- `capacity too small` - below minCapacity
- `locktime too soon` - insufficient time before expiry
- `keyset not from approved mint`
- `channel validation failed` - DLEQ verification failed
- `unknown channel` - no cached funding
- `invalid signature`
- `insufficient balance`
- `channel closed`

### 200 OK Confirmation

```json
{
  "channel_id": "abc123...",
  "balance": 150,
  "amount_due": 145,
  "capacity": 1000,
  "size": 524288
}
```

## Data Stores

### Server-Side (In-Memory)

| Store | Key | Fields |
|-------|-----|--------|
| `channelFunding` | channel_id | paramsJson, fundingProofsJson, sharedSecret, keysetInfoJson |
| `channelBalance` | channel_id | balance, signature |
| `channelUsage` | channel_id | blobsServed, bytesServed |
| `channelClosed` | channel_id | locktime, closedAmount, valueAfterStage1, receiverProofsJson |

### Client-Side (IndexedDB)

Database: `cashu_channels`, version 6

| Store | Key | Fields |
|-------|-----|--------|
| `channels` | channel_id | sender_json, alice_secret, charlie_pubkey, server_url, mint, status |
| `request_counts` | channel_id | count, bytes |
| `video_positions` | master_hash | position, timestamp |

### Client-Side (localStorage)

- `cashu_alice_secret` - Alice's private key (hex)
- `cashutube_server_unit` - Last selected server + unit

## Video Database Schema

```sql
CREATE TABLE videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  master_hash TEXT NOT NULL,
  duration INTEGER NOT NULL,
  uploaded INTEGER NOT NULL,
  description TEXT,
  source TEXT,
  preview_hash TEXT,
  sprite_meta_hash TEXT,
  views INTEGER DEFAULT 0,
  width INTEGER,
  height INTEGER,
  blob_count INTEGER,
  total_size INTEGER,
  max_blob_size INTEGER,
  quality_stats TEXT
);
```

## HLS Encoding Tools

Blossom stores blobs by SHA256 hash (content-addressed). The HLS tools create hash-based playlists.

### Encoding

```bash
# Encode video to multiple qualities
./tools/hls-encode.sh /path/to/video.mp4
```

The encoder:
- Detects source height, only encodes qualities at or below it
- Caps at 1080p for H.264 level 4.1 browser compatibility
- Converts 10-bit HDR to 8-bit SDR
- Generates `preview.jpg` thumbnail
- Generates `sprite.jpg` sprite sheet for scrubbing
- Outputs blob stats for cost estimation

### Uploading

```bash
# Upload to Blossom and register
BLOSSOM_ADMIN_PASS=xxx ./tools/hls-upload.sh http://localhost:3000 "Video Title"

# Or encode + upload in one step
BLOSSOM_ADMIN_PASS=xxx ./tools/hls-publish.sh http://localhost:3000 /path/to/video.mp4 "Video Title"
```

## Channel Closing

When closing a channel, the server performs a swap with the mint:

```
Client                          Server                          Mint
   |  POST /channel/:id/close      |                               |
   |  {balance, signature}         |                               |
   |------------------------------>|                               |
   |                               |                               |
   |                    [Verify balance == amount_due]             |
   |                    [Create 2-of-2 signed swap]                |
   |                               |                               |
   |                               |  POST /v1/swap                |
   |                               |------------------------------>|
   |                               |  {signatures}                 |
   |                               |<------------------------------|
   |                               |                               |
   |                    [Unblind, verify DLEQ]                     |
   |                    [Store receiver proofs]                    |
   |                               |                               |
   |  {success, sender_proofs}     |                               |
   |<------------------------------|                               |
```

The close endpoint is idempotent:
- Same amount: returns `{success: true, already_closed: true}`
- Different amount: returns 400 error

## Player URL Format

Direct link to videos using URL fragment:

```
http://localhost:3000/#<master_hash>
http://localhost:3000/#<master_hash>&t=90      # Start at 90 seconds
http://localhost:3000/#<master_hash>&t=1m30s   # Start at 1:30
```

## HLS.js Integration Note

When using HLS.js `xhrSetup` to add custom headers, call `xhr.open()` before `xhr.setRequestHeader()`:

```javascript
xhrSetup: function(xhr, url) {
    if (xhr.readyState === XMLHttpRequest.UNSENT) {
        xhr.open('GET', url, true);
    }
    xhr.setRequestHeader('X-Cashu-Channel', paymentHeader);
}
```

The XHR starts in `UNSENT` state (readyState=0), and `setRequestHeader` only works after `open()`.
