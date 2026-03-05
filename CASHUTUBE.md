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

For each HLS segment, the player adds an `X-Cashu-Channel` header with **base64-encoded JSON**:

```javascript
const payment = {
  channel_id: "abc123...",
  balance: 150,
  signature: "schnorr_sig_hex",
  params: { ... },           // Optional: only on first request
  funding_proofs: [ ... ]    // Optional: only on first request
};
headers["X-Cashu-Channel"] = btoa(JSON.stringify(payment));
```

### 3. Server Validation

The server validates payments in order:

1. Decode base64 and parse JSON from `X-Cashu-Channel` header
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
cost = ceil((blobs * price.blobs + bytes * price.bytes) / pricing_scale)
```

Both usage counters and price values are integers. Use `pricing_scale` to express fractional prices without floats.

## Server Configuration

Add to `config.yml`:

```yaml
channel:
  enabled: true
```

Create `channel-config.yml`:

```yaml
enabled: true
secretKey: "your-64-char-hex-secret-key"  # Charlie's private key
mints:
  http://localhost:3338: [sat, usd]
min_expiry_seconds: 3600
pricing_scale: 1000
pricing:
  sat:
    min_capacity: 100
    variables: { blobs: 500, bytes: 10 }
  usd:
    min_capacity: 10
    variables: { blobs: 100, bytes: 2 }
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /channel/params` | Returns receiver pubkey, pricing, and mint info |
| `GET /channel/:id/status` | Returns channel capacity, balance, and usage |
| `POST /channel/:id/close` | Cooperative close |
| `POST /channel/:id/unilateral-close` | Server-initiated unilateral close |
| `GET /videos` | List registered videos with metadata |
| `GET /<sha256>` | Fetch blob (requires payment header) |

## Data Stores

### Server-Side (In-Memory Reference)

| Store | Purpose |
|-------|---------|
| `channelFunding` | params, funding proofs, `_channel secret_` |
| `channelBalance` | latest balance and signature |
| `channelUsage` | blobs and bytes served |
| `channelClosed` | final proofs and amounts |

---

## HLS Encoding

The server uses content-addressed storage (BLOBs) for HLS segments. The HLS tools create hash-based playlists.

```bash
# Encode video to multiple qualities
./tools/hls-encode.sh /path/to/video.mp4

# Upload and register
BLOSSOM_ADMIN_PASS=xxx ./tools/hls-publish.sh http://localhost:3000 /path/to/video.mp4 "Video Title"
```
