# TypeScript ASCII Art - Spilman Payment Channel Demo

This example demonstrates Spilman unidirectional payment channels using TypeScript/Node.js with the CDK WASM bindings.

## Overview

- **Server**: Express-based HTTP server that generates ASCII art for 1 sat per character
- **Client**: Creates a payment channel, makes paid requests, and closes the channel

## Prerequisites

1. Build the WASM bindings (from repo root):
   ```bash
   make build-wasm
   ```

2. Have a Cashu mint running (default: `http://localhost:3338`):
   ```bash
   # Option 1: Use CDK development mint
   make run-mint-cdk
   
   # Option 2: Use any compatible mint
   MINT_URL=http://your-mint:3338 npm run server
   ```

## Quick Start

```bash
# Install dependencies
npm install

# Terminal 1: Start the server
npm run server

# Terminal 2: Run the client
npm run client Hello World Cashu
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `SERVER_URL` | `http://localhost:5002` | ASCII art server URL |
| `PORT` | `5002` | Server listen port |
| `SERVER_SECRET_KEY` | Random | Server's 32-byte secret key (hex) |

## API Endpoints

### `GET /channel/params`

Returns server configuration for channel setup.

```json
{
  "receiver_pubkey": "02abc...",
  "pricing": { "sat": { "per_char": 1, "minCapacity": 10 } },
  "mint": "http://localhost:3338",
  "min_expiry_in_seconds": 3600
}
```

### `POST /ascii`

Generate ASCII art. Requires `X-Cashu-Channel` header with base64-encoded payment.

**Request:**
```
POST /ascii
Content-Type: application/json
X-Cashu-Channel: base64({"channel_id": "...", "balance": 5, "signature": "...", ...})

{"message": "Hello"}
```

**Response (200 OK):**
```json
{
  "art": "  _   _      _ _       \n | | | | ___| | | ___  \n ...",
  "message": "Hello",
  "cost": 5,
  "payment": { "channel_id": "...", "balance": 5, "capacity": 50 }
}
```

### `GET /channel/:id/status`

Get channel status and amount due.

```json
{
  "channel_id": "abc123...",
  "capacity": 50,
  "balance": 15,
  "chars_served": 15,
  "amount_due": 15,
  "closed": false
}
```

### `POST /channel/:id/close`

Close channel cooperatively. Client sends final balance and signature.

**Request:**
```json
{ "balance": 15, "signature": "schnorr_sig_hex" }
```

**Response:**
```json
{
  "success": true,
  "channel_id": "abc123...",
  "total_value": 50,
  "sender_proofs": [...],
  "already_closed": false
}
```

## Payment Flow

1. **Setup**: Client fetches `/channel/params` and generates keypair
2. **Fund**: Client mints tokens locked to channel (ECDH-derived secret)
3. **Pay**: Each request includes incrementing balance + Schnorr signature
4. **Close**: Client calls `/channel/:id/close` with final balance, gets change proofs

## File Structure

```
examples/ts-ascii-art/
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── src/
│   ├── index.ts          # CLI entry point
│   ├── server.ts         # Express server + SpilmanHost
│   ├── client.ts         # Channel funding and payments
│   ├── stores.ts         # In-memory channel state
│   └── wasm/             # Symlink to WASM bindings
├── tests/
│   └── integration.test.ts  # Vitest integration tests
└── README.md
```

## Testing

Run the automated demo test:

```bash
# From repo root
make test-demo-ts
```

This starts a temporary mint, runs the server, and executes 3 parallel clients.
