# CDK WASM Bindings

WASM bindings for Spilman payment channels, compiled from the core Rust implementation. Usable from TypeScript and JavaScript in both Node.js and browser environments.

## Installation

```bash
npm install cdk-wasm
```

## Usage

### Server-Side: SpilmanBridge

The `SpilmanBridge` handles payment validation and channel registration. It delegates storage and policy to a "host" object you provide.

```javascript
import * as wasm from "cdk-wasm";

// 1. Initialize WASM
await wasm.default();

// 2. Implement the required host hooks
class MyHost {
  get_amount_due(channel_id, context) { ... }
  save_funding(channel_id, funding, payment) { ... }
  // ... see Architecture docs for full list
}

// 3. Create the bridge
const bridge = new wasm.WasmSpilmanBridge(new MyHost());

// 4. Process a payment
try {
  const result = bridge.processPayment(paymentJson, contextJson);
  console.log("Payment accepted. New balance:", result.balance);
} catch (e) {
  console.error(e.status, e.reason); // Structured error object
}
```

### Client-Side: Setup

```javascript
// Compute `_channel secret_` with receiver
const sharedSecret = wasm.compute_channel_secret(senderSecret, receiverPubkey);

// Create funding outputs for minting
const funding = wasm.create_funding_outputs(paramsJson, senderSecret, keysetJson);

// Sign a payment
const payment = wasm.spilman_channel_sender_create_signed_balance_update(
  paramsJson, keysetJson, senderSecret, proofsJson, balance
);
```

## API Reference

### Classes
- `WasmSpilmanBridge` - Main bridge for server-side payment validation

### Core Functions
- `compute_channel_secret(secret, pubkey)` - Derive `_channel secret_`
- `verify_channel(params, proofs, keyset)` - Validate channel funding
- `spilman_channel_sender_create_signed_balance_update(...)` - Sign a payment

## Error Handling

Errors thrown by the bridge are structured objects:

```json
{
  "error": "Payment required",
  "reason": "insufficient balance",
  "status": 402,
  "code": "insufficient_balance",
  "extra": { "balance": 10, "amount_due": 20 }
}
```

## Build Outputs

- `web/wasm-nodejs/` - WASM build output (copied to TS integration kit by `make build-wasm`)
