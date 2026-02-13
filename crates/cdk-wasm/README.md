# CDK WASM Bindings

WASM bindings for Spilman payment channels, usable from TypeScript/JavaScript in both Node.js and browser environments.

## Installation

### Building from Source (requires Rust + wasm-pack)

```bash
# Using the Makefile
make build

# Or manually
wasm-pack build --target nodejs --out-dir ../../web/wasm-nodejs
wasm-pack build --target web --out-dir ../../web/wasm-web
```

### From npm (coming soon)

```bash
npm install @cashu/cdk-wasm
```

## Usage

### Server-Side (Node.js)

```typescript
import * as wasm from "./wasm/cdk_wasm.js";

// Initialize WASM
await wasm.default();

// Create bridge for payment validation
class MyHost {
  // Implement SpilmanHost methods
}
const bridge = new wasm.WasmSpilmanBridge(new MyHost(), serverSecretKeyHex);

// Process payments
const result = bridge.process_payment(paymentJson, contextJson);
console.log(`Payment accepted: balance=${result.balance}`);
```

### Client-Side (Sender)

```typescript
import { randomBytes } from "crypto";
import * as secp from "@noble/secp256k1";
import * as wasm from "./wasm/cdk_wasm.js";

// Generate keypair (use @noble/secp256k1, not WASM)
const secretBytes = randomBytes(32);
const pubkeyBytes = secp.getPublicKey(secretBytes, true);
const secret = secretBytes.toString("hex");
const pubkey = Buffer.from(pubkeyBytes).toString("hex");

// Compute shared secret with receiver (WASM)
const sharedSecret = wasm.compute_channel_secret(secret, receiverPubkey);

// Get channel ID (WASM)
const channelId = wasm.channel_parameters_get_channel_id(
  paramsJson,
  sharedSecret,
  keysetJson
);

// Create funding outputs for minting (WASM)
const fundingJson = wasm.create_funding_outputs(paramsJson, secret, keysetJson);

// Create signed payment (WASM)
const paymentJson = wasm.spilman_channel_sender_create_signed_balance_update(
  paramsJson,
  keysetJson,
  secret,
  proofsJson,
  balance
);
```

## Testing

### Integration Tests

Integration tests require a Cashu mint running:

```bash
# Start a mint (from CDK repo root)
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# In another terminal, run integration tests
make test-integration

# Or with custom mint URL
MINT_URL=http://my-mint:3338 make test-integration
```

### Full Integration Suite

The comprehensive 52-test integration suite is run from the CDK root:

```bash
# From CDK repository root
make test-server-ts
```

## Example Server

An ASCII art demo server is included:

```bash
# Install dependencies
make install

# Start the server
make run-server

# In another terminal, run the client
make run-client
```

See `examples/ts-ascii-art/README.md` for more details.

## Build Outputs

The WASM build produces two targets:

- `web/wasm-nodejs/` - For Node.js (CommonJS-compatible)
- `web/wasm-web/` - For browsers (ES modules)

Each contains:
- `cdk_wasm.js` - JavaScript bindings
- `cdk_wasm.d.ts` - TypeScript declarations
- `cdk_wasm_bg.wasm` - WASM binary

## API Reference

### Classes

- `WasmSpilmanBridge` - Main bridge for server-side payment validation

### Functions

- `generate_keypair()` - Generate a new secp256k1 keypair (returns JSON)
- `secret_key_to_pubkey(secret_hex)` - Derive public key from secret
- `compute_channel_secret(my_secret, their_pubkey)` - Compute ECDH shared secret
- `channel_parameters_get_channel_id(params_json, channel_secret, keyset_json)` - Get channel ID
- `create_funding_outputs(params_json, secret, keyset_json)` - Create blinded outputs for funding
- `construct_proofs(signatures_json, secrets_json, keyset_json)` - Construct proofs from signatures
- `spilman_channel_sender_create_signed_balance_update(...)` - Sign a payment
- `unblind_and_verify_dleq(...)` - Unblind signatures and verify DLEQ proofs
- `verify_channel(...)` - Verify a channel is valid
- `verify_balance_update_signature(...)` - Verify a balance update signature

## Protocol

See [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) for the full protocol specification.

## License

MIT
