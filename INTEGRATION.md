# Spilman Channel Integration Guide

This guide is for server developers who want to accept Cashu micropayments via Spilman channels.

**Prerequisites**: Basic familiarity with [Cashu](https://cashu.space/) ecash (tokens, mints, proofs).

**Further reading**: For cryptographic details (DLEQ, P2BK, blinded keys), see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Overview

Spilman channels enable **streaming micropayments** between a client (payer) and your server (payee). Instead of paying per-request with individual Cashu tokens, the client opens a channel with some capacity (e.g., 1000 sats) and then makes many small payments by signing balance updates.

**Why use channels?**

- **Efficiency**: One funding transaction, unlimited micropayments
- **Low trust**: Client only releases small amounts at a time
- **Privacy**: Channel uses blinded keys; mint can't link payments to identities
- **Flexibility**: Works with any Cashu mint, any currency unit

---

## How It Works

### 1. Funding

The client creates a Cashu token locked to a 2-of-2 multisig:

```
Spendable by: (Client AND Server) OR (Client after locktime)
```

This means:
- **Cooperative spend**: Both parties sign to split the funds
- **Refund**: If the server disappears, the client reclaims everything after the locktime

The client sends the funding proofs and channel parameters to your server.

### 2. Payments

To pay, the client signs a message saying "the server is owed X sats":

```
channel_id: "abc123..."
balance: 150
signature: <schnorr_sig>
```

Each payment increases the balance. If the previous balance was 145 and the new balance is 150, the client just paid 5 sats.

Your server verifies the signature, checks `balance >= amount_due`, and provides the service.

### 3. Closing

When you're done (or before the locktime expires), either party can close the channel:

- **Cooperative close**: Client sends a final balance update; server submits a swap to the mint that splits the funds (server gets `balance`, client gets `capacity - balance`)
- **Unilateral close**: Server uses the best signature it has stored to close without client cooperation

After closing, both parties receive standard Cashu proofs they can spend normally.

---

## Trust Model

```
┌────────┐         ┌────────┐         ┌────────┐
│ Client │ ──────► │ Server │ ──────► │  Mint  │
│ (Alice)│ channel │(Charlie│  swap   │        │
└────────┘         └────────┘         └────────┘
     │                                     │
     └─────────── both trust ──────────────┘
```

- **Client trusts the mint**: Their funds are Cashu tokens
- **Server trusts the mint**: The swap will honor valid signatures
- **Neither trusts the other**: 
  - Client only releases small amounts for actual service
  - Server can close anytime, collecting what's owed
  - Client can refund after locktime if server disappears

---

## Channel Lifecycle

```
 (unknown)     ┌─────────┐    ┌─────────┐    ┌────────┐
 ── funding ──►│  OPEN   │───►│ CLOSING │───►│ CLOSED │
               └─────────┘    └─────────┘    └────────┘
                   │  ▲
                   │  │ payments
                   └──┘

Note: Payments are rejected if channel is CLOSING or CLOSED.
```

**State transitions:**

| From | To | Trigger |
|------|-----|---------|
|      | OPEN | First valid payment or explicit registration |
| OPEN | OPEN | Each valid payment (balance increases) |
| OPEN | CLOSING | Close request received, swap prepared |
| CLOSING | CLOSED | Mint swap succeeds, proofs stored |
| CLOSING | OPEN | Swap fails, channel reopened (optional) |

---

## Architecture: Bridge and Host

The Spilman implementation uses a **Bridge + Host** architecture:

```
                         Your Server
┌───────────────────────────────────────────────────────────┐
│                                                           │
│   ┌─────────────┐      ┌───────────────────────────────┐  │
│   │  Transport  │      │        SpilmanBridge          │  │
│   │  (HTTP,     │      │  (Cryptography + Validation)  │  │
│   │  WebSocket, │─────►│                               │  │
│   │  gRPC, ...) │      │  delegates to:                │  │
│   └─────────────┘      │         │                     │  │
│                        │         ▼                     │  │
│                        │  ┌─────────────┐              │  │
│                        │  │    Host     │ (you write)  │  │
│                        │  │  - Pricing  │              │  │
│                        │  │  - Storage  │              │  │
│                        │  └─────────────┘              │  │
│                        └───────────────────────────────┘  │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

**The Bridge** (provided by the library):
- Verifies signatures and DLEQ proofs
- Validates channel parameters against your policy
- Computes deterministic outputs for closing
- Handles all cryptographic operations

**The Host** (implemented by you):
- Defines pricing policy (how much does each request cost?)
- Stores channel state (funding, balances, usage)
- Decides which mints and receiver keys are acceptable
- Communicates with the mint for swaps

### Transport Independence

**The bridge operates on typed data, not HTTP or JSON.** It takes parameters like `channel_id: &str`, `balance: u64`, `signature: &str` and returns typed results or errors.

The convenience methods (`*_via_json`, `*_via_base64_header`) are provided for common cases, but you can call the core typed methods directly.

This means Spilman channels work over **any transport**:
- HTTP headers (like the reference demos)
- HTTP request/response bodies
- WebSocket messages
- gRPC calls
- Custom binary protocols
- Anything else

The examples in this guide use HTTP with JSON for simplicity, but adapt the patterns to your transport.

---

## The SpilmanHost Interface

You implement this interface to connect the bridge to your server's policy and storage:

```rust
trait SpilmanHost {
    // ==================== Policy ====================
    
    /// Is this receiver pubkey your server's key?
    /// Return true only for your own pubkey(s).
    fn receiver_key_is_acceptable(&self, pubkey: &PublicKey) -> bool;
    
    /// Is this mint and keyset allowed?
    /// Check against your allowlist of trusted mints.
    /// This may include inactive keysets, but it's advised to reject
    /// keysets that are close to expiry. When the bridge requires
    /// and active keyset for swapping, it will call 'get_active_keyset_ids'.
    /// For efficiency and DOS protection, this function should *not* call
    /// the mint, instead it should use a cache of acceptable keysets for
    /// each mint.
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool;
    
    /// Return your channel policy (pricing, limits) as JSON.
    fn get_channel_policy(&self) -> String;
    
    /// Current time in seconds (for locktime validation).
    fn now_seconds(&self) -> u64;

    // ==================== Pricing ====================
    
    /// How much is owed for this channel, including the current request?
    /// 
    /// `context_json` describes the current request (e.g., file size, action type).
    /// Return the cumulative amount due based on all usage so far plus this request.
    /// If no context_json is passed, just return based on all usage so far.
    /// There is no schema requirement on the `context_json`, in fact it
    /// does not need to be JSON. You provide it when calling 'process_payment'.
    fn get_amount_due(&self, channel_id: &str, context_json: Option<&str>) -> u64;

    // ==================== Storage: Funding ====================
    
    /// Store funding data for a new channel, including the initial payment proof.
    /// 
    /// Called after the bridge validates a new channel's params, proofs, and signature.
    /// The initial_balance/initial_signature should be stored for closing the channel.
    /// Even if initial_balance is 0, the signature is valid and can be used for closing.
    fn save_funding(
        &self,
        channel_id: &str,
        params_json: &str,
        funding_proofs_json: &str,
        shared_secret_hex: &str,
        keyset_info_json: &str,
        initial_balance: u64,
        initial_signature: &str,
    );
    
    /// Retrieve stored funding data for a channel.
    /// Returns (params_json, funding_proofs_json, shared_secret_hex, keyset_info_json)
    fn get_funding_and_params(&self, channel_id: &str) 
        -> Option<(String, String, String, String)>;

    // ==================== Storage: Payments ====================
    
    /// Record a successful payment.
    /// Store the balance and signature (needed for closing).
    /// Update your usage tracking based on context_json.
    fn record_payment(
        &self, 
        channel_id: &str, 
        balance: u64, 
        signature: &str, 
        context_json: &str
    );
    
    /// Get the best payment proof for unilateral close.
    /// Returns (balance, signature) of the highest balance payment received.
    fn get_balance_and_signature_for_unilateral_exit(&self, channel_id: &str) 
        -> Option<(u64, String)>;

    // ==================== Storage: Channel State ====================
    
    /// Get current channel state: Open, Closing, or Closed.
    /// Returns `Open` for unknown channels (they're implicitly open until funded).
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;
    
    /// Mark channel as CLOSING (before swap attempt).
    ///
    /// Called before attempting the mint swap. The host should:
    /// - Store the closing parameters (locktime, balance, signature)
    /// - Return `Closing` from `get_channel_state()` for this channel
    /// - Reject further payments to this channel
    ///
    /// # Behavior by channel state:
    /// - **Open**: Transition to Closing, store the data
    /// - **Closing**: Update the stored data (supports retry with different balance)
    /// - **Closed**: Return error (bridge checks state first, but host should also reject)
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(message)` if the operation fails (e.g., channel already closed)
    ///
    /// # Language-specific error handling
    /// - **Rust**: Return `Err(message)` on failure
    /// - **TypeScript/WASM**: Throw an Error on failure
    /// - **Python**: Raise an exception on failure
    /// - **Go**: Return a non-nil error on failure
    ///
    /// Note: The bridge checks `get_channel_state()` before calling this and will
    /// reject attempts to close already-closed channels with `BridgeError::ChannelClosed`.
    fn mark_channel_closing(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        signature: &str,
    ) -> Result<(), String>;
    
    /// Get stored closing data for retry.
    fn get_closing_data(&self, channel_id: &str) -> Option<ClosingData>;
    
    /// Mark channel as CLOSED (after successful swap).
    ///
    /// Called after the mint has accepted the swap. The host should:
    /// - Store the final proofs for record-keeping
    /// - Return `Closed` from `get_channel_state()` for this channel
    /// - Remove any CLOSING state data (channel is now finalized)
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(message)` if the operation fails (e.g., channel already closed)
    ///
    /// # Language-specific error handling
    /// - **Rust**: Return `Err(message)` on failure
    /// - **TypeScript/WASM**: Throw an Error on failure
    /// - **Python**: Raise an exception on failure
    /// - **Go**: Return a non-nil error on failure
    fn mark_channel_closed(
        &self,
        channel_id: &str,
        locktime: u64,
        balance: u64,
        receiver_proofs_json: &str,
        sender_proofs_json: &str,
        receiver_sum: u64,
        sender_sum: u64,
    ) -> Result<(), String>;

    // ==================== Keyset Cache ====================
    
    /// Get active keyset IDs for a mint and unit.
    fn get_active_keyset_ids(&self, mint: &str, unit: &CurrencyUnit) -> Vec<Id>;
    
    /// Get full keyset info JSON for a specific keyset.
    fn get_keyset_info(&self, mint: &str, keyset_id: &Id) -> Option<String>;
    
    /// Refresh keyset cache from mint (called on swap failure).
    fn refresh_active_keysets(&self, mint: &str) -> Result<(), String>;

    // ==================== Mint Communication ====================
    
    /// Submit a swap request to the mint.
    /// Returns the response JSON on success.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) 
        -> Result<String, String>;
}
```

---

## State Management

You need to persist several pieces of data per channel. Here's what each store contains:

You are free to decide how to store this. Perhaps you will have a single complex
`State` type and store a mapping of `channel_id` to `State`.
The four examples servers users four separate in-memory stores like this:

| Store | Key | Data | Purpose |
|-------|-----|------|---------|
| **Funding** | channel_id | params, proofs, shared_secret, keyset_info | Validate signatures, construct close |
| **Balance** | channel_id | balance, signature | Track highest payment, close channel |
| **Usage** | channel_id | service-specific metrics | Calculate amount_due |
| **Closing** | channel_id | locktime, balance, signature | Retry failed swaps |
| **Closed** | channel_id | final amounts, proofs | Prevent reuse, audit trail |

### Optional Stores

| Store | Purpose |
|-------|---------|
| **Activity** | Track last payment time for idle channel cleanup |
| **Keyset Cache** | Cache mint keysets to avoid repeated fetches |

### Data Structures

```typescript
// Funding: Everything needed to validate payments and close
interface ChannelFunding {
  paramsJson: string;        // Channel parameters
  fundingProofsJson: string; // The locked Cashu proofs
  sharedSecret: string;      // ECDH secret (hex)
  keysetInfoJson: string;    // Keyset keys and fees
}

// Balance: The payment proof for closing
interface ChannelBalance {
  balance: number;           // Cumulative amount owed to server
  signature: string;         // Client's Schnorr signature
}

// Usage: Service-specific (examples)
interface ChannelUsage {
  requestsServed: number;
  bytesServed: number;
  // ... whatever metrics drive your pricing
}

// Closing: Pre-swap state for retry
interface ClosingData {
  locktime: number;
  balance: number;
  signature: string;
}

// Closed: Final state
interface ClosedChannel {
  locktime: number;
  closedAmount: number;      // Balance at close
  receiverSum: number;       // Server's proofs value
  senderSum: number;         // Client's change value
  receiverProofsJson: string;
  senderProofsJson: string;
}
```

### Important: Balance Updates Are Monotonic

Always store the **highest** balance seen:

```typescript
function updateBalance(channelId: string, balance: number, signature: string) {
  const current = balanceStore.get(channelId);
  if (!current || balance > current.balance) {
    balanceStore.set(channelId, { balance, signature });
  }
  // Ignore if balance <= current (replay or out-of-order)
}
```

---

## Using the Bridge

### Creating the Bridge

```typescript
// TypeScript (WASM)
import { SpilmanBridge } from "cdk-wasm";

const bridge = new SpilmanBridge(spilmanHooks, serverSecretKeyHex);
```

```rust
// Rust
use cdk::spilman::{SpilmanBridge, SpilmanHost};

let bridge = SpilmanBridge::new(my_host, Some(server_secret_key));
```

```python
# Python
from cdk_spilman_python import SpilmanBridge

bridge = SpilmanBridge(hooks, server_secret_key_hex)
```

### Key Methods

#### `process_payment` - Validate and Record

The most common method for you to call from your server.
Validates the payment and calls `record_payment` on success:

```rust
let result = bridge.process_payment(
    channel_id,
    balance,
    signature,
    params,           // Option<&Value> - only needed for new channels
    funding_proofs,   // Option<&[Proof]> - only needed for new channels
    context_json,     // Describes the current request
)?;
// result.balance, result.amount_due, result.capacity
```

#### `validate_payment` - Validate Only

Same as `process_payment` but doesn't record. Use when you need to check before committing:

```rust
let result = bridge.validate_payment(...)?;
// Manually call host.record_payment() if you proceed
```

#### `fund_channel` - Explicit Registration

Register a channel without recording usage. Useful for pre-registration endpoints:

```rust
let result = bridge.fund_channel(
    channel_id,
    balance,      // Can be 0 or non-zero
    signature,
    params,
    funding_proofs,
)?;
// result.channel_id, result.capacity, result.already_known
```

Note: The bridge accepts any balance for funding. If you want to enforce `balance=0` for registration, check it in your server code before calling.

#### `execute_cooperative_close` - Client-Initiated Close

Client sends their final balance; server closes the channel:

```rust
let result = bridge.execute_cooperative_close(payment_json)?;
// result.channel_id, result.receiver_sum, result.sender_sum, result.sender_proofs_json
```

#### `execute_unilateral_close` - Server-Initiated Close

Server closes using the best stored payment:

```rust
let result = bridge.execute_unilateral_close(channel_id)?;
// Same fields as cooperative close
```

### Convenience Methods

Each core method has variants for common input formats:

```rust
// Typed parameters (core)
bridge.process_payment(channel_id, balance, signature, params, proofs, context)

// JSON string input
bridge.process_payment_via_json(payment_json, context_json)

// Base64-encoded JSON (HTTP header)
bridge.process_payment_via_base64_header(base64_header, context_json)
```

---

## Error Handling

The bridge returns typed errors. Map them to your transport's error format:

### BridgeError Types

| Error | Meaning | Suggested HTTP Status |
|-------|---------|----------------------|
| `InvalidRequest` | Malformed input | 400 Bad Request |
| `UnknownChannel` | No funding data, params not provided | 402 Payment Required |
| `InsufficientBalance` | balance < amount_due | 402 Payment Required |
| `InvalidSignature` | Signature verification failed | 400 Bad Request |
| `ChannelClosed` | Channel already closed | 410 Gone |
| `ChannelClosing` | Swap in progress | 409 Conflict |
| `BalanceExceedsCapacity` | balance > capacity | 400 Bad Request |
| `CapacityTooSmall` | Below minimum | 400 Bad Request |
| `LocktimeTooSoon` | Expires too soon | 400 Bad Request |
| `UnsupportedUnit` | Currency not accepted | 400 Bad Request |
| `ReceiverKeyNotAcceptable` | Wrong server pubkey | 400 Bad Request |
| `MintOrKeysetNotAcceptable` | Mint not in allowlist | 400 Bad Request |

### Error Response Pattern

```typescript
function handlePaymentError(error: BridgeError): Response {
  if (error.type === "InsufficientBalance" || error.type === "UnknownChannel") {
    return new Response(JSON.stringify({
      error: error.message,
      amount_due: error.amount_due,  // Include so client knows how much to pay
    }), { status: 402 });
  }
  if (error.type === "ChannelClosed") {
    return new Response(JSON.stringify({ error: "channel closed" }), { status: 410 });
  }
  // ... other cases
  return new Response(JSON.stringify({ error: error.message }), { status: 400 });
}
```

---

## HTTP Protocol (Reference Implementation)

The reference demos use HTTP headers to transport payments. Adapt this pattern to your transport.

### Request: X-Cashu-Channel Header

The client sends a **base64-encoded JSON** header:

```http
GET /resource HTTP/1.1
X-Cashu-Channel: eyJjaGFubmVsX2lkIjoiYWJjLi4uIiwiYmFsYW5jZSI6MTUwLC4uLn0=
```

Decoded payload:

```json
{
  "channel_id": "abc123...",
  "balance": 150,
  "signature": "schnorr_signature_hex",
  "params": { ... },           // Optional: only on first request
  "funding_proofs": [ ... ]    // Optional: only on first request
}
```

### Response: Success

On success, return the resource with a confirmation header:

```http
HTTP/1.1 200 OK
X-Cashu-Channel: {"channel_id":"abc...","balance":150,"amount_due":145,"capacity":1000}
Content-Type: application/octet-stream

<resource data>
```

### Response: Payment Required

When payment is missing or insufficient:

```http
HTTP/1.1 402 Payment Required
Content-Type: application/json

{
  "error": "insufficient balance",
  "channel_id": "abc123...",
  "balance": 100,
  "amount_due": 150,
  "capacity": 1000
}
```

### Channel Endpoints

Typical REST endpoints for channel management:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/channel/params` | GET | Get server pubkey, pricing, policy |
| `/channel/register` | POST | Pre-register a channel (optional) |
| `/channel/:id/status` | GET | Get channel balance and usage |
| `/channel/:id/close` | POST | Client-initiated cooperative close |

---

## Configuration

### Channel Policy

Define your policy and return it from `get_channel_policy()`:

```json
{
  "min_expiry_in_seconds": 3600,
  "pricing": {
    "sat": {
      "minCapacity": 100,
      "perRequestPpk": 500,
      "perMegabytePpk": 1000,
      "maxAmountPerOutput": 64
    },
    "usd": {
      "minCapacity": 10,
      "perRequestPpk": 100,
      "perMegabytePpk": 200
    }
  }
}
```

**Fields:**

- `min_expiry_in_seconds`: Minimum time until locktime (reject channels that expire too soon)
- `pricing[unit].minCapacity`: Minimum channel capacity for this unit
- `pricing[unit].perRequestPpk`: Cost per request in parts-per-thousand
- `pricing[unit].perMegabytePpk`: Cost per megabyte in parts-per-thousand
- `pricing[unit].maxAmountPerOutput`: Maximum denomination (affects proof count)

### Pricing Formula

```
amount_due = ceil((requests * perRequestPpk + megabytes * perMegabytePpk) / 1000)
```

Adapt the formula to your service's pricing model.

---

## Quick Start Checklist

1. **Generate a server keypair**
   - Create a secp256k1 secret key (32 bytes, hex-encoded)
   - This is your "Charlie" key for receiving payments

2. **Implement SpilmanHost**
   - Start with in-memory stores (upgrade to database later)
   - Implement `receiver_key_is_acceptable` to check for your pubkey
   - Implement `mint_and_keyset_is_acceptable` with your mint allowlist
   - Implement `get_amount_due` with your pricing logic

3. **Initialize keysets**
   - Fetch `/v1/keysets` and `/v1/keys/{keyset_id}` from approved mints
   - Cache the keyset info for `get_keyset_info`

4. **Add payment validation to your endpoints**
   - Extract payment from your transport (e.g., decode header)
   - Call `bridge.process_payment(...)`
   - Return appropriate response or error

5. **Add channel management endpoints**
   - `/channel/params`: Return your pubkey, policy, mint info
   - `/channel/:id/close`: Call `bridge.execute_cooperative_close()`

6. **Handle channel expiry**
   - Monitor channels approaching locktime
   - Call `execute_unilateral_close()` before they expire

---

## Working Examples

### ASCII Art Demos

Four implementations showing the same pattern in different languages:

| Language | Location | Notes |
|----------|----------|-------|
| TypeScript | `crates/cdk-wasm/examples/ascii-art/` | Reference implementation |
| Rust | `examples/rust-ascii-art/` | Native Rust server |
| Python | `crates/cdk-spilman-python/examples/ascii-art/` | PyO3 bindings |
| Go | `crates/cdk-spilman-go/examples/ascii-art/` | CGO bindings |

Each demo implements a simple service: pay per character of ASCII art. Study the `SpilmanHost` implementation in each.

### CashuTube

A more complete example: pay-per-segment video streaming.

Note that this is in a seperate repository.

| Component | Location |
|-----------|----------|
| Server | `web/blossom-server/src/api/` |
| Hooks | `web/blossom-server/src/api/bridge-hooks.ts` |
| Stores | `web/blossom-server/src/api/stores.ts` |

### Key Files to Study

```
# TypeScript host implementation
crates/cdk-wasm/examples/ascii-art/src/server.ts  # Hooks inline in server
web/blossom-server/src/api/bridge-hooks.ts

# Rust host implementation  
examples/rust-ascii-art/src/host.rs
examples/rust-ascii-art/src/stores.rs

# Bridge interface (Rust source)
crates/cdk/src/spilman/bridge.rs
```

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) - Cryptographic protocol details (P2BK, DLEQ, blinding)
- [CASHUTUBE.md](CASHUTUBE.md) - CashuTube-specific API documentation
- [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) - Protocol specification
