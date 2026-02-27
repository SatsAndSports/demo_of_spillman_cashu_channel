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

**Shortcut for Rust servers**: `ConfigurableHost` (feature-gated behind `configurable-host`) is a ready-made `SpilmanHost` implementation that reads pricing and policy from YAML and tracks usage via named variables with linear pricing. It supports pluggable storage backends: in-memory (default) or SQLite for persistence. See the [Rust ASCII Art server](examples/rust-ascii-art/) for a working example using `ConfigurableHost::from_yaml()`.

**Shortcut for TypeScript/Express servers**: The [TypeScript Integration Kit](integration-kits/ts/) provides a drop-in management router and in-memory host for Express applications. It handles keyset caching, registration, and closing endpoints out of the box.

### Transport Independence

**The bridge operates on typed data, not HTTP or JSON.** It takes parameters like `channel_id: &str`, `balance: u64`, `signature: &str`, and a generic request context `&C`, then returns typed results or errors.

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
trait SpilmanHost<C = String> {
    // ==================== Policy ====================

    /// Is this receiver pubkey your server's key?
    /// Return true only for your own pubkey(s).
    fn receiver_key_is_acceptable(&self, receiver_pubkey: &PublicKey) -> bool;

    /// Is this mint and keyset allowed?
    /// Check against your allowlist of trusted mints.
    /// This may include inactive keysets, but it's advised to reject
    /// keysets that are close to expiry. When the bridge requires
    /// an active keyset for swapping, it will call `get_active_keyset_ids`.
    /// For efficiency and DOS protection, this function should *not* call
    /// the mint, instead it should use a cache of acceptable keysets for
    /// each mint.
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset_id: &Id) -> bool;

    /// Return funding-time validation thresholds for a unit.
    /// Returns `None` if the unit is not supported.
    fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy>;

    /// Current time in seconds (for locktime validation).
    fn now_seconds(&self) -> u64;

    // ==================== Pricing ====================

    /// How much is owed for this channel, including the current request?
    ///
    /// `context` describes the current request (e.g., file size, action type).
    /// Return the cumulative amount due based on all usage so far plus this request.
    /// If no context is passed, just return based on all usage so far.
    /// The context type is yours to choose; `String` is the default for JSON.
    fn get_amount_due(&self, channel_id: &str, context: Option<&C>) -> u64;

    // ==================== Storage: Funding ====================

    /// Retrieve stored funding data for a channel.
    fn get_funding(&self, channel_id: &str) -> Option<ChannelFunding>;

    /// Store funding data for a new channel, including the initial payment proof.
    ///
    /// Called after the bridge validates a new channel's params, proofs, and signature.
    /// The initial payment should be stored for closing the channel.
    /// Even if initial_payment.balance is 0, the signature is valid and can be used for closing.
    fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    );

    // ==================== Storage: Payments ====================

    /// Record a successful payment.
    /// Store the balance and signature (needed for closing).
    /// Update your usage tracking based on context.
    fn record_payment(&self, channel_id: &str, payment: PaymentProof, context: &C);

    /// Get the best payment proof for unilateral close.
    fn get_balance_and_signature_for_unilateral_exit(&self, channel_id: &str)
        -> Option<PaymentProof>;

    // ==================== Storage: Channel State ====================

    /// Get current channel state: Open, Closing, or Closed.
    /// Returns `Open` for unknown channels (they're implicitly open until funded).
    fn get_channel_state(&self, channel_id: &str) -> ChannelState;

    /// Mark channel as CLOSING (before swap attempt).
    ///
    /// Called before attempting the mint swap. The host should:
    /// - Store the closing parameters (locktime, payment)
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
        payment: PaymentProof,
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

    // ==================== Cryptographic Operations ====================
    // The bridge never holds the server's secret key. These callbacks
    // allow the host to perform key operations without exposing the key.

    /// Compute the hashed ECDH channel secret.
    /// The host performs ECDH(charlie_secret, alice_pubkey) and hashes with
    /// domain separator "Cashu_Spilman_channel_secret_v1".
    /// For hosts holding raw keys, use compute_channel_secret_from_hex().
    fn compute_channel_secret(
        &self,
        charlie_pubkey_hex: &str,   // Receiver's (your server's) pubkey - identifies which key
        alice_pubkey_hex: &str,     // Sender's public key
    ) -> Result<String, String>;

    /// Sign a message with a tweaked key (BIP-340 Schnorr).
    /// The bridge computes the tweak (P2BK blinding scalar) and message hash,
    /// then asks the host to produce a signature using (secret + tweak).
    /// For hosts holding raw keys, use sign_with_tweaked_key_util().
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,    // Identifies which key to use
        message_hex: &str,          // SHA-256 hash (32 bytes, hex)
        tweak_scalar_hex: &str,     // P2BK blinding scalar (32 bytes, hex)
    ) -> Result<String, String>;
}

trait SpilmanNetworking {
    /// Submit a swap request to the mint.
    /// Returns the response JSON on success.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;

    /// Refresh ALL keysets (active and inactive) from the mint.
    /// Called on swap failure. Must retain inactive keyset data
    /// so existing channels can still look up their keyset info.
    fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}

#[async_trait]
trait SpilmanAsyncNetworking {
    async fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
    async fn refresh_all_keysets(&self, mint: &str) -> Result<(), String>;
}
```

---

## Channel Policy and Pricing

### Funding Validation

When a client funds a new channel, the bridge calls `get_channel_policy(unit)` to
enforce three constraints:

1. **Capacity** must be at least `min_capacity`
2. **Locktime** must be at least `now + min_expiry_in_seconds` in the future
3. **Denomination** of the largest proof must not exceed `max_amount_per_output` (if set)

If `get_channel_policy` returns `None`, the unit is rejected entirely.

### ChannelPolicy Struct

```rust
pub struct ChannelPolicy {
    pub min_expiry_in_seconds: u64,
    pub min_capacity: u64,
    pub max_amount_per_output: Option<u64>,
}
```

Example implementation:

```rust
fn get_channel_policy(&self, unit: &str) -> Option<ChannelPolicy> {
    match unit {
        "sat" => Some(ChannelPolicy {
            min_expiry_in_seconds: 3600,
            min_capacity: 100,
            max_amount_per_output: None,
        }),
        "usd" => Some(ChannelPolicy {
            min_expiry_in_seconds: 3600,
            min_capacity: 10,
            max_amount_per_output: Some(64),
        }),
        _ => None,
    }
}
```

**Fields:**

- `min_expiry_in_seconds`: Minimum time until locktime (reject channels that expire too soon)
- `min_capacity`: Minimum channel capacity for this unit
- `max_amount_per_output`: Optional cap on the largest single proof denomination

### Pricing

The bridge calls `get_amount_due(channel_id, context)` on every request to determine
how much the client owes. The pricing model is entirely yours. A common formula:

```
amount_due = ceil((requests * perRequestPpk + megabytes * perMegabytePpk) / 1000)
```

Adapt the formula to your service's pricing model.

`ConfigurableHost` provides a ready-made linear pricing model driven by YAML — see the
[Rust ASCII Art server](examples/rust-ascii-art/) for a working example.

### ConfigurableHost Storage

`ConfigurableHost` uses a pluggable `SpilmanStorage` trait internally. Two backends are provided:

- **Memory** (default): In-memory `RwLock<HashMap>` stores. Fast, but all data is lost on restart.
- **SQLite**: File-backed persistence using `rusqlite`. Channels, balances, usage, and keyset cache survive restarts.

Configure via the optional `storage` section in your YAML:

```yaml
# Default: in-memory (omit the section entirely, or specify explicitly)
storage:
  type: memory

# Persistent: SQLite file
storage:
  type: sqlite
  path: "./spilman.db"
```

You can also pass a custom storage backend via `ConfigurableHost::with_storage()`.

### Networking "Batteries" (Rust)

For Rust servers, you can use the built-in `ReqwestNetworking` to eliminate almost all mint-communication boilerplate. Enable the `configurable-host-reqwest` feature:

```toml
cdk = { version = "0.14", default-features = false, features = ["configurable-host-reqwest"] }
```

This provides:

1.  **`host.initialize_keysets().await`**: A one-line helper that fetches and caches keysets from every mint in your config at startup.
2.  **`ReqwestNetworking`**: A ready-made struct implementing `SpilmanAsyncNetworking` for `execute_cooperative_close_async` and `execute_unilateral_close_async`.

#### Example Setup (Rust)

```rust
use cdk::spilman::configurable_host::ConfigurableHost;
use cdk::spilman::configurable_networking::ReqwestNetworking;
use cdk::spilman::SpilmanBridge;

// 1. Load config and secret key
let yaml = std::fs::read_to_string("config.yaml")?;
let secret_key = "0123...def";

// 2. Create host (reads storage type from YAML)
let host = Arc::new(ConfigurableHost::from_yaml(&yaml, secret_key)?);

// 3. Initialize keysets from all configured mints
host.initialize_keysets().await?;

// 4. Create bridge and networking
let bridge = SpilmanBridge::new((*host).clone());
let networking = Arc::new(ReqwestNetworking::new(host.clone()));

// Now use bridge.process_payment_via_base64_header() and 
// bridge.execute_cooperative_close_async(json, &*networking)
```

### Axum Management Router (Rust)

For Rust servers using `axum`, you can eliminate almost all management boilerplate by nesting the library-provided router. Enable the `spilman-axum` feature:

```toml
cdk = { version = "0.14", default-features = false, features = ["spilman-axum", "configurable-host-reqwest"] }
```

#### Example Router Integration (Rust)

```rust
use cdk::spilman::axum::{configurable_management_router, SpilmanState};

// 1. Bundle your Spilman components
let spilman_state = SpilmanState {
    bridge: Arc::new(SpilmanBridge::new((*host).clone())),
    host: host.clone(),
    networking: Arc::new(ReqwestNetworking::new(host.clone())),
};

// 2. Nest the management routes in your Axum app
let app = Router::new()
    .route("/my-service", post(handle_service))
    // Adds /channel/params, /channel/register, /channel/{id}/status, etc.
    .nest("/channel", configurable_management_router(spilman_state))
    .with_state(app_state);
```

This handles the mapping of `BridgeError` to 402/400/500 responses automatically and implements standard idempotency logic for closing.

---

## State Management

You need to persist several pieces of data per channel. Here's what each store contains:

You are free to decide how to store this. Perhaps you will have a single complex
`State` type and store a mapping of `channel_id` to `State`.
The four examples servers users four separate in-memory stores like this:

| Store | Key | Data | Purpose |
|-------|-----|------|---------|
| **Funding** | channel_id | params, proofs, channel_secret, keyset_info | Validate signatures, construct close |
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
  channelSecret: string;     // ECDH channel secret (hex)
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

The bridge is keyless — it never holds or sees the server's secret key. Cryptographic operations are delegated to the host via `compute_channel_secret` and `sign_with_tweaked_key` callbacks.

```typescript
// TypeScript (WASM)
import { SpilmanBridge } from "cdk-wasm";

const bridge = new SpilmanBridge(spilmanHooks);
```

```rust
// Rust
use cdk::spilman::{SpilmanBridge, SpilmanHost};

let bridge = SpilmanBridge::new(my_host);
```

```python
# Python
from cdk_spilman_python import SpilmanBridge

bridge = SpilmanBridge(hooks)
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
    context,          // Describes the current request (type C)
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

These methods require a networking provider that implements `SpilmanNetworking`.
In most servers the host implements it, so `bridge.host()` works as the net arg.

```rust
let result = bridge.execute_cooperative_close(payment_json, bridge.host())?;
// result.channel_id, result.receiver_sum, result.sender_sum, result.sender_proofs_json
```

#### `execute_unilateral_close` - Server-Initiated Close

Server closes using the best stored payment:

```rust
let result = bridge.execute_unilateral_close(channel_id, bridge.host())?;
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

## Keyset Caching Strategy

For robustness and testability, it is highly recommended to follow the "Persistent Cache" pattern used in the reference implementations:

1.  **Use a Mockable Helper**: Implement a standalone function (e.g., `fetchAllKeysetsFromMint`) that performs the actual HTTP calls to the mint's `/v1/keysets` and `/v1/keys/{id}` endpoints. This makes your host easy to test without a running mint.
2.  **Merge, Don't Replace**: When refreshing keysets, **merge** the new data into your existing cache. 
    - Update the `active` status of existing entries.
    - Add new entries.
    - **Crucial**: Do not delete entries that are missing from the mint's latest response. Existing channels often rely on older, deactivated keysets; removing them will cause those channels to fail validation.
3.  **In-Place Updates**: If your language supports it (like JavaScript/TypeScript or Python), update the properties of existing keyset objects in-place rather than replacing the whole object. This ensures the Bridge sees the updated state if it holds a reference to the entry.

---

## Quick Start Checklist

1. **Generate a server keypair**
   - Create a secp256k1 secret key (32 bytes, hex-encoded)
   - This is your "Charlie" key for receiving payments

2. **Implement SpilmanHost** (or use the ready-made one for Rust)
   - **Rust shortcut**: Use `ConfigurableHost::from_yaml(yaml, secret_key_hex)` — define pricing in YAML, no custom trait impl needed. Add `storage: { type: sqlite, path: "./spilman.db" }` to your YAML for persistence. See [examples/rust-ascii-art/](examples/rust-ascii-art/) and `config.yaml`.
   - **Custom impl**: Start with in-memory stores (upgrade to database later). Implement `receiver_key_is_acceptable` to check for your pubkey, `mint_and_keyset_is_acceptable` with your mint allowlist, and `get_amount_due` with your pricing logic.

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
| TypeScript | `integration-kits/ts/` | **Recommended** - Modular kit for Express |
| TypeScript | `examples/ts-ascii-art/` | Golden template demo (ConfigurableSpilman + SpilmanClientBridge) |
| Rust | `examples/rust-ascii-art/` | Uses `ConfigurableHost` with YAML config |
| Python | `examples/python-ascii-art/` | Golden template demo (ConfigurableSpilman + SpilmanClient) |
| Go | `examples/go-ascii-art/` | Golden template demo (ConfigurableSpilman + ClientBridge) |

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
examples/ts-ascii-art/src/server.ts  # ConfigurableSpilman + Express routes
web/blossom-server/src/api/bridge-hooks.ts

# Rust host implementation (ConfigurableHost + YAML)
examples/rust-ascii-art/config.yaml
crates/cdk/src/spilman/configurable_host.rs

# Bridge interface (Rust source)
crates/cdk/src/spilman/bridge.rs
```

---

## Client-Side: SpilmanClientBridge

For clients (payers) who want to open and manage channels programmatically, the `SpilmanClientBridge` provides a mirror of the server-side pattern.

### The SpilmanClientHost Interface

You implement this interface to connect the client bridge to your app's key management and storage:

```rust
trait SpilmanClientHost {
    /// Submit a swap request to the mint.
    fn call_mint_swap(&self, mint_url: &str, swap_request_json: &str) -> Result<String, String>;
    
    /// Save channel state. The bridge passes an opaque channel JSON blob
    /// and the channel secret separately (so the host can encrypt it).
    fn save_channel(&self, channel_id: &str, channel_json: &str, channel_secret_hex: &str);
    
    /// Retrieve channel state. Returns None if not found.
    fn get_channel(&self, channel_id: &str) -> Option<ChannelData>;
    
    /// List all stored channel IDs.
    fn list_channel_ids(&self) -> Vec<String>;
    
    /// Delete a channel from storage.
    fn delete_channel(&self, channel_id: &str);
    
    /// Sign a message with a tweaked key (BIP-340 Schnorr).
    /// The bridge computes the tweak and message hash, then asks the host
    /// to produce a signature using (secret + tweak).
    /// For hosts holding raw keys, use sign_with_tweaked_key_util().
    fn sign_with_tweaked_key(
        &self,
        signer_pubkey_hex: &str,   // Identifies which key to use
        message_hex: &str,          // SHA-256 hash (32 bytes, hex)
        tweak_scalar_hex: &str,     // P2BK blinding scalar (32 bytes, hex)
    ) -> Result<String, String>;
    
    /// Compute the hashed ECDH channel secret.
    /// The host performs ECDH(alice_secret, charlie_pubkey) and hashes with
    /// domain separator "Cashu_Spilman_channel_secret_v1".
    /// For hosts holding raw keys, use compute_channel_secret_from_hex().
    fn compute_channel_secret(
        &self,
        alice_pubkey_hex: &str,     // Identifies which secret key to use
        charlie_pubkey_hex: &str,   // Receiver's public key
    ) -> Result<String, String>;
}
```

### Key Design: Bridge Never Sees the Secret Key

The bridge is **stateless and keyless**. All cryptographic operations requiring Alice's secret key are delegated to the host. This enables:

- **External signers / HSMs**: The host can delegate to hardware
- **Per-channel keys**: The caller passes `alice_pubkey_hex` to `open_channel_from_token()`, so different channels can use different keys
- **Key rotation**: The host manages key lifecycle independently

### Using the Client Bridge

```rust
// Create bridge (no key parameter)
let bridge = SpilmanClientBridge::new(my_host);

// Open a channel from a Cashu token
let result = bridge.open_channel_from_token(
    token_string,
    charlie_pubkey_hex,
    alice_pubkey_hex,  // Caller chooses which key for this channel
    locktime,
    keyset_info_json,
    max_amount,
)?;

// Sign balance updates
let update_json = bridge.sign_balance_update(&result.channel_id, 10)?;

// Build payment headers (base64-encoded, ready for X-Cashu-Channel)
let header = bridge.build_payment_header(&result.channel_id, 10, true)?;  // with funding
let header = bridge.build_payment_header(&result.channel_id, 20, false)?; // without
```

### Available in All Languages

| Language | Bridge | Host Interface |
|----------|--------|----------------|
| Rust | `SpilmanClientBridge` | `SpilmanClientHost` trait |
| Go | `ClientBridge` | `SpilmanClientHost` interface |
| Python | `ClientBridge` | Duck-typed class with required methods |

See the integration tests in each language for complete working examples:
- Rust: `crates/cdk/src/spilman/tests.rs` (`test_client_bridge`)
- Go: `crates/cdk-spilman-go/spilman/integration_test.go` (`TestClientBridge`)
- Python: `crates/cdk-spilman-python/tests/integration_test.py` (`TestClientBridge`)

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) - Cryptographic protocol details (P2BK, DLEQ, blinding)
- [CASHUTUBE.md](CASHUTUBE.md) - CashuTube-specific API documentation
- [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) - Protocol specification
