# Spilman Channel Architecture

This document describes the technical design of Spilman-style unidirectional payment channels for Cashu ecash.

## Overview

A Spilman channel is a unidirectional payment channel between:
- **Alice (sender)**: The payer (e.g., video viewer)
- **Charlie (receiver)**: The payee (e.g., video server)

Alice locks funds in a 2-of-2 multisig with a time-locked refund path. She then signs off-chain balance updates that incrementally transfer value to Charlie. Charlie can close the channel at any time by submitting the latest balance update to the mint.

## Key Concepts

### 1. 2-of-2 Multisig Funding

The channel is funded with Cashu tokens that require **both** Alice and Charlie to spend cooperatively. The funding token's spending conditions are:

```
P2PK: (Alice AND Charlie) OR (Alice after locktime)
```

This is implemented using Cashu's NUT-11 spending conditions:
- `pubkeys`: [Charlie's pubkey] - requires Charlie's signature
- `data`: Alice's pubkey - requires Alice's signature  
- `refund_keys`: [Alice's refund pubkey] - allows Alice to reclaim after locktime
- `locktime`: Unix timestamp when refund becomes valid

### 2. Deterministic Outputs

Both parties can compute the **same** blinded outputs for the commitment transaction using a shared secret derived via ECDH. This eliminates round trips during payment:

1. Alice and Charlie derive `shared_secret = ECDH(alice_secret, charlie_pubkey)`
2. Both use the shared secret to deterministically generate blinding factors
3. Both can independently compute the same `BlindedMessage` outputs

### 3. Balance Updates

Alice signs off-chain messages that increment Charlie's balance:

```json
{
  "channel_id": "abc123...",
  "amount": 150,
  "signature": "schnorr_sig_hex"
}
```

The signature covers `SHA256(channel_id || amount)` using Alice's **blinded** secret key.

### 4. Channel ID

The channel ID is a SHA256 hash of the canonical channel parameters:

```
channel_id = SHA256(
  mint_url || 
  alice_pubkey || 
  charlie_pubkey || 
  capacity || 
  locktime || 
  nonce || 
  keyset_id
)
```

This binds all parameters together cryptographically. Any tampering changes the channel ID.

### 5. DLEQ Verification

When Charlie receives funding proofs, he verifies the DLEQ proofs to ensure:
- The mint actually signed these proofs (not fabricated by Alice)
- The keyset ID matches the public keys provided
- No token inflation is possible

## P2BK (Pay-to-Blinded-Key) Privacy

The channel uses **blinded pubkeys** in the funding token so the mint cannot correlate channels to real identities.

### Why Blinding?

Without blinding, the mint sees:
- Alice's real pubkey in multiple funding tokens
- Charlie's real pubkey as recipient
- Pattern: "Alice pays Charlie repeatedly"

With P2BK:
- Each channel uses fresh blinded pubkeys
- Mint sees uncorrelated random-looking keys
- No pattern linking channels to identities

### Blinding Derivation

```
r = SHA256("Cashu_Spilman_P2BK_v1" || channel_id || shared_secret || context || retry_counter)

If pubkey has even Y:  blinded_pubkey = raw_pubkey + r*G
If pubkey has odd Y:   blinded_pubkey = -raw_pubkey + r*G  (BIP-340 parity)

blinded_secret = raw_secret + r  (or -raw_secret + r for odd Y)
```

### Blinding Contexts

Different contexts ensure keys are unlinkable across roles:

| Context | Purpose |
|---------|---------|
| `"sender_stage1"` | Alice's key for 2-of-2 spending |
| `"receiver_stage1"` | Charlie's key for 2-of-2 spending |
| `"sender_stage1_refund"` | Alice's refund key (unlinkable to 2-of-2) |
| `"sender_stage2"` | Alice's key for spending stage 1 outputs |
| `"receiver_stage2"` | Charlie's key for spending stage 1 outputs |

### Funding Token Structure

```
Secret: P2PK with SIG_ALL flag
  - data: Alice's blinded pubkey (sender_stage1)
  - pubkeys: [Charlie's blinded pubkey (receiver_stage1)]
  - refund_keys: [Alice's blinded refund pubkey (sender_stage1_refund)]
  - locktime: Unix timestamp
  - sigflag: SIG_ALL (signatures cover inputs AND outputs)
```

## Universal Bridge Architecture

To make Spilman channels adoptable across different tech stacks, we use a **"Pure Brain + Language Bridges"** model.

### The Core (Rust)

The Spilman logic is implemented as a structured **Protocol Bridge** (`SpilmanBridge`):

- **Input**: Payment Request JSON + Context JSON
- **Output**: `PaymentResponse` (200 OK or 402 Error with metadata)
- **Portability**: Compiles to WASM (JS/TS) and FFI (Python/Go)

### The SpilmanHost Trait

The bridge delegates policy decisions to the host application:

```rust
trait SpilmanHost {
    // Is this pubkey our server's key?
    fn receiver_key_is_acceptable(&self, pubkey: &str) -> bool;
    
    // Is this mint/keyset allowed?
    fn mint_and_keyset_is_acceptable(&self, mint: &str, keyset: &str) -> bool;
    
    // How much does this request cost?
    fn get_amount_due(&self, channel_id: &str, context: Option<&str>) -> u64;
    
    // Atomically record payment and update usage
    fn record_payment(&self, channel_id: &str, balance: u64, sig: &str, context: &str);
    
    // Storage hooks
    fn get_funding(&self, channel_id: &str) -> Option<FundingData>;
    fn save_funding(&self, channel_id: &str, data: FundingData);
    
    // Channel state
    fn is_closed(&self, channel_id: &str) -> bool;
    fn get_channel_policy(&self) -> ChannelPolicy;
    fn now_seconds(&self) -> u64;
}
```

### Language Bridges

Each language implements the `SpilmanHost` trait/interface:

| Language | Bridge Location | Example |
|----------|-----------------|---------|
| **TypeScript** | `cdk-wasm` | CashuTube (Blossom server) |
| **Python** | `cdk-spilman-python` | ASCII art demo |
| **Go** | `cdk-spilman-go` | Go demo server |

The security-critical logic (DLEQ, signatures, channel ID) stays in Rust.

## Channel Lifecycle

### 1. Channel Setup

```
Alice                                Charlie
  |                                     |
  |  GET /channel/params                |
  |------------------------------------>|
  |  {receiver_pubkey, pricing, ...}    |
  |<------------------------------------|
  |                                     |
  |  [Compute shared_secret via ECDH]   |
  |  [Generate channel_id]              |
  |  [Create funding token]             |
  |  [Mint/swap to get proofs]          |
```

### 2. Payments

```
Alice                                Charlie
  |                                     |
  |  GET /blob/xyz                      |
  |  X-Cashu-Channel: {                 |
  |    channel_id, balance, signature,  |
  |    params?, funding_proofs?         |
  |  }                                  |
  |------------------------------------>|
  |                                     |
  |  [Verify signature]                 |
  |  [Check balance >= amount_due]      |
  |  [Record payment atomically]        |
  |                                     |
  |  200 OK + blob data                 |
  |  X-Cashu-Channel: {confirmation}    |
  |<------------------------------------|
```

### 3. Channel Closing

```
Alice                                Charlie                              Mint
  |                                     |                                   |
  |  POST /channel/:id/close            |                                   |
  |  {balance, signature}               |                                   |
  |------------------------------------>|                                   |
  |                                     |                                   |
  |                    [Verify balance == amount_due]                       |
  |                    [Create 2-of-2 signed swap request]                  |
  |                                     |                                   |
  |                                     |  POST /v1/swap                    |
  |                                     |  {inputs: funding, outputs: P2PK} |
  |                                     |---------------------------------->|
  |                                     |                                   |
  |                                     |  {signatures: blind_sigs}         |
  |                                     |<----------------------------------|
  |                                     |                                   |
  |                    [Unblind signatures]                                 |
  |                    [Verify DLEQ proofs]                                 |
  |                    [Store receiver proofs]                              |
  |                                     |                                   |
  |  {success, sender_proofs}           |                                   |
  |<------------------------------------|                                   |
```

## Core Rust Files

| File | Purpose |
|------|---------|
| `spilman/params.rs` | `ChannelParameters`, channel ID derivation, P2BK key derivation |
| `spilman/keysets_and_amounts.rs` | Fee calculations, amount decomposition |
| `spilman/deterministic.rs` | Deterministic blinded output generation |
| `spilman/balance_update.rs` | Balance update messages and Schnorr signatures |
| `spilman/sender_and_receiver.rs` | `SpilmanChannelSender`, `SpilmanChannelReceiver`, `verify_valid_channel` |
| `spilman/established_channel.rs` | `EstablishedChannel` state container |
| `spilman/bridge.rs` | `SpilmanBridge` and `SpilmanHost` trait |
| `spilman/bindings.rs` | FFI-friendly wrapper functions |
| `spilman/tests.rs` | Integration tests against real mint |

## Future Work

### Two-Stage Channel Closing

Currently, the closing logic is spread across server code and multiple WASM functions. A cleaner approach:

**Stage 1: `close_stage1()`** - Validation & Swap Preparation
- Verify Alice's signature
- Verify `balance === get_amount_due()`
- Output: Prepared swap request JSON

**Stage 2: `close_stage2()`** - Settle & Finalize
- Unblind mint's signatures
- Verify DLEQ proofs
- Call `mark_closed()` host hook
- Output: Sender proofs (Alice's change)

### Keyset Rotation Handling

When `initializeChannelKeysets()` refreshes, deactivated keysets are removed from cache. Existing channels using those keysets will fail validation. Possible solutions:
- Keep old keysets indefinitely
- Store keyset info per-channel in `channelFunding`
- Query mint on-demand for unknown keysets
