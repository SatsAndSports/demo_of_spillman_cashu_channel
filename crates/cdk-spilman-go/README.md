# spilman-go

Go bindings for Spilman payment channels - unidirectional payment channels for Cashu ecash.

## Overview

Spilman channels allow a sender to make multiple micropayments to a receiver without requiring on-chain transactions for each payment. The sender locks funds in a channel and can incrementally transfer value to the receiver by signing balance updates. The receiver can close the channel at any time to claim their funds.

This package provides:
- **Server-side**: `Bridge` and `SpilmanHost` interface for implementing payment channel receivers
- **Client-side**: Utility functions for creating channels and signing payments

## Installation

```bash
go get github.com/cashubtc/spilman-go/spilman
```

**Note**: This package requires CGO and includes pre-built native libraries for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)  
- Windows (amd64)

## Quick Start

### Server Implementation

To accept payments, implement the `SpilmanHost` interface and create a `Bridge`:

```go
package main

import (
    "github.com/cashubtc/spilman-go/spilman"
)

// MyHost implements spilman.SpilmanHost
type MyHost struct {
    // Your storage, config, etc.
}

func (h *MyHost) ReceiverKeyIsAcceptable(pubkeyHex string) bool {
    return pubkeyHex == h.myReceiverPubkey
}

func (h *MyHost) GetAmountDue(channelId string, contextJson *string) uint64 {
    // Return the price for the requested resource
    return 10 // 10 sats
}

// ... implement other SpilmanHost methods ...

func main() {
    host := &MyHost{}
    
    // Create bridge (generates receiver key if empty string provided)
    bridge := spilman.NewBridge(host, "")
    defer bridge.Free()
    
    // Process incoming payment
    result, err := bridge.ProcessPayment(paymentJson, contextJson)
    if err != nil {
        // Payment failed - return 402 Payment Required
    }
    // Payment succeeded - serve the content
}
```

### Client Usage

```go
package main

import (
    "github.com/cashubtc/spilman-go/spilman"
)

func main() {
    // Generate a keypair for the channel
    secret, pubkey, _ := spilman.GenerateKeypair()
    
    // Compute shared secret with receiver's pubkey (for deterministic blinding)
    channelSecret, _ := spilman.ComputeChannelSecret(secret, receiverPubkey)
    
    // Create a signed balance update
    signature, _ := spilman.CreateSignedBalanceUpdate(
        paramsJson,
        keysetJson, 
        channelSecret,
        proofsJson,
        balance,
    )
}
```

## SpilmanHost Interface

The `SpilmanHost` interface defines callbacks for policy and storage:

```go
type SpilmanHost interface {
    // Policy
    ReceiverKeyIsAcceptable(pubkeyHex string) bool
    MintAndKeysetIsAcceptable(mint string, keysetId string) bool
    GetChannelPolicy() string
    NowSeconds() uint64
    GetAmountDue(channelId string, contextJson *string) uint64
    
    // Storage
    GetFundingAndParams(channelId string) (paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, ok bool)
    SaveFunding(channelId, paramsJson, proofsJson, channelSecretHex, keysetInfoJson string, initialBalance uint64, initialSignature string)
    RecordPayment(channelId string, balance uint64, signature, contextJson string)
    GetBalanceAndSignatureForUnilateralExit(channelId string) (balance uint64, signature string, ok bool)
    
    // Channel lifecycle
    GetChannelState(channelId string) string  // "open", "closing", "closed"
    MarkChannelClosing(channelId string, locktime, balance uint64, signature string) error
    GetClosingData(channelId string) *ClosingData
    MarkChannelClosed(channelId string, locktime, balance uint64, receiverProofsJson, senderProofsJson string, receiverSum, senderSum uint64) error
    
    // Mint communication
    GetActiveKeysetIds(mint, unit string) []string
    GetKeysetInfo(mint, keysetId string) (string, bool)
    CallMintSwap(mintUrl, swapRequestJson string) (string, error)
    RefreshAllKeysets(mintUrl string) error

    // Cryptographic operations
    ComputeChannelSecret(alicePubkeyHex, charliePubkeyHex string) (string, error)
    SignWithTweakedKey(signerPubkeyHex, messageHex, tweakScalarHex string) (string, error)
}
```

See [host.go](spilman/host.go) for full documentation of each method.

## Bridge Methods

| Method | Description |
|--------|-------------|
| `NewBridge(host, secretKey)` | Create a new bridge with the given host |
| `Free()` | Release bridge resources |
| `ProcessPayment(payment, context)` | Validate and record a payment |
| `ValidatePayment(payment, context)` | Validate without recording |
| `FundChannel(payment)` | Register a new channel |
| `ExecuteCooperativeClose(payment)` | Close channel cooperatively |
| `ExecuteUnilateralClose(channelId)` | Server-initiated close |

## Client Functions

| Function | Description |
|----------|-------------|
| `GenerateKeypair()` | Generate a new secp256k1 keypair |
| `SecretKeyToPubkey(secret)` | Derive public key from secret |
| `ComputeChannelSecret(mySecret, theirPubkey)` | Compute channel secret (hashed ECDH) |
| `CreateSignedBalanceUpdate(...)` | Create signed payment |
| `CreateFundingOutputs(...)` | Create blinded outputs for funding |
| `ConstructProofs(...)` | Construct proofs from mint response |
| `ChannelParametersGetChannelId(...)` | Compute channel ID |

## Examples

See the [examples/go-ascii-art](examples/go-ascii-art) directory for a complete server implementation.

## Building from Source

If you need to build the native library yourself:

```bash
# Clone the CDK repository
git clone https://github.com/cashubtc/cdk
cd cdk

# Build the native library for your platform
./scripts/build-go-libs.sh

# The library will be in crates/cdk-spilman-go/packaged/lib/{platform}/
```

### Cross-compilation

To build for other platforms, install [cross](https://github.com/cross-rs/cross):

```bash
cargo install cross

# Build all platforms
./scripts/build-go-libs.sh all
```

## Development

For development without pre-built libraries, use the `spilman_dev` build tag:

```bash
# Build the Rust library
cargo build -p cdk-spilman-go

# Run with dev tag and library path
LD_LIBRARY_PATH=./target/debug go run -tags spilman_dev .
```

## Testing

This package includes a standalone Makefile for testing.

### Unit Tests (no external dependencies)

```bash
make test
```

Unit tests verify the core functionality using the packaged static libraries.
No mint or external services required.

### Integration Tests

Integration tests require a Cashu mint running. Start a mint, then:

```bash
# With default mint at localhost:3338
make test-integration

# With custom mint URL
MINT_URL=http://my-mint:3338 make test-integration
```

### Development Testing

If you're building from the CDK source repository (requires Rust):

```bash
make test-dev              # Unit tests with local debug build
make test-integration-dev  # Integration tests with local debug build
```

### Full Integration Suite

The comprehensive 52-test integration suite is run from the CDK root:

```bash
# From CDK repository root
make test-server-go
```

## Protocol

Spilman channels use the Cashu protocol with P2BK (Pay-to-Blinded-Key) spending conditions for deterministic output generation. See [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) for the full protocol specification.

## License

MIT
