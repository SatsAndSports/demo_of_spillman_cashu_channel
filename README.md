# Spilman Channels for Cashu

> Unidirectional payment channels for Cashu ecash - enabling instant, off-chain micropayments.

This is an extension of [CDK (Cashu Development Kit)](https://github.com/cashubtc/cdk) that adds **Spilman-style payment channels**. It enables services to accept streaming micropayments without round-trip latency or on-chain settlement for each payment.

## What Are Spilman Channels?

A Spilman channel is a simple unidirectional payment channel:

1. **Alice** (payer) locks funds in a 2-of-2 multisig with **Charlie** (payee)
2. Alice signs off-chain balance updates, incrementally transferring value to Charlie
3. Charlie can close the channel anytime, settling with the mint
4. If Charlie disappears, Alice can reclaim her funds after a timeout

**Key features:**
- **Instant payments** - No mint round-trips during the channel lifetime
- **Privacy** - Blinded keys prevent the mint from correlating payments
- **Deterministic** - Both parties compute the same outputs without communication
- **Multi-language** - Core logic in Rust, with WASM/Python/Go bindings

## Demo Applications

### CashuTube (TypeScript/WASM)

A pay-per-segment video streaming service built on [Blossom](https://github.com/hzrd149/blossom) (decentralized blob storage).

```bash
# Start a mint
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# Build and run CashuTube
cd web/blossom-server
make wasm && npx pnpm install && npx pnpm start

# Open http://localhost:3000
```

See [CASHUTUBE.md](CASHUTUBE.md) for full documentation.

### Python ASCII Art (PyO3)

A minimal demo showing how to integrate Spilman payments into a Python service.

```bash
cd examples/python-ascii-art

# Install dependencies
pip install -r requirements.txt
cd ../../crates/cdk-spilman-python && maturin develop && cd -

# Run server (in one terminal)
python server.py

# Run client (in another terminal)
python client.py
```

The server charges per character of ASCII art generated. The client:
1. Creates a channel with the server
2. Funds it via Lightning invoice
3. Makes multiple requests, paying incrementally
4. Closes the channel when done

### Go Demo (CGO)

Feature-complete Go implementation with the same capabilities as Python.

```bash
# Build Go bindings
make build-go

# Run parallel test
make test-go-parallel
```

## Architecture

The core Spilman logic lives in Rust (`crates/cdk/src/spilman/`) and is exposed via:

| Binding | Location | Use Case |
|---------|----------|----------|
| **WASM** | `crates/cdk-wasm/` | Browser clients, Node.js servers |
| **Python** | `crates/cdk-spilman-python/` | Python services |
| **Go** | `crates/cdk-spilman-go/` | Go services |

Each binding implements a **SpilmanHost** interface that handles:
- Storage (channel state, proofs)
- Pricing (amount due per request)
- Policy (approved mints, minimum capacity)

The security-critical cryptography (DLEQ, Schnorr signatures, channel ID derivation) stays in Rust.

See [ARCHITECTURE.md](ARCHITECTURE.md) for protocol details.

## Quick Start

### Prerequisites

- Rust toolchain
- A Cashu mint (see below)

### Running a Mint

The easiest option is the CDK mint with the dev configuration:

```bash
# Build with fakewallet (auto-pays invoices for testing)
cargo build -p cdk-mintd --features fakewallet

# Start the mint
./target/debug/cdk-mintd --config dev-mint/config.dev.toml --work-dir dev-mint
```

The mint runs at `http://localhost:3338` with fixed keyset IDs for reproducibility.

### Running Tests

```bash
# Spilman-specific tests
cargo test -p cdk spilman

# All checks
cargo clippy -p cdk -p cdk-wasm -p cdk-spilman-python -p cdk-spilman-go -- -D warnings
```

See [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) for full setup instructions.

## Project Structure

```
cdk/
├── crates/
│   ├── cdk/src/spilman/           # Core protocol implementation
│   ├── cdk-wasm/                   # WASM bindings
│   ├── cdk-spilman-python/         # Python bindings (PyO3)
│   └── cdk-spilman-go/             # Go bindings (CGO)
├── examples/
│   └── python-ascii-art/           # Python demo
├── web/
│   └── blossom-server/             # CashuTube demo
└── dev-mint/                       # Mint dev config
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Protocol design, P2BK privacy, bridge architecture |
| [CASHUTUBE.md](CASHUTUBE.md) | Video streaming demo, API reference, HLS encoding |
| [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) | Development setup, running mints, testing |
| [SPILMAN_CHANGELOG.md](SPILMAN_CHANGELOG.md) | Completed features history |

## How It Works

1. **Channel Setup**: Alice and Charlie derive a shared secret via ECDH. Alice creates a funding token with 2-of-2 spending conditions.

2. **Payments**: For each request, Alice signs a balance update message. Charlie verifies the signature and serves the content.

3. **Closing**: Charlie submits the funding token + balance update to the mint, receiving proofs for his share. Alice gets her change.

4. **Privacy**: All pubkeys in the funding token are blinded, preventing the mint from linking channels to identities.

## Status

This is experimental software. The protocol works but:
- Server-side state is in-memory only (no persistence)
- Some edge cases around keyset rotation need handling

See the TODO section in [AGENTS.md](AGENTS.md) for active work items.

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

Built on [CDK](https://github.com/cashubtc/cdk) by the Cashu community.
