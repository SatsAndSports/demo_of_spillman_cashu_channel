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

### ASCII Art Demos (Rust/TypeScript/Python/Go)

Minimal pay-per-character demos across all four languages. Each has a server
and a client. The client supports `--close` to cooperatively close the channel.

Rust (port 5003):

```bash
PORT=5003 MINT_URL=http://localhost:3338 cargo run -p rust-ascii-art
```

TypeScript (port 5001):

```bash
make build-wasm
cd examples/ts-ascii-art
npm install
npm run server
npm run client -- "Hello World" --close
```

Python (port 5000):

```bash
make -C crates/cdk-spilman-python build
cd examples/python-ascii-art
pip install -r requirements.txt
pip install -e ../../integration-kits/python
python server.py
python client.py "Hello World" --close
```

Go (port 5001):

```bash
cargo build -p cdk-spilman-go
cd examples/go-ascii-art
go run -tags spilman_dev . server
go run -tags spilman_dev . client "Hello World" --close
```

## Architecture

The core Spilman logic lives in Rust (`crates/cdk/src/spilman/`) and is exposed via:

| Binding | Location | Use Case |
|---------|----------|----------|
| **WASM** | `crates/cdk-wasm/` | Browser clients, Node.js servers |
| **TS Kit** | `integration-kits/ts/` | Express.js servers (drop-in router) |
| **Python Kit** | `integration-kits/python/` | Flask/FastAPI servers |
| **Go Kit** | `integration-kits/go/` | Standard library HTTP servers |
| **Python Bindings** | `crates/cdk-spilman-python/` | PyO3 bindings |
| **Go Bindings** | `crates/cdk-spilman-go/` | CGO bindings |

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

### Containerized Testing (No Local Rust Required)

If you don't have Rust installed, you can run tests using Podman or Docker (recommended for VPS/Laptop).

**Note for Raspberry Pi/Raspiblitz:** Containerized tests are not supported due to cgroup restrictions. Please use [Native Development](SPILMAN_DEVELOPMENT.md#native-development-recommended-for-pi) instead.

```bash
# Using Podman (default)
make test-rust-only-containerized

# Using Docker
make test-rust-only-containerized CONTAINER_ENGINE=docker
```

This builds a development container with the Rust toolchain and runs the integration tests in isolation. Uses host networking on ports 33380 (mint) and 50080 (server). Configuration is in `docker-compose.spilman.yml`. See [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) for details.

## Project Structure

```
cdk/
├── crates/
│   ├── cdk/src/spilman/           # Core protocol implementation
│   ├── cdk-wasm/                   # WASM bindings
│   ├── cdk-spilman-python/         # Python bindings (PyO3)
│   └── cdk-spilman-go/             # Go bindings (CGO)
├── integration-kits/
│   ├── ts/                         # TypeScript/Express integration kit
│   ├── python/                     # Python integration kit
│   └── go/                         # Go integration kit
├── containers/                     # Podman/Docker dev environment
├── examples/
│   ├── rust-ascii-art/             # Rust demo (native, uses core cdk)
│   ├── ts-ascii-art/               # TypeScript demo server + client
│   ├── python-ascii-art/           # Python demo server + client
│   └── go-ascii-art/               # Go demo server + client
├── web/
│   └── blossom-server/             # CashuTube demo
└── dev-mint/                       # Mint dev config
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Protocol design, P2BK privacy, bridge architecture |
| [INTEGRATION.md](INTEGRATION.md) | Server integration guide and host/bridge API |
| [CASHUTUBE.md](CASHUTUBE.md) | Video streaming demo, API reference, HLS encoding |
| [SPILMAN_DEVELOPMENT.md](SPILMAN_DEVELOPMENT.md) | Development setup, running mints, testing |

## How It Works

1. **Channel Setup**: Alice and Charlie derive a shared secret via ECDH. Alice creates a funding token with 2-of-2 spending conditions.

2. **Payments**: For each request, Alice signs a balance update message. Charlie verifies the signature and serves the content.

3. **Closing**: Charlie submits the funding token + balance update to the mint, receiving proofs for his share. Alice gets her change.

4. **Privacy**: All pubkeys in the funding token are blinded, preventing the mint from linking channels to identities.

## Status

This is experimental software. The protocol works but:
- Storage is pluggable (in-memory or SQLite); demos default to memory
- Some edge cases around keyset rotation need handling

See the TODO section in [AGENTS.md](AGENTS.md) for active work items.

## License

MIT License - see [LICENSE](LICENSE)

## Acknowledgments

Built on [CDK](https://github.com/cashubtc/cdk) by the Cashu community.
