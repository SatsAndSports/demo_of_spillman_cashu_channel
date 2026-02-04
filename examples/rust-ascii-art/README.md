# Rust ASCII Art Server

A demo server implementing Spilman payment channels in Rust using Axum.

This example demonstrates how to build a Spilman channel server using the `cdk` crate with minimal dependencies.

## Features

- Pay-per-character ASCII art generation
- Spilman payment channels (unidirectional, sender-to-receiver)
- Cooperative and unilateral channel closing
- Multi-unit support (sat, msat, usd)

## Usage

### Using the Makefile

```bash
# Show available commands
make help

# Build the server
make build

# Run the server (requires mint at localhost:3338)
make run-server

# Run with custom mint URL
MINT_URL=http://my-mint:3338 make run-server
```

### Manual Commands

```bash
# Build
cargo build -p rust-ascii-art --release

# Run
MINT_URL=http://localhost:3338 PORT=5003 cargo run -p rust-ascii-art
```

## Testing

Integration tests require a Cashu mint running:

```bash
# Start a mint (from CDK repo root)
cargo run -p cdk-mintd --features fakewallet -- --config dev-mint/config.dev.toml --work-dir dev-mint

# In another terminal, run integration tests
make test-integration

# Or with custom mint URL
MINT_URL=http://my-mint:3338 make test-integration
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/channel/params` | GET | Get server pubkey and pricing info |
| `/channel/register` | POST | Pre-register a channel (balance=0) |
| `/ascii` | POST | Generate ASCII art (requires `X-Cashu-Channel` header) |
| `/channel/:id/status` | GET | Get channel status and amount due |
| `/channel/:id/close` | POST | Close channel cooperatively |
| `/channel/:id/unilateral-close` | POST | Server-initiated close |

## Minimal Dependencies

This example uses `cdk` with `default-features = false`, which significantly reduces the dependency tree:

```toml
[dependencies]
cdk = { version = "0.14", default-features = false }
```

This pulls in only the core Cashu types and Spilman implementation, without the full wallet/mint code.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `PORT` | `5003` | Server port |
| `SERVER_SECRET_KEY` | (generated) | Server's secret key (hex) |

## Protocol

See [NUT-XX: Spilman Channels](https://github.com/cashubtc/nuts/pull/296) for the full protocol specification.
