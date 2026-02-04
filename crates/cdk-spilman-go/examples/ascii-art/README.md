# ASCII Art Server Example

This example demonstrates a complete Spilman payment channel server implementation in Go.
It's a simple ASCII art generator that charges per character.

## Features

- Full SpilmanHost implementation with in-memory storage
- HTTP server with payment channel endpoints
- Client mode for testing payments
- Support for multiple currency units (sat, msat, usd)
- Cooperative and unilateral channel closing

## Running

### Prerequisites

1. A running Cashu mint (default: `http://localhost:3338`)
2. The spilman-go library built (see main README)

### Start the Server

```bash
# From this directory
go run -tags spilman_dev . server

# Or with custom settings
MINT_URL=http://localhost:3338 PORT=5001 go run -tags spilman_dev . server
```

### Run the Client

In a separate terminal:

```bash
# Generate some ASCII art
go run -tags spilman_dev . client "Hello World"

# Multiple messages use the same channel
go run -tags spilman_dev . client "First" "Second" "Third"
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/channel/params` | GET | Get server's channel parameters (receiver pubkey, pricing, policy) |
| `/channel/register` | POST | Pre-register a channel (optional, for explicit funding) |
| `/channel/{id}/status` | GET | Get channel status (balance, amount_due) |
| `/channel/{id}/close` | POST | Initiate cooperative close |
| `/channel/{id}/unilateral-close` | POST | Server-initiated unilateral close |
| `/ascii` | POST | Generate ASCII art (requires X-Cashu-Channel header) |

## Payment Flow

1. Client fetches `/channel/params` to get receiver pubkey and pricing
2. Client creates channel parameters and funds the channel via mint swap
3. Client sends requests to `/ascii` with `X-Cashu-Channel` header containing:
   - `channel_id` - identifies the channel
   - `balance` - cumulative amount spent
   - `signature` - Schnorr signature over the balance
   - `params` and `funding_proofs` - on first request only
4. Server validates payment and returns the ASCII art
5. Client can close channel via `/channel/{id}/close` to get refund

## Code Structure

The `main.go` file contains:

- `AsciiArtHost` - implements `SpilmanHost` interface
- Server HTTP handlers for all endpoints
- Client logic for channel creation and payments
- In-memory stores for channel data

This example is a good starting point for building your own payment channel server.
