# Python ASCII Art Demo - Spilman Payment Channels

This demo shows the Spilman payment channel bridge working in Python:
- **Server**: ASCII art generator that charges 1 sat per character
- **Client**: Creates a payment channel, funds it, and makes multiple paid requests

## Prerequisites

1. **Rust toolchain** - for building the Python bindings
2. **Python 3.8+**
3. **Nutshell mint** running at localhost:3338 (test mint that auto-pays invoices)

## Setup

### 1. Start Nutshell Mint

```bash
# Clone Nutshell if you haven't
git clone https://github.com/cashubtc/nutshell.git
cd nutshell
git checkout 1568e51  # Tested version

# Apply SIG_ALL patch (required for Spilman channels)
sed -ire 's/\[p.secret for p in proofs\] + \[o.B_ for o in outputs\]/[p.secret + p.C for p in proofs] + [str(o.amount) + o.B_ for o in outputs]/' cashu/mint/conditions.py

# Build and run
docker compose build mint
docker compose up mint
```

### 2. Build Python Bindings

```bash
# From the cdk repo root
cd crates/cdk-spilman-python

# Install maturin (Python/Rust build tool)
pip install maturin

# Build and install the bindings
maturin develop
```

### 3. Install Demo Dependencies

```bash
cd examples/python-ascii-art
pip install -r requirements.txt
```

## Running the Demo

### Terminal 1: Start the Server

```bash
cd examples/python-ascii-art
python server.py
```

You should see:
```
============================================================
ASCII Art Server - Spilman Payment Channel Demo
============================================================

Server pubkey: 02...
Mint URL:      http://localhost:3338
Pricing:       1 sat per character
Listening on:  http://0.0.0.0:5000

Endpoints:
  GET  http://localhost:5000/channel/params
  POST http://localhost:5000/ascii

============================================================
```

### Terminal 2: Run the Client

```bash
cd examples/python-ascii-art
python client.py Hello World Cashu
```

Or with custom messages:
```bash
python client.py "Hello World" Bitcoin Lightning
```

## Expected Output

```
============================================================
ASCII Art Client - Spilman Payment Channel Demo
============================================================

Mint URL:   http://localhost:3338
Server URL: http://localhost:5000
Messages:   ['Hello', 'World', 'Cashu']

[1/8] Fetching server params...
  Server pubkey: 02a1b2c3d4...

[2/8] Generating keypair...
  Alice pubkey: 03d4e5f6a1...

[3/8] Fetching keyset info from mint...
  Fetching keysets from http://localhost:3338...
  Found keyset: 00abcdef12...

[4/8] Computing shared secret...
  Shared secret: abcdef1234...

[5/8] Building channel parameters...
  Channel ID: 1234abcd5678...
  Capacity:   50 sat

[6/8] Creating funding outputs...
  Funding amount: 52 sat
  Blinded messages: 3

[7/8] Minting funding token...
  Requesting mint quote for 52 sat...
  Quote ID: abc123def456...
  Waiting for quote to be paid...
  Quote paid!
  Minting tokens...
  Got 3 blind signatures

[8/8] Constructing proofs...
  Got 3 proofs

============================================================
Channel funded! Making requests...
============================================================

[Request 1/3] 'Hello' (5 sat)
  Payment accepted! Balance: 5/50 sat
----------------------------------------
 _   _      _ _       
| | | | ___| | | ___  
| |_| |/ _ \ | |/ _ \ 
|  _  |  __/ | | (_) |
|_| |_|\___|_|_|\___/ 

[Request 2/3] 'World' (5 sat)
  Payment accepted! Balance: 10/50 sat
----------------------------------------
__        __         _     _ 
\ \      / /__  _ __| | __| |
 \ \ /\ / / _ \| '__| |/ _` |
  \ V  V / (_) | |  | | (_| |
   \_/\_/ \___/|_|  |_|\__,_|

[Request 3/3] 'Cashu' (5 sat)
  Payment accepted! Balance: 15/50 sat
----------------------------------------
  ____           _           
 / ___|__ _ ___| |__  _   _ 
| |   / _` / __| '_ \| | | |
| |__| (_| \__ \ | | | |_| |
 \____\__,_|___/_| |_|\__,_|

============================================================
Done! Total spent: 15 sat
Channel balance: 15/50 sat
Remaining: 35 sat
============================================================
```

## How It Works

### Server Side

1. **SpilmanBridge** - Rust bridge compiled to Python via PyO3
2. **AsciiArtHost** - Python class implementing the `SpilmanHost` interface:
   - `receiver_key_is_acceptable()` - validates server pubkey
   - `mint_and_keyset_is_acceptable()` - validates approved mints
   - `get_funding_and_params()` / `save_funding()` - channel storage
   - `get_amount_due()` - calculates pricing (1 sat per char)
   - `record_payment()` - tracks usage after successful payment

3. **Payment Flow**:
   - Client sends `X-Cashu-Channel` header with payment
   - Bridge validates signature, checks balance >= amount_due
   - On success, host records payment and server returns ASCII art

### Client Side

1. **Channel Setup**:
   - Fetches server pubkey and keyset info
   - Generates Alice keypair
   - Computes ECDH shared secret
   - Creates channel parameters

2. **Funding**:
   - Creates blinded messages for funding outputs
   - Requests mint quote (test mint auto-pays Lightning invoice)
   - Mints tokens and constructs proofs

3. **Payments**:
   - For each request, creates signed balance update
   - First request includes full params + proofs
   - Subsequent requests only need channel_id, balance, signature

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_SECRET_KEY` | `00...01` | Server's secret key (64 hex chars) |
| `MINT_URL` | `http://localhost:3338` | Cashu mint URL |
| `PORT` | `5000` | Server port |
| `SERVER_URL` | `http://localhost:5000` | Server URL (client) |

### Example with Custom Config

```bash
# Server with custom secret key
SERVER_SECRET_KEY=abcd...1234 python server.py

# Client connecting to different server
SERVER_URL=http://example.com:5000 python client.py Hello
```

## Troubleshooting

### "Cannot connect to server"
Make sure the server is running: `python server.py`

### "Cannot connect to mint"
Make sure Nutshell is running: `docker compose up mint`

### "No active sat keyset found"
The mint may not be fully initialized. Restart it and try again.

### "Quote was not paid in time"
The test mint may not be auto-paying. Check the mint logs.
