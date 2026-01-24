# Spilman Channels Development Guide

This guide covers setting up the development environment for Spilman payment channels.

## Quick Start

```bash
# Clone the repo
git clone git@github.com:SatsAndSports/demo_of_spillman_cashu_channel.git
cd demo_of_spillman_cashu_channel
git checkout spilman.channel

# Run the Spilman-specific tests
cargo test -p cdk spilman
```

## Running a Mint

The demos and tests require a Cashu mint. Choose one of:

### CDK Mint (Recommended)

The easiest option with a pre-configured development setup:

```bash
# Build with fakewallet (auto-pays invoices for testing)
cargo build -p cdk-mintd --features fakewallet

# Start the mint
./target/debug/cdk-mintd --config dev-mint/config.dev.toml --work-dir dev-mint
```

The dev config uses a fixed mnemonic for reproducible keyset IDs:
- **sat keyset:** `001b6c716bf42c7e`
- **msat keyset:** `00ffedc2dbb87212`
- **usd keyset:** `00818d176a78e7f0`

**Database location:** `dev-mint/cdk-mintd.sqlite`

To reset the mint, delete the database and restart.

### NutMix (Go-based)

Requires Docker for PostgreSQL:

```bash
# Using helper script (recommended)
./scripts/run_temporary_mint.sh nutmix 13338

# Or with custom units
NUTMIX_UNITS="sat msat usd" ./scripts/run_temporary_mint.sh nutmix 13338
```

The script handles Docker setup, keyset creation, and cleanup automatically.

### Nutshell (Python-based)

```bash
git clone https://github.com/cashubtc/nutshell.git
cd nutshell
git checkout 1568e51  # Tested version (0.18.2)

# Apply SIG_ALL message update
sed -ire 's/\[p.secret for p in proofs\] + \[o.B_ for o in outputs\]/[p.secret + p.C for p in proofs] + [str(o.amount) + o.B_ for o in outputs]/' cashu/mint/conditions.py

docker compose build mint
docker compose up mint
```

## Building WASM

The WASM bindings are used by both browser clients and Node.js servers:

```bash
cd web/blossom-server/

# Fast build (~2s) - for development
make wasm-dev

# Optimized build (~32s) - for production
make wasm

# Build TypeScript project
make build

# Start development server
make dev

# Clean WASM directories
make clean
```

## Running Tests

### Rust Tests

```bash
# All CDK tests
cargo test -p cdk

# Spilman-specific tests (includes mint integration)
cargo test -p cdk spilman

# Clippy checks
cargo clippy -p cdk -p cdk-wasm -p cdk-spilman-python -p cdk-spilman-go -- -D warnings
```

### Blossom Server Tests

Requires a mint running at `localhost:3338`:

```bash
cd web/blossom-server

npm test                           # All tests
npm test -- tests/payment.test.ts  # Specific file

# Or via Makefile
make test       # Tests only
make test-full  # Build WASM + tests
```

Test coverage includes:
- `blobs.test.ts` - Upload, fetch (402), HEAD, 404
- `channel.test.ts` - `/channel/params` endpoint
- `minting.test.ts` - Funding token creation, DLEQ verification
- `payment.test.ts` - Full payment flow, channel closing

### Python Demo Tests

```bash
cd examples/python-ascii-art

# Install dependencies
pip install -r requirements.txt
pip install maturin

# Build Python bindings
cd ../../crates/cdk-spilman-python
maturin develop

# Run demo (requires mint at localhost:3338)
cd ../../examples/python-ascii-art
python server.py &
python client.py
```

### Go Demo Tests

```bash
# Build Go bindings
make build-go

# Run parallel test
make test-go-parallel
```

## Setting Up Blossom Server

```bash
cd web/
git clone git@github.com:SatsAndSports/blossom-server.git
cd blossom-server
git checkout spilman.channel

# Build WASM and copy to server
cd ..  # back to web/
make wasm

# Install and build
cd blossom-server
npx pnpm install
npx pnpm build

# Run
npx pnpm start
```

The server runs on `http://localhost:3000` by default.

## Directory Structure

```
cdk/
├── crates/
│   ├── cdk/src/spilman/          # Core Spilman implementation
│   ├── cdk-wasm/                  # WASM bindings (browser + Node.js)
│   ├── cdk-spilman-python/        # PyO3 bindings
│   └── cdk-spilman-go/            # CGO bindings
├── examples/
│   └── python-ascii-art/          # Python demo server + client
├── web/
│   ├── Makefile                   # WASM build targets
│   ├── wasm-web/                  # Browser WASM output
│   ├── wasm-nodejs/               # Node.js WASM output
│   └── blossom-server/            # CashuTube server + player
└── dev-mint/                      # CDK mint dev config
```

## Baseline Commits

For reviewing Spilman-specific changes:

- **CDK repo:** `4a505bae` (origin/main)
- **Blossom-server repo:** `5d84316`

```bash
# See all Spilman changes
git diff 4a505bae --stat
```

## Conventions

- **Line endings:** LF (Unix style), not CRLF
- **Default mint:** `http://localhost:3338`
- **Blossom server:** Port 3000
- **Test server:** Port 3099

## Troubleshooting

### Mint database issues

If keyset IDs change unexpectedly:
```bash
rm dev-mint/cdk-mintd.sqlite
# Restart mint
```

### WASM build fails

Ensure wasm-pack is installed:
```bash
cargo install wasm-pack
```

### Python bindings won't build

Ensure maturin is installed:
```bash
pip install maturin
```

### Go bindings won't build

Ensure CGO is enabled:
```bash
CGO_ENABLED=1 go build
```
