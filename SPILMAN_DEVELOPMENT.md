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

The WASM bindings are used by both browser clients and Node.js servers.

### From CDK root (recommended)

The root Makefile uses **sentinel-based dependency tracking** for fast incremental builds:

```bash
# Build WASM - instant if nothing changed, ~3-6s if rebuild needed
make wasm-dev

# The sentinel file .wasm-dev-built tracks when WASM was last built
# Only rebuilds if these change:
#   - crates/cdk/src/**/*.rs
#   - crates/cdk-wasm/src/**/*.rs  
#   - Cargo.toml, Cargo.lock
```

Test targets automatically build/copy WASM as needed:

```bash
make test-blossom-cdk    # Builds WASM if needed, copies to blossom-server, runs tests
make test-ts-ascii-cdk   # Builds WASM if needed (ts-ascii-art uses symlink), runs tests
```

### WASM distribution

- **ts-ascii-art**: Uses symlink (`src/wasm` → `../../../web/wasm-nodejs`) - always uses latest
- **blossom-server**: Gets WASM copied (separate git repo, can't use symlinks)

### From blossom-server directory

```bash
cd web/blossom-server/

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

From CDK root (recommended - handles mint and WASM automatically):

```bash
make test-blossom-cdk     # Uses CDK mint
make test-blossom-nutmix  # Uses NutMix mint (requires Docker)
```

Or manually with a mint running at `localhost:3338`:

```bash
cd web/blossom-server
npm test                           # All tests
npm test -- tests/payment.test.ts  # Specific file
```

Test coverage includes:
- `blobs.test.ts` - Upload, fetch (402), HEAD, 404
- `channel.test.ts` - `/channel/params` endpoint
- `minting.test.ts` - Funding token creation, DLEQ verification
- `payment.test.ts` - Full payment flow, channel closing

### TypeScript ASCII Art Tests

The ts-ascii-art example has a comprehensive test suite (36 tests) and serves as the **reference implementation** for the ASCII Art demo pattern.

#### Cross-Server Verification
Since all three servers (TS, Python, Go) use the same Rust core, we use the TS test suite to validate all of them:

```bash
make test-python-via-ts-cdk  # Runs TS tests against Python server
make test-go-via-ts-cdk      # Runs TS tests against Go server
```

From CDK root (recommended - handles mint and WASM automatically):

```bash
make test-ts-ascii-cdk     # Uses CDK mint
make test-ts-ascii-nutmix  # Uses NutMix mint (requires Docker)
```

Or manually with a mint running at `localhost:3338`:

```bash
cd examples/ts-ascii-art
npm install
npm test
```

Test coverage includes:
- `channel.test.ts` - `/channel/params` and `/channel/:id/status` endpoints
- `minting.test.ts` - Funding token creation, DLEQ verification
- `payment.test.ts` - Payment flow, channel policy (minCapacity)
- `validation.test.ts` - Invalid signatures, balance errors, tampered DLEQ, locktime
- `closing.test.ts` - Cooperative close, idempotent close, error cases

### Python Demo

**Note:** This is a proof-of-concept demonstrating Python bindings. For comprehensive test coverage, see the TypeScript ASCII Art tests above.

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

### Go Demo

**Note:** This is a proof-of-concept demonstrating Go bindings. For comprehensive test coverage, see the TypeScript ASCII Art tests above.

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

### HTTP 431 / Request Header Fields Too Large
This happens when the `X-Cashu-Channel` header exceeds the server's limit (usually 16KB). This is common when funding high-capacity `msat` channels with many small proofs.

**Workaround**: Use a larger `maximumAmount` when creating the channel (e.g., 8192 instead of the default 64) to reduce the number of funding proofs.

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
