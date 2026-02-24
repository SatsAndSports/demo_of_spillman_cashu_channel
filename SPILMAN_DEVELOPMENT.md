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

## Native Development (Recommended for Pi)

For environments like **Raspiblitz/Raspberry Pi** where containerization is restricted, we recommend a native Rust installation.

### User-Only Rust Installation

If your system has a locked-down system-wide Rust (like `/opt/rust` on Raspiblitz), you can install a private copy for your user:

```bash
# Set install locations to your home directory
export RUSTUP_HOME="$HOME/.rustup"
export CARGO_HOME="$HOME/.cargo"

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add to your PATH
source "$HOME/.cargo/env"
```

Then run tests as usual:
```bash
make test-rust-only
```

## Containerized Development (No Local Rust Required)

For developers without a local Rust toolchain, or for reproducible builds, you can run everything in containers using Podman or Docker.

### Prerequisites

**Podman:**
- Podman 4.0+ and podman-compose
- **Note:** Containerized tests are not supported on **Raspiblitz/Raspberry Pi** due to cgroup restrictions. Pi users should use [Native Development](#native-development-recommended-for-pi) instead.

**Docker:**
- Docker 20.10+ with Docker Compose v2 (`docker compose`)
- User must be in the `docker` group: `sudo usermod -aG docker $USER`

### Quick Start

```bash
# Run the full integration test suite (52 tests) - default: Podman
make test-containerized

# Using Docker instead
make test-containerized CONTAINER_ENGINE=docker
```

This single command:
1. Builds the `cdk-devenv` image (Rust toolchain + dependencies)
2. Compiles all binaries inside the container
3. Starts the mint and server in isolated containers
4. Runs 52 integration tests
5. Cleans up automatically

### How It Works

The setup uses a **devenv** approach:
- One image (`cdk-devenv`) contains the Rust toolchain
- Source code is volume-mounted from your host
- Build artifacts are cached in container volumes (`cargo-cache`, `target-cache`)
- Incremental compilation works across runs

### Commands

```bash
# Build the devenv image (first time, or after rust-toolchain.toml changes)
make build-devenv
make build-devenv CONTAINER_ENGINE=docker  # For Docker

# Run integration tests
make test-rust-only-containerized
make test-rust-only-containerized CONTAINER_ENGINE=docker  # For Docker

# Clean up everything (containers, volumes, image)
make clean-containers
make clean-containers CONTAINER_ENGINE=docker  # For Docker

# Check disk usage (Podman)
podman system df

# Reclaim space (Podman)
podman system prune -a --volumes
```

### Volume Caching

Two Podman volumes persist between runs:
- `cdk_cargo-cache` - Downloaded crate dependencies
- `cdk_target-cache` - Compiled artifacts

This means subsequent builds are fast (incremental compilation). To force a clean build:

```bash
podman volume rm cdk_cargo-cache cdk_target-cache
```

### Files

| File | Purpose |
|------|---------|
| `containers/Dockerfile.devenv` | Rust toolchain image |
| `containers/mint-config.toml` | Mint configuration for containerized tests |
| `docker-compose.spilman.yml` | Service orchestration (build, mint, server, tests) |

### VPS / Cloud Environments

The containerized tests use **host networking** (`--network=host`) to work on VPS and cloud environments where bridge networking may be restricted (common with OpenVZ, LXC, or security-hardened providers like Njalla).

**Port assignments:**
- Mint: **33380**
- Rust ASCII Art Server: **50080**

The Makefile automatically checks that these ports are available before starting tests. If they're in use, you'll see:
```
ERROR: Required ports are already in use. Free ports 33380 and 50080 and try again.
```

To free the ports:
```bash
# Find what's using the ports
lsof -i :33380
lsof -i :50080

# Kill those processes or wait for them to finish
```

If you need to use different ports, edit `docker-compose.spilman.yml` and update:
- `CDK_MINTD_LISTEN_PORT` environment variable
- `PORT` environment variable for the server
- Health check URLs
- Test environment variables (`MINT_URL`, `SERVER_URL`)

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
make build-wasm

# The sentinel file .wasm-built tracks when WASM was last built
# Only rebuilds if these change:
#   - crates/cdk/src/**/*.rs
#   - crates/cdk-wasm/src/**/*.rs  
#   - Cargo.toml, Cargo.lock
```

Test targets automatically build/copy WASM as needed:

```bash
make test-blossom      # Builds WASM if needed, copies to blossom-server, runs tests
make test-server-ts    # Builds WASM if needed (examples/ts-ascii-art uses symlink), runs tests
```

### WASM distribution

- **examples/ts-ascii-art**: Uses symlink (`src/wasm` → `../../../web/wasm-nodejs`) - always uses latest
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
# Quick: Spilman unit tests + Rust server integration
make test-rust-only

# Spilman-specific unit tests (includes mint integration)
# Now includes all configurable-host and SQLite tests by default
cargo test -p cdk --features configurable-host spilman

# All CDK tests
cargo test -p cdk
```

### Blossom Server Tests

From CDK root (recommended - handles mint and WASM automatically):

```bash
make test-blossom          # Uses CDK mint (default)
make test-blossom-nutmix   # Uses NutMix mint (requires Docker)
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

### Server Integration Tests (Rust)

The `cdk-spilman-server-integration-tests` crate provides a comprehensive Rust test client (52 tests) that validates all four server implementations (TypeScript, Rust, Python, Go).

```bash
# Test individual servers
make test-server-ts        # Test TypeScript server (52 tests)
make test-server-rust      # Test Rust server (52 tests)
make test-server-python    # Test Python server (52 tests)
make test-server-go        # Test Go server (52 tests)

# Test all servers
make test-server-all       # Runs all four above sequentially
```

Tests run in parallel by default using `tokio::sync::OnceCell` for thread-safe lazy initialization of the shared mint and server processes.

Test coverage includes:
- `channel_params` - `/channel/params` endpoint (pricing, keysets, receiver pubkey)
- `channel_status` - `/channel/:id/status` endpoint
- `channel_register` - Pre-registration with balance=0
- `minting` - Funding token creation with deterministic outputs
- `verification` - DLEQ verification, keyset tampering detection
- `payment` - Payment flow, sat/msat/usd units
- `validation` - Invalid signatures, balance errors, tampered DLEQ, locktime
- `closing` - Cooperative close, idempotent close, error cases
- `unilateral_closing` - Server-initiated close, overpayment handling

### Go Integration Tests

The Go bindings (`cdk-spilman-go`) include both unit tests and integration tests (the latter require a running mint):

```bash
# Unit tests (no mint needed)
make test-unit-go

# Integration tests (starts mint automatically)
make test-integration-go
```

The integration tests cover standalone functions (keypair generation, channel secret, funding outputs, channel ID) and the full `ClientBridge` end-to-end flow (mint proofs, open channel, sign payments, server-side validation).

### Python Integration Tests

The Python bindings (`cdk-spilman-python`) include integration tests that require a running mint:

```bash
# Integration tests (starts mint automatically, builds Python wheel)
make test-integration-python
```

The tests cover standalone functions (keypair generation, channel secret, funding outputs) and the full `ClientBridge` end-to-end flow, including server-side validation with a `MockServerHost`.

### Rust ASCII Art Server

The Rust ASCII Art server (`examples/rust-ascii-art/`) uses `ConfigurableHost` with a YAML config file and the library-provided Axum router — no manual route handlers for channel management are needed. Pricing and policy are defined in `config.yaml`.

```bash
# Build
cargo build -p rust-ascii-art

# Run tests
make test-server-rust

# Run manually (requires mint at localhost:3338)
PORT=5003 MINT_URL=http://localhost:3338 cargo run -p rust-ascii-art
```

The server consists of:
- `config.yaml` — YAML pricing config (usage variables: `chars`)
- `main.rs` — Loads YAML, constructs `ConfigurableHost`, and merges the management router.
- `routes.rs` — Contains only the business logic (`/ascii`) and the `nest()` call for the library router.

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

**Note:** This is a proof-of-concept demonstrating Go bindings. For comprehensive test coverage, see the server integration tests above.

```bash
# Build Go bindings
make build-go

# Run parallel test
make test-go-parallel
```

### Running All Tests

```bash
# Quick: Spilman unit tests + Rust server integration
make test-rust-only

# Everything except blossom: unit tests + Go/Python integration + all 4 server suites
make test-all

# Everything including blossom (requires web/blossom-server repo)
make test-all-with-blossom
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
│   ├── cdk/src/spilman/                      # Core Spilman implementation
│   ├── cdk-spilman-server-integration-tests/ # Rust test client for all servers
│   ├── cdk-wasm/                             # WASM bindings (browser + Node.js)
│   ├── cdk-spilman-python/                   # PyO3 bindings
│   └── cdk-spilman-go/                       # CGO bindings
├── examples/
│   ├── rust-ascii-art/                       # Rust ASCII Art server (native)
│   ├── ts-ascii-art/                         # TypeScript demo server + client
│   ├── python-ascii-art/                     # Python demo server + client
│   └── go-ascii-art/                         # Go demo server + client
├── web/
│   ├── wasm-web/                  # Browser WASM output
│   ├── wasm-nodejs/               # Node.js WASM output
│   └── blossom-server/            # CashuTube server + player
└── dev-mint/                      # CDK mint dev config
```

## Baseline Commits

For reviewing Spilman-specific changes:

- **CDK repo:** `origin/main`
- **Blossom-server repo:** `origin/master` (in `web/blossom-server/`)

```bash
# See all CDK Spilman changes
git diff origin/main --stat

# See all blossom-server Spilman changes
cd web/blossom-server && git diff origin/master --stat
```

## Conventions

- **Line endings:** LF (Unix style), not CRLF
- **Default mint:** `http://localhost:3338`
- **Blossom server:** Port 3000
- **Test server:** Port 3099

## Troubleshooting

### Orphaned Test Processes

If tests are interrupted (Ctrl+C, timeout, panic), server and mint processes may be left running:

```bash
# List orphaned processes
make list-orphans

# Kill them all
make kill-orphans
```

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
