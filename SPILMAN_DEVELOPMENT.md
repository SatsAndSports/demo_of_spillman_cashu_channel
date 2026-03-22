# Spilman Channels Development Guide

This guide covers setting up the development environment for Spilman payment channels.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/cashubtc/cdk.git
cd cdk

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

### Full Suite Execution

```bash
# Run the full integration test suite - default: Podman
make test-containerized

# Using Docker instead
make test-containerized CONTAINER_ENGINE=docker
```

This command:
1. Builds the `cdk-devenv` image (Rust toolchain + dependencies)
2. Compiles all binaries inside the container
3. Starts the mint and server in isolated containers
4. Runs the integration test suite
5. Cleans up automatically

### Volume Caching

Two volumes persist between runs to speed up incremental compilation:
- `cdk_cargo-cache` - Downloaded crate dependencies
- `cdk_target-cache` - Compiled artifacts

To force a clean build:
```bash
podman volume rm cdk_cargo-cache cdk_target-cache
```

### Volume Files

| File | Purpose |
|------|---------|
| `containers/Dockerfile.devenv` | Rust toolchain image |
| `containers/mint-config.toml` | Mint configuration for containerized tests |
| `docker-compose.spilman.yml` | Service orchestration (build, mint, server, tests) |

---

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

To reset the mint, delete the database and restart:
```bash
rm dev-mint/cdk-mintd.sqlite
```

### NutMix (Go-based)

Requires Docker for PostgreSQL:

```bash
# Using helper script
./scripts/run_temporary_mint.sh nutmix 13338

# Or with custom units
NUTMIX_UNITS="sat msat usd" ./scripts/run_temporary_mint.sh nutmix 13338
```

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

---

## Building WASM

The WASM bindings are used by both browser clients and Node.js servers. The root Makefile uses sentinel-based dependency tracking for fast builds.

```bash
# Build WASM - instant if nothing changed
make build-wasm
```

Test targets automatically build/copy WASM as needed:
```bash
make test-blossom      # Builds WASM and copies to blossom-server
make test-server-ts    # Builds WASM and copies to integration-kits/ts/wasm
```

---

## Running Tests

### Rust Tests

```bash
# Spilman unit tests + Rust server integration
make test-rust-only

# Comprehensive Spilman tests (includes configurable-host and SQLite)
cargo test -p cdk --features configurable-host spilman
```

### Blossom Server Tests

From CDK root (handles mint and WASM automatically):
```bash
make test-blossom          # Uses CDK mint (default)
make test-blossom-nutmix   # Uses NutMix mint (requires Docker)
```

Or manually:
```bash
cd web/blossom-server
npm test
```

### Server Integration Tests (Rust)

The `cdk-spilman-server-integration-tests` crate validates all four server implementations (TypeScript, Rust, Python, Go).

```bash
# Test individual servers
make test-server-ts
make test-server-rust
make test-server-python
make test-server-go

# Test all servers sequentially
make test-server-all
```

---

## Directory Structure

```
cdk/
├── crates/
│   ├── cdk/src/spilman/                      # Core implementation
│   ├── cdk-spilman-server-integration-tests/ # Test client for all servers
│   ├── cdk-wasm/                             # WASM bindings (JS/TS)
│   ├── cdk-spilman-python/                   # Python bindings
│   └── cdk-spilman-go/                       # Go bindings
├── integration-kits/
│   └── ts/                                   # TypeScript kit (Express)
├── examples/
│   ├── rust-ascii-art/                       # Rust server (native)
│   ├── ts-ascii-art/                         # TypeScript server + client
│   ├── python-ascii-art/                     # Python server + client
│   └── go-ascii-art/                         # Go server + client
├── web/
│   ├── wasm-web/                  # Browser WASM output
│   ├── wasm-nodejs/               # Node.js WASM output
│   └── blossom-server/            # Video streaming demo
└── dev-mint/                      # CDK mint dev config
```

## Troubleshooting

### Orphaned Test Processes

If tests are interrupted, server and mint processes may be left running:
```bash
make kill-orphans
```

### HTTP 431 / Request Header Fields Too Large

Usually caused by high-capacity `msat` channels with many small proofs.
**Workaround**: Use a larger `maximum_amount` (e.g., 8192) when funding to reduce the proof count.
