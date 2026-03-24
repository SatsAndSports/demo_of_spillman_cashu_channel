# CDK Mintd

[![crates.io](https://img.shields.io/crates/v/cdk-mintd.svg)](https://crates.io/crates/cdk-mintd)
[![Documentation](https://docs.rs/cdk-mintd/badge.svg)](https://docs.rs/cdk-mintd)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cashubtc/cdk/blob/main/LICENSE)

> **Warning**
> This project is in early development, it does however work with real sats! Always use amounts you don't mind losing.

Cashu mint daemon implementation for the Cashu Development Kit (CDK). In this repo it is maintained primarily as a local fakewallet+sqlite dev mint for Spilman testing.

## Features

- **SQLite dev database**: lightweight local storage for test runs
- **FakeWallet backend**: auto-paid mint quotes for deterministic local testing
- **Multi-unit support**: local test mint is configured for `sat`, `msat`, and `usd`
- **HTTP mint API**: served via `cdk-axum`
- **Docker/test support**: ready-to-use local developer workflows

## Installation

### Option 1: Download Pre-built Binary

Statically-linked x86_64 Linux binaries are published to each [GitHub release](https://github.com/cashubtc/cdk/releases). These have zero runtime dependencies and run on any x86_64 Linux system.

Each release also includes a `SHA256SUMS` file to verify downloads:

```bash
# Download the binary and checksums
curl -LO https://github.com/cashubtc/cdk/releases/latest/download/cdk-mintd-{version}-x86_64
curl -LO https://github.com/cashubtc/cdk/releases/latest/download/SHA256SUMS

# Verify the checksum
sha256sum -c SHA256SUMS --ignore-missing

# Make executable and run
chmod +x cdk-mintd-*-x86_64
./cdk-mintd-*-x86_64 --help
```

To build static binaries locally, see the [Static Binaries](../../DEVELOPMENT.md#static-binaries) section in the Development Guide.

### Option 2: Build from Source

This project uses [Nix](https://nixos.org/) to manage development dependencies.

```bash
git clone https://github.com/cashubtc/cdk.git
cd cdk

# Enter lean development environment
nix develop

# Build binary used by local Spilman test flows
cargo build --bin cdk-mintd --no-default-features --features fakewallet,sqlite --release
# Binary will be at ./target/release/cdk-mintd
```

## Configuration

> **Important**: You must create the working directory and configuration file before starting the mint. The mint does not create them automatically.

### Setup Steps

1. **Create working directory**:
   ```bash
   mkdir -p ~/.cdk-mintd
   ```

2. **Create configuration file**:
   ```bash
   # Copy and customize the example config
   cp example.config.toml ~/.cdk-mintd/config.toml
   # Edit ~/.cdk-mintd/config.toml with your settings
   ```

3. **Start the mint**:
   ```bash
   cdk-mintd  # Uses ~/.cdk-mintd/config.toml automatically
   ```

### Configuration File Locations (in order of precedence)

1. **Explicit path**: `cdk-mintd --config /path/to/config.toml`
2. **Working directory**: `./config.toml` (in current directory) 
3. **Default location**: `~/.cdk-mintd/config.toml`
4. **Environment variables**: All config options can be set via environment variables

### Alternative Setup Methods

**Custom working directory**:
```bash
mkdir -p /my/custom/path
cp example.config.toml /my/custom/path/config.toml
cdk-mintd --work-dir /my/custom/path
```

**Environment variables only**:
```bash
export CDK_MINTD_LISTEN_PORT=3000
export CDK_MINTD_LN_BACKEND=fakewallet
export CDK_MINTD_DATABASE=sqlite
cdk-mintd
```

### Keyset Version Management

The mint supports rotating keysets to newer versions (e.g., migrating from V1 to V2).

**Policy Configuration:**
By default, the mint will use V2 (Version01) for *new* keysets but will preserve existing V1 (Version00) keysets to avoid unnecessary rotation. You can force a specific policy using `config.toml` or environment variables:

- `use_keyset_v2 = true` (or `CDK_MINTD_USE_KEYSET_V2=true`): Forces V2. If the current active keyset is V1, it will be rotated to V2 on startup.
- `use_keyset_v2 = false` (or `CDK_MINTD_USE_KEYSET_V2=false`): Forces V1. If the current active keyset is V2, it will be rotated to V1 on startup.
- **Unset (Default)**: Preserves the current keyset version. If no keyset exists, V2 is created.

**Manual Rotation:**
You can manually trigger a rotation to a specific version using the CLI:

```bash
mint-cli rotate-next-keyset --use-keyset-v2       # Rotate to V2
mint-cli rotate-next-keyset --use-keyset-v2=false # Rotate to V1
```

## Local Testing Example

### FakeWallet + SQLite (default in this repo)
```toml
[info]
url = "http://127.0.0.1:3338"
listen_host = "127.0.0.1"
listen_port = 3338

[ln]
ln_backend = "fakewallet"

[fake_wallet]
supported_units = ["sat", "msat", "usd"]

[database]
engine = "sqlite"
```

## Directory Structure

After setup and first run, your directory will look like:

```
~/.cdk-mintd/                    # Working directory (create manually)
├── config.toml                  # Config file (create manually)
├── cdk-mintd.db                # SQLite database (created automatically)
├── logs/                       # Log files (created automatically if enabled)
│   ├── cdk-mintd.2024-01-01.log
│   └── cdk-mintd.2024-01-02.log
└── ldk-node/                   # LDK Node data (if using LDK backend)
    ├── wallet/
    └── graph/
```

**What you must create manually:**
- Working directory (e.g., `~/.cdk-mintd/`)
- Config file (`config.toml`)

**What gets created automatically:**
- Database files
- Log directories and files
- Lightning backend data directories

## Docker Usage

CDK Mintd provides ready-to-use Docker images with multiple Lightning backend options.

### Quick Start

#### Standard mint with fakewallet backend (testing only):
```bash
docker-compose up
```

#### Mint with LDK Node backend:
```bash
# Option 1: Use dedicated ldk-node compose file
docker-compose -f docker-compose.ldk-node.yaml up

# Option 2: Use main compose file with profile
docker-compose --profile ldk-node up
```

### Available Images

- **`cashubtc/mintd:latest`** - Standard mint with default features
- **`cashubtc/mintd-ldk-node:latest`** - Mint with LDK Node support

### Configuration via Environment Variables

All configuration can be done through environment variables:

```yaml
environment:
  - CDK_MINTD_LN_BACKEND=ldk-node
  - CDK_MINTD_DATABASE=sqlite
  - CDK_MINTD_LISTEN_HOST=0.0.0.0
  - CDK_MINTD_LISTEN_PORT=8085
  - CDK_MINTD_LDK_NODE_NETWORK=testnet
  - CDK_MINTD_LDK_NODE_ESPLORA_URL=https://blockstream.info/testnet/api
```

### Monitoring

Both Prometheus metrics and Grafana dashboards are included:
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3011 (admin/admin)

For detailed Docker documentation, see [README-ldk-node.md](../../README-ldk-node.md).

## Testing Your Mint

1. **Verify the mint is running**:
   ```bash
   curl http://127.0.0.1:8085/v1/info
   ```

2. **Get mint keys**:
    ```bash
    curl http://127.0.0.1:8085/v1/keysets
    ```

3. **Create a fakewallet quote**:
    ```bash
    curl -X POST http://127.0.0.1:8085/v1/mint/quote/bolt11 \
      -H 'Content-Type: application/json' \
      -d '{"amount":100,"unit":"sat"}'
    ```

## Command Line Usage

```bash
# Start with default configuration
cdk-mintd

# Start with custom config file
cdk-mintd --config /path/to/config.toml

# Start with custom working directory
cdk-mintd --work-dir /path/to/work/dir

# Disable logging
cdk-mintd --enable-logging false

# Show help
cdk-mintd --help
```

## Key Environment Variables

- `CDK_MINTD_DATABASE`: Database engine (`sqlite`)
- `CDK_MINTD_LN_BACKEND`: Lightning backend (`fakewallet`)
- `CDK_MINTD_LISTEN_HOST`: Host to bind to (default: `127.0.0.1`)
- `CDK_MINTD_LISTEN_PORT`: Port to bind to (default: `8085`)

For complete configuration options, see the [example configuration file](./example.config.toml).

## Documentation

- **[Configuration Examples](./example.config.toml)** - Complete configuration reference
- **[Development Guide](../../DEVELOPMENT.md)** - Contributing and development setup

## License

This project is licensed under the [MIT License](../../LICENSE).
