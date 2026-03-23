#!/bin/bash
# run_with_mint.sh (standalone workspace version)
#
# Runs a command with MINT_URL available.
#
# Behavior:
#   1. If MINT_URL is already set, use it directly (external mint).
#   2. Otherwise, if CDK_REPO_ROOT is set, build and spawn cdk-mintd from there.
#   3. Otherwise, fail with a clear message.
#
# Usage:
#   ./scripts/run_with_mint.sh <command...>
#
# Examples:
#   # Use an already-running mint:
#   MINT_URL=http://localhost:3338 ./scripts/run_with_mint.sh pytest tests/ -v
#
#   # Auto-spawn from a local CDK checkout:
#   CDK_REPO_ROOT=~/code/cdk ./scripts/run_with_mint.sh pytest tests/ -v

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <command...>" >&2
    echo "" >&2
    echo "Environment:" >&2
    echo "  MINT_URL       Use an already-running mint (skips spawn)" >&2
    echo "  CDK_REPO_ROOT  Path to a local CDK checkout (spawns cdk-mintd)" >&2
    exit 1
fi

# ============================================================================
# Case 1: MINT_URL already set — just run the command
# ============================================================================

if [ -n "$MINT_URL" ]; then
    echo "Using existing mint at $MINT_URL"
    exec "$@"
fi

# ============================================================================
# Case 2: CDK_REPO_ROOT set — build and spawn cdk-mintd
# ============================================================================

if [ -z "$CDK_REPO_ROOT" ]; then
    echo "ERROR: Neither MINT_URL nor CDK_REPO_ROOT is set." >&2
    echo "" >&2
    echo "To use an existing mint:" >&2
    echo "  export MINT_URL=http://localhost:3338" >&2
    echo "" >&2
    echo "To auto-spawn from a local CDK checkout:" >&2
    echo "  export CDK_REPO_ROOT=/path/to/cdk" >&2
    exit 1
fi

CDK_REPO_ROOT="$(cd "$CDK_REPO_ROOT" && pwd)"
CDK_MANIFEST="$CDK_REPO_ROOT/Cargo.toml"
CDK_CONFIG="$CDK_REPO_ROOT/dev-mint/config.dev.toml"

if [ ! -f "$CDK_MANIFEST" ]; then
    echo "ERROR: CDK_REPO_ROOT ($CDK_REPO_ROOT) does not contain Cargo.toml" >&2
    exit 1
fi

if [ ! -f "$CDK_CONFIG" ]; then
    echo "ERROR: CDK_REPO_ROOT ($CDK_REPO_ROOT) does not contain dev-mint/config.dev.toml" >&2
    exit 1
fi

# Build cdk-mintd if needed
echo "Building cdk-mintd from $CDK_REPO_ROOT..."
cargo build -p cdk-mintd --features fakewallet --manifest-path "$CDK_MANIFEST" 2>&1

MINTD_BIN="$CDK_REPO_ROOT/target/debug/cdk-mintd"
if [ ! -f "$MINTD_BIN" ]; then
    echo "ERROR: cdk-mintd binary not found at $MINTD_BIN after build" >&2
    exit 1
fi

# Find a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

# Create temp working directory
MINT_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/spilman-mint.XXXXXX")
MINT_LOG="$MINT_WORK_DIR/mint.log"

# Write config with the chosen port
sed -e "s/listen_port = 3338/listen_port = $PORT/" \
    -e "s|url = \"http://127.0.0.1:3338\"|url = \"http://127.0.0.1:$PORT\"|" \
    "$CDK_CONFIG" > "$MINT_WORK_DIR/config.toml"

# Start mint in background
echo "Starting cdk-mintd on port $PORT..."
"$MINTD_BIN" --config "$MINT_WORK_DIR/config.toml" --work-dir "$MINT_WORK_DIR" > "$MINT_LOG" 2>&1 &
MINT_PID=$!

cleanup() {
    local exit_code=$?
    echo "Stopping mint (PID $MINT_PID)..."
    kill "$MINT_PID" 2>/dev/null || true
    wait "$MINT_PID" 2>/dev/null || true
    if [ $exit_code -ne 0 ] && [ -f "$MINT_LOG" ]; then
        echo ""
        echo "=== Last 30 lines of mint log ==="
        tail -30 "$MINT_LOG"
    fi
    rm -rf "$MINT_WORK_DIR"
}
trap cleanup EXIT INT TERM

# Wait for mint to be ready
echo "Waiting for mint to be ready..."
for i in $(seq 1 60); do
    if curl -s "http://localhost:$PORT/v1/info" > /dev/null 2>&1; then
        echo "Mint ready at http://localhost:$PORT"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: Mint did not start within 30 seconds" >&2
        tail -20 "$MINT_LOG" >&2
        exit 1
    fi
    sleep 0.5
done

echo "Running: $*"
echo ""

# Run command with MINT_URL set
MINT_URL="http://localhost:$PORT" "$@"
