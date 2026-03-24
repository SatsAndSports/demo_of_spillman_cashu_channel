#!/bin/bash
# run_with_mint.sh (standalone workspace version)
#
# Runs a command with MINT_URL available.
#
# Behavior:
#   1. If MINT_URL is already set, use it directly (external mint).
#   2. Otherwise, build and spawn the standalone test mint locally.
#
# Usage:
#   ./scripts/run_with_mint.sh <command...>
#
# Examples:
#   # Use an already-running mint:
#   MINT_URL=http://localhost:3338 ./scripts/run_with_mint.sh pytest tests/ -v
#
#   # Auto-spawn the standalone test mint:
#   ./scripts/run_with_mint.sh pytest tests/ -v

set -e

print_mint_summary() {
    local source="$1"
    local mint_url="$2"
    local helper="$STANDALONE_ROOT/scripts/print_mint_summary.py"

    if ! python3 "$helper" "$source" "$mint_url"; then
        echo "MINT_READY source=$source url=$mint_url name=\"unknown\" version=\"unknown\" units=[]"
    fi
}

if [ $# -eq 0 ]; then
    echo "Usage: $0 <command...>" >&2
    echo "" >&2
    echo "Environment:" >&2
    echo "  MINT_URL  Use an already-running mint (skips spawn)" >&2
    exit 1
fi

# ============================================================================
# Case 1: MINT_URL already set — just run the command
# ============================================================================

if [ -n "$MINT_URL" ]; then
    STANDALONE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    print_mint_summary "external" "$MINT_URL"
    exec "$@"
fi

# ============================================================================
# Case 2: build and spawn the standalone test mint
# ============================================================================

STANDALONE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STANDALONE_MANIFEST="$STANDALONE_ROOT/Cargo.toml"

# Build standalone test mint
echo "Building standalone test mint from $STANDALONE_ROOT..."
cargo build -p cdk-spilman-test-mint --manifest-path "$STANDALONE_MANIFEST" 2>&1

MINTD_BIN="$STANDALONE_ROOT/target/debug/cdk-spilman-test-mintd"
if [ ! -f "$MINTD_BIN" ]; then
    echo "ERROR: standalone mint binary not found at $MINTD_BIN after build" >&2
    exit 1
fi

# Find a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

MINT_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/spilman-mint.XXXXXX")
MINT_LOG="$MINT_WORK_DIR/mint.log"
MINT_URL_LOCAL="http://127.0.0.1:$PORT"

# Start mint in background
echo "Starting standalone test mint on port $PORT..."
"$MINTD_BIN" --listen-port "$PORT" --base-url "$MINT_URL_LOCAL" > "$MINT_LOG" 2>&1 &
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
    if curl -s "$MINT_URL_LOCAL/v1/info" > /dev/null 2>&1; then
        print_mint_summary "spawned" "$MINT_URL_LOCAL"
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
MINT_URL="$MINT_URL_LOCAL" "$@"
