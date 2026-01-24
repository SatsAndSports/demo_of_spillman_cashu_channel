#!/bin/bash
# run_with_mint.sh
# Starts an ephemeral mint, runs a command with MINT_URL set, then cleans up.
#
# Usage: ./scripts/run_with_mint.sh <mint_type> <command...>
# Example: ./scripts/run_with_mint.sh cdk make -C web/blossom-server test
#          ./scripts/run_with_mint.sh nutmix npm test
#
# The mint runs in the background. On command completion (success or failure),
# the mint is automatically stopped and cleaned up.

set -e

MINT_TYPE="${1:-cdk}"
shift

if [ $# -eq 0 ]; then
    echo "Usage: $0 <mint_type> <command...>" >&2
    echo "Example: $0 cdk make -C web/blossom-server test" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Find a free port
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

# Create log directory and file
LOG_DIR="$REPO_ROOT/testing"
mkdir -p "$LOG_DIR"
MINT_LOG="$LOG_DIR/mint-${MINT_TYPE}-${PORT}.log"

echo "Starting $MINT_TYPE mint on port $PORT..."
echo "Mint logs: $MINT_LOG"

# Start mint in background with output redirected to log file
"$REPO_ROOT/scripts/run_temporary_mint.sh" "$MINT_TYPE" "$PORT" > "$MINT_LOG" 2>&1 &
MINT_PID=$!

cleanup() {
    local exit_code=$?
    echo "Stopping mint (PID $MINT_PID)..."
    kill "$MINT_PID" 2>/dev/null || true
    wait "$MINT_PID" 2>/dev/null || true
    # On failure, show tail of mint log to help debug
    if [ $exit_code -ne 0 ] && [ -f "$MINT_LOG" ]; then
        echo ""
        echo "=== Last 30 lines of mint log ($MINT_LOG) ==="
        tail -30 "$MINT_LOG"
    fi
}
trap cleanup EXIT INT TERM

# Wait for mint to be ready (blossom-server tests need sat, msat, usd)
"$REPO_ROOT/scripts/wait_for_mint.sh" "$PORT" 60 "sat msat usd"

echo "Mint ready at http://localhost:$PORT"
echo "Running: $*"
echo ""

# Run command with MINT_URL set
MINT_URL="http://localhost:$PORT" "$@"
