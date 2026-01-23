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

echo "Starting $MINT_TYPE mint on port $PORT..."

# Start mint in background
"$REPO_ROOT/scripts/run_temporary_mint.sh" "$MINT_TYPE" "$PORT" &
MINT_PID=$!

cleanup() {
    echo "Stopping mint (PID $MINT_PID)..."
    kill "$MINT_PID" 2>/dev/null || true
    wait "$MINT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for mint to be ready
"$REPO_ROOT/scripts/wait_for_mint.sh" "$PORT" 60

echo "Mint ready at http://localhost:$PORT"
echo "Running: $*"
echo ""

# Run command with MINT_URL set
MINT_URL="http://localhost:$PORT" "$@"
