#!/bin/bash

# python-parallel-demo.sh (standalone workspace version)
# Automated test for Spilman Python Demo with dynamic ports and parallel clients.
#
# Requires: MINT_URL to be set (use run_with_mint.sh to auto-spawn)
#
# Usage: MINT_URL=http://localhost:3338 ./scripts/python-parallel-demo.sh

set -e
set -u
set -o pipefail

if [ -z "${MINT_URL:-}" ]; then
    echo "ERROR: MINT_URL must be set." >&2
    echo "Usage: MINT_URL=http://... $0" >&2
    exit 1
fi

# Configuration
STANDALONE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$STANDALONE_ROOT/testing/python-demo"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_COUNT=3
PYTHON="$STANDALONE_ROOT/crates/cdk-spilman-python/.venv/bin/python"

# Verify venv exists
if [ ! -x "$PYTHON" ]; then
    echo "ERROR: Python venv not found. Run: make -C $STANDALONE_ROOT/crates/cdk-spilman-python build" >&2
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    JOBS=$(jobs -p)
    if [ -n "$JOBS" ]; then
        echo "Killing background processes: $JOBS"
        kill $JOBS || true
    fi
    echo "Cleanup complete. Logs available in $LOG_DIR"
}
trap cleanup EXIT

# Find a free port for the server
SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
echo "SERVER_PORT: $SERVER_PORT"
echo "MINT_URL:    $MINT_URL"

# Start Python Server
echo "--- Starting Python Server (logging to $SERVER_LOG) ---"
export PORT="$SERVER_PORT"
export CONFIG_PATH="$STANDALONE_ROOT/examples/python-ascii-art/config.yaml"
export PYTHONPATH="$STANDALONE_ROOT/integration-kits/python:$STANDALONE_ROOT/crates/cdk-spilman-python"
$PYTHON "$STANDALONE_ROOT/examples/python-ascii-art/server.py" > "$SERVER_LOG" 2>&1 &

# Wait for server to be ready
echo "Waiting for server to start on port $SERVER_PORT..."
for i in {1..20}; do
    if curl -s "http://localhost:$SERVER_PORT/channel/params" > /dev/null; then
        echo "Server is ready."
        break
    fi
    if [ $i -eq 20 ]; then
        echo "ERROR: Server failed to start."
        cat "$SERVER_LOG"
        exit 1
    fi
    sleep 0.5
done

# Run Parallel Clients
echo "--- Running $CLIENT_COUNT Clients in Parallel (logging to $LOG_DIR/client_N.log) ---"

PIDS=()
for i in $(seq 1 $CLIENT_COUNT); do
    MSG="Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    SERVER_URL="http://localhost:$SERVER_PORT" PYTHONPATH="$STANDALONE_ROOT/integration-kits/python:$STANDALONE_ROOT/crates/cdk-spilman-python" $PYTHON "$STANDALONE_ROOT/examples/python-ascii-art/client.py" "$MSG" --close > "$LOG" 2>&1 &
    PIDS+=($!)
done

# Wait for all clients and check results
SUCCESS=true
for i in "${!PIDS[@]}"; do
    PID="${PIDS[$i]}"
    echo "Waiting for Client $((i+1)) (PID $PID)..."
    if ! wait "$PID"; then
        echo "ERROR: Client $((i+1)) failed! See $LOG_DIR/client_$((i+1)).log"
        SUCCESS=false
    else
        echo "Client $((i+1)) finished successfully."
    fi
done

# Verify closure on server
echo ""
echo "--- Verifying channel closure on server ---"
for i in $(seq 1 $CLIENT_COUNT); do
    LOG="$LOG_DIR/client_$i.log"
    CHANNEL_ID=$(grep -oP 'Full channel ID: \K[a-f0-9]+' "$LOG" | head -1 || true)

    if [ -n "$CHANNEL_ID" ]; then
        STATUS=$(curl -s "http://localhost:$SERVER_PORT/channel/$CHANNEL_ID/status")
        if echo "$STATUS" | grep -q '"closed":\s*true'; then
            echo "  Channel ${CHANNEL_ID:0:16} is closed. OK."
        else
            echo "  ERROR: Channel ${CHANNEL_ID:0:16} is NOT closed!"
            echo "  Status: $STATUS"
            SUCCESS=false
        fi
    fi
done

# Final Result
if [ "$SUCCESS" = true ]; then
    echo ""
    echo "***********************************"
    echo "* ALL PYTHON PARALLEL TESTS PASSED *"
    echo "***********************************"
    echo ""
    exit 0
else
    echo ""
    echo "***********************************"
    echo "* SOME PYTHON TESTS FAILED        *"
    echo "***********************************"
    echo ""
    exit 1
fi
