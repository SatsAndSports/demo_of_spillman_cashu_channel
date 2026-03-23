#!/bin/bash

# ts-parallel-demo.sh (standalone workspace version)
# Automated test for Spilman TypeScript Demo with dynamic ports and parallel clients.
#
# Requires: MINT_URL to be set (use run_with_mint.sh to auto-spawn)
#
# Usage: MINT_URL=http://localhost:3338 ./scripts/ts-parallel-demo.sh

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
LOG_DIR="$STANDALONE_ROOT/testing/ts-demo"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_COUNT=3
TS_DEMO_DIR="$STANDALONE_ROOT/examples/ts-ascii-art"
KIT_DIR="$STANDALONE_ROOT/integration-kits/ts"

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

# Install npm dependencies
echo "--- Installing npm dependencies ---"
(cd "$KIT_DIR" && npm install --silent --no-package-lock --no-fund --no-audit)
(cd "$TS_DEMO_DIR" && rm -rf node_modules/cdk-spilman-kit && npm install --silent --no-package-lock --no-fund --no-audit)

# Find a free port for the server
SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
echo "SERVER_PORT: $SERVER_PORT"
echo "MINT_URL:    $MINT_URL"

# Start TypeScript Server
echo "--- Starting TypeScript Server (logging to $SERVER_LOG) ---"
export PORT="$SERVER_PORT"

(cd "$TS_DEMO_DIR" && npm run server) > "$SERVER_LOG" 2>&1 &

# Wait for server to be ready
echo "Waiting for server to start on port $SERVER_PORT..."
for i in {1..60}; do
    if curl -s "http://localhost:$SERVER_PORT/channel/params" > /dev/null; then
        echo "Server is ready."
        break
    fi
    if [ $i -eq 60 ]; then
        echo "ERROR: Server failed to start within 30 seconds."
        cat "$SERVER_LOG"
        exit 1
    fi
    sleep 0.5
done

# Run Parallel Clients
echo "--- Running $CLIENT_COUNT Clients in Parallel (logging to $LOG_DIR/client_N.log) ---"

PIDS=()
for i in $(seq 1 $CLIENT_COUNT); do
    MSG="TS-Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    (cd "$TS_DEMO_DIR" && MINT_URL="$MINT_URL" SERVER_URL="http://localhost:$SERVER_PORT" npm run client -- "$MSG") > "$LOG" 2>&1 &
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

# Final Result
if [ "$SUCCESS" = true ]; then
    echo ""
    echo "***********************************"
    echo "* ALL TS PARALLEL TESTS PASSED    *"
    echo "***********************************"
    echo ""
    exit 0
else
    echo ""
    echo "***********************************"
    echo "* SOME TS TESTS FAILED            *"
    echo "***********************************"
    echo ""
    exit 1
fi
