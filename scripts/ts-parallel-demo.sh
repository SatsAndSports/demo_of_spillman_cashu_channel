#!/bin/bash

# ts-parallel-demo.sh
# Automated test for Spilman TypeScript Demo with dynamic ports and parallel clients.
#
# Usage: ./scripts/ts-parallel-demo.sh [cdk|nutmix]

set -e
set -u
set -o pipefail

# 1. Configuration
MINT_TYPE="${1:-cdk}"
LOG_DIR="./testing/ts-demo-$MINT_TYPE"
SERVER_LOG="$LOG_DIR/server.log"
MINT_LOG="$LOG_DIR/mint.log"
CLIENT_COUNT=3
TS_DEMO_DIR="examples/ts-ascii-art"

# Create log directory
mkdir -p "$LOG_DIR"

# 2. Cleanup function
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    # Kill background jobs (mint and server)
    JOBS=$(jobs -p)
    if [ -n "$JOBS" ]; then
        echo "Killing background processes: $JOBS"
        kill $JOBS || true
    fi
    echo "Cleanup complete. Logs available in $LOG_DIR"
}

# Register the cleanup function to run on exit (success or failure)
trap cleanup EXIT

# 3. Install npm dependencies
echo "--- Installing npm dependencies ---"
(cd "$TS_DEMO_DIR" && npm install --silent)

# 4. Find two distinct free ports
echo "--- Finding free ports ---"
read -r MINT_PORT SERVER_PORT < <(python3 -c 'import socket; s1=socket.socket(); s1.bind(("", 0)); s2=socket.socket(); s2.bind(("", 0)); print(f"{s1.getsockname()[1]} {s2.getsockname()[1]}"); s1.close(); s2.close()')
echo "MINT_PORT:   $MINT_PORT"
echo "SERVER_PORT: $SERVER_PORT"

# 5. Start Mint
echo "--- Starting $MINT_TYPE Mint (logging to $MINT_LOG) ---"
./scripts/run_temporary_mint.sh "$MINT_TYPE" "$MINT_PORT" > "$MINT_LOG" 2>&1 &

# Wait for mint to be ready (TS demo only uses sat)
./scripts/wait_for_mint.sh "$MINT_PORT" 50 "sat" || { echo "Mint log:"; cat "$MINT_LOG"; exit 1; }

# 6. Start TypeScript Server
echo "--- Starting TypeScript Server (logging to $SERVER_LOG) ---"
export MINT_URL="http://localhost:$MINT_PORT"
export PORT="$SERVER_PORT"

(cd "$TS_DEMO_DIR" && npm run server) > "$SERVER_LOG" 2>&1 &

# Wait for server to be ready (up to 30 seconds for slow mints like NutMix)
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

# 7. Run Parallel Clients
echo "--- Running $CLIENT_COUNT Clients in Parallel (logging to $LOG_DIR/client_N.log) ---"

PIDS=()
for i in $(seq 1 $CLIENT_COUNT); do
    MSG="TS-Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    (cd "$TS_DEMO_DIR" && MINT_URL="http://localhost:$MINT_PORT" SERVER_URL="http://localhost:$SERVER_PORT" npm run client -- "$MSG") > "$LOG" 2>&1 &
    PIDS+=($!)
done

# 8. Wait for all clients and check results
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

# 9. Final Result
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
