#!/bin/bash

# python-parallel-demo.sh
# Automated test for Spilman Python Demo with dynamic ports and parallel clients.
#
# Usage: ./scripts/python-parallel-demo.sh [cdk|nutmix]

set -e
set -u
set -o pipefail

# 1. Configuration
MINT_TYPE="${1:-cdk}"
LOG_DIR="./testing/python-demo-$MINT_TYPE"
SERVER_LOG="$LOG_DIR/server.log"
MINT_LOG="$LOG_DIR/mint.log"
CLIENT_COUNT=3
PYTHON=".venv/bin/python"

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

# 3. Find two distinct free ports
echo "--- Finding free ports ---"
read -r MINT_PORT SERVER_PORT < <(python3 -c 'import socket; s1=socket.socket(); s1.bind(("", 0)); s2=socket.socket(); s2.bind(("", 0)); print(f"{s1.getsockname()[1]} {s2.getsockname()[1]}"); s1.close(); s2.close()')
echo "MINT_PORT:   $MINT_PORT"
echo "SERVER_PORT: $SERVER_PORT"

# 4. Start Mint
echo "--- Starting $MINT_TYPE Mint (logging to $MINT_LOG) ---"
./scripts/run_temporary_mint.sh "$MINT_TYPE" "$MINT_PORT" > "$MINT_LOG" 2>&1 &

# Wait for mint to be ready (Python demo only uses sat)
./scripts/wait_for_mint.sh "$MINT_PORT" 50 "sat" || { echo "Mint log:"; cat "$MINT_LOG"; exit 1; }

# 5. Start Python Server
echo "--- Starting Python Server (logging to $SERVER_LOG) ---"
export MINT_URL="http://localhost:$MINT_PORT"
export PORT="$SERVER_PORT"
$PYTHON examples/python-ascii-art/server.py > "$SERVER_LOG" 2>&1 &

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

# 6. Run Parallel Clients
echo "--- Running $CLIENT_COUNT Clients in Parallel (logging to $LOG_DIR/client_N.log) ---"

PIDS=()
for i in $(seq 1 $CLIENT_COUNT); do
    MSG="Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    SERVER_URL="http://localhost:$SERVER_PORT" $PYTHON examples/python-ascii-art/client.py "$MSG" > "$LOG" 2>&1 &
    PIDS+=($!)
done

# 7. Wait for all clients and check results
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

# 8. Final Result
if [ "$SUCCESS" = true ]; then
    echo ""
    echo "***********************************"
    echo "* ALL PYTHON PARALLEL TESTS PASSED       *"
    echo "***********************************"
    echo ""
    exit 0
else
    echo ""
    echo "***********************************"
    echo "* SOME PYTHON TESTS FAILED               *"
    echo "***********************************"
    echo ""
    exit 1
fi
