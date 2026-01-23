#!/bin/bash

# python-parallel-demo.sh
# Automated test for Spilman Python Demo with dynamic ports and parallel clients.

set -e
set -u
set -o pipefail

# 1. Configuration
MINT_BIN="./target/debug/cdk-mintd"
MINT_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mint-test-python.XXXXXX")
CONFIG_FILE="$MINT_WORK_DIR/config.toml"
LOG_DIR="./testing/python-demo"
SERVER_LOG="$LOG_DIR/server.log"
MINT_LOG="$LOG_DIR/mint.log"
CLIENT_COUNT=3
REPO_ROOT=$(pwd)
PYTHON=".venv/bin/python"

# Create log directory
mkdir -p "$LOG_DIR"

# 2. Cleanup function
cleanup() {
    echo ""
    echo "--- Cleaning up ---"
    # Kill background jobs (mint and server)
    # We use jobs -p to get PIDs of background processes started in this subshell
    JOBS=$(jobs -p)
    if [ -n "$JOBS" ]; then
        echo "Killing background processes: $JOBS"
        kill $JOBS || true
    fi
    # Remove temporary mint work directory (includes config file)
    rm -rf "$MINT_WORK_DIR"
    echo "Cleanup complete. Logs available in $LOG_DIR"
}

# Register the cleanup function to run on exit (success or failure)
trap cleanup EXIT

# 3. Build verification
if [ ! -f "$MINT_BIN" ]; then
    echo "ERROR: Mint binary not found at $MINT_BIN"
    echo "Please build it first: cargo build -p cdk-mintd --features fakewallet"
    exit 1
fi

# 4. Find two distinct free ports
echo "--- Finding free ports ---"
read -r MINT_PORT SERVER_PORT < <(python3 -c 'import socket; s1=socket.socket(); s1.bind(("", 0)); s2=socket.socket(); s2.bind(("", 0)); print(f"{s1.getsockname()[1]} {s2.getsockname()[1]}"); s1.close(); s2.close()')
echo "MINT_PORT:   $MINT_PORT"
echo "SERVER_PORT: $SERVER_PORT"

# 5. Setup dynamic mint config
echo "--- Setting up test mint ---"
echo "MINT_WORK_DIR: $MINT_WORK_DIR"
sed -e "s/listen_port = 3338/listen_port = $MINT_PORT/" \
    -e "s|url = \"http://127.0.0.1:3338\"|url = \"http://127.0.0.1:$MINT_PORT\"|" \
    dev-mint/config.toml > "$CONFIG_FILE"

# 6. Start Mint
echo "--- Starting Mint (logging to $MINT_LOG) ---"
$MINT_BIN --config "$CONFIG_FILE" --work-dir "$MINT_WORK_DIR" --enable-logging > "$MINT_LOG" 2>&1 &

# Wait for mint to be ready
echo "Waiting for mint to start on port $MINT_PORT..."
for i in {1..20}; do
    if curl -s "http://localhost:$MINT_PORT/v1/info" > /dev/null; then
        MINT_VERSION=$(curl -s "http://localhost:$MINT_PORT/v1/info" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        echo "Mint is ready. Version: $MINT_VERSION"
        break
    fi
    if [ $i -eq 20 ]; then
        echo "ERROR: Mint failed to start."
        cat "$MINT_LOG"
        exit 1
    fi
    sleep 0.5
done

# 7. Start Python Server
echo "--- Starting Python Server (logging to $SERVER_LOG) ---"
export MINT_URL="http://localhost:$MINT_PORT"
export PORT="$SERVER_PORT"
# Use python from the environment (assumes venv is active if needed)
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

# 8. Run Parallel Clients
echo "--- Running $CLIENT_COUNT Clients in Parallel (logging to $LOG_DIR/client_N.log) ---"

PIDS=()
for i in $(seq 1 $CLIENT_COUNT); do
    MSG="Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    SERVER_URL="http://localhost:$SERVER_PORT" $PYTHON examples/python-ascii-art/client.py "$MSG" > "$LOG" 2>&1 &
    PIDS+=($!)
done

# 9. Wait for all clients and check results
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

# 10. Final Result
if [ "$SUCCESS" = true ]; then
    echo ""
    echo "***********************************"
    echo "* ALL PARALLEL TESTS PASSED       *"
    echo "***********************************"
    echo ""
    exit 0
else
    echo ""
    echo "***********************************"
    echo "* SOME TESTS FAILED               *"
    echo "***********************************"
    echo ""
    exit 1
fi
