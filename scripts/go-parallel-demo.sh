#!/bin/bash

# go-parallel-demo.sh
# Automated test for Spilman Go Demo with dynamic ports and parallel clients.

set -e
set -u
set -o pipefail

# 1. Configuration
MINT_BIN="./target/debug/cdk-mintd"
MINT_WORK_DIR="dev-mint-test-go"
LOG_DIR="./testing/go-demo"
SERVER_LOG="$LOG_DIR/server.log"
MINT_LOG="$LOG_DIR/mint.log"
CLIENT_COUNT=3
REPO_ROOT=$(pwd)
GO_DEMO_DIR="examples/go-ascii-art"

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
    # Remove temporary files
    rm -f config.test.go.toml
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

echo "--- Building Go demo and Rust bridge ---"
make go-build-rust
(cd "$GO_DEMO_DIR" && go build -o main .)

# 4. Find two distinct free ports
echo "--- Finding free ports ---"
read -r MINT_PORT SERVER_PORT < <(python3 -c 'import socket; s1=socket.socket(); s1.bind(("", 0)); s2=socket.socket(); s2.bind(("", 0)); print(f"{s1.getsockname()[1]} {s2.getsockname()[1]}"); s1.close(); s2.close()')
echo "MINT_PORT:   $MINT_PORT"
echo "SERVER_PORT: $SERVER_PORT"

# 5. Setup dynamic mint config
echo "--- Setting up test mint ---"
mkdir -p "$MINT_WORK_DIR"
sed -e "s/listen_port = 3338/listen_port = $MINT_PORT/" \
    -e "s|url = \"http://127.0.0.1:3338\"|url = \"http://127.0.0.1:$MINT_PORT\"|" \
    dev-mint/config.toml > config.test.go.toml

# 6. Start Mint
echo "--- Starting Mint (logging to $MINT_LOG) ---"
$MINT_BIN --config config.test.go.toml --work-dir "$MINT_WORK_DIR" --enable-logging > "$MINT_LOG" 2>&1 &

# Wait for mint to be ready
echo "Waiting for mint to start on port $MINT_PORT..."
for i in {1..20}; do
    if curl -s "http://localhost:$MINT_PORT/v1/info" > /dev/null; then
        echo "Mint is ready."
        break
    fi
    if [ $i -eq 20 ]; then
        echo "ERROR: Mint failed to start."
        cat "$MINT_LOG"
        exit 1
    fi
    sleep 0.5
done

# 7. Start Go Server
echo "--- Starting Go Server (logging to $SERVER_LOG) ---"
export MINT_URL="http://localhost:$MINT_PORT"
export PORT="$SERVER_PORT"
export SERVER_URL="http://localhost:$SERVER_PORT"
export LD_LIBRARY_PATH="$REPO_ROOT/target/debug"

cd "$GO_DEMO_DIR"
./main server > "$REPO_ROOT/$SERVER_LOG" 2>&1 &
cd "$REPO_ROOT"

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
    MSG="Go-Parallel-$i"
    LOG="$LOG_DIR/client_$i.log"
    echo "Starting Client $i with message: '$MSG'..."
    # We must run client from GO_DEMO_DIR to find main if we didn't use absolute path
    # But we built it as ./main there.
    (cd "$GO_DEMO_DIR" && MINT_URL="http://localhost:$MINT_PORT" SERVER_URL="http://localhost:$SERVER_PORT" LD_LIBRARY_PATH="$REPO_ROOT/target/debug" ./main client "$MSG") > "$LOG" 2>&1 &
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
    echo "* ALL GO PARALLEL TESTS PASSED    *"
    echo "***********************************"
    echo ""
    exit 0
else
    echo ""
    echo "***********************************"
    echo "* SOME GO TESTS FAILED            *"
    echo "***********************************"
    echo ""
    exit 1
fi
