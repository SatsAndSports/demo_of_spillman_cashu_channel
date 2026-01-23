#!/bin/bash
# wait_for_mint.sh
# Waits for a mint to be ready and prints version info.
#
# Usage: ./scripts/wait_for_mint.sh <port> [timeout_seconds]
# Example: ./scripts/wait_for_mint.sh 12345 10
#
# Checks:
# 1. /v1/info endpoint responds
# 2. /v1/keysets has at least one active keyset
#
# On success: prints "Mint is ready. Version: X (N active keysets)" and exits 0
# On timeout: prints error to stderr and exits 1

set -e
set -u

PORT="${1:-3338}"
TIMEOUT="${2:-10}"

ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if curl -s "http://localhost:$PORT/v1/info" > /dev/null 2>&1; then
        # Check for active keysets
        ACTIVE_COUNT=$(curl -s "http://localhost:$PORT/v1/keysets" | grep -o '"active":true' | wc -l)
        if [ "$ACTIVE_COUNT" -gt 0 ]; then
            VERSION=$(curl -s "http://localhost:$PORT/v1/info" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            echo "Mint is ready. Version: ${VERSION:-unknown} ($ACTIVE_COUNT active keysets)"
            exit 0
        fi
    fi
    sleep 0.5
    ELAPSED=$((ELAPSED + 1))
done

echo "ERROR: Mint did not start within ${TIMEOUT}s on port $PORT" >&2
exit 1
