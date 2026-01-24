#!/bin/bash
# wait_for_mint.sh
# Waits for a mint to be ready and prints version info.
#
# Usage: ./scripts/wait_for_mint.sh <port> [timeout_seconds] [required_units]
# Example: ./scripts/wait_for_mint.sh 12345 10
#          ./scripts/wait_for_mint.sh 3338 60 "sat msat usd"
#
# Checks:
# 1. /v1/info endpoint responds
# 2. /v1/keysets has at least one active keyset
# 3. (optional) All required units have active keysets
#
# On success: prints "Mint is ready. Version: X (N active keysets: unit1, unit2)" and exits 0
# On timeout: prints error to stderr and exits 1

set -e
set -u

PORT="${1:-3338}"
TIMEOUT="${2:-10}"
REQUIRED_UNITS="${3:-}"

# Check for jq dependency
if ! command -v jq &> /dev/null; then
    echo "ERROR: jq is required but not installed." >&2
    echo "Install with: apt install jq / brew install jq" >&2
    exit 1
fi

if [ -n "$REQUIRED_UNITS" ]; then
    echo "Waiting for units: $REQUIRED_UNITS" >&2
fi

ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if curl -s "http://localhost:$PORT/v1/info" > /dev/null 2>&1; then
        KEYSETS_JSON=$(curl -s "http://localhost:$PORT/v1/keysets")
        
        # Count active keysets
        ACTIVE_COUNT=$(echo "$KEYSETS_JSON" | jq '[.keysets[] | select(.active)] | length')
        
        if [ "$ACTIVE_COUNT" -gt 0 ]; then
            # Get available units (sorted, unique)
            AVAILABLE_UNITS=$(echo "$KEYSETS_JSON" | jq -r '[.keysets[] | select(.active) | .unit] | unique | sort | join(", ")')
            
            # Check required units if specified
            if [ -n "$REQUIRED_UNITS" ]; then
                # Check if all required units are present
                MISSING=$(echo "$KEYSETS_JSON" | jq -r --arg units "$REQUIRED_UNITS" '
                    ($units | split(" ")) as $required |
                    [.keysets[] | select(.active) | .unit] | unique as $available |
                    ($required - $available) | join(" ")
                ')
                
                if [ -n "$MISSING" ]; then
                    # Not all units available yet, keep waiting
                    sleep 0.5
                    ELAPSED=$((ELAPSED + 1))
                    continue
                fi
            fi
            
            # Get version
            VERSION=$(curl -s "http://localhost:$PORT/v1/info" | jq -r '.version // "unknown"')
            
            echo "Mint is ready. Version: $VERSION ($ACTIVE_COUNT active keysets: $AVAILABLE_UNITS)"
            exit 0
        fi
    fi
    sleep 0.5
    ELAPSED=$((ELAPSED + 1))
done

# Timeout - provide helpful error message
if [ -n "$REQUIRED_UNITS" ]; then
    # Try to get current state for error message
    AVAILABLE=""
    if curl -s "http://localhost:$PORT/v1/keysets" > /dev/null 2>&1; then
        AVAILABLE=$(curl -s "http://localhost:$PORT/v1/keysets" | jq -r '[.keysets[] | select(.active) | .unit] | unique | sort | join(" ")' 2>/dev/null || echo "none")
    fi
    echo "ERROR: Mint did not have all required units within ${TIMEOUT}s on port $PORT" >&2
    echo "  Required: $REQUIRED_UNITS" >&2
    echo "  Available: ${AVAILABLE:-none}" >&2
else
    echo "ERROR: Mint did not start within ${TIMEOUT}s on port $PORT" >&2
fi
exit 1
