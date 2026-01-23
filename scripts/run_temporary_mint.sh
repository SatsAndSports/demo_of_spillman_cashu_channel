#!/bin/bash
# run_temporary_mint.sh
# Starts a temporary mint with auto-cleanup on exit.
#
# Usage: ./scripts/run_temporary_mint.sh <mint_type> <port>
# Example: ./scripts/run_temporary_mint.sh cdk 12345
#
# Supported mint types: cdk
# The mint runs in the foreground. Use & to background it.
# On exit (SIGTERM, SIGINT, or normal), temp directory is cleaned up.

set -e
set -u

MINT_TYPE="${1:-cdk}"
MINT_PORT="${2:-3338}"

# Locate repo root (script is in scripts/)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

MINT_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mint-${MINT_TYPE}.XXXXXX")
CONFIG_FILE="$MINT_WORK_DIR/config.toml"

MINT_PID=""

cleanup() {
    if [ -n "$MINT_PID" ]; then
        kill "$MINT_PID" 2>/dev/null || true
        wait "$MINT_PID" 2>/dev/null || true
    fi
    rm -rf "$MINT_WORK_DIR"
}
trap cleanup EXIT INT TERM

case "$MINT_TYPE" in
    cdk)
        MINT_BIN="$REPO_ROOT/target/debug/cdk-mintd"
        if [ ! -f "$MINT_BIN" ]; then
            echo "ERROR: $MINT_BIN not found. Run: cargo build -p cdk-mintd --features fakewallet" >&2
            exit 1
        fi
        
        sed -e "s/listen_port = 3338/listen_port = $MINT_PORT/" \
            -e "s|url = \"http://127.0.0.1:3338\"|url = \"http://127.0.0.1:$MINT_PORT\"|" \
            "$REPO_ROOT/dev-mint/config.toml" > "$CONFIG_FILE"
        
        "$MINT_BIN" --config "$CONFIG_FILE" --work-dir "$MINT_WORK_DIR" &
        MINT_PID=$!
        wait "$MINT_PID"
        ;;
    *)
        echo "Unknown mint type: $MINT_TYPE (supported: cdk)" >&2
        exit 1
        ;;
esac
