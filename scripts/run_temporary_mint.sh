#!/bin/bash
# run_temporary_mint.sh
# Starts a temporary mint with auto-cleanup on exit.
#
# Usage: ./scripts/run_temporary_mint.sh <mint_type> <port>
# Example: ./scripts/run_temporary_mint.sh cdk 12345
#          ./scripts/run_temporary_mint.sh nutmix 12345
#          ./scripts/run_temporary_mint.sh nutmix-native 12345
#
# Supported mint types:
#   cdk           - CDK mint with fakewallet
#   nutmix        - NutMix via Docker Compose (for local development)
#   nutmix-native - NutMix with PostgreSQL directly (for Docker test image)
#
# The mint runs in the foreground. Use & to background it.
# On exit (SIGTERM, SIGINT, or normal), temp directory is cleaned up.

set -e
set -u

MINT_TYPE="${1:-cdk}"
MINT_PORT="${2:-3338}"

# Locate repo root (script is in scripts/)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

MINT_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/mint-${MINT_TYPE}.XXXXXX")

# Variables for cleanup (set per mint type)
MINT_PID=""
COMPOSE_PROJECT=""
COMPOSE_FILES=""
NUTMIX_DB_NAME=""  # For Docker mode: PostgreSQL database to drop

cleanup() {
    # CDK / NutMix process cleanup
    if [ -n "$MINT_PID" ]; then
        kill "$MINT_PID" 2>/dev/null || true
        wait "$MINT_PID" 2>/dev/null || true
    fi
    # NutMix Docker Compose cleanup (local mode)
    if [ -n "$COMPOSE_PROJECT" ] && [ -n "$COMPOSE_FILES" ]; then
        # shellcheck disable=SC2086
        docker compose $COMPOSE_FILES -p "$COMPOSE_PROJECT" down -v 2>/dev/null || true
    fi
    # NutMix PostgreSQL cleanup (Docker mode)
    if [ -n "$NUTMIX_DB_NAME" ]; then
        sudo -u postgres dropdb "$NUTMIX_DB_NAME" 2>/dev/null || true
    fi
    rm -rf "$MINT_WORK_DIR"
}
trap cleanup EXIT INT TERM

case "$MINT_TYPE" in
    cdk)
        CONFIG_FILE="$MINT_WORK_DIR/config.toml"
        MINT_BIN="$REPO_ROOT/target/debug/cdk-mintd"
        if [ ! -f "$MINT_BIN" ]; then
            echo "ERROR: $MINT_BIN not found. Run: cargo build -p cdk-mintd --features fakewallet" >&2
            exit 1
        fi
        
        sed -e "s/listen_port = 3338/listen_port = $MINT_PORT/" \
            -e "s|url = \"http://127.0.0.1:3338\"|url = \"http://127.0.0.1:$MINT_PORT\"|" \
            "$REPO_ROOT/dev-mint/config.dev.toml" > "$CONFIG_FILE"
        
        "$MINT_BIN" --config "$CONFIG_FILE" --work-dir "$MINT_WORK_DIR" &
        MINT_PID=$!
        wait "$MINT_PID"
        ;;

    nutmix)
        # ============================================================
        # NutMix via Docker Compose (for local development)
        # ============================================================
        NUTMIX_DIR="/home/aaron/MyCode/Cashu/NutMix/nutmix"
        NUTMIX_COMPOSE="$NUTMIX_DIR/docker-compose-dev.yml"
        NUTMIX_SETUP_UNITS="$REPO_ROOT/scripts/nutmix-setup-units/nutmix-setup-units"
        
        # Units to create (can be overridden via NUTMIX_UNITS env var)
        NUTMIX_UNITS="${NUTMIX_UNITS:-msat usd}"
        
        # Known test keys (from nutmix .env)
        NUTMIX_PRIVATE_KEY="6d892d6ae13c60c497ca9d806b84697e7178bdc22e5c21e74c2be426d661c983"
        NUTMIX_ADMIN_NSEC="nsec1rt4m77wy6lrac7u85ya55eslhm07ufld44aacwu0tqpwpjf59xhs5alxef"
        NUTMIX_ADMIN_NPUB="npub1rvmqlgrxqeh8hm78n5qeh7nn6027whu44j87qxddh3rjsx463lysjjxgxx"
        
        # Verify prerequisites
        if [ ! -f "$NUTMIX_COMPOSE" ]; then
            echo "ERROR: $NUTMIX_COMPOSE not found." >&2
            exit 1
        fi
        
        # Build setup-units if needed
        if [ ! -x "$NUTMIX_SETUP_UNITS" ]; then
            echo "Building nutmix-setup-units..." >&2
            (cd "$REPO_ROOT/scripts/nutmix-setup-units" && go build -o nutmix-setup-units .) || {
                echo "ERROR: Failed to build nutmix-setup-units" >&2
                exit 1
            }
        fi
        
        if ! docker image inspect nutmix-mint:latest > /dev/null 2>&1; then
            echo "ERROR: Docker image nutmix-mint:latest not found." >&2
            echo "Build it with: cd $NUTMIX_DIR && docker compose -f docker-compose-dev.yml build" >&2
            exit 1
        fi
        
        # Find a free port for postgres
        DB_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
        
        # Create temp directory structure
        mkdir -p "$MINT_WORK_DIR/logs" "$MINT_WORK_DIR/config"
        
        # Write override compose file
        # Note: We explicitly set environment vars here to avoid .env file conflicts
        cat > "$MINT_WORK_DIR/override.yml" <<EOF
services:
  mint:
    image: nutmix-mint:latest
    ports: !override
      - "${MINT_PORT}:8081"
    volumes: !override
      - ${MINT_WORK_DIR}/logs:/var/log/nutmix
      - ${MINT_WORK_DIR}/config:/root/.config/nutmix
    environment:
      MINT_PRIVATE_KEY: "${NUTMIX_PRIVATE_KEY}"
      MINT_LIGHTNING_BACKEND: "FakeWallet"
      SIGNER_TYPE: "memory"
      NETWORK: "regtest"
      DATABASE_URL: "postgres://postgres:testpass@db/postgres"
      ADMIN_NOSTR_NPUB: "${NUTMIX_ADMIN_NPUB}"
  db:
    ports: !override
      - "127.0.0.1:${DB_PORT}:5432"
    environment:
      POSTGRES_USER: "postgres"
      POSTGRES_PASSWORD: "testpass"
EOF
        
        # Set compose variables for cleanup
        COMPOSE_PROJECT="nutmix-test-${MINT_PORT}"
        COMPOSE_FILES="-f $NUTMIX_COMPOSE -f $MINT_WORK_DIR/override.yml"
        
        echo "Starting NutMix on port $MINT_PORT (postgres on $DB_PORT)..." >&2
        
        # Start containers (not detached - runs in background)
        # shellcheck disable=SC2086
        docker compose $COMPOSE_FILES \
            -p "$COMPOSE_PROJECT" \
            up &
        COMPOSE_PID=$!
        
        # Wait for mint to respond to /v1/info
        echo "Waiting for NutMix to start..." >&2
        for i in {1..60}; do
            if curl -s "http://localhost:$MINT_PORT/v1/info" > /dev/null 2>&1; then
                echo "NutMix is responding." >&2
                break
            fi
            if [ $i -eq 60 ]; then
                echo "ERROR: NutMix did not start within 30 seconds." >&2
                exit 1
            fi
            sleep 0.5
        done
        
        # Run setup-units to create keysets
        echo "Creating keysets via setup-units ($NUTMIX_UNITS)..." >&2
        MINT_URL="http://localhost:$MINT_PORT" \
        ADMIN_NOSTR_NSEC="$NUTMIX_ADMIN_NSEC" \
            "$NUTMIX_SETUP_UNITS" $NUTMIX_UNITS
        
        echo "NutMix ready on port $MINT_PORT" >&2

        #sleep 1
        #curl "http://localhost:$MINT_PORT"/v1/keysets | jq '.keysets[].unit'
        
        # Block until compose exits or we're killed
        wait "$COMPOSE_PID"
        ;;

    nutmix-native)
        # ============================================================
        # NutMix with PostgreSQL directly (for Docker test image)
        # Requires: /nutmix/build/nutmix binary and PostgreSQL installed
        # ============================================================
        NUTMIX_BIN="/nutmix/build/nutmix"
        NUTMIX_SETUP_UNITS="$REPO_ROOT/scripts/nutmix-setup-units/nutmix-setup-units"
        
        # Units to create (can be overridden via NUTMIX_UNITS env var)
        # Note: 'sat' is created by default, so we only add 'msat usd'
        NUTMIX_UNITS="${NUTMIX_UNITS:-msat usd}"
        
        # Known test keys (from nutmix .env)
        NUTMIX_PRIVATE_KEY="6d892d6ae13c60c497ca9d806b84697e7178bdc22e5c21e74c2be426d661c983"
        NUTMIX_ADMIN_NSEC="nsec1rt4m77wy6lrac7u85ya55eslhm07ufld44aacwu0tqpwpjf59xhs5alxef"
        NUTMIX_ADMIN_NPUB="npub1rvmqlgrxqeh8hm78n5qeh7nn6027whu44j87qxddh3rjsx463lysjjxgxx"
        
        # Verify prerequisites
        if [ ! -x "$NUTMIX_BIN" ]; then
            echo "ERROR: $NUTMIX_BIN not found or not executable." >&2
            echo "This mint type is intended for the Docker test image." >&2
            exit 1
        fi
        
        if [ ! -x "$NUTMIX_SETUP_UNITS" ]; then
            echo "ERROR: $NUTMIX_SETUP_UNITS not found. Build it first." >&2
            exit 1
        fi
        
        NUTMIX_DB_NAME="nutmix_test_${MINT_PORT}"
        
        echo "Starting PostgreSQL..." >&2
        sudo pg_ctlcluster 15 main start 2>/dev/null || true
        
        # Wait for PostgreSQL to be ready
        for i in {1..30}; do
            if sudo -u postgres pg_isready -q; then
                break
            fi
            if [ "$i" -eq 30 ]; then
                echo "ERROR: PostgreSQL did not start within 15 seconds." >&2
                exit 1
            fi
            sleep 0.5
        done
        
        # Create database
        sudo -u postgres createdb "$NUTMIX_DB_NAME" 2>/dev/null || true
        
        # Set environment for NutMix
        export DATABASE_URL="postgres://postgres:@localhost:5432/$NUTMIX_DB_NAME"
        export MINT_PRIVATE_KEY="$NUTMIX_PRIVATE_KEY"
        export ADMIN_NOSTR_NPUB="$NUTMIX_ADMIN_NPUB"
        export MINT_LIGHTNING_BACKEND="FakeWallet"
        export SIGNER_TYPE="memory"
        export PORT="$MINT_PORT"
        
        echo "Starting NutMix on port $MINT_PORT..." >&2
        "$NUTMIX_BIN" &
        MINT_PID=$!
        
        # Wait for mint to respond
        for i in {1..60}; do
            if curl -s "http://localhost:$MINT_PORT/v1/info" > /dev/null 2>&1; then
                echo "NutMix is responding." >&2
                break
            fi
            if [ "$i" -eq 60 ]; then
                echo "ERROR: NutMix did not start within 30 seconds." >&2
                exit 1
            fi
            sleep 0.5
        done
        
        # Run setup-units to create keysets
        echo "Creating keysets via setup-units ($NUTMIX_UNITS)..." >&2
        MINT_URL="http://localhost:$MINT_PORT" \
        ADMIN_NOSTR_NSEC="$NUTMIX_ADMIN_NSEC" \
            "$NUTMIX_SETUP_UNITS" $NUTMIX_UNITS
        
        echo "NutMix ready on port $MINT_PORT" >&2
        wait "$MINT_PID"
        ;;

    *)
        echo "Unknown mint type: $MINT_TYPE (supported: cdk, nutmix, nutmix-native)" >&2
        exit 1
        ;;
esac
