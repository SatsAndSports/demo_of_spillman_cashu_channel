# CDK Payment Channels Root Makefile

# --- Container Engine Configuration ---
# Edit this to switch between container engines (podman or docker)
# Or override from command line: make test-rust-only-containerized CONTAINER_ENGINE=docker
CONTAINER_ENGINE := podman

# Container command (same for both podman and docker)
CONTAINER_CMD := $(CONTAINER_ENGINE)

# Compose command differs between engines:
# - Podman: podman-compose (standalone command)
# - Docker: docker compose (subcommand with space)
ifeq ($(CONTAINER_ENGINE),podman)
    COMPOSE_CMD := podman-compose
else
    COMPOSE_CMD := docker compose
endif

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MATURIN := $(VENV)/bin/maturin

PYTHON_CRATE_DIR := crates/cdk-spilman-python

.PHONY: venv python-dev python-build python-install clean python-demo-server python-demo-client \
	go-build-rust go-demo-server go-demo-client \
	ts-demo-server ts-demo-client \
	cdk-mintd rust-ascii-build \
	test test-rust-only \
	test-python-parallel-cdkmintd test-python-parallel-nutmix test-python-parallel-nutmix-native \
	test-go-parallel-cdkmintd test-go-parallel-nutmix test-go-parallel-nutmix-native \
	test-ts-parallel-cdkmintd test-ts-parallel-nutmix test-ts-parallel-nutmix-native \
	test-blossom-cdkmintd test-blossom-nutmix \
	test-ts-cdkmintd test-rust-cdkmintd test-python-cdkmintd test-go-cdkmintd test-servers-cdkmintd \
	wasm-dev blossom-wasm ts-ascii-wasm test-spilman \
	test-all-cdkmintd test-all-nutmix test-all-nutmix-native test-all \
	build-nutmix-setup-units clean-nutmix-setup-units clean-test-logs \
	ensure-nutmix-image \
	list-orphans kill-orphans \
	build-devenv test-rust-only-containerized clean-containers

# Create virtual environment and install maturin
$(MATURIN):
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install maturin patchelf
	$(PIP) install -r examples/python-ascii-art/requirements.txt

venv: $(MATURIN)

# Development mode: compiles and installs in the venv
python-dev: venv
	cd $(PYTHON_CRATE_DIR) && ../../$(MATURIN) develop

# Build: creates a wheel in crates/cdk-spilman-python/target/wheels
python-build: venv
	cd $(PYTHON_CRATE_DIR) && ../../$(MATURIN) build --release

# Install: builds and installs the wheel into the venv
python-install: venv
	cd $(PYTHON_CRATE_DIR) && ../../$(MATURIN) build --release && ../../$(PIP) install target/wheels/*.whl --force-reinstall

# Run the Python demo server
python-demo-server: python-dev
	$(PYTHON) examples/python-ascii-art/server.py

# Run the Python demo client
python-demo-client:
	$(PYTHON) examples/python-ascii-art/client.py

# --- Go Demo ---

GO_CRATE_DIR := crates/cdk-spilman-go
GO_DEMO_DIR := examples/go-ascii-art

# Build the Rust library for Go
go-build-rust:
	cargo build -p cdk-spilman-go

# Run the Go demo server
go-demo-server: go-build-rust
	fuser -k 5001/tcp || true
	cd $(GO_DEMO_DIR) && go mod tidy && LD_LIBRARY_PATH=$(shell pwd)/target/debug go run . server

# Run the Go demo client
go-demo-client:
	cd $(GO_DEMO_DIR) && LD_LIBRARY_PATH=$(shell pwd)/target/debug go run . client "Hello Go"

# --- TypeScript Demo ---

TS_DEMO_DIR := examples/ts-ascii-art

# Run the TypeScript demo server
ts-demo-server: wasm-dev
	cd $(TS_DEMO_DIR) && npm install && npm run server

# Run the TypeScript demo client
ts-demo-client:
	cd $(TS_DEMO_DIR) && npm run client -- "Hello TypeScript"

# --- Parallel Demo Tests (CDK) ---
#

cdk-mintd:
	cargo build -p cdk-mintd --features fakewallet

test-python-parallel-cdkmintd: python-dev cdk-mintd
	@bash scripts/python-parallel-demo.sh cdk

test-go-parallel-cdkmintd: go-build-rust cdk-mintd
	@bash scripts/go-parallel-demo.sh cdk

test-ts-parallel-cdkmintd: wasm-dev cdk-mintd
	@bash scripts/ts-parallel-demo.sh cdk

# --- Parallel Demo Tests (NutMix via Docker Compose) ---

test-python-parallel-nutmix: python-dev build-nutmix-setup-units ensure-nutmix-image
	@bash scripts/python-parallel-demo.sh nutmix

test-go-parallel-nutmix: go-build-rust build-nutmix-setup-units ensure-nutmix-image
	@bash scripts/go-parallel-demo.sh nutmix

test-ts-parallel-nutmix: wasm-dev build-nutmix-setup-units ensure-nutmix-image
	@bash scripts/ts-parallel-demo.sh nutmix

# --- Parallel Demo Tests (NutMix Native - for Docker test image) ---

test-python-parallel-nutmix-native: python-dev
	@bash scripts/python-parallel-demo.sh nutmix-native

test-go-parallel-nutmix-native: go-build-rust
	@bash scripts/go-parallel-demo.sh nutmix-native

test-ts-parallel-nutmix-native: wasm-dev
	@bash scripts/ts-parallel-demo.sh nutmix-native

# --- Rust Tests ---

# Default: run Rust-only channel tests (no Node.js, Python, or Go required)
test: test-rust-only

# Run all Rust-only channel tests
# Includes: spilman unit tests + Rust ASCII server integration tests
test-rust-only: test-spilman test-rust-cdkmintd
	@echo ""
	@echo "========================================="
	@echo "  ALL RUST-ONLY CHANNEL TESTS PASSED"
	@echo "========================================="

# Run Spilman channel unit tests
test-spilman:
	cargo test -p cdk spilman

# --- Blossom Server ---

BLOSSOM_DIR := web/blossom-server

# Run blossom server tests with ephemeral CDK mint
test-blossom-cdkmintd: cdk-mintd blossom-wasm
	./scripts/run_with_mint.sh cdk $(MAKE) -C $(BLOSSOM_DIR) test

# Run blossom server tests with ephemeral NutMix mint
test-blossom-nutmix: build-nutmix-setup-units blossom-wasm
	./scripts/run_with_mint.sh nutmix $(MAKE) -C $(BLOSSOM_DIR) test

# --- Server Integration Tests (Rust test client against all servers) ---

# Run Rust integration tests against TypeScript server
# Tests run in parallel (auto-detect thread count) - see context.rs for how this works
test-ts-cdkmintd: cdk-mintd ts-ascii-wasm
	SERVER_TYPE=ts cargo test -p cdk-spilman-server-integration-tests --test integration -- --nocapture

# Run Rust integration tests against Rust server
test-rust-cdkmintd: cdk-mintd rust-ascii-build
	SERVER_TYPE=rust cargo test -p cdk-spilman-server-integration-tests --test integration -- --nocapture

# Run Rust integration tests against Python server
test-python-cdkmintd: cdk-mintd python-dev
	SERVER_TYPE=python cargo test -p cdk-spilman-server-integration-tests --test integration -- --nocapture

# Run Rust integration tests against Go server
test-go-cdkmintd: cdk-mintd go-build-rust
	SERVER_TYPE=go cargo test -p cdk-spilman-server-integration-tests --test integration -- --nocapture

# Run all server integration tests
test-servers-cdkmintd: test-ts-cdkmintd test-rust-cdkmintd test-python-cdkmintd test-go-cdkmintd
	@echo ""
	@echo "========================================="
	@echo "  ALL SERVER INTEGRATION TESTS PASSED"
	@echo "========================================="

# Build the Rust ASCII Art server
rust-ascii-build:
	cargo build -p cdk-ascii-art

# --- WASM Build ---

WASM_CRATE := crates/cdk-wasm

# Source files that WASM depends on
WASM_SOURCES := $(shell find crates/cdk-wasm/src crates/cdk/src -name '*.rs' 2>/dev/null)

# Sentinel file tracks when WASM was last built
# Only rebuilds if Rust sources, Cargo.toml, or Cargo.lock changed
.wasm-dev-built: $(WASM_SOURCES) crates/cdk-wasm/Cargo.toml crates/cdk/Cargo.toml Cargo.lock
	cd $(WASM_CRATE) && wasm-pack build --release --no-opt --target web --out-dir ../../web/wasm-web
	cd $(WASM_CRATE) && wasm-pack build --release --no-opt --target nodejs --out-dir ../../web/wasm-nodejs
	@touch .wasm-dev-built
	@echo "WASM dev build complete (web/wasm-web, web/wasm-nodejs)"

wasm-dev: .wasm-dev-built

# Blossom server needs WASM copied (separate git repo)
BLOSSOM_WASM := web/blossom-server/src/wasm/cdk_wasm_bg.wasm
$(BLOSSOM_WASM): web/wasm-nodejs/cdk_wasm_bg.wasm
	@mkdir -p web/blossom-server/src/wasm web/blossom-server/public/wasm
	cp web/wasm-nodejs/cdk_wasm* web/blossom-server/src/wasm/
	cp web/wasm-web/cdk_wasm* web/blossom-server/public/wasm/
	@echo "WASM copied to blossom-server"

blossom-wasm: .wasm-dev-built $(BLOSSOM_WASM)

# TS ASCII Art uses symlink to web/wasm-nodejs, just needs WASM built
ts-ascii-wasm: .wasm-dev-built

# --- All Tests ---

# Run all CDK test suites
test-all-cdkmintd: test-spilman test-blossom-cdkmintd test-servers-cdkmintd
	@echo ""
	@echo "========================================="
	@echo "  ALL CDKMINTD TEST SUITES PASSED"
	@echo "========================================="

# Run all NutMix test suites (Docker Compose mode)
test-all-nutmix: test-blossom-nutmix
	@echo ""
	@echo "========================================="
	@echo "  ALL NUTMIX TEST SUITES PASSED"
	@echo "========================================="

# Run all NutMix test suites (native mode - for Docker test image)
test-all-nutmix-native: test-python-parallel-nutmix-native test-go-parallel-nutmix-native test-ts-parallel-nutmix-native
	@echo ""
	@echo "========================================="
	@echo "  ALL NUTMIX-NATIVE TEST SUITES PASSED"
	@echo "========================================="

# Run all test suites (CDK + NutMix)
test-all: test-all-cdkmintd test-all-nutmix
	@echo ""
	@echo "========================================="
	@echo "  ALL TEST SUITES PASSED"
	@echo "========================================="

# --- NutMix Setup Units ---

NUTMIX_SETUP_UNITS_DIR := scripts/nutmix-setup-units

# Build the nutmix-setup-units tool
build-nutmix-setup-units:
	cd $(NUTMIX_SETUP_UNITS_DIR) && go build -o nutmix-setup-units .

# Clean the nutmix-setup-units binary
clean-nutmix-setup-units:
	rm -f $(NUTMIX_SETUP_UNITS_DIR)/nutmix-setup-units

# Ensure nutmix-mint Docker image exists, build if needed
ensure-nutmix-image:
	@if ! docker image inspect nutmix-mint:latest > /dev/null 2>&1; then \
		echo "Building nutmix-mint Docker image..."; \
		cd /home/aaron/MyCode/Cashu/NutMix/nutmix && docker compose -f docker-compose-dev.yml build; \
	fi

# --- Cleanup ---

# Clean test logs
clean-test-logs:
	rm -rf testing/

clean: clean-nutmix-setup-units clean-test-logs
	cargo clean
	rm -rf $(PYTHON_CRATE_DIR)/target
	rm -rf $(GO_CRATE_DIR)/target
	rm -rf $(VENV)
	rm -f .wasm-dev-built

# --- Orphan Process Management ---

# List orphaned test processes (servers and mints left running after tests)
list-orphans:
	@echo "=== Orphaned test processes ==="
	@echo "cdk-mintd:"
	@pgrep -af "cdk-mintd" | grep -v pgrep || echo "  (none)"
	@echo "cdk-ascii-art:"
	@pgrep -af "cdk-ascii-art" | grep -v pgrep || echo "  (none)"
	@echo "python server.py:"
	@pgrep -af "python.*server\.py" | grep -v pgrep || echo "  (none)"
	@echo "tsx server:"
	@pgrep -af "tsx.*server" | grep -v pgrep || echo "  (none)"
	@echo "go-ascii-art:"
	@pgrep -af "go-ascii-art" | grep -v pgrep || echo "  (none)"

# Kill orphaned test processes
kill-orphans:
	@echo "Killing orphaned test processes..."
	-@pkill -f "cdk-ascii-art" 2>/dev/null || true
	-@pkill -f "python.*server\.py" 2>/dev/null || true
	-@pkill -f "tsx.*server" 2>/dev/null || true
	-@pkill -f "go-ascii-art" 2>/dev/null || true
	-@pkill -f "cdk-mintd.*--config.*/tmp/" 2>/dev/null || true
	@echo "Done. Run 'make list-orphans' to verify."

# --- Containerized Tests (requires Podman or Docker) ---
#
# Uses a devenv image with volume-mounted source code.
# Fast iteration: source changes are picked up immediately.
# No local Rust required - just a container engine.
#
# To use Docker instead of Podman:
#   make test-rust-only-containerized CONTAINER_ENGINE=docker

# Build the devenv image (one-time setup, or after Dockerfile.devenv/rust-toolchain.toml changes)
# Uses --network=host to work in VPS/cloud environments where bridge networking may be restricted
build-devenv:
	$(CONTAINER_CMD) build --network=host -f containers/Dockerfile.devenv -t cdk-devenv .

# Run Rust-only channel tests in containers
# This runs: build -> mint -> rust-server -> test-rust
# Note: We run 'build' separately because podman-compose 1.3.0 has issues with
# service_completed_successfully condition.
test-rust-only-containerized: build-devenv
	@echo "Checking that ports 33380 and 50080 are available..."
	@python3 -c "import socket, sys; ports=[33380, 50080]; \
		busy = [p for p in ports if not socket.socket().connect_ex(('127.0.0.1', p))]; \
		[print(f'  Port {p}: OK') for p in ports if p not in busy]; \
		[print(f'  Port {p}: IN USE - please free this port first', file=sys.stderr) for p in busy]; \
		sys.exit(1 if busy else 0)" || \
		(echo ""; echo "ERROR: Required ports are already in use. Free ports 33380 and 50080 and try again."; exit 1)
	@echo "Ports are available."
	@echo ""
	@echo "=== Building ===" && \
	$(COMPOSE_CMD) run --rm build && \
	echo "" && \
	echo "=== Running tests ===" && \
	$(COMPOSE_CMD) up --force-recreate --abort-on-container-exit --exit-code-from test-rust mint rust-server test-rust; \
	status=$$?; \
	$(COMPOSE_CMD) down; \
	if [ $$status -eq 0 ]; then \
		echo ""; \
		echo "========================================="; \
		echo "  CONTAINERIZED TESTS PASSED"; \
		echo "========================================="; \
	else \
		echo ""; \
		echo "========================================="; \
		echo "  CONTAINERIZED TESTS FAILED"; \
		echo "========================================="; \
	fi; \
	exit $$status

# Clean up containers, volumes, and devenv image
clean-containers:
	$(COMPOSE_CMD) down -v
	$(CONTAINER_CMD) rmi cdk-devenv 2>/dev/null || true
	@echo "Containers and devenv image cleaned up."
