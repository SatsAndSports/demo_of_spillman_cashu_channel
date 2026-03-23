# CDK Payment Channels Makefile
#
# Naming conventions:
#   build-*     Build/compile targets
#   run-*       Run servers/clients
#   test-*      Test targets
#   clean-*     Cleanup targets
#
# Test target patterns:
#   test-unit-*           Unit tests
#   test-server-*         Server integration tests (52-test Rust client suite)
#   test-demo-*           Demo tests (simple client/server sanity check)
#   test-blossom*         Blossom server tests
#   test-all*             Aggregate test suites
#
# Mint variants (default is CDK mint):
#   test-demo-python          Uses CDK mint (default)
#   test-demo-python-nutmix   Uses NutMix mint

# ===========================================================================
# Configuration
# ===========================================================================

# Container engine: podman (default) or docker
# Override: make test-containerized CONTAINER_ENGINE=docker
CONTAINER_ENGINE := podman

ifeq ($(CONTAINER_ENGINE),podman)
    COMPOSE_CMD := podman-compose
else
    COMPOSE_CMD := docker compose
endif

COMPOSE_FILE := -f docker-compose.spilman.yml

# Directories
PYTHON_CRATE_DIR := crates/cdk-spilman-python
GO_CRATE_DIR := crates/cdk-spilman-go
GO_DEMO_DIR := examples/go-ascii-art
TS_DEMO_DIR := examples/ts-ascii-art
PYTHON_DEMO_DIR := examples/python-ascii-art
BLOSSOM_DIR := web/blossom-server
WASM_CRATE := crates/cdk-wasm
NUTMIX_SETUP_DIR := scripts/nutmix-setup-units

# Python tools (single venv lives in the Python crate)
PYTHON_VENV := $(PYTHON_CRATE_DIR)/.venv
PYTHON := $(PYTHON_VENV)/bin/python
PIP := $(PYTHON_VENV)/bin/pip
MATURIN := $(PYTHON_VENV)/bin/maturin

# ===========================================================================
# .PHONY declarations
# ===========================================================================

.PHONY: venv \
	build-python build-python-wheel install-python \
	build-go build-mintd build-rust-server \
	build-wasm build-blossom-wasm build-ts-wasm build-kit-ts \
	build-devenv build-nutmix-setup \
	run-python-server run-python-client \
	run-go-server run-go-client \
	run-ts-server run-ts-client \
	test test-rust-only test-unit-spilman test-integration-rust \
	test-unit-go test-integration-go test-integration-python test-integration-ts \
	test-server-ts test-server-rust test-server-python test-server-go test-server-all \
	test-demo-python test-demo-go test-demo-ts \
	test-demo-python-nutmix test-demo-go-nutmix test-demo-ts-nutmix \
	test-demo-python-nutmix-native test-demo-go-nutmix-native test-demo-ts-nutmix-native \
	test-blossom test-blossom-nutmix \
	test-all test-all-with-blossom test-all-nutmix-native test-all-with-nutmix \
	test-containerized \
	clean clean-logs clean-nutmix-setup clean-containers \
	list-orphans kill-orphans ensure-nutmix-image

# ===========================================================================
# Build Targets
# ===========================================================================

# --- Python Bindings ---

# Python venv (delegates to the Python crate's Makefile)
venv:
	$(MAKE) -C $(PYTHON_CRATE_DIR) venv

# Build Python bindings (development mode)
build-python:
	$(MAKE) -C $(PYTHON_CRATE_DIR) build

# Build Python wheel
build-python-wheel: venv
	cd $(PYTHON_CRATE_DIR) && $(CURDIR)/$(MATURIN) build --release

# Install Python wheel
install-python: build-python-wheel
	$(PIP) install $(PYTHON_CRATE_DIR)/target/wheels/*.whl --force-reinstall

# --- Go Bindings ---

# Build Go bindings (Rust library, debug)
build-go:
	cargo build -p cdk-spilman-go

# Build Go distribution libraries (optimized, stripped)
build-go-dist:
	./scripts/build-go-libs.sh

build-go-dist-linux-amd64:
	./scripts/build-go-libs.sh linux-amd64

build-go-dist-linux-arm64:
	./scripts/build-go-libs.sh linux-arm64

build-go-dist-darwin-amd64:
	./scripts/build-go-libs.sh darwin-amd64

build-go-dist-darwin-arm64:
	./scripts/build-go-libs.sh darwin-arm64

build-go-dist-windows-amd64:
	./scripts/build-go-libs.sh windows-amd64

build-go-dist-all:
	./scripts/build-go-libs.sh all

# --- Rust Builds ---

# Build CDK mint daemon
build-mintd:
	cargo build -p cdk-mintd --features fakewallet

# Build Rust ASCII Art server
build-rust-server:
	cargo build -p rust-ascii-art

# --- WASM Bindings ---

# WASM build artifacts
BLOSSOM_WASM := web/blossom-server/src/wasm/cdk_wasm_bg.wasm
TS_KIT_WASM := integration-kits/ts/wasm/cdk_wasm_bg.wasm

# Source files that WASM depends on
WASM_SOURCES := $(shell find crates/cdk-wasm/src crates/cdk/src crates/cdk-spilman/src -name '*.rs' 2>/dev/null)

# Sentinel file tracks when WASM was last built
.wasm-built: $(WASM_SOURCES) crates/cdk-wasm/Cargo.toml crates/cdk/Cargo.toml crates/cdk-spilman/Cargo.toml Cargo.lock
	cd $(WASM_CRATE) && wasm-pack build --release --no-opt --target web --out-dir ../../web/wasm-web
	cd $(WASM_CRATE) && wasm-pack build --release --no-opt --target web --out-dir ../../web/wasm-nodejs
	@touch .wasm-built
	@echo "WASM build complete (web/wasm-web, web/wasm-nodejs)"

# Build WASM bindings
build-wasm: .wasm-built $(TS_KIT_WASM)

# Build WASM and copy to blossom-server
$(BLOSSOM_WASM): web/wasm-nodejs/cdk_wasm_bg.wasm
	@mkdir -p web/blossom-server/src/wasm web/blossom-server/public/wasm
	cp web/wasm-nodejs/cdk_wasm* web/blossom-server/src/wasm/
	cp web/wasm-web/cdk_wasm* web/blossom-server/public/wasm/
	@echo "WASM copied to blossom-server"

# Build WASM and copy to TS integration kit
$(TS_KIT_WASM): web/wasm-nodejs/cdk_wasm_bg.wasm
	@mkdir -p integration-kits/ts/wasm
	cp web/wasm-nodejs/cdk_wasm* integration-kits/ts/wasm/
	@echo "WASM copied to TS integration kit"

build-blossom-wasm: build-wasm $(BLOSSOM_WASM) build-kit-ts

# Build WASM for TS ASCII Art (uses symlink, just needs WASM built)
build-ts-wasm: .wasm-built $(TS_KIT_WASM)

# --- TS Integration Kit ---

# Build TS integration kit (compiles TypeScript to dist/)
TS_KIT_DIR := integration-kits/ts
TS_KIT_SOURCES := $(shell find $(TS_KIT_DIR)/src -name '*.ts' 2>/dev/null)

.kit-ts-built: $(TS_KIT_SOURCES) $(TS_KIT_WASM)
	cd $(TS_KIT_DIR) && npm install --ignore-scripts && npm run build
	@touch .kit-ts-built
	@echo "TS integration kit built"

build-kit-ts: .kit-ts-built

# --- Container/NutMix Builds ---

# Build container dev environment image
build-devenv:
	$(CONTAINER_ENGINE) build --network=host -f containers/Dockerfile.devenv -t cdk-devenv .

# Build NutMix setup tool
build-nutmix-setup:
	cd $(NUTMIX_SETUP_DIR) && go build -o nutmix-setup-units .

# Ensure NutMix Docker image exists
ensure-nutmix-image:
	@if ! docker image inspect nutmix-mint:latest > /dev/null 2>&1; then \
		echo "Building nutmix-mint Docker image..."; \
		cd /home/aaron/MyCode/Cashu/NutMix/nutmix && docker compose -f docker-compose-dev.yml build; \
	fi

# ===========================================================================
# Run Targets (Demo Servers/Clients)
# ===========================================================================

# --- Python Demo ---

run-python-server: build-python
	$(PYTHON) $(PYTHON_DEMO_DIR)/server.py

run-python-client:
	$(PYTHON) $(PYTHON_DEMO_DIR)/client.py

# --- Go Demo ---
# Note: Uses -tags spilman_dev to link against target/debug instead of packaged libs

run-go-server: build-go
	fuser -k 5001/tcp || true
	cd $(GO_DEMO_DIR) && go mod tidy && LD_LIBRARY_PATH=$(shell pwd)/target/debug go run -tags spilman_dev . server

run-go-client:
	cd $(GO_DEMO_DIR) && LD_LIBRARY_PATH=$(shell pwd)/target/debug go run -tags spilman_dev . client "Hello Go"

# --- TypeScript Demo ---

run-ts-server: build-wasm
	cd $(TS_DEMO_DIR) && npm install && npm run server

run-ts-client:
	cd $(TS_DEMO_DIR) && npm run client -- "Hello TypeScript"

# ===========================================================================
# Test Targets - Unit Tests
# ===========================================================================

# Run Spilman unit tests (Rust)
test-unit-spilman:
	cargo test -p cdk-spilman --features configurable-host

# Run standalone workspace tests
test-standalone-core:
	cargo test -p cdk-spilman --manifest-path spilman-standalone/Cargo.toml

test-standalone-interop:
	cargo test -p cdk-spilman-interop-tests --manifest-path spilman-standalone/Cargo.toml

test-standalone-wasm:
	cargo test -p cdk-wasm --manifest-path spilman-standalone/Cargo.toml

test-standalone-rust-demo:
	cargo test -p rust-ascii-art --manifest-path spilman-standalone/Cargo.toml

test-standalone-go:
	$(MAKE) -C spilman-standalone/crates/cdk-spilman-go test-dev

test-standalone-python:
	$(MAKE) -C spilman-standalone/crates/cdk-spilman-python test-unit

# Standalone integration tests (require mint via MINT_URL or CDK_REPO_ROOT)
# Default CDK_REPO_ROOT to this repo so it works out of the box during transition
STANDALONE_CDK_REPO_ROOT ?= $(shell pwd)
STANDALONE_MINT_RUNNER := CDK_REPO_ROOT=$(STANDALONE_CDK_REPO_ROOT) spilman-standalone/scripts/run_with_mint.sh

test-standalone-integration-python:
	$(STANDALONE_MINT_RUNNER) $(MAKE) -C spilman-standalone/crates/cdk-spilman-python test-integration

test-standalone-integration-go:
	$(STANDALONE_MINT_RUNNER) $(MAKE) -C spilman-standalone/crates/cdk-spilman-go test-integration-dev

test-standalone: test-standalone-core test-standalone-interop test-standalone-wasm test-standalone-rust-demo test-standalone-go test-standalone-python
	@echo ""
	@echo "========================================="
	@echo "  ALL STANDALONE TESTS PASSED"
	@echo "========================================="

test-standalone-demo-python: test-standalone-python
	$(STANDALONE_MINT_RUNNER) spilman-standalone/scripts/python-parallel-demo.sh

test-standalone-demo-go: test-standalone-go
	$(STANDALONE_MINT_RUNNER) spilman-standalone/scripts/go-parallel-demo.sh

test-standalone-integration-ts:
	$(STANDALONE_MINT_RUNNER) $(MAKE) -C spilman-standalone/crates/cdk-wasm test-integration

test-standalone-demo-ts:
	$(STANDALONE_MINT_RUNNER) spilman-standalone/scripts/ts-parallel-demo.sh

# Standalone server integration tests (shared Rust harness against each server type)
test-standalone-server-python:
	SERVER_TYPE=python cargo test -p cdk-spilman-server-integration-tests --manifest-path spilman-standalone/Cargo.toml --test integration -- --nocapture

test-standalone-server-go:
	SERVER_TYPE=go cargo test -p cdk-spilman-server-integration-tests --manifest-path spilman-standalone/Cargo.toml --test integration -- --nocapture

test-standalone-server-rust:
	SERVER_TYPE=rust cargo test -p cdk-spilman-server-integration-tests --manifest-path spilman-standalone/Cargo.toml --test integration -- --nocapture

test-standalone-server-ts:
	SERVER_TYPE=ts cargo test -p cdk-spilman-server-integration-tests --manifest-path spilman-standalone/Cargo.toml --test integration -- --nocapture

test-standalone-all: test-standalone test-standalone-integration-python test-standalone-integration-go test-standalone-integration-ts test-standalone-demo-python test-standalone-demo-go test-standalone-demo-ts test-standalone-server-python test-standalone-server-go test-standalone-server-rust test-standalone-server-ts
	@echo ""
	@echo "========================================="
	@echo "  ALL STANDALONE TESTS PASSED"
	@echo "========================================="

# Run Rust ASCII Art integration tests (requires mint)
test-integration-rust: build-mintd
	./scripts/run_with_mint.sh cdk cargo test -p rust-ascii-art --test integration -- --nocapture

# Run Go unit tests (delegates to Go Makefile)
test-unit-go: build-go
	$(MAKE) -C $(GO_CRATE_DIR) test-dev

# Run Go integration tests (uses standalone workspace)
test-integration-go: test-standalone-integration-go

# Run Python integration tests (uses standalone workspace)
test-integration-python: test-standalone-integration-python

# Run TypeScript integration tests (uses standalone workspace)
test-integration-ts: test-standalone-integration-ts

# Run all integration tests (Go, Python, TS, Rust)
test-integration-all: test-integration-rust test-integration-go test-integration-python test-integration-ts
	@echo ""
	@echo "========================================="
	@echo "  ALL INTEGRATION TESTS PASSED"
	@echo "========================================="

# ===========================================================================
# Test Targets - Server Integration Tests (common Rust suite against all servers)
# ===========================================================================

# Test TypeScript server
# Test TypeScript server (uses standalone workspace)
test-server-ts: test-standalone-server-ts

# Test Rust server (uses standalone workspace)
test-server-rust: test-standalone-server-rust

# Test Python server (uses standalone workspace)
test-server-python: test-standalone-server-python

# Test Go server (uses standalone workspace)
test-server-go: test-standalone-server-go

# Test all servers
test-server-all: test-server-ts test-server-rust test-server-python test-server-go
	@echo ""
	@echo "========================================="
	@echo "  ALL SERVER INTEGRATION TESTS PASSED"
	@echo "========================================="

# ===========================================================================
# Test Targets - Demo Tests (simple client/server sanity check)
# ===========================================================================

# --- Demo Tests with CDK Mint (default) ---

test-demo-python: test-standalone-demo-python

test-demo-go: test-standalone-demo-go

test-demo-ts: test-standalone-demo-ts

# Test all demos
test-demo-all: test-demo-python test-demo-go test-demo-ts
	@echo ""
	@echo "========================================="
	@echo "  ALL DEMO TESTS PASSED"
	@echo "========================================="


# --- Demo Tests with NutMix (Docker Compose) ---

test-demo-python-nutmix: build-python build-nutmix-setup ensure-nutmix-image
	@bash scripts/python-parallel-demo.sh nutmix

test-demo-go-nutmix: build-go build-nutmix-setup ensure-nutmix-image
	@bash scripts/go-parallel-demo.sh nutmix

test-demo-ts-nutmix: build-wasm build-nutmix-setup ensure-nutmix-image
	@bash scripts/ts-parallel-demo.sh nutmix

# --- Demo Tests with NutMix (Native - for Docker test image) ---

test-demo-python-nutmix-native: build-python
	@bash scripts/python-parallel-demo.sh nutmix-native

test-demo-go-nutmix-native: build-go
	@bash scripts/go-parallel-demo.sh nutmix-native

test-demo-ts-nutmix-native: build-wasm
	@bash scripts/ts-parallel-demo.sh nutmix-native

# ===========================================================================
# Test Targets - Blossom Server Tests
# ===========================================================================

# Test blossom server with CDK mint
test-blossom: build-mintd build-blossom-wasm build-kit-ts
	./scripts/run_with_mint.sh cdk $(MAKE) -C $(BLOSSOM_DIR) test

# Test blossom server with NutMix
test-blossom-nutmix: build-nutmix-setup build-blossom-wasm build-kit-ts
	./scripts/run_with_mint.sh nutmix $(MAKE) -C $(BLOSSOM_DIR) test

# ===========================================================================
# Test Targets - Aggregate Suites
# ===========================================================================

# Default test target: Rust-only tests (no Node.js, Python, or Go required)
test: test-rust-only

# Rust-only tests: unit tests + Rust server integration tests
test-rust-only: test-unit-spilman test-server-rust
	@echo ""
	@echo "========================================="
	@echo "  ALL RUST-ONLY TESTS PASSED"
	@echo "========================================="

# All tests with CDK mint (does not require blossom-server repo)
test-all: test-unit-spilman test-integration-all test-server-all test-demo-all
	@echo ""
	@echo "========================================="
	@echo "  ALL TESTS PASSED (CDK mint)"
	@echo "========================================="

# All tests including blossom (requires web/blossom-server repo)
test-all-with-blossom: test-unit-spilman test-integration-all test-blossom test-server-all test-demo-all
	@echo ""
	@echo "========================================="
	@echo "  ALL TESTS PASSED (CDK mint + blossom)"
	@echo "========================================="

# All tests with NutMix (native mode - for Docker test image)
test-all-nutmix-native: test-demo-python-nutmix-native test-demo-go-nutmix-native test-demo-ts-nutmix-native
	@echo ""
	@echo "========================================="
	@echo "  ALL TESTS PASSED (NutMix native)"
	@echo "========================================="

# All tests with both CDK mint and NutMix (requires blossom-server repo)
test-all-with-nutmix: test-all-with-blossom test-blossom-nutmix
	@echo ""
	@echo "========================================="
	@echo "  ALL TESTS PASSED (CDK + NutMix)"
	@echo "========================================="

# Containerized tests (Rust-only, no local Rust required)
test-containerized: build-devenv
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
	$(COMPOSE_CMD) $(COMPOSE_FILE) run --rm build && \
	echo "" && \
	echo "=== Running tests ===" && \
	$(COMPOSE_CMD) $(COMPOSE_FILE) up --force-recreate --abort-on-container-exit --exit-code-from test-rust mint rust-server test-rust; \
	status=$$?; \
	$(COMPOSE_CMD) $(COMPOSE_FILE) down; \
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

# ===========================================================================
# Cleanup Targets
# ===========================================================================

# Clean test logs
clean-logs:
	rm -rf testing/

# Clean NutMix setup tool
clean-nutmix-setup:
	rm -f $(NUTMIX_SETUP_DIR)/nutmix-setup-units

# Clean containers and devenv image
clean-containers:
	$(COMPOSE_CMD) $(COMPOSE_FILE) down -v
	$(CONTAINER_ENGINE) rmi cdk-devenv 2>/dev/null || true
	@echo "Containers and devenv image cleaned up."

# Full clean
clean: clean-nutmix-setup clean-logs
	cargo clean
	rm -rf $(PYTHON_CRATE_DIR)/target
	rm -rf $(GO_CRATE_DIR)/target
	rm -rf $(PYTHON_VENV)
	rm -f .wasm-built .kit-ts-built
	rm -rf web/wasm-web web/wasm-nodejs
	rm -rf integration-kits/ts/node_modules integration-kits/ts/dist examples/ts-ascii-art/node_modules
	rm -rf integration-kits/ts/wasm
	rm -f examples/*-ascii-art/*.db
	@if [ -d $(BLOSSOM_DIR) ]; then $(MAKE) -C $(BLOSSOM_DIR) clean; fi

# ===========================================================================
# Utility Targets
# ===========================================================================

# List orphaned test processes
list-orphans:
	@echo "=== Orphaned test processes ==="
	@echo "cdk-mintd:"
	@pgrep -af "cdk-mintd" | grep -v pgrep || echo "  (none)"
	@echo "rust-ascii-art:"
	@pgrep -af "rust-ascii-art" | grep -v pgrep || echo "  (none)"
	@echo "python server.py:"
	@pgrep -af "python.*server\.py" | grep -v pgrep || echo "  (none)"
	@echo "tsx server:"
	@pgrep -af "tsx.*server" | grep -v pgrep || echo "  (none)"
	@echo "ascii-art:"
	@pgrep -af "ascii-art" | grep -v pgrep || echo "  (none)"

# Kill orphaned test processes
kill-orphans:
	@echo "Killing orphaned test processes..."
	-@pkill -f "rust-ascii-art" 2>/dev/null || true
	-@pkill -f "python.*server\.py" 2>/dev/null || true
	-@pkill -f "tsx.*server" 2>/dev/null || true
	-@pkill -f "ascii-art" 2>/dev/null || true
	-@pkill -f "cdk-mintd.*--config.*/tmp/" 2>/dev/null || true
	@echo "Done. Run 'make list-orphans' to verify."
