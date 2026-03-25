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
#   test-server-*         Server integration tests (54-test Rust client suite)
#   test-demo-*           Demo tests (simple client/server sanity check)
#   test-all*             Aggregate test suites
#
# Mint variants:
#   Default uses the standalone test mint (auto-spawned).
#   Set MINT_URL to test against an external mint (see SPILMAN_DEVELOPMENT.md).

# ===========================================================================
# Configuration
# ===========================================================================

# Directories
STANDALONE_ROOT := .
PYTHON_CRATE_DIR := crates/cdk-spilman-python
GO_CRATE_DIR := crates/cdk-spilman-go
GO_DEMO_DIR := examples/go-ascii-art
TS_DEMO_DIR := examples/ts-ascii-art
PYTHON_DEMO_DIR := examples/python-ascii-art
WASM_CRATE := crates/cdk-wasm

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
	build-go build-rust-server \
	build-wasm build-ts-wasm build-kit-ts \
	run-python-server run-python-client \
	run-go-server run-go-client \
	run-ts-server run-ts-client \
	test test-rust-only test-unit-spilman test-integration-rust \
	test-unit-go test-integration-go test-integration-python test-integration-ts \
	test-server-ts test-server-rust test-server-python test-server-go test-server-all \
	test-demo-python test-demo-go test-demo-ts \
	test-all \
	clean clean-logs \
	list-orphans kill-orphans

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
	cargo build -p cdk-spilman-go --manifest-path Cargo.toml

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

# Build Rust ASCII Art server
build-rust-server:
	cargo build -p rust-ascii-art --manifest-path Cargo.toml

# --- WASM Bindings ---

# WASM build artifacts
TS_KIT_WASM := $(STANDALONE_ROOT)/integration-kits/ts/wasm/cdk_wasm_bg.wasm

# Source files that WASM depends on
WASM_SOURCES := $(shell find $(WASM_CRATE)/src $(STANDALONE_ROOT)/crates/cdk-spilman/src -name '*.rs' 2>/dev/null)

# Sentinel file tracks when WASM was last built
.wasm-built: $(WASM_SOURCES) $(WASM_CRATE)/Cargo.toml crates/cdk-spilman/Cargo.toml Cargo.toml Cargo.lock
	cd $(WASM_CRATE) && wasm-pack build --release --no-opt --target web --out-dir ../../web/wasm-nodejs
	@touch .wasm-built
	@echo "WASM build complete (web/wasm-nodejs)"

# Build WASM bindings
build-wasm: .wasm-built $(TS_KIT_WASM)

# Build WASM and copy to TS integration kit
$(TS_KIT_WASM): web/wasm-nodejs/cdk_wasm_bg.wasm
	@mkdir -p $(STANDALONE_ROOT)/integration-kits/ts/wasm
	cp web/wasm-nodejs/cdk_wasm* $(STANDALONE_ROOT)/integration-kits/ts/wasm/
	@echo "WASM copied to TS integration kit"

# Build WASM for TS ASCII Art (uses symlink, just needs WASM built)
build-ts-wasm: .wasm-built $(TS_KIT_WASM)

# --- TS Integration Kit ---

# Build TS integration kit (compiles TypeScript to dist/)
TS_KIT_DIR := $(STANDALONE_ROOT)/integration-kits/ts
TS_KIT_SOURCES := $(shell find $(TS_KIT_DIR)/src -name '*.ts' 2>/dev/null)

.kit-ts-built: $(TS_KIT_SOURCES) $(TS_KIT_WASM)
	cd $(TS_KIT_DIR) && npm install --ignore-scripts && npm run build
	@touch .kit-ts-built
	@echo "TS integration kit built"

build-kit-ts: .kit-ts-built

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
	cd $(GO_DEMO_DIR) && go mod tidy && LD_LIBRARY_PATH=$(shell pwd)/$(STANDALONE_ROOT)/target/debug go run -tags spilman_dev . server

run-go-client:
	cd $(GO_DEMO_DIR) && LD_LIBRARY_PATH=$(shell pwd)/$(STANDALONE_ROOT)/target/debug go run -tags spilman_dev . client "Hello Go"

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
	cargo test -p cdk-spilman --features configurable-host --manifest-path $(STANDALONE_ROOT)/Cargo.toml

# Run standalone workspace tests
test-standalone-core:
	cargo test -p cdk-spilman --manifest-path Cargo.toml

test-standalone-interop:
	cargo test -p cdk-spilman-interop-tests --manifest-path Cargo.toml

test-standalone-wasm:
	cargo test -p cdk-wasm --manifest-path Cargo.toml

test-standalone-rust-demo:
	$(STANDALONE_MINT_RUNNER) cargo test -p rust-ascii-art --manifest-path Cargo.toml

test-standalone-go:
	$(MAKE) -C crates/cdk-spilman-go test-dev

test-standalone-python:
	$(MAKE) -C crates/cdk-spilman-python test-unit

# Standalone integration tests (require mint via MINT_URL or auto-spawned standalone test mint)
STANDALONE_MINT_RUNNER := scripts/run_with_mint.sh

test-standalone-integration-python:
	$(STANDALONE_MINT_RUNNER) $(MAKE) -C crates/cdk-spilman-python test-integration

test-standalone-integration-go:
	$(STANDALONE_MINT_RUNNER) $(MAKE) -C crates/cdk-spilman-go test-integration-dev

test-standalone: test-standalone-core test-standalone-interop test-standalone-wasm test-standalone-rust-demo test-standalone-go test-standalone-python
	@echo ""
	@echo "========================================="
	@echo "  ALL STANDALONE TESTS PASSED"
	@echo "========================================="

test-standalone-demo-python: test-standalone-python
	$(STANDALONE_MINT_RUNNER) scripts/python-parallel-demo.sh

test-standalone-demo-go: test-standalone-go
	$(STANDALONE_MINT_RUNNER) scripts/go-parallel-demo.sh

test-standalone-integration-ts:
	$(STANDALONE_MINT_RUNNER) $(MAKE) -C crates/cdk-wasm test-integration

test-standalone-demo-ts:
	$(STANDALONE_MINT_RUNNER) scripts/ts-parallel-demo.sh

# Standalone server integration tests (shared Rust harness against each server type)
test-standalone-server-python: test-standalone-python
	SERVER_TYPE=python cargo test -p cdk-spilman-server-integration-tests --manifest-path Cargo.toml --test integration -- --nocapture

test-standalone-server-go: test-standalone-go
	SERVER_TYPE=go cargo test -p cdk-spilman-server-integration-tests --manifest-path Cargo.toml --test integration -- --nocapture

test-standalone-server-rust: test-standalone-rust-demo
	SERVER_TYPE=rust cargo test -p cdk-spilman-server-integration-tests --manifest-path Cargo.toml --test integration -- --nocapture

test-standalone-server-ts: test-standalone-integration-ts
	SERVER_TYPE=ts cargo test -p cdk-spilman-server-integration-tests --manifest-path Cargo.toml --test integration -- --nocapture

test-standalone-all: test-standalone test-standalone-integration-python test-standalone-integration-go test-standalone-integration-ts test-standalone-demo-python test-standalone-demo-go test-standalone-demo-ts test-standalone-server-python test-standalone-server-go test-standalone-server-rust test-standalone-server-ts
	@echo ""
	@echo "========================================="
	@echo "  ALL STANDALONE TESTS PASSED"
	@echo "========================================="

# Run Rust ASCII Art integration tests (requires mint)
test-integration-rust:
	$(STANDALONE_MINT_RUNNER) cargo test -p rust-ascii-art --manifest-path Cargo.toml --test integration -- --nocapture

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

# --- Demo Tests with standalone test mint (default) ---

test-demo-python: test-standalone-demo-python

test-demo-go: test-standalone-demo-go

test-demo-ts: test-standalone-demo-ts

# Test all demos
test-demo-all: test-demo-python test-demo-go test-demo-ts
	@echo ""
	@echo "========================================="
	@echo "  ALL DEMO TESTS PASSED"
	@echo "========================================="

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

# All tests
test-all: test-unit-spilman test-integration-all test-server-all test-demo-all
	@echo ""
	@echo "========================================="
	@echo "  ALL TESTS PASSED"
	@echo "========================================="

# ===========================================================================
# Cleanup Targets
# ===========================================================================

# Clean test logs
clean-logs:
	rm -rf testing/

# Full clean
clean: clean-logs
	cargo clean --manifest-path Cargo.toml
	rm -rf $(PYTHON_CRATE_DIR)/target
	rm -rf $(GO_CRATE_DIR)/target
	rm -rf $(PYTHON_VENV)
	rm -rf $(PYTHON_CRATE_DIR)/.pytest_cache
	rm -f .wasm-built .kit-ts-built
	rm -rf web/wasm-nodejs
	rm -rf $(STANDALONE_ROOT)/integration-kits/ts/node_modules $(STANDALONE_ROOT)/integration-kits/ts/dist $(TS_DEMO_DIR)/node_modules $(TS_DEMO_DIR)/dist
	rm -rf $(STANDALONE_ROOT)/integration-kits/python/*.egg-info
	find $(PYTHON_CRATE_DIR) $(STANDALONE_ROOT)/integration-kits/python -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -f $(STANDALONE_ROOT)/examples/go-ascii-art/ascii-art $(STANDALONE_ROOT)/examples/go-ascii-art/main $(STANDALONE_ROOT)/examples/go-ascii-art/demo $(STANDALONE_ROOT)/examples/go-ascii-art/*.exe
	rm -f $(STANDALONE_ROOT)/examples/*-ascii-art/*.db

# ===========================================================================
# Utility Targets
# ===========================================================================

# List orphaned test processes
list-orphans:
	@echo "=== Orphaned test processes ==="
	@echo "cdk-spilman-test-mintd:"
	@pgrep -af "cdk-spilman-test-mintd" | grep -v pgrep || echo "  (none)"
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
	-@pkill -f "cdk-spilman-test-mintd" 2>/dev/null || true
	@echo "Done. Run 'make list-orphans' to verify."
