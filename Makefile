# CDK Payment Channels Root Makefile

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MATURIN := $(VENV)/bin/maturin

PYTHON_CRATE_DIR := crates/cdk-spilman-python

.PHONY: venv python-dev python-build python-install clean python-demo-server python-demo-client \
	go-build-rust go-demo-server go-demo-client \
	ts-demo-server ts-demo-client \
	cdk-mintd \
	test-python-parallel-cdk test-python-parallel-nutmix test-python-parallel-nutmix-native \
	test-go-parallel-cdk test-go-parallel-nutmix test-go-parallel-nutmix-native \
	test-ts-parallel-cdk test-ts-parallel-nutmix test-ts-parallel-nutmix-native \
	test-blossom-cdk test-blossom-nutmix \
	test-ts-ascii-cdk test-ts-ascii-nutmix \
	wasm-dev blossom-wasm ts-ascii-wasm test-spilman \
	test-all-cdk test-all-nutmix test-all-nutmix-native test-all \
	build-nutmix-setup-units clean-nutmix-setup-units clean-test-logs

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

test-python-parallel-cdk: python-dev cdk-mintd
	@bash scripts/python-parallel-demo.sh cdk

test-go-parallel-cdk: go-build-rust cdk-mintd
	@bash scripts/go-parallel-demo.sh cdk

test-ts-parallel-cdk: wasm-dev cdk-mintd
	@bash scripts/ts-parallel-demo.sh cdk

# --- Parallel Demo Tests (NutMix via Docker Compose) ---

test-python-parallel-nutmix: python-dev build-nutmix-setup-units
	@bash scripts/python-parallel-demo.sh nutmix

test-go-parallel-nutmix: go-build-rust build-nutmix-setup-units
	@bash scripts/go-parallel-demo.sh nutmix

test-ts-parallel-nutmix: wasm-dev build-nutmix-setup-units
	@bash scripts/ts-parallel-demo.sh nutmix

# --- Parallel Demo Tests (NutMix Native - for Docker test image) ---

test-python-parallel-nutmix-native: python-dev
	@bash scripts/python-parallel-demo.sh nutmix-native

test-go-parallel-nutmix-native: go-build-rust
	@bash scripts/go-parallel-demo.sh nutmix-native

test-ts-parallel-nutmix-native: wasm-dev
	@bash scripts/ts-parallel-demo.sh nutmix-native

# --- Rust Tests ---

# Run Spilman channel unit tests
test-spilman:
	cargo test -p cdk spilman

# --- Blossom Server ---

BLOSSOM_DIR := web/blossom-server

# Run blossom server tests with ephemeral CDK mint
test-blossom-cdk: cdk-mintd blossom-wasm
	./scripts/run_with_mint.sh cdk $(MAKE) -C $(BLOSSOM_DIR) test

# Run blossom server tests with ephemeral NutMix mint
test-blossom-nutmix: build-nutmix-setup-units blossom-wasm
	./scripts/run_with_mint.sh nutmix $(MAKE) -C $(BLOSSOM_DIR) test

# --- TS ASCII Art Server Tests ---

TS_ASCII_DIR := examples/ts-ascii-art

# Run ts-ascii-art tests with ephemeral CDK mint
test-ts-ascii-cdk: cdk-mintd ts-ascii-wasm
	./scripts/run_with_mint.sh cdk $(MAKE) -C $(TS_ASCII_DIR) test

# Run ts-ascii-art tests with ephemeral NutMix mint
test-ts-ascii-nutmix: build-nutmix-setup-units ts-ascii-wasm
	./scripts/run_with_mint.sh nutmix $(MAKE) -C $(TS_ASCII_DIR) test

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
test-all-cdk: test-spilman test-python-parallel-cdk test-go-parallel-cdk test-ts-parallel-cdk test-blossom-cdk
	@echo ""
	@echo "========================================="
	@echo "  ALL CDK TEST SUITES PASSED"
	@echo "========================================="

# Run all NutMix test suites (Docker Compose mode)
test-all-nutmix: test-python-parallel-nutmix test-go-parallel-nutmix test-ts-parallel-nutmix test-blossom-nutmix
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
test-all: test-all-cdk test-all-nutmix
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
