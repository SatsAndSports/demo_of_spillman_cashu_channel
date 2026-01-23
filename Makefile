# CDK Payment Channels Root Makefile

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MATURIN := $(VENV)/bin/maturin

PYTHON_CRATE_DIR := crates/cdk-spilman-python

.PHONY: venv python-dev python-build python-install clean python-demo-server python-demo-client \
	go-build-rust go-demo-server go-demo-client \
	cdk-mintd \
	test-python-parallel-cdk test-python-parallel-nutmix \
	test-go-parallel-cdk test-go-parallel-nutmix \
	test-blossom-cdk test-blossom-nutmix test-blossom-full-cdk test-blossom-full-nutmix \
	wasm wasm-dev test-spilman \
	test-all-cdk test-all-nutmix test-all \
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

# --- Parallel Demo Tests (CDK) ---
#

cdk-mintd:
	cargo build -p cdk-mintd --features fakewallet

test-python-parallel-cdk: python-dev cdk-mintd
	@bash scripts/python-parallel-demo.sh cdk

test-go-parallel-cdk: go-build-rust cdk-mintd
	@bash scripts/go-parallel-demo.sh cdk

# --- Parallel Demo Tests (NutMix) ---

test-python-parallel-nutmix: python-dev build-nutmix-setup-units
	@bash scripts/python-parallel-demo.sh nutmix

test-go-parallel-nutmix: go-build-rust build-nutmix-setup-units
	@bash scripts/go-parallel-demo.sh nutmix

# --- Rust Tests ---

# Run Spilman channel unit tests
test-spilman:
	cargo test -p cdk spilman

# --- Blossom Server ---

BLOSSOM_DIR := web/blossom-server

# Run blossom server tests with ephemeral CDK mint
test-blossom-cdk: cdk-mintd
	./scripts/run_with_mint.sh cdk $(MAKE) -C $(BLOSSOM_DIR) test

# Run blossom server tests with ephemeral NutMix mint
test-blossom-nutmix: build-nutmix-setup-units
	./scripts/run_with_mint.sh nutmix $(MAKE) -C $(BLOSSOM_DIR) test

# Run blossom server tests with WASM rebuild + CDK mint
test-blossom-full-cdk: cdk-mintd
	./scripts/run_with_mint.sh cdk $(MAKE) -C $(BLOSSOM_DIR) test-full

# Run blossom server tests with WASM rebuild + NutMix mint
test-blossom-full-nutmix: build-nutmix-setup-units
	./scripts/run_with_mint.sh nutmix $(MAKE) -C $(BLOSSOM_DIR) test-full

# Fast WASM build (~2s) - for development
wasm-dev:
	$(MAKE) -C $(BLOSSOM_DIR) wasm-dev

# Optimized WASM build (~32s) - for production
wasm:
	$(MAKE) -C $(BLOSSOM_DIR) wasm

# --- All Tests ---

# Run all CDK test suites
test-all-cdk: test-spilman test-python-parallel-cdk test-go-parallel-cdk test-blossom-cdk
	@echo ""
	@echo "========================================="
	@echo "  ALL CDK TEST SUITES PASSED"
	@echo "========================================="

# Run all NutMix test suites
test-all-nutmix: test-python-parallel-nutmix test-go-parallel-nutmix test-blossom-nutmix
	@echo ""
	@echo "========================================="
	@echo "  ALL NUTMIX TEST SUITES PASSED"
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
