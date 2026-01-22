# CDK Payment Channels Root Makefile

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MATURIN := $(VENV)/bin/maturin

PYTHON_CRATE_DIR := crates/cdk-spilman-python

.PHONY: venv python-dev python-build python-install clean python-demo-server python-demo-client \
	go-build-rust go-demo-server go-demo-client test-python-parallel test-go-parallel

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

# Run parallel python demo test
test-python-parallel: python-dev
	@bash scripts/python-parallel-demo.sh

# Run parallel go demo test
test-go-parallel: go-build-rust
	@bash scripts/go-parallel-demo.sh

clean:
	cargo clean
	rm -rf $(PYTHON_CRATE_DIR)/target
	rm -rf $(GO_CRATE_DIR)/target
	rm -rf $(VENV)
