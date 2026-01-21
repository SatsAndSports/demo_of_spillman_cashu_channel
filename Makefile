# CDK Payment Channels Root Makefile

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
MATURIN := $(VENV)/bin/maturin

PYTHON_CRATE_DIR := crates/cdk-spilman-python

.PHONY: venv python-dev python-build python-install clean python-demo-server python-demo-client

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

clean:
	cargo clean
	rm -rf $(PYTHON_CRATE_DIR)/target
	rm -rf $(VENV)
