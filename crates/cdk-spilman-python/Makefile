# CDK Spilman Python Bindings - Standalone Makefile
#
# For Python developers using this package:
#   make build             - Build and install using maturin
#   make test-integration  - Run integration tests (requires mint at MINT_URL)
#
# Example server:
#   make run-server        - Start the ASCII art server
#   make run-client        - Run the client

# Configuration
MINT_URL ?= http://localhost:3338
PORT ?= 5002

# Directories
EXAMPLE_DIR := ./examples/ascii-art
VENV_DIR := $(EXAMPLE_DIR)/venv
PYTHON := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip

.PHONY: build venv test-integration run-server run-client clean help

# Default target
help:
	@echo "CDK Spilman Python Bindings"
	@echo ""
	@echo "Usage:"
	@echo "  make build             Build and install using maturin"
	@echo "  make test-integration  Run integration tests (requires mint at MINT_URL)"
	@echo "  make run-server        Start the ASCII art example server"
	@echo "  make run-client        Run the example client"
	@echo ""
	@echo "Environment variables:"
	@echo "  MINT_URL    Mint URL (default: $(MINT_URL))"
	@echo "  PORT        Server port (default: $(PORT))"

# ============================================================================
# Build
# ============================================================================

# Create virtual environment
venv:
	@if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Creating virtual environment..."; \
		python3 -m venv $(VENV_DIR); \
		$(PIP) install --upgrade pip; \
		$(PIP) install maturin pytest requests; \
		$(PIP) install -r $(EXAMPLE_DIR)/requirements.txt; \
	fi

# Build and install the package into the local venv
build: venv
	. $(VENV_DIR)/bin/activate && maturin develop

# ============================================================================
# Tests
# ============================================================================

# Integration tests (requires mint running at MINT_URL)
test-integration: build
	MINT_URL=$(MINT_URL) $(PYTHON) -m pytest tests/ -v

# ============================================================================
# Example
# ============================================================================

run-server: build
	MINT_URL=$(MINT_URL) PORT=$(PORT) $(PYTHON) $(EXAMPLE_DIR)/server.py

run-client: build
	MINT_URL=$(MINT_URL) SERVER_URL=http://localhost:$(PORT) $(PYTHON) $(EXAMPLE_DIR)/client.py "Hello Python"

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -rf $(VENV_DIR)
	rm -rf target/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
