# CDK WASM Bindings - Standalone Makefile
#
# For TypeScript/JavaScript developers using this package:
#   make build             - Build WASM using wasm-pack
#   make test-integration  - Run integration tests (requires mint at MINT_URL)
#
# Example server:
#   make run-server        - Start the ASCII art server
#   make run-client        - Run the client

# Configuration
MINT_URL ?= http://localhost:3338
PORT ?= 5001

# Directories
EXAMPLE_DIR := ./examples/ascii-art
WASM_NODEJS_DIR := ../../web/wasm-nodejs
WASM_WEB_DIR := ../../web/wasm-web

.PHONY: build build-wasm install test-integration run-server run-client clean help

# Default target
help:
	@echo "CDK WASM Bindings"
	@echo ""
	@echo "Usage:"
	@echo "  make build             Build WASM (requires Rust + wasm-pack)"
	@echo "  make install           Install example dependencies"
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

# Build WASM
build: build-wasm

build-wasm:
	@echo "Building WASM for Node.js..."
	wasm-pack build --target nodejs --out-dir $(WASM_NODEJS_DIR)
	@echo "Building WASM for web..."
	wasm-pack build --target web --out-dir $(WASM_WEB_DIR)
	@echo "WASM build complete"

# Install example dependencies
install:
	cd $(EXAMPLE_DIR) && npm install

# ============================================================================
# Tests
# ============================================================================

# Integration tests (requires mint running at MINT_URL)
test-integration: install
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) npm test

# ============================================================================
# Example
# ============================================================================

run-server: install
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) PORT=$(PORT) npm run server

run-client: install
	cd $(EXAMPLE_DIR) && MINT_URL=$(MINT_URL) SERVER_URL=http://localhost:$(PORT) npm run client -- "Hello TypeScript"

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -rf $(EXAMPLE_DIR)/node_modules
	rm -rf $(WASM_NODEJS_DIR)/*
	rm -rf $(WASM_WEB_DIR)/*
