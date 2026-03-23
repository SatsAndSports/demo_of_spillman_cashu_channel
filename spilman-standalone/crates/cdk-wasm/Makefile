# CDK WASM Bindings - Standalone Workspace Makefile
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

# Standalone workspace root
STANDALONE_ROOT ?= ../..

# Directories
EXAMPLE_DIR := $(STANDALONE_ROOT)/examples/ts-ascii-art
KIT_DIR := $(STANDALONE_ROOT)/integration-kits/ts
WASM_OUT_DIR := $(KIT_DIR)/wasm

.PHONY: build build-wasm install test-integration run-server run-client clean help

# Default target
help:
	@echo "CDK WASM Bindings (standalone workspace)"
	@echo ""
	@echo "Usage:"
	@echo "  make build             Build WASM (requires Rust + wasm-pack)"
	@echo "  make install           Install example dependencies"
	@echo "  make test-integration  Run integration tests (requires mint at MINT_URL)"
	@echo "  make run-server        Start the ASCII art example server"
	@echo "  make run-client        Run the example client"
	@echo ""
	@echo "Environment variables:"
	@echo "  MINT_URL         Mint URL (default: $(MINT_URL))"
	@echo "  PORT             Server port (default: $(PORT))"
	@echo "  STANDALONE_ROOT  Standalone workspace root (default: $(STANDALONE_ROOT))"

# ============================================================================
# Build
# ============================================================================

# Build WASM for Node.js into the TS integration kit's wasm/ directory
# Only rebuilds if wasm artifacts are missing; use `make rebuild-wasm` to force.
build: build-wasm

build-wasm:
	@if [ ! -f "$(WASM_OUT_DIR)/cdk_wasm.js" ]; then \
		echo "Building WASM for Node.js..."; \
		wasm-pack build --target nodejs --out-dir $(WASM_OUT_DIR); \
		echo "WASM build complete (output: $(WASM_OUT_DIR))"; \
	else \
		echo "WASM artifacts already exist in $(WASM_OUT_DIR), skipping build (use rebuild-wasm to force)"; \
	fi

rebuild-wasm:
	@echo "Rebuilding WASM for Node.js..."
	wasm-pack build --target nodejs --out-dir $(WASM_OUT_DIR)
	@echo "WASM build complete (output: $(WASM_OUT_DIR))"

# Build TS kit (compile TypeScript to dist/) and install example dependencies
install:
	cd $(KIT_DIR) && npm install --no-package-lock --no-fund --no-audit
	@if [ ! -d "$(KIT_DIR)/dist" ]; then \
		echo "Building TS kit (tsc)..."; \
		cd $(KIT_DIR) && npm run build; \
	else \
		echo "TS kit dist/ already exists, skipping tsc"; \
	fi
	rm -rf $(EXAMPLE_DIR)/node_modules/cdk-spilman-kit
	cd $(EXAMPLE_DIR) && npm install --no-package-lock --no-fund --no-audit

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
	rm -rf $(WASM_OUT_DIR)/*.js $(WASM_OUT_DIR)/*.wasm $(WASM_OUT_DIR)/*.d.ts
