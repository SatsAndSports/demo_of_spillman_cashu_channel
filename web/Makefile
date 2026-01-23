# Cashu WASM Build Makefile
#
# Usage:
#   make wasm-web                # Build WASM module (for browser)
#   make wasm-nodejs             # Build WASM module (for Node.js)
#   make wasm-to-blossom-server  # Build both WASM targets and copy to blossom-server
#
# For video encoding/uploading, see blossom-server/tools/hls-*.sh

.PHONY: wasm-web wasm-nodejs wasm-to-blossom-server

# Build WASM module (for browser)
wasm-web:
	cd ../crates/cdk-wasm && wasm-pack build --target web --out-dir ../../web/wasm-web

# Build WASM module (for Node.js)
wasm-nodejs:
	cd ../crates/cdk-wasm && wasm-pack build --target nodejs --out-dir ../../web/wasm-nodejs

# Build both WASM targets and copy to blossom-server
BLOSSOM_WASM_DIR := blossom-server/public/wasm
BLOSSOM_WASM_NODEJS_DIR := blossom-server/src/wasm
wasm-to-blossom-server: wasm-web wasm-nodejs
	@mkdir -p $(BLOSSOM_WASM_DIR)
	cp wasm-web/cdk_wasm.js wasm-web/cdk_wasm.d.ts wasm-web/cdk_wasm_bg.wasm wasm-web/cdk_wasm_bg.wasm.d.ts wasm-web/package.json $(BLOSSOM_WASM_DIR)/
	@echo "Browser WASM copied to $(BLOSSOM_WASM_DIR)/"
	@mkdir -p $(BLOSSOM_WASM_NODEJS_DIR)
	cp wasm-nodejs/cdk_wasm.js wasm-nodejs/cdk_wasm.d.ts wasm-nodejs/cdk_wasm_bg.wasm wasm-nodejs/cdk_wasm_bg.wasm.d.ts wasm-nodejs/package.json $(BLOSSOM_WASM_NODEJS_DIR)/
	@echo "Node.js WASM copied to $(BLOSSOM_WASM_NODEJS_DIR)/"
