# Cashu Video Server Makefile
#
# Usage:
#   make run_server              # Build PyO3 and start the server
#   make wasm                    # Build WASM module (for browser)
#   make wasm-to-blossom-server  # Build WASM and copy to blossom-server
#   make pyo3                    # Build PyO3 module (for server)
#   make rust                    # Build both WASM and PyO3
#
# Video processing:
#   make                  # Process all videos in sources/
#   make media/myvideo    # Process just sources/myvideo.mp4
#   make clean            # Remove all generated media
#
# Drop .mp4 files in sources/ and run make.

SOURCES := $(wildcard sources/*.mp4)
VIDEOS := $(patsubst sources/%.mp4,%,$(SOURCES))
OUTPUTS := $(addprefix media/,$(VIDEOS))

# Quality levels: name, resolution, bitrate
QUALITIES := 720p:1280x720:2800k 480p:854x480:1400k 360p:640x360:800k

# Segment duration in seconds (1 sec = ~1 payment/sec for demo)
SEGMENT_DURATION := 1

.PHONY: all clean list wasm wasm-to-blossom-server pyo3 rust run_server

all: $(OUTPUTS)
	@echo "Done. Processed videos: $(VIDEOS)"

# Build WASM module (for browser)
wasm:
	cd ../crates/cdk-wasm && wasm-pack build --target web --out-dir ../../web/wasm

# Build WASM and copy to blossom-server
BLOSSOM_WASM_DIR := blossom-server/public/wasm
wasm-to-blossom-server: wasm
	@test -f $(BLOSSOM_WASM_DIR)/.gitkeep || (echo "Error: $(BLOSSOM_WASM_DIR)/.gitkeep not found" && exit 1)
	cp wasm/cdk_wasm.js wasm/cdk_wasm.d.ts wasm/cdk_wasm_bg.wasm wasm/cdk_wasm_bg.wasm.d.ts wasm/package.json $(BLOSSOM_WASM_DIR)/
	@echo "WASM copied to $(BLOSSOM_WASM_DIR)/"

# Create the Python virtual environment. It's for running the
# server, including compiling the Rust to be used by the server
server/.venv:
	python3 -m venv server/.venv
	. server/.venv/bin/activate && pip install -r server/requirements.txt


# Build PyO3 module (for server)
pyo3: server/.venv
	. server/.venv/bin/activate && cd ../crates/cdk-py && maturin develop

# Build both WASM and PyO3
rust: wasm pyo3

# Run the server (does not detach. start this in another terminal)
run_server: pyo3
	. server/.venv/bin/activate && cd server && python server.py --debug

# Process a single video
media/%: sources/%.mp4
	@echo "Processing $<..."
	@mkdir -p $@
	$(call process_video,$<,$@)
	$(call generate_master,$@)
	@echo "Created $@"

# Clean generated media
clean:
	rm -rf media/*/

# List available source videos
list:
	@echo "Source videos:"
	@for f in $(SOURCES); do echo "  $$f"; done
	@echo ""
	@echo "Generated outputs:"
	@for d in media/*/; do echo "  $$d"; done 2>/dev/null || echo "  (none)"

# Function to process video at all quality levels
define process_video
	$(foreach q,$(QUALITIES),$(call process_quality,$(1),$(2),$(q)))
endef

# Function to process a single quality level
# Args: input, output_dir, quality_spec (e.g., 720p:1280x720:2800k)
define process_quality
	$(eval NAME := $(word 1,$(subst :, ,$(3))))
	$(eval RES := $(word 2,$(subst :, ,$(3))))
	$(eval BITRATE := $(word 3,$(subst :, ,$(3))))
	@mkdir -p $(2)/$(NAME)
	ffmpeg -i $(1) -y \
		-vf scale=$(RES) \
		-c:v libx264 -b:v $(BITRATE) \
		-g 30 -keyint_min 30 \
		-c:a aac -b:a 128k \
		-f hls \
		-hls_time $(SEGMENT_DURATION) \
		-hls_list_size 0 \
		-hls_segment_filename '$(2)/$(NAME)/seg%03d.ts' \
		$(2)/$(NAME)/playlist.m3u8 \
		2>/dev/null

endef

# Function to generate master playlist
define generate_master
	@echo '#EXTM3U' > $(1)/master.m3u8
	@echo '#EXT-X-STREAM-INF:BANDWIDTH=2800000,RESOLUTION=1280x720' >> $(1)/master.m3u8
	@echo '720p/playlist.m3u8' >> $(1)/master.m3u8
	@echo '#EXT-X-STREAM-INF:BANDWIDTH=1400000,RESOLUTION=854x480' >> $(1)/master.m3u8
	@echo '480p/playlist.m3u8' >> $(1)/master.m3u8
	@echo '#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360' >> $(1)/master.m3u8
	@echo '360p/playlist.m3u8' >> $(1)/master.m3u8
endef
