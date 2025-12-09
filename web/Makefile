# HLS Video Processing Makefile
#
# Usage:
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

# Segment duration in seconds
SEGMENT_DURATION := 4

.PHONY: all clean list

all: $(OUTPUTS)
	@echo "Done. Processed videos: $(VIDEOS)"

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
