# Raw i915
#
# Three small programs that talk to the Intel GPU through DRM ioctls only:
# no Mesa, no libOpenCL, no Level Zero, no libdrm wrappers.
#
#   make            build all three into ../../build
#   make probe      build/i915-probe   (identity, submission, benchmarks)
#   make dump       build/i915-dump.so (LD_PRELOAD: record what a driver submits)
#   make replay     build/i915-replay  (replay a recorded dispatch)

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
BUILD   ?= ../../build
HDRS    := /usr/include/drm/drm.h /usr/include/drm/i915_drm.h

all: $(BUILD)/i915-probe $(BUILD)/i915-dump.so $(BUILD)/i915-replay

$(BUILD):
	mkdir -p $@

$(BUILD)/i915-probe: i915_probe.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/i915-dump.so: i915_dump.c | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl

$(BUILD)/i915-replay: i915_replay.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

probe: $(BUILD)/i915-probe
dump: $(BUILD)/i915-dump.so
replay: $(BUILD)/i915-replay

# End-to-end: capture a vendor dispatch, then run it raw and time it.
capture: all
	bash ./capture.sh

clean:
	rm -f $(BUILD)/i915-probe $(BUILD)/i915-dump.so $(BUILD)/i915-replay

.PHONY: all probe dump replay capture clean
