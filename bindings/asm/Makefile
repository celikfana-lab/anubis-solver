# Builds and runs the assembly demos.
#
#   make run        # x86-64, native
#   make arm        # assemble+link the aarch64 demo (and run it under qemu if present)
#   make clean
REPO     ?= ../..
BUILD    := build
X86_GCC  ?= cc
ARM_GCC  ?= aarch64-linux-gnu-gcc
QEMU     ?= $(shell command -v qemu-aarch64 || echo /tmp/qprefix/usr/bin/qemu-aarch64)
RPATH    := $(abspath $(REPO))

all: x86 arm

x86: $(BUILD)/demo-x86_64

$(BUILD)/demo-x86_64: x86_64/demo.s x86_64/anubis.inc $(REPO)/libanubis_solver.so
	@mkdir -p $(BUILD)
	$(X86_GCC) -no-pie -Ix86_64 -o $@ x86_64/demo.s \
	    -L$(RPATH) -lanubis_solver -Wl,-rpath,$(RPATH)

run: x86
	./$(BUILD)/demo-x86_64

# The aarch64 demo needs an aarch64 build of the library; `make arm-lib` at the
# repository root produces one in build-arm64/.
arm: $(BUILD)/demo-aarch64

# The root Makefile detects the CPU architecture with `uname -m`, i.e. the host,
# so a cross build has to say which kernel and which Argon2id implementation to
# use: neon.s for ARM, and argon2's portable ref.c rather than its SSE opt.c.
ARM_ARGS := NATIVE= ASM_SRC=src/cpu/neon.s CFLAGS="-O3 -fPIC -Wall -Wextra" \
    ARGON2_SRC="third_party/argon2/argon2.c third_party/argon2/core.c \
                 third_party/argon2/encoding.c third_party/argon2/ref.c \
                 third_party/argon2/thread.c third_party/argon2/blake2/blake2b.c"

arm-lib:
	$(MAKE) -C $(REPO) CC=$(ARM_GCC) BUILD=$(REPO)/build-arm64 \
	    LIB=$(REPO)/build-arm64/libanubis_solver.so $(ARM_ARGS) \
	    CUDA=0 VULKAN=0

$(BUILD)/demo-aarch64: aarch64/demo.s aarch64/anubis.inc $(REPO)/build-arm64/libanubis_solver.so
	@mkdir -p $(BUILD)
	$(ARM_GCC) -no-pie -Iaarch64 -o $@ aarch64/demo.s \
	    -L$(REPO)/build-arm64 -lanubis_solver -Wl,-rpath,$(REPO)/build-arm64

run-arm: arm
	$(QEMU) -L /usr/aarch64-linux-gnu ./$(BUILD)/demo-aarch64

clean:
	rm -rf $(BUILD)

.PHONY: all x86 arm arm-lib run run-arm clean
