CC      ?= cc
CFLAGS  ?= -O3 -fPIC -Wall -Wextra
NATIVE  ?= -march=native
LDFLAGS ?= -shared -pthread
INC     := -Isrc -Ithird_party/argon2

LIB      := libanubis_solver.so
BUILD    := build
CORE_SRC := src/anubis_solver.c src/hashx.c

# Optional Vulkan backend (SHA-256 challenges). Auto-detects the headers;
# the library dlopen()s libvulkan.so.1 at runtime, so there is no hard
# dependency on a Vulkan loader being present.
VULKAN ?= auto
ifneq ($(VULKAN),0)
ifneq ($(wildcard /usr/include/vulkan/vulkan.h),)
CORE_SRC += src/vulkan.c
CFLAGS  += -DANUBIS_HAVE_VULKAN
LDFLAGS += -ldl
endif
endif
# The assembly kernels are x86-64 only; the C fallbacks are always compiled.
ifeq ($(shell uname -m),x86_64)
ASM_SRC  := src/avx2.s src/shani.s
else
ASM_SRC  :=
endif
ARGON2_SRC := $(wildcard third_party/argon2/*.c third_party/argon2/blake2/*.c)

OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(CORE_SRC)) \
       $(patsubst src/%.s,$(BUILD)/%.o,$(ASM_SRC)) \
       $(patsubst third_party/argon2/%.c,$(BUILD)/argon2/%.o,$(ARGON2_SRC))

.PHONY: all test clean shader

all: $(LIB)

$(BUILD):
	mkdir -p $(BUILD)/argon2/blake2

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) $(INC) -pthread -c $< -o $@

$(BUILD)/%.o: src/%.s | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/argon2/%.o: third_party/argon2/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) $(INC) -pthread -c $< -o $@

$(LIB): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ)

test: $(LIB)
	python3 tests/test_core.py

shader:
	bash tools/build_shader.sh

clean:
	rm -rf $(BUILD) $(LIB)
