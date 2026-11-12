CC      ?= cc
CFLAGS  ?= -O3 -fPIC -Wall -Wextra
NATIVE  ?= -march=native
LDFLAGS ?= -shared -pthread
INC     := -Isrc -Ithird_party/argon2

# Optional CUDA backend (NVIDIA). Built when nvcc is available; the library
# then links libcudart and prefers CUDA over Vulkan at runtime.
CUDA ?= auto
NVCC ?= nvcc
CUDA_SRC :=
ifneq ($(CUDA),0)
ifneq ($(shell command -v $(NVCC) 2>/dev/null),)
CUDA_SRC := src/cuda_sha256.cu
CFLAGS   += -DANUBIS_HAVE_CUDA
# nvcc is the linker here; it rejects bare -pthread, so pass it to the host
# compiler explicitly.
LDFLAGS  := $(filter-out -pthread,$(LDFLAGS)) -Xcompiler -pthread -lcudart
LINK      = $(NVCC)
endif
endif
LINK     ?= $(CC)

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
# Optional oneAPI Level Zero backend (Intel GPUs). Needs the Level Zero
# headers; the loader is dlopen()ed at runtime, so there is no hard link.
L0 ?= auto
L0_INC ?= /usr/include
ifneq ($(L0),0)
ifneq ($(wildcard $(L0_INC)/level_zero/ze_api.h),)
CORE_SRC += src/levelzero_sha256.c
CFLAGS   += -DANUBIS_HAVE_LEVELZERO -I$(L0_INC)
LDFLAGS  += -ldl
endif
endif

# Assembly kernels: x86-64 (AVX2 + SHA-NI) or AArch64 (NEON + SHA-2).
# The portable C fallbacks are always compiled.
ifeq ($(shell uname -m),x86_64)
ASM_SRC  := src/avx2.s src/shani.s src/avx512.s
else ifeq ($(shell uname -m),aarch64)
ASM_SRC  := src/neon.s
CFLAGS   += -DANUBIS_HAVE_NEON_ASM
else
ASM_SRC  :=
endif
ARGON2_ALL := $(wildcard third_party/argon2/*.c third_party/argon2/blake2/*.c)
# opt.c needs x86 SSE/AVX intrinsics; ref.c is the portable implementation.
ifeq ($(shell uname -m),x86_64)
ARGON2_SRC := $(filter-out third_party/argon2/ref.c,$(ARGON2_ALL))
else
ARGON2_SRC := $(filter-out third_party/argon2/opt.c,$(ARGON2_ALL))
endif

OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(CORE_SRC)) \
       $(patsubst src/%.s,$(BUILD)/%.o,$(ASM_SRC)) \
       $(patsubst src/%.cu,$(BUILD)/%.o,$(CUDA_SRC)) \
       $(patsubst third_party/argon2/%.c,$(BUILD)/argon2/%.o,$(ARGON2_SRC))

.PHONY: all test clean shader

all: $(LIB)

$(BUILD):
	mkdir -p $(BUILD)/argon2/blake2

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) $(INC) -pthread -c $< -o $@

$(BUILD)/%.o: src/%.cu | $(BUILD)
	$(NVCC) -O3 -Xcompiler -fPIC -c $< -o $@

$(BUILD)/%.o: src/%.s | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/argon2/%.o: third_party/argon2/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) $(INC) -pthread -c $< -o $@

$(LIB): $(OBJ)
	$(LINK) $(LDFLAGS) -o $@ $(OBJ)

test: $(LIB)
	python3 tests/test_core.py

shader:
	bash tools/build_shader.sh

clean:
	rm -rf $(BUILD) $(LIB)
