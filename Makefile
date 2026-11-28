CC      ?= cc
PY      ?= python3
CFLAGS  ?= -O3 -fPIC -Wall -Wextra -std=gnu17
NATIVE  ?= -march=native
LDFLAGS ?= -shared -pthread
LDLIBS  ?=
INC     := -Iinclude -Isrc -Isrc/core -Isrc/hashx -Isrc/cpu -Isrc/nvidia/cuda \
           -Isrc/intel/levelzero -Isrc/vulkan -Isrc/opencl -Ithird_party/argon2

# ---- build configuration --------------------------------------------------
# `make config` answers three questions and writes config.mk:
#   which GPU architecture (a T4 is sm_75), which CPU architecture (x86_64 or
#   aarch64), and what that CPU supports (AVX2 / AVX-512 / SHA-NI, or NEON).
# config.mk is generated, per-machine and git-ignored; overrides on the command
# line win, e.g. make config CUDA_ARCH=sm_86 CPU_SIMD=avx2
CONFIG_ARGS ?=
-include config.mk
ifeq ($(wildcard config.mk),)
$(info [anubis] no config.mk yet - run 'make config' to detect GPU arch, CPU arch and SIMD)
endif
NVCC_ARCH := $(if $(CUDA_ARCH),-arch=$(CUDA_ARCH),)

.PHONY: config
config:
	$(PY) tools/configure.py $(CONFIG_ARGS)

# ---- universal build -------------------------------------------------------
# `make universal` is the one-file build: every backend whose toolchain and
# headers exist is compiled into libanubis_solver.so, and the library picks one
# at run time from what the machine actually has. Every vendor API is
# dlopen()ed, so the same file runs on a box with none of them:
#
#   CPU     always, with every SIMD variant compiled in and chosen at runtime
#   CUDA    NVIDIA      needs nvcc at build time (CUDA_RUNTIME=static)
#   L0      Intel Xe    needs level_zero/ze_api.h
#   Vulkan  AMD/Intel/NVIDIA/llvmpipe, needs vulkan.h
#   OpenCL  any ICD      needs CL/cl.h
#   TPU     Google       needs nothing at build time; libtpu is dlopen()ed
#
# `make universal STRICT=1` refuses to finish if a requested backend could not
# be compiled in. Without it each skip is printed with the reason.
UNIVERSAL ?= 0
STRICT    ?= 0
# A universal build *tries* every backend. `auto` is what makes a missing
# toolchain a printed skip rather than the hard error the per-backend `=1`
# path raises; STRICT=1 below turns the skip back into an error. Forcing `=1`
# here made `make universal` fail on any machine without nvcc.
ifeq ($(UNIVERSAL),1)
CUDA   ?= auto
VULKAN ?= auto
OPENCL ?= auto
L0     ?= auto
TPU    ?= auto
FETCH  ?= auto
endif

# Optional CUDA backend (NVIDIA). Built when nvcc is available; the library
# then prefers CUDA over the other accelerators at runtime. cudart is linked
# statically by default so the .so has no DT_NEEDED on libcudart: static cudart
# opens libcuda.so.1 itself, lazily, and reports "no device" where the driver
# is absent instead of failing at load time. That is what makes one universal
# .so possible. CUDA_RUNTIME=shared restores a normal -lcudart link.
CUDA ?= auto
CUDA_RUNTIME ?= static
NVCC ?= nvcc
CUDA_SRC :=
HAVE_CUDA :=
ifneq ($(CUDA),0)
ifeq ($(shell command -v $(NVCC) 2>/dev/null),)
ifeq ($(CUDA),1)
$(error CUDA=1 but nvcc ($(NVCC)) is not on PATH; install the CUDA toolkit, or build with CUDA=0)
endif
else
CUDA_SRC := src/nvidia/cuda/cuda_sha256.cu src/nvidia/cuda/cuda_argon2.cu src/nvidia/cuda/cuda_hashx.cu \
            src/nvidia/cuda/cuda_tensor.cu src/meatrider/meatrider_cuda.cu
CFLAGS   += -DANUBIS_HAVE_CUDA -DANUBIS_MEATRIDER_CUDA
HAVE_CUDA := 1
# nvcc is the linker here; it rejects bare -pthread, so pass it to the host
# compiler explicitly.
LDFLAGS  := $(filter-out -pthread,$(LDFLAGS)) -Xcompiler -pthread -cudart=$(CUDA_RUNTIME)
NVCC_LINK_ARCH := $(NVCC_ARCH)
LINK      = $(NVCC)
endif
endif
LINK     ?= $(CC)

# A '-shared' link leaves the ELF entry point at 0, so `./libanubis_solver.so`
# loads the file as a static PIE, jumps to address 0 and dies with SIGSEGV.
# Point the entry at src/core/direct_run.c instead: it prints "this is a shared
# library, not an executable" plus the credit line through raw syscalls and
# exits 1. dlopen() ignores the entry point, so loading is unchanged.
# nvcc is the linker on CUDA builds and wants -Xlinker rather than -Wl,.
ENTRY_SYM  := anubis_lib_entry
ENTRY_FLAG := $(if $(findstring nvcc,$(notdir $(LINK))),-Xlinker -e -Xlinker $(ENTRY_SYM),-Wl,-e,$(ENTRY_SYM))
LDFLAGS    += $(ENTRY_FLAG)

LIB      := libanubis_solver.so
BUILD    := build
CORE_SRC := src/core/anubis_solver.c src/core/nvidia_boost.c src/core/direct_run.c \
            src/hashx/hashx.c src/meatrider/meatrider.c \
            src/meatrider/meatrider_simd.c src/meatrider/meatrider_backend.c \
            src/meatrider/meatrider_ptx_loader.c

# Optional Vulkan backend (SHA-256 challenges). Auto-detects the headers;
# the library dlopen()s libvulkan.so.1 at runtime, so there is no hard
# dependency on a Vulkan loader being present.
VULKAN ?= auto
HAVE_VULKAN :=
ifneq ($(VULKAN),0)
ifneq ($(wildcard /usr/include/vulkan/vulkan.h),)
CORE_SRC += src/vulkan/vulkan.c
CFLAGS  += -DANUBIS_HAVE_VULKAN -DANUBIS_MEATRIDER_VULKAN
LDFLAGS += -ldl
HAVE_VULKAN := 1
else ifeq ($(VULKAN),1)
$(error VULKAN=1 but /usr/include/vulkan/vulkan.h is missing; install libvulkan-dev, or build with VULKAN=0)
endif
endif
# Optional OpenCL backend (any GPU with an ICD: Intel, AMD, NVIDIA, Mesa).
# dlopen()s libOpenCL.so.1, so there is no hard link and no -lOpenCL here.
# Vulkan is still the preferred path where it works; this one is used when no
# other GPU backend answers, or when ANUBIS_OPENCL=1 asks for it by name.
OPENCL ?= auto
HAVE_OPENCL :=
ifneq ($(OPENCL),0)
ifneq ($(wildcard /usr/include/CL/cl.h),)
CORE_SRC += src/opencl/opencl_backend.c
CFLAGS   += -DANUBIS_HAVE_OPENCL -DANUBIS_MEATRIDER_OPENCL
LDFLAGS  += -ldl
HAVE_OPENCL := 1
else ifeq ($(OPENCL),1)
$(error OPENCL=1 but /usr/include/CL/cl.h is missing; install ocl-icd-opencl-dev opencl-headers, or build with OPENCL=0)
endif
endif
# Optional oneAPI Level Zero backend (Intel GPUs, "the Xe"). The API header is
# vendored under src/intel/levelzero/level_zero/ so this builds without
# libze-dev; the loader is dlopen()ed at runtime, so there is no hard link.
# A system header wins if you point L0_INC at it.
L0 ?= auto
L0_INC ?= $(if $(wildcard src/intel/levelzero/level_zero/ze_api.h),src/intel/levelzero,\
            $(if $(wildcard /usr/include/level_zero/ze_api.h),/usr/include,\
            $(if $(wildcard /usr/local/include/level_zero/ze_api.h),/usr/local/include,)))
HAVE_L0 :=
ifneq ($(L0),0)
ifneq ($(wildcard $(L0_INC)/level_zero/ze_api.h),)
CORE_SRC += src/intel/levelzero/levelzero_sha256.c src/intel/levelzero/levelzero_argon2.c \
             src/intel/levelzero/levelzero_hashx.c
CFLAGS   += -DANUBIS_HAVE_LEVELZERO -I$(L0_INC)
LDFLAGS  += -ldl
HAVE_L0 := 1
else ifeq ($(L0),1)
$(error L0=1 but level_zero/ze_api.h was not found; install libze-dev, or build with L0=0)
endif
endif
# Optional TPU backend (Google, PJRT C API). The plugin (libtpu.so) is
# dlopen()ed at runtime, so this needs no headers beyond the vendored
# pjrt_c_api.h and no library at build time. ANUBIS_TPU_LIB points the loader
# at a specific libtpu.so.
TPU ?= auto
HAVE_TPU :=
ifneq ($(TPU),0)
ifneq ($(wildcard src/google/tpu/tpu_backend.c),)
CORE_SRC += src/google/tpu/tpu_backend.c
CFLAGS   += -DANUBIS_HAVE_TPU -DANUBIS_MEATRIDER_TPU -Isrc/google/tpu
LDFLAGS  += -ldl
HAVE_TPU := 1
else ifeq ($(TPU),1)
$(error TPU=1 but src/google/tpu/tpu_backend.c is missing)
endif
endif

# The architecture of what we are building, not of what we are building on:
#   make ARCH=aarch64 CC=aarch64-linux-gnu-gcc NATIVE=
# is how the released ARM binaries are produced on an x86 box.
ARCH     ?= $(shell uname -m)

# Assembly kernels: x86-64 (AVX2, AVX-512, SHA-NI) or AArch64 (NEON + SHA-2,
# plus a 4-way SVE2 kernel).
# The portable C fallbacks are always compiled.
ifeq ($(ARCH),x86_64)
ASM_SRC  := src/cpu/x64/avx2.s src/cpu/x64/shani.s src/cpu/x64/avx512.s \
            src/meatrider/meatrider_avx2.s src/meatrider/meatrider_shani.s \
            src/meatrider/meatrider_avx512.s
else ifeq ($(ARCH),aarch64)
ASM_SRC  := src/cpu/arm/neon.s src/cpu/arm/sve2.s
CFLAGS   += -DANUBIS_HAVE_NEON_ASM -DANUBIS_HAVE_SVE2_ASM
else
ASM_SRC  :=
endif
# The C fetch layer: follow an Anubis challenge and solve it, over HTTPS.
# It lives in the library so the services and every .so consumer (Python, the
# language bindings) share one client. It needs OpenSSL headers; the
# libcurl-impersonate browser fingerprint is dlopen()ed at runtime, so there is
# no build-time dependency on it. `make FETCH=0` drops the layer, and the .so
# then has no OpenSSL dependency at all.
FETCH_SRC := src/fetch/anubis_fetch.c src/fetch/fetch_impersonate.c
FETCH ?= auto
HAVE_FETCH :=
ifneq ($(FETCH),0)
ifneq ($(ARCH),none)
ifneq ($(shell printf '#include <openssl/ssl.h>\n' | $(CC) -x c -E - >/dev/null 2>&1 && echo yes),)
CORE_SRC += $(FETCH_SRC)
CFLAGS   += -I$(CURDIR)/src/fetch -DANUBIS_HAVE_FETCH
LDLIBS   += -lssl -lcrypto -ldl
HAVE_FETCH := 1
endif
endif
endif

# ---- what a universal build actually contains -----------------------------
# Each line is "yes" or the reason it is not. Kept next to the blocks so a new
# backend has to add its own row and cannot be skipped silently.
CUDA_ROW   := $(if $(HAVE_CUDA),yes,$(if $(filter 0,$(CUDA)),no (CUDA=0),no (nvcc not found; install the CUDA toolkit)))
L0_ROW     := $(if $(HAVE_L0),yes,$(if $(filter 0,$(L0)),no (L0=0),no (level_zero/ze_api.h not found)))
VULKAN_ROW := $(if $(HAVE_VULKAN),yes,$(if $(filter 0,$(VULKAN)),no (VULKAN=0),no (vulkan/vulkan.h not found)))
OPENCL_ROW := $(if $(HAVE_OPENCL),yes,$(if $(filter 0,$(OPENCL)),no (OPENCL=0),no (CL/cl.h not found)))
TPU_ROW    := $(if $(HAVE_TPU),yes,$(if $(filter 0,$(TPU)),no (TPU=0),no (src/google/tpu/tpu_backend.c not found)))
FETCH_ROW  := $(if $(HAVE_FETCH),yes,$(if $(filter 0,$(FETCH)),no (FETCH=0),no (openssl/ssl.h not found)))
BACKENDS_IN := $(strip $(if $(HAVE_CUDA),cuda) $(if $(HAVE_L0),levelzero) \
                  $(if $(HAVE_VULKAN),vulkan) $(if $(HAVE_OPENCL),opencl) \
                  $(if $(HAVE_TPU),tpu) $(if $(HAVE_FETCH),fetch) cpu)

ifeq ($(UNIVERSAL),1)
ifeq ($(STRICT),1)
ifneq ($(CUDA),0)
ifeq ($(HAVE_CUDA),)
$(error STRICT=1: universal build could not compile CUDA in ($(CUDA_ROW)))
endif
endif
ifneq ($(L0),0)
ifeq ($(HAVE_L0),)
$(error STRICT=1: universal build could not compile Level Zero in ($(L0_ROW)))
endif
endif
ifneq ($(VULKAN),0)
ifeq ($(HAVE_VULKAN),)
$(error STRICT=1: universal build could not compile Vulkan in ($(VULKAN_ROW)))
endif
endif
ifneq ($(OPENCL),0)
ifeq ($(HAVE_OPENCL),)
$(error STRICT=1: universal build could not compile OpenCL in ($(OPENCL_ROW)))
endif
endif
ifneq ($(TPU),0)
ifeq ($(HAVE_TPU),)
$(error STRICT=1: universal build could not compile the TPU backend in ($(TPU_ROW)))
endif
endif
endif
$(info [anubis] universal build: $(BACKENDS_IN))
$(foreach r,CUDA L0 VULKAN OPENCL TPU FETCH,$(if $(filter no%,$($(r)_ROW)),$(info [anubis]   $(r): $($(r)_ROW))))
endif

ARGON2_ALL := $(wildcard third_party/argon2/*.c third_party/argon2/blake2/*.c)
# opt.c needs x86 SSE/AVX intrinsics; ref.c is the portable implementation.
ifeq ($(ARCH),x86_64)
ARGON2_SRC := $(filter-out third_party/argon2/ref.c,$(ARGON2_ALL))
else
ARGON2_SRC := $(filter-out third_party/argon2/opt.c,$(ARGON2_ALL))
endif

OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(CORE_SRC)) \
       $(patsubst src/%.s,$(BUILD)/%.o,$(ASM_SRC)) \
       $(patsubst src/%.cu,$(BUILD)/%.o,$(CUDA_SRC)) \
       $(patsubst third_party/argon2/%.c,$(BUILD)/argon2/%.o,$(ARGON2_SRC))

DEP := $(OBJ:.o=.d)
-include $(DEP)

.DEFAULT_GOAL := all

.PHONY: all test clean shader windows services test-api test-mcp test-impersonate impersonate-lib \
        universal report test-universal test-tpu vpu-probe

# The Windows pair and the release zip/msi: a mingw-w64 cross build, no Windows
# needed. `make windows WIN_ARGS=--smoke` also runs a challenge/pass round trip
# under wine. See betterAnusbis/win32/build-windows.sh and RELEASING.md.
windows:
	./betterAnusbis/win32/build-windows.sh $(WIN_ARGS)

all: $(LIB)

$(BUILD):
	mkdir -p $(BUILD)/argon2/blake2

# Object files depend on the flags they were compiled with, not only on their
# sources: adding a backend changes -DANUBIS_HAVE_* and must rebuild the core.
# Without this, a `make` that suddenly has the Level Zero or TPU headers would
# link new objects into a core compiled without them, and the inventory would
# quietly lie. The stamp is rewritten only when the flags actually change.
FLAGS_STAMP := $(BUILD)/.cflags
.PHONY: FORCE
FORCE:
$(FLAGS_STAMP): FORCE | $(BUILD)
	@printf '%s\n' '$(CC) $(CFLAGS) $(NATIVE) $(INC) $(CUDAFLAGS)' > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

$(OBJ): $(FLAGS_STAMP)

$(BUILD)/%.o: src/%.c | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(NATIVE) $(INC) -pthread -MMD -MP -c $< -o $@

$(BUILD)/%.o: src/%.cu | $(BUILD)
	@mkdir -p $(dir $@)
	$(NVCC) -O3 $(NVCC_ARCH) -Xcompiler -fPIC $(INC) -c $< -o $@

$(BUILD)/%.o: src/%.s | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/argon2/%.o: third_party/argon2/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(NATIVE) $(INC) -pthread -MMD -MP -c $< -o $@

$(LIB): $(OBJ)
	$(LINK) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

# ---------------------------------------------------------------------------
# The C services (2.50 "mule"): an MCP server and an HTTP API service,
# both thin layers over libanubis_solver.so plus the shared fetch client. They
# are separate binaries on purpose - a gate operator should not have to install
# a JSON-RPC server, and an agent should not have to run a gate.
# ---------------------------------------------------------------------------
SERVICE_LIBS := -L. -lanubis_solver -Wl,-rpath,'$$ORIGIN' -lpthread

# The fetch layer lives in the library (see the FETCH block above), so the
# services are one translation unit plus the .so. Building it into the library
# as well means .so consumers (Python, the bindings) get the same client.
ifeq ($(HAVE_FETCH),1)
SERVICES := anubis_api anubis_mcp
else
SERVICES :=
endif

anubis_api: src/api/anubis_api.c $(LIB)
	$(CC) $(CFLAGS) -Isrc/fetch -Iinclude -o $@ src/api/anubis_api.c $(SERVICE_LIBS)

anubis_mcp: src/mcp/anubis_mcp.c $(LIB)
	$(CC) $(CFLAGS) -Isrc/fetch -Iinclude -o $@ src/mcp/anubis_mcp.c $(SERVICE_LIBS)

services: $(SERVICES)
ifeq ($(HAVE_FETCH),1)
	@echo "services: anubis_api and anubis_mcp are up to date"
else
	@echo "services need OpenSSL headers (libssl-dev) and the fetch layer;" >&2
	@echo "this build ran with FETCH=0 or a compiler that has no <openssl/ssl.h>" >&2
	@false
endif

# The browser impersonation profile is a runtime library: copy it into the
# layout the fetch layer searches. It is not linked, and not needed to build.
# Point CURL_IMPERSONATE_LIB at a libcurl-impersonate-chrome.so.4 (from a
# curl-impersonate build, or a curl_cffi wheel's lib64/ directory).
CURL_IMPERSONATE_LIB ?=
impersonate-lib:
	@if [ -z "$(CURL_IMPERSONATE_LIB)" ]; then \
	    echo "usage: make impersonate-lib CURL_IMPERSONATE_LIB=/path/to/libcurl-impersonate-chrome.so.4"; \
	    false; \
	fi
	@if [ ! -f "$(CURL_IMPERSONATE_LIB)" ]; then \
	    echo "not a file: $(CURL_IMPERSONATE_LIB)"; false; \
	fi
	@mkdir -p 3rd_party/curl-impersonate/lib
	cp -a "$(CURL_IMPERSONATE_LIB)" 3rd_party/curl-impersonate/lib/
	@echo "installed 3rd_party/curl-impersonate/lib/$$(basename $(CURL_IMPERSONATE_LIB))"
	@echo "run: ./anubis_mcp   (or anubis_api) and look for \"curl-impersonate\" in the fetch result"

test-api: anubis_api
	tests/api_test.sh

test-mcp: anubis_mcp
	tests/mcp_test.sh

test-impersonate: $(LIB) anubis_mcp anubis_api
	tests/impersonate_test.sh

# The one-file build's own checks: exports, no accelerator in DT_NEEDED, the
# Makefile flags against the compiled-in mask, and the C API's inventory.
test-universal: $(LIB) anubis_api
	tests/test_universal.sh

# The TPU backend's own checks. Without libtpu they prove the graceful path
# (unavailable, -1, outputs untouched); with ANUBIS_TPU_LIB set they solve.
test-tpu:
	$(MAKE) -C src/google/tpu selftest
	src/google/tpu/tpu_backend_selftest

test: $(LIB) test-tpu
	python3 tests/test_core.py
	python3 tests/test_tensor_v.py
	python3 tests/test_tensor_v_gate.py

# First contact with an Intel VPU/NPU ("Versatile Processing Unit", the
# Meteor Lake+ neural accelerator): does Level Zero see one, and does its
# driver accept our SPIR-V sha256 kernel? Needs only libze_loader at run time
# and the vendored ze_api.h at build time, so it builds and runs anywhere -
# a machine with no VPU reports exactly that. See docs/vpu.md.
.PHONY: vpu-probe
vpu-probe: $(BUILD)/vpu-probe
$(BUILD)/vpu-probe: tools/vpu_probe.c | $(BUILD)
	$(CC) $(CFLAGS) $(INC) -o $@ $< -ldl

shader:
	bash tools/build_shader.sh

# Assemble the hand-written Intel Xe listing. iga64 is Intel's assembler; it
# comes from libigc2-tools, or from a built IGC tree (see src/intel/xe/README.md).
#
#   make xe-asm        -> build/intelXe_sha256.krn (the machine code)
#   make xe-loader     -> build/xe-loader, which runs it through OpenCL
IGA64 ?= $(shell command -v iga64 2>/dev/null)
.PHONY: xe-asm
xe-asm: | $(BUILD)
ifneq ($(IGA64),)
	$(IGA64) -p 12p1 -a src/intel/xe/intelXe_sha256.xe -o $(BUILD)/intelXe_sha256.krn
	@echo "assembled $(BUILD)/intelXe_sha256.krn: $$(wc -c < $(BUILD)/intelXe_sha256.krn) bytes, $$(( $$(wc -c < $(BUILD)/intelXe_sha256.krn) / 16 )) instructions"
else
	@echo "xe-asm needs iga64: apt install libigc2-tools, or build visa/iga from IGC"
	@false
endif

# HashX as Intel Xe assembly.  The HashX program is generated per challenge, so
# the listing is generated too: the keys and the 512 instructions are baked in
# as immediates and the whole kernel becomes straight-line code.
#
#   make xe-hashx        -> regenerate, check the digests, assemble
#   python3 tools/gen_xe_hashx.py --selftest    -> just the 64-bit primitives
#   python3 tools/gen_xe_hashx.py --stages      -> the register file vs the C
.PHONY: xe-hashx
xe-hashx:
	python3 tools/gen_xe_hashx.py --assemble

# Intel Xe assembly loader: patches a listing assembled by IGA into an IGC Zebin
# and loads it through OpenCL, which is the only way to execute hand-written gen
# instructions on this machine (Vulkan and OpenCL both take SPIR-V otherwise).
# Opt-in, because it is a research tool, not part of the library.
#
#   make xe-loader
#   build/xe-loader --text /tmp/ours.krn --count 65536
#
# Needs OpenCL headers; the driver is loaded at runtime.
XE_CL_HDR ?= $(wildcard /usr/include/CL/cl.h)
.PHONY: xe-loader
xe-loader: | $(BUILD)
ifneq ($(XE_CL_HDR),)
	$(CC) -O2 -DCL_TARGET_OPENCL_VERSION=300 -o $(BUILD)/xe-loader tools/xe_load.c -lOpenCL
	@echo "built $(BUILD)/xe-loader"
else
	@echo "xe-loader needs OpenCL headers: apt install ocl-icd-opencl-dev opencl-headers"
	@false
endif

# ---------------------------------------------------------------------------
# The universal .so: every backend that can be compiled in, is. Vendor driver
# libraries are dlopen()ed at runtime, so the result runs everywhere; the
# library then probes the machine and picks the best backend it finds.
#
#   make universal              build the one file
#   make universal STRICT=1     fail instead of skipping a missing backend
#   make report                 what is in the .so that is on disk now
# ---------------------------------------------------------------------------
universal:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory -j$$(nproc) UNIVERSAL=1 $(LIB)
	@$(MAKE) --no-print-directory UNIVERSAL=1 report

report:
	@echo "libanubis_solver.so: $(BACKENDS_IN)"
	@printf '  %-9s %s\n' cpu "yes" \
	    cuda "$(CUDA_ROW)" levelzero "$(L0_ROW)" vulkan "$(VULKAN_ROW)" \
	    opencl "$(OPENCL_ROW)" tpu "$(TPU_ROW)" fetch "$(FETCH_ROW)"
	@if [ -f $(LIB) ]; then \
	    echo "  deps:    $$(readelf -d $(LIB) 2>/dev/null | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | paste -sd' ')"; \
	    echo "  run:     python3 -c \"import anubis_solver as a; print(a.AnubisSolver().backends())\""; \
	else \
	    echo "  $(LIB) not built yet"; \
	fi

clean:
	rm -rf $(BUILD) $(LIB) anubis_api anubis_mcp
	@if [ -f src/google/tpu/Makefile ]; then \
	    $(MAKE) -C src/google/tpu clean >/dev/null 2>&1 || true; \
	fi


# PyPI sdist + wheel. Build from /tmp so the repo's own build/ directory does
# not shadow the `build` module, and let the caller name the platform tag.
dist:
	rm -rf dist
	cd /tmp && python3 -m build --outdir "$(CURDIR)/dist" "$(CURDIR)"
	-twine check dist/*
