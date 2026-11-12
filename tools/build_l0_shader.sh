#!/usr/bin/env bash
# Regenerate src/sha256_pow.spv and src/sha256_pow.spv.h.
#
# Needs a clang that can emit LLVM IR for the spir64 triple plus llvm-spirv:
#   CLANG=/path/to/clang-19 LLVM_SPIRV=/path/to/llvm-spirv-19 \
#       bash tools/build_l0_shader.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CLANG="${CLANG:-clang}"
LLVM_SPIRV="${LLVM_SPIRV:-llvm-spirv}"

"$CLANG" -x cl -cl-std=CL2.0 -target spir64-unknown-unknown -emit-llvm -c \
    src/sha256_pow.cl -o build/sha256_pow.bc
"$LLVM_SPIRV" build/sha256_pow.bc -o src/sha256_pow.spv \
    --spirv-max-version=1.2
python3 tools/embed_l0_spv.py
