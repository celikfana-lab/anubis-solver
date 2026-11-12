#!/usr/bin/env bash
# Regenerate src/vulkan/sha256_comp.spv and src/vulkan/sha256_comp.spv.h.
# Requires glslangValidator (glslang-tools package, or GLSLANG=/path/to it).
set -euo pipefail
cd "$(dirname "$0")/.."

GLSLANG="${GLSLANG:-glslangValidator}"
if ! command -v "$GLSLANG" >/dev/null 2>&1; then
    echo "error: $GLSLANG not found; install glslang-tools or set GLSLANG=" >&2
    exit 1
fi

"$GLSLANG" -V --target-env vulkan1.1 -o src/vulkan/sha256_comp.spv src/vulkan/sha256_comp.comp
python3 tools/embed_spv.py
