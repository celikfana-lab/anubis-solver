#!/usr/bin/env bash
# Regenerate src/argon2id.spv from src/argon2id.comp (Vulkan compute).
# Requires glslangValidator (package glslang-tools, or GLSLANG=/path/to it).
set -euo pipefail
cd "$(dirname "$0")/.."
GLSLANG="${GLSLANG:-glslangValidator}"
if ! command -v "$GLSLANG" >/dev/null 2>&1; then
    echo "error: $GLSLANG not found; install glslang-tools or set GLSLANG=" >&2
    exit 1
fi
"$GLSLANG" -V --target-env vulkan1.1 -o src/argon2id.spv src/argon2id.comp
echo "wrote src/argon2id.spv ($(stat -c%s src/argon2id.spv) bytes)"
