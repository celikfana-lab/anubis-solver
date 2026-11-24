#!/usr/bin/env bash
# Regenerate src/vulkan/meatrider_comp.spv and src/vulkan/meatrider_comp.spv.h.
# Requires glslangValidator (package glslang-tools, or GLSLANG=/path/to it).
#
#   GLSLANG=/tmp/glslang-try/bin/glslangValidator tools/build_meatrider_vk.sh
#
# The SPIR-V blob is embedded in a header because the library dlopen()s
# libvulkan.so.1 and has no data files to find at run time.
set -euo pipefail
cd "$(dirname "$0")/.."

GLSLANG="${GLSLANG:-glslangValidator}"
if ! command -v "$GLSLANG" >/dev/null 2>&1; then
    echo "error: $GLSLANG not found; install glslang-tools or set GLSLANG=" >&2
    exit 1
fi

"$GLSLANG" -V --target-env vulkan1.1 \
    -o src/vulkan/meatrider_comp.spv src/vulkan/meatrider_comp.comp

python3 - <<'PY'
from pathlib import Path

root = Path(__file__).resolve().parent if "__file__" in dir() else Path(".")
spv = Path("src/vulkan/meatrider_comp.spv")
out = Path("src/vulkan/meatrider_comp.spv.h")
data = spv.read_bytes()
words = [int.from_bytes(data[i:i + 4], "little") for i in range(0, len(data), 4)]
lines = ["    " + ", ".join(f"0x{w:08x}" for w in words[i:i + 8]) + ","
         for i in range(0, len(words), 8)]
header = (
    "/* Generated from src/vulkan/meatrider_comp.comp by "
    "tools/build_meatrider_vk.sh — do not edit. */\n"
    "static const unsigned int meatrider_comp_spv[] = {\n"
    + "\n".join(lines)
    + "\n};\n"
    + f"static const unsigned long meatrider_comp_spv_bytes = {len(data)}ul;\n"
)
out.write_text(header)
print(f"wrote {out} ({len(data)} bytes of SPIR-V)")
PY
