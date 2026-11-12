#!/usr/bin/env bash
# Regenerate src/argon2id_l0.spv (SPIR-V 1.2) from src/argon2id_l0.cl.
set -euo pipefail
cd "$(dirname "$0")/.."
CLANG="${CLANG:-clang}"
LLVM_SPIRV="${LLVM_SPIRV:-llvm-spirv}"
"$CLANG" -x cl -cl-std=CL2.0 -target spir64-unknown-unknown -emit-llvm -c -O2 \
    src/argon2id_l0.cl -o build/argon2id_l0.bc
"$LLVM_SPIRV" build/argon2id_l0.bc -o src/argon2id_l0.spv --spirv-max-version=1.2
python3 - <<'PY'
from pathlib import Path
data = Path('src/argon2id_l0.spv').read_bytes()
words = [int.from_bytes(data[i:i+4], 'little') for i in range(0, len(data), 4)]
lines = ["    " + ", ".join(f"0x{w:08x}" for w in words[i:i+8]) + "," for i in range(0, len(words), 8)]
header = ("/* Generated from src/argon2id_l0.cl — do not edit. */\n"
          "static const unsigned int argon2id_l0_spv[] = {\n" + "\n".join(lines) + "\n};\n"
          f"static const unsigned long argon2id_l0_spv_bytes = {len(data)}ul;\n")
Path('src/argon2id_l0.spv.h').write_text(header)
print(f"wrote src/argon2id_l0.spv.h ({len(data)} bytes)")
PY
