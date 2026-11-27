#!/usr/bin/env bash
# Capture a real Intel OpenCL dispatch, then replay it on raw i915 and time it.
#
#   bash capture.sh [capture-dir]
#
# Needs Intel's OpenCL stack (intel-opencl-icd) for the capture only; the
# replay itself touches nothing but /dev/dri/renderD128.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
dir="${1:-/tmp/i915dump}"
clrun=/tmp/anubis-i915-clrun

CC="${CC:-cc}"
mkdir -p "$here/../../build"

echo "== building"
make -s -C "$here" all

echo "== building the OpenCL reference harness"
"$CC" -O2 -o "$clrun" "$repo/tools/xe-sha256-opencl.c" -lOpenCL

echo "== capturing Intel's dispatch into $dir"
rm -rf "$dir"
mkdir -p "$dir"
LD_PRELOAD="$here/../../build/i915-dump.so" "$clrun" | tail -3

echo "== replaying it through raw i915 (timed)"
"$here/../../build/i915-replay" --dump "$dir" --upto 8 --bench 12 --nonces 4194304

echo "== solving: scan nonces 0..4M at difficulty 16, raw i915"
"$here/../../build/i915-replay" --dump "$dir" --upto 8 --solve 16 --bench 1 \
    --nonces 4194304 | tee "$dir/solve.txt" | grep -E 'dispatch|hits|hit '
python3 "$here/verify_solve.py" --difficulty 16 --base 0 --count 4194304 \
    < "$dir/solve.txt"

echo
echo "capture kept in $dir (log.txt is the manifest)"
