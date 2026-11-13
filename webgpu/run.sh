#!/bin/sh
# run.sh — drive the WebGPU harness in headless Chrome.
#
# WebGPU is not available in Node, so the measurement has to happen in a browser.
# This serves the repository, starts headless Chrome with the flags that give a
# real Vulkan adapter (without them Chrome silently falls back to SwiftShader,
# which is a CPU emulator and would make the numbers meaningless), and prints the
# harness's result object.
#
#   ./run.sh            # native Vulkan adapter
#   ./run.sh swiftshader   # force the CPU backend (correct, but slow)
set -eu
cd "$(dirname "$0")/.."

PORT=8092
if ! curl -sf -o /dev/null "http://127.0.0.1:$PORT/webgpu/hashx.html"; then
    python3 -m http.server $PORT --bind 127.0.0.1 >/dev/null 2>&1 &
    srv=$!
    trap 'kill "$srv" 2>/dev/null || true' EXIT INT TERM
    sleep 1
fi

FLAGS="--enable-unsafe-webgpu"
if [ "${1:-}" != "swiftshader" ]; then
    FLAGS="$FLAGS --enable-features=Vulkan --use-angle=vulkan --use-vulkan=native"
fi

node "$(dirname "$0")/../tools/webgpu-run.mjs" "http://127.0.0.1:$PORT/webgpu/hashx.html?quick=1" $FLAGS
