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

PAGE=hashx.html
case "${1:-}" in
    argon2id)   PAGE=argon2id.html ;;
    swiftshader) ;;                       # CPU backend, flags below
    *)          ;;
esac

FLAGS="--enable-unsafe-webgpu"
case "${1:-}" in
    swiftshader) ;;                       # no Vulkan flags: Chrome falls back to SwiftShader
    *)          FLAGS="$FLAGS --enable-features=Vulkan --use-angle=vulkan --use-vulkan=native" ;;
esac

# QUICK=1 runs the self-check only. Worth it for Argon2id, where one hash is
# seconds on the CPU backend and a few hundred ms even on the GPU.
QUERY=""
[ "${QUICK:-0}" = "1" ] && QUERY="?quick=1"

node "$(dirname "$0")/../tools/webgpu-run.mjs" "http://127.0.0.1:$PORT/webgpu/$PAGE$QUERY" $FLAGS
