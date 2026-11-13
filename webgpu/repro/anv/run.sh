#!/bin/sh
# run.sh — reproduce the ANV wrong-result with no browser in the picture.
#
# One SPIR-V file, one 200-line Vulkan harness, the same libvulkan. The Intel
# driver gets it wrong and Mesa's own software driver gets it right, which is
# the whole bug report in two commands.
set -eu
cd "$(dirname "$0")"

[ -x ./vkrun ] || gcc -O1 -o vkrun vkrun.c -lvulkan

ICC=/usr/share/vulkan/icd.d/lvp_icd.json

echo "== Intel ANV =="
./vkrun hashx.spv 0 8 0

if [ -f "$ICC" ]; then
    echo
    echo "== llvmpipe, same SPIR-V, same loader, same binary =="
    VK_ICD_FILENAMES="$ICC" ./vkrun hashx.spv 0 8 0
else
    echo
    echo "(no llvmpipe ICD at $ICC — install mesa-vulkan-drivers to compare)"
fi
