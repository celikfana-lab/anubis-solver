# Testing WebGPU on Kaggle

A Kaggle kernel that clones this repository, installs a browser, and runs
`webgpu/hashx.html` and `webgpu/argon2id.html` against whatever adapter Chrome can
get, printing a `result.json`.

```bash
kaggle kernels push -p webgpu/kaggle     # needs ~/.kaggle credentials
kaggle kernels status monktelv31/anubis-webgpu-on-nvidia
kaggle kernels output monktelv31/anubis-webgpu-on-nvidia -p /tmp/out \
    --file-pattern 'result\.json'
```

**What it found: a Kaggle T4 cannot run WebGPU.** The kernel gets two Tesla T4s and
CUDA 13.0 works, but the image has no graphics userspace - no
`/usr/share/vulkan/icd.d`, no `libGLX_nvidia.so*`, only Mesa's GLX - so
`vulkaninfo` reports "Found no drivers!" and Chrome falls back to SwiftShader. The
Vulkan ICD belongs to NVIDIA's graphics driver, and `nvidia-container-toolkit` only
mounts it when `NVIDIA_DRIVER_CAPABILITIES` includes the graphics parts, which
cannot be set from inside a kernel.

The run is still useful: it is a third independent backend where both kernels are
bit-exact (HashX self-check passes, Argon2id produces the same digest as
`wasm/argon2id_pow.wasm`), which is one more data point that the Intel gen-12lp
failure is a driver bug and not our WGSL.

If you want a hosted GPU that actually works, the container has to expose Vulkan:
`docker run --gpus all -e NVIDIA_DRIVER_CAPABILITIES=all` with a driver that
installs `nvidia_icd.json`, or a desktop with a vendor graphics driver.
