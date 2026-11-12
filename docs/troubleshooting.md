# Troubleshooting

## "could not find or build libanubis_solver.so"

The Python package could not find the shared library and `make` failed or is
not available.

```bash
make                       # see the compiler error
export ANUBIS_SOLVER_LIB=/absolute/path/to/libanubis_solver.so
```

## The build skips CUDA / Level Zero / Vulkan

It is by design — a backend is only compiled when its headers/toolchain are
present:

| backend | what to install |
|---|---|
| CUDA | CUDA toolkit (`nvcc`), then `make` again |
| Level Zero | `libze-dev`; build with `make L0_INC=/usr/include` (or wherever `level_zero/ze_api.h` lives) |
| Vulkan | `libvulkan-dev` |

`make clean && make` after installing.

## `ANUBIS_GPU_ARGON2=1` does not speed anything up

The GPU attempt is verified and silently falls back to the CPU when:

- the GPU cannot allocate the Argon2 matrix (~19 MiB × lanes; 64 lanes ≈ 1.3 GB),
- the driver is missing (Vulkan/Level Zero),
- the digest does not match (driver/compiler problem).

Check `AnubisSolver().gpu` and the environment variables in
[gpu.md](gpu.md). Try fewer lanes (`ANUBIS_VULKAN_ARGON2_LANES=8`).

## Vulkan device not found / `gpu` is `None`

```bash
vulkaninfo --summary        # from vulkan-tools
```

No device means no ICD: install `mesa-vulkan-drivers` (or the vendor driver).
Permission problems need the user in the `video`/`render` group for
`/dev/dri/*`.

## OpenCL device not found

```bash
clinfo
```

Mesa `rusticl` only enumerates the Intel GPU with `RUSTICL_ENABLE=iris`
(`RUSTICL_ENABLE=iris,llvmpipe` to include the CPU). Vendor ICDs are preferred.

## The Pi 5 "GPU" is slower than the CPU

Expected: the V3DV compute path is not usable with these kernels, so the solver
falls back to the CPU.

## `UnsupportedAlgorithm`

The challenge uses an algorithm the build does not know. Supported:
`fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx`.

## The search seems slow

- make sure `--threads` is not `1` on a multicore box,
- check `solver.affinity` — pinning to P-cores helps on hybrid CPUs,
- for `fast`/`slow`, the AVX-512/AVX2 kernels are only built on x86-64.

## Linker cannot find `-lanubis_solver`

Add `-L.` and an rpath:

```bash
cc demo.c -L. -lanubis_solver -Wl,-rpath,'$ORIGIN' -o demo
```

## Tests fail with a missing `argon2`

```bash
pip install argon2-cffi
```
