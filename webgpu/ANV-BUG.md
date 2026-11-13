# ANV bug report — wrong compute results on gen-12lp

Ready to paste into <https://gitlab.freedesktop.org/mesa/mesa/-/issues/new>. Attach:

- `webgpu/repro/anv/hashx.spv` (59,096 B, sha256 `88881bed1e8da418d1bc49dfc65fcf836c27f6242237f049ac58ea25cc9ee0ad`)
- `webgpu/hashx.wgsl` (the source it came from, 930 lines)
- `webgpu/repro/anv/vkrun.c` (the harness, so nobody has to write one)

---

## Title

`[ANV, gen-12lp] Wrong compute shader results for 64-bit arithmetic emulated as vec2<u32> (HashX); llvmpipe is correct on the same SPIR-V`

## Environment

| | |
|---|---|
| GPU | Intel Alder Lake-P GT2 [Iris Xe], `0x46a6`, `gen-12lp` |
| driver | `Intel open-source Mesa driver`, `driverVersion 25.2.8`, `Mesa 25.2.8-0ubuntu0.25.10.2` |
| Vulkan | device `apiVersion 1.4.318`, loader `1.4.321` |
| kernel | 6.17.0-41-generic (i915) |
| distro | Ubuntu 25.10 |
| also observed through | Chrome 154.0.8037.97 WebGPU (Dawn/Tint), and `naga` 30.0.2 SPIR-V |

## Summary

A compute shader that emulates 64-bit integers as `vec2<u32>` (no 64-bit types
anywhere; only `u32` add/sub/xor/shift and 16-bit-limb multiplies) produces wrong
results on Intel ANV. All 8 test nonces are wrong, deterministically, on every
run.

The same SPIR-V file produces the correct results on **llvmpipe**, through the
same `libvulkan`, from the same binary, with the same buffers. The correct
digests agree with an independent WebAssembly implementation of the same
algorithm that is checked against the reference implementation.

This is reproducible without WebGPU, without Chrome, and without Dawn. Two
different WGSL front-ends (Tint, inside Chrome, and naga) produce different
SPIR-V for this shader, and **both** produce the identical wrong digest on ANV.
That is the reason I am filing this against Mesa rather than against Dawn.

## Reproduction

```sh
git clone https://github.com/celikfana-lab/anubis-solver
cd anubis-solver/webgpu/repro/anv
gcc -O1 -o vkrun vkrun.c -lvulkan
./run.sh
```

or directly, which is the same thing:

```sh
./vkrun hashx.spv 0 8 0                                                    # ANV: wrong
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json ./vkrun hashx.spv 0 8 0   # llvmpipe: right
```

`vkrun.c` is a minimal Vulkan 1.0 compute dispatcher: one uniform buffer of 16
bytes (`code_size, difficulty, base, count`), one storage buffer of 304 bytes
(`total, hits, pad, pad, nonces[8], hashes[64]`), one workgroup of 64
invocations, `difficulty = 0` so every invocation writes its digest. Nothing is
timed; this only asks what the numbers are.

Expected digests in that output are the llvmpipe column below.

## Expected vs actual

| nonce | expected (llvmpipe, wasm) | ANV |
|---:|---|---|
| 0 | `365720544aec6e042e293b754024fa925c2b4c1d1c12f4933f5348202fa39de3` | `17ca683d1642bdc958c6291292823104e8c27d36bb11c9848ca50eeb32e31f47` |
| 1 | `2d7677d1f030e4e6a51cbbc86ac8eb7a5d8047da3c807b629b86506f7861d4f6` | `d66488b4d8930380e82075de05c1e585b6fcc1a272e3d066f1edb83339788c32` |
| 2 | `4134d053b16b20f9089de3c825a0f808fba77751cccc75274545ff6b950e7585` | `a454bf35f46dcf838848acf945a48f4eca1d23aa7eca603483c9477cbe60a885` |
| 3 | `a2abd14df5975b62d3300fcfce0df2c09ec1e9b1027149284789ad11ca7e7ea1` | `3da2f451d2bd9befdc7f5945e57bded4e8415207b93aece416bb0d4f9fef844d` |

8 of 8 nonces differ. The ANV values are stable across runs, and identical to
what Chrome's WebGPU reports for the same nonces.

## What has been ruled out

- **The shader logic / the harness.** Same SPIR-V bytes, same binary, same
  buffers; llvmpipe returns the expected digest for every nonce.
- **The values being expected at all.** The expected column matches an
  independent WebAssembly build of the same algorithm (`wasm/hashx_pow.wasm`),
  which is itself verified against Anubis's own module and against the C engine.
- **A race, a barrier bug or occupancy.** The wrong value does not depend on the
  dispatch shape: it is identical when the nonce is the only active invocation in
  the workgroup, when it is one of eight, and when it sits at a different
  invocation index. It is also identical across repeated runs.
- **Dawn / Tint.** Chrome's Tint and naga emit different SPIR-V, and both get the
  same wrong answer through ANV. A front-end bug would not survive that.
- **ANV being broken in general.** Other kernels in the same project are exact on
  this driver: a SHA-256 kernel (pure `u32`, `vec4<u32>`) is 8/8 correct, and an
  Argon2id kernel (`u32` arithmetic, `mulhi32`, 38,912 block fills) is exact too.
  Those run through the browser, not through `vkrun`.

## Bisecting the shader

The program is 512 instructions compiled into straight-line code, and the
generator can emit a prefix of it (`--truncate N`). Running each prefix on both
drivers gives a clean divergence point:

| prefix (instructions) | ANV vs llvmpipe |
|---:|---|
| 0 … 113 | identical |
| **114** | **differ** |
| 128, 192, 256, 384, 512 | differ (and the full program differs at 8/8 nonces) |

Instruction `#113` (0-based) is a conditional branch. That alone would be
suspicious but explainable — a truncated prefix can branch past the end of the
emitted code. So the same prefix series was re-run with branch handling omitted
(`--no-branch`, which is correct whenever the guarded branch is not taken, as it
is not for these nonces):

| prefix | llvmpipe digest | ANV digest |
|---:|---|---|
| 113 | `6340ea3a…` | `6340ea3a…` |
| 114 | `6340ea3a…` (unchanged) | **`8890e53a…`** |

With the branch omitted, instruction #113 has no effect on the result — llvmpipe's
digest is unchanged. ANV's answer changes anyway. So the divergence is not about
what that instruction computes; the shader's answer moves when a piece of code
that should not be able to move it is added. That looks like an optimisation or
register-allocation bug that depends on the shape and size of the shader rather
than on one opcode. (For what it is worth, adding more instructions keeps it
wrong, so it is not a one-off at 114 either.)

The same WGSL with `--dump-after` dumps the 16 register words after the program,
and **all 16 differ** between the two drivers, which is consistent with an early
divergence that then propagates.

## Guess at the cause

The shader is large (59 KB of SPIR-V, 930 lines of WGSL, 512 instructions of
straight-line code, 64-bit arithmetic emulated from `u32`). It is exactly the
kind of input where a scheduling, spilling or copy-propagation pass can produce
wrong code without a single obviously wrong instruction.

There is precedent for this class of bug in ANV:
[mesa#2999](https://gitlab.freedesktop.org/mesa/mesa/-/issues/2999),
"Miscompiled compute shaders with 32-bit arithmetic, but not 8/16-bit
arithmetic".

If something like `INTEL_DEBUG=cs` output, or a reduced SPIR-V from
`spirv-reduce`, would help, tell me which one and I will produce it — the
bisect above runs in about two seconds per step on this machine, so I can
narrow it a long way.

## Attached

- `hashx.spv` — the SPIR-V that misbehaves (generated by naga 30.0.2 from the
  attached WGSL; Chrome's Tint produces different SPIR-V with the same symptom).
- `hashx.wgsl` — the source. WGSL has no 64-bit integers, so `u64` is
  `vec2<u32>(lo, hi)` and the 32x32->64 multiplies are built from 16-bit limbs.
- `vkrun.c` — the 200-line harness, in case it is useful for other reports.

## Willing to test

Happy to test any patch, any Mesa version, any `INTEL_DEBUG` output, and to run a
`spirv-reduce`d version once I know which reduction keeps the bug. This machine
has the GPU and nothing else to do with it.
