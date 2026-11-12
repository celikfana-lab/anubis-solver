# anubis-solver

A C proof-of-work engine with a Python face, for solving
[TecharoHQ/anubis](https://github.com/TecharoHQ/anubis) challenges. It does the
same flow a browser does — fetch the challenge page, compute the proof-of-work,
GET `pass-challenge`, keep the auth cookie — with the hot loops in hand-written
x86-64 assembly.

> **Authorized use only.** Running this against a site circumvents the bot
> mitigation its operator deliberately installed. Use it on systems you own or
> have explicit permission to test. See [SECURITY.md](SECURITY.md).

## Layout

```
src/                 C core and assembly kernels
  anubis_solver.c    hash backends, nonce search, verification, threading
  avx2.s             8-way AVX2 SHA-256 compression (hand-written asm)
  shani.s            SHA-NI single-block compression (hand-written asm)
  neon.s             AArch64 NEON + ARMv8 SHA-2 single-block compression
  hashx.c/.h         C port of tevador/hashx (LGPL-3.0) — see notices
  vulkan.c           optional Vulkan compute backend (dlopen, SHA-256 only)
  sha256_comp.comp   GLSL compute shader for the GPU path
third_party/argon2/  reference Argon2 (CC0-1.0 / Apache-2.0)
anubis_solver.py     Python library (ctypes) + requests client + CLI
tests/               unit, local end-to-end, version-matrix and CVE harnesses
examples/            small runnable snippets for library users
tools/gen_avx2_s.py  emits the unrolled avx2.s (checked in)
tools/build_shader.sh compiles the shader and embeds the SPIR-V header
tools/bench_tiers.py benchmarks every light/medium/hard difficulty tier
results/             raw results from the version, speed and CVE runs
```

## Build

```bash
make                 # libanubis_solver.so (needs cc + x86-64 assembler)
make test            # unit tests
```

The Python module also builds the library on first import if `make` has not
been run.

On AArch64 (Raspberry Pi 5, Apple silicon under Linux, servers) the build
uses `src/neon.s` — NEON plus the ARMv8 SHA-2 crypto instructions. Runtime
dispatch checks `HWCAP_SHA2`; CPUs without it (e.g. Pi 4) fall back to the
portable C compression. `ANUBIS_NO_NEON=1` forces the fallback for A/B tests.

CUDA support is auto-detected: if `nvcc` is on PATH the `fast`/`slow` and
`sha256` challenges run on NVIDIA GPUs (all visible devices), and CUDA is
preferred over Vulkan. Argon2id also has opt-in GPU paths
(`ANUBIS_GPU_ARGON2=1`): CUDA runs one block per hash with up to 128
concurrent hashes per device (~1750 h/s on two T4s vs ~85 h/s on a 4-vCPU
host), the Level Zero backend does the same on Intel GPUs (~200 h/s on an Iris Xe
vs ~43 h/s for one CPU thread), and the Vulkan backend (GLSL with uvec2
emulation) reaches ~230-330 h/s on the same GPU. `make CUDA=0` compiles it out; `ANUBIS_NO_CUDA=1`
disables it at runtime.

Intel GPUs are reached through **oneAPI Level Zero** (oneAPI's low-level C
API): the build picks up `level_zero/ze_api.h` (`L0_INC=/path` if it lives
elsewhere), the SPIR-V kernel is `src/sha256_pow.cl`, and the loader is
`dlopen`ed. Runtime needs the Intel Level Zero driver + IGC; `ANUBIS_NO_LEVELZERO=1`
forces the fallback. Dispatch order is CUDA → Level Zero → Vulkan → CPU.

Vulkan support is auto-detected from `/usr/include/vulkan/vulkan.h`; the
library `dlopen`s `libvulkan.so.1` at runtime, so a machine without Vulkan just
uses the CPU paths. Build with `VULKAN=0` to compile it out. With both
backends built, the order is CUDA → Level Zero → Vulkan → CPU. If you change the
shader, regenerate `src/sha256_comp.spv.h` with `make shader` (needs
`glslangValidator`).

```bash
pip install -r requirements.txt   # requests; curl_cffi and argon2-cffi optional
```

## Python library

```python
from anubis_solver import AnubisClient

client = AnubisClient("http://127.0.0.1:8923", threads=4)
resp = client.get("/")             # solves the challenge automatically
print(resp.status_code, resp.text)

for sol in client.solutions:
    print(sol.algorithm, sol.difficulty, sol.nonce, f"{sol.elapsed_ms:.1f} ms")
```

Lower-level use:

```python
from anubis_solver import AnubisSolver, parse_challenge

challenge = parse_challenge(html)          # AnubisChallenge | None
sol = AnubisSolver(threads=8).solve(challenge)
print(sol.nonce, sol.response)
```

CLI:

```bash
python3 anubis_solver.py http://127.0.0.1:8923/ --threads 8
```

## Examples

[`examples/`](examples/) has standalone snippets:

| file | shows |
|---|---|
| [`basic.py`](examples/basic.py) | fetch a protected page with the high-level client |
| [`solver.py`](examples/solver.py) | parse a challenge, solve it, verify the digest (offline) |
| [`impersonate.py`](examples/impersonate.py) | `curl_cffi` TLS/JA3 impersonation |
| [`gpu.py`](examples/gpu.py) | report GPU/affinity and solve on the GPU |

```bash
python3 examples/solver.py
python3 examples/basic.py http://127.0.0.1:8923
python3 examples/gpu.py --solve
```

## Supported challenges

| `rules.algorithm` | Primitive | Difficulty unit | Status |
|---|---|---|---|
| `fast` | SHA-256(`challenge` + decimal nonce) | leading zero hex nibbles | ✅ |
| `slow` | same primitive, different client-side implementation | nibbles | ✅ |
| `sha256` (WASM) | SHA-256(raw challenge + uint32 nonce) | leading zero bits | ✅ |
| `argon2id` (WASM) | Argon2id(password=challenge, salt=u64 nonce) | leading zero bits | ✅ |
| `hashx` (WASM) | HashX program derived from the challenge | leading zero bits | ✅ |

Byte-exact details:

- **sha256 / argon2id / hashx**: the 32-bit nonce is little-endian when the last
  decoded challenge byte is `>= 0x80`, big-endian otherwise. Argon2id encodes it
  as a 64-bit salt with the same byte order.
- **argon2id parameters**: Argon2id v1.3, `m=19456 KiB`, `t=2`, `p=1`, 32-byte
  output — the Rust `argon2::Argon2::default()`. Each worker needs ~19 MiB, so
  the C layer caps Argon2id at 16 threads.
- **hashx**: `HashX::new(challenge)`; if the generator rejects the seed, a
  little-endian u32 counter is appended and the seed retried — the port does the
  same, so client and server agree on the program.

Unknown algorithms raise `UnsupportedAlgorithm`.

### Protocol eras handled

| releases | how the challenge arrives | quirks |
|---|---|---|
| v1.12.1 – v1.16.0 | none in the page; client `POST`s `.../api/make-challenge` | requires `X-Real-IP`; the client falls back automatically |
| v1.17.0 – v1.21.3 | `{"challenge": "<hex>", "rules": {...}}` | challenge is a string, no `id` |
| v1.22.0 – latest | `{"challenge": {"id", "randomData", ...}, "rules": {...}}` | current shape; `id` is sent to `pass-challenge` |

## curl_cffi (browser fingerprint impersonation)

Anubis can weigh JA3/JA4H or expect the User-Agent to match the TLS stack. Use a
`curl_cffi` profile instead of the plain `requests` session:

```python
client = AnubisClient("https://example.com", impersonate="chrome")

# or bring your own session
from curl_cffi import requests as cr
client = AnubisClient("https://example.com", session=cr.Session(impersonate="chrome120"))
```

```bash
python3 anubis_solver.py https://example.com/ --impersonate chrome
```

`curl_cffi` is optional. When impersonating, the profile's browser User-Agent is
kept so fingerprint and UA agree.

## CVE-2026-62314 (opt-in)

Anubis v1.22.0 .. < v1.26.0-pre1 trusts the client-controlled `X-Original-URI`
header in `lib/policy/checker.go` `PathChecker.Check()`, so a request can match
the shipped `keep-internet-working` ALLOW rules (`^/\.well-known/.*$`, …) and
skip the challenge entirely.

This is an exploit of a known vulnerability, not part of the documented
protocol, so the client:

- does **not** use it by default (`use_cve=False`);
- only tries it after a challenge was issued;
- only targets loopback/private addresses unless `allow_remote_cve=True`;
- emits a warning when it fires.

```python
client = AnubisClient("http://127.0.0.1:8923", use_cve=True)
resp = client.get("/")
if client.cve_bypasses:
    print("bypassed, no PoW run")
```

`tests/test_cve_2026_62314.py` verifies the bypass against locally built
releases; results are in [`results/cve-2026-62314.json`](results/cve-2026-62314.json).

## Performance

Per-tier and per-version timings live in **[SPEED.md](SPEED.md)**. Summary:
difficulty 6 (`git.ffmpeg.org`'s setting, ~16.7M hashes expected), one pinned
core of an i7-1260P:

| path | `fast` | `sha256` (WASM bits20) |
|---|---|---|
| portable C | 1.56 MH/s | 1.90 MH/s |
| `shani.s` only | 5.57 MH/s | 5.65 MH/s |
| `avx2.s` + C scalar | 7.27 MH/s | — |
| `avx2.s` + `shani.s` | **7.51 MH/s** | **6.80 MH/s** |

- `avx2.s`: eight candidate messages in one SHA-256 compression — PoW walks the
  nonce, so a batch shares message length (and padding), and one `__m256i` holds
  the same word of eight messages. State stays in `ymm0..7` with roles rotated
  by macro arguments; the message schedule lives in a 2 KiB stack frame.
- `shani.s`: Intel SHA extensions (`sha256rnds2`, `sha256msg1/2`) for
  single-block hashing; used when a batch cannot form and by `verify_*`.
- Runtime dispatch on x86-64: AVX-512 16-way → AVX2 8-way → SHA-NI single →
  portable C; on AArch64: ARMv8 SHA-2 (NEON) single block → portable C. `ANUBIS_NO_AVX2=1`,
  `ANUBIS_NO_SHANI=1` and `ANUBIS_NO_NEON=1` force the lower paths for A/B
  comparison.

Expected time by tier (one core): `fast`/`slow` light 0.1 ms, medium ~10 ms,
hard ~2 s; `sha256` similar; `hashx` 0.2 ms / 15 ms / 294 ms; `argon2id`
148 ms / 508 ms / 1.85 s. Versions up to v1.27.0 only offer `fast`/`slow`;
v1.28.0+ adds the three WASM algorithms.

With a Vulkan GPU, `fast`/`slow` hard drops to ~77 ms and `sha256` 24 bits to
~78 ms on an Iris Xe; see [SPEED.md](SPEED.md#gpu-vulkan).

On a Raspberry Pi 5 (Cortex-A76, 2.4 GHz) the NEON/SHA-2 path reaches
~10.1 MH/s (`fast`) and ~12.8 MH/s (`sha256`) per core, scaling to
40.4 / 43.2 MH/s on four cores — about 5× faster than the portable C path.
The AArch64 HashX JIT does ~1.6 MH/s per core (6.35 MH/s on four), ~5.3×
the interpreter.

Threading and CPU affinity: on hybrid CPUs (Intel P/E cores) workers are pinned
to the physical P-cores by default and the default thread count is the P-core
count. `ANUBIS_CPU_AFFINITY=off` disables pinning, and an explicit mask such as
`ANUBIS_CPU_AFFINITY=0,2,4,6` pins to those CPUs. `solver.affinity` reports the
result. On power-limited laptops fewer threads can be faster regardless of
pinning; pass `--threads` to override the default.

## GPU (Vulkan)

The SHA-256 challenges (`fast`, `slow`, `sha256`) can run on any Vulkan compute
device. The host code loads `libvulkan.so.1` at runtime, so there is no build or
run dependency on Vulkan unless a device is present. `argon2id` and `hashx`
remain CPU-only.

```python
from anubis_solver import AnubisSolver
solver = AnubisSolver()
print(solver.gpu)                  # e.g. "Intel(R) Iris(R) Xe Graphics (ADL GT2)"
```

The GPU is used only when the expected work is large enough to pay for dispatch
(`fast`/`slow` difficulty ≥ 5, `sha256` ≥ 16 bits by default); lower difficulties
stay on the CPU, where they are faster. Every GPU result is recomputed with the
CPU implementation before it is accepted, so a shader bug cannot produce an
invalid proof.

Measured on an Intel Iris Xe (i7-1260P), one CPU core vs the iGPU:

| challenge | CPU | GPU | speedup |
|---|---:|---:|---:|
| `fast` difficulty 5 | 108 ms | 29 ms | 3.7× |
| `fast` difficulty 6 | 2.27 s | 77 ms | 29× |
| `sha256` 20 bits | 396 ms | 26 ms | 15× |
| `sha256` 24 bits | 1.75 s | 78 ms | 22× |

Environment variables:

| variable | effect |
|---|---|
| `ANUBIS_NO_VULKAN=1` | disable the backend and always use the CPU |
| `ANUBIS_VULKAN_ALLOW_CPU=1` | allow a CPU-type Vulkan device (Mesa lavapipe) |
| `ANUBIS_VULKAN_DEVICE=NAME` | substring match to choose a device |
| `ANUBIS_VULKAN_CHUNK=N` | invocations per dispatch (default 4 MiB) |
| `ANUBIS_VULKAN_MIN_WORK=N` | override the dispatch threshold |

First use in a process pays device/queue/pipeline creation (tens of ms when the
driver's shader cache is warm, longer on a cold cache).

## Tested versions

Every stable Anubis release and every pre-release tag was built from source and
challenged through the algorithms it supports:

```
version   fast  slow  sha256  hashx  argon2id
v1.12.1   ok
...
v1.27.0   ok    ok
v1.28.0   ok    ok    ok      ok     ok
v1.28.2   ok    ok    ok      ok     ok
```

**110/110 cases across all 56 tags** (31 stable + 25 pre-release; the
`v1.17.0.signed` tag is a signing artifact and is skipped). Raw results:
[`results/version-matrix.json`](results/version-matrix.json),
[`results/version-matrix-prereleases.json`](results/version-matrix-prereleases.json).

HashX also has a CUDA backend (`ANUBIS_GPU_HASHX=1`): the generated program is
interpreted on the GPU, one thread per nonce, ~70-110 MH/s on two T4s versus
~8.8 MH/s for one CPU thread. Hits are re-verified by the CPU. A Level Zero
HashX kernel also exists (`ANUBIS_L0_HASHX=1`), and a Vulkan one
(`ANUBIS_VULKAN_HASHX=1`), but both are slower than the CPU on an Iris Xe
(~2-3 vs ~4 MH/s), so they are off by default.

## Tests

```bash
make test                                 # C core vs hashlib / argon2-cffi
python3 tests/test_local.py               # full flow against a local Anubis
python3 tests/test_versions.py            # all git tags (builds each in /tmp)
python3 tests/test_cve_2026_62314.py      # CVE-2026-62314 across tags
```

`test_local.py` and the version matrix build Anubis from a checkout
(`ANUBIS_SRC`, default `../anubis`) and start it in front of a throwaway
backend. Building Anubis from a fresh clone needs its generated assets and WASM
modules:

```bash
cd anubis
npm ci --ignore-scripts
export PATH="$PWD/node_modules/.bin:$PATH"
./lib/challenge/preact/build.sh
./lib/challenge/challengepage/build.sh
./web/build.sh            # the wasm2js worker may fail; not needed for these tests
./xess/build.sh
rustup target add wasm32-unknown-unknown
bash wasm/scripts/build_wasm.sh
go build -o /tmp/anubis-build/anubis ./cmd/anubis
```

## License

Original code is MIT (see [LICENSE](LICENSE)). `src/hashx.c` is a port of
tevador/hashx and remains **LGPL-3.0**; `third_party/argon2` is CC0-1.0 /
Apache-2.0. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before
redistributing binaries.

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
