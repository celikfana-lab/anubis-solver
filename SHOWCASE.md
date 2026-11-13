# What this repository demonstrates

One session's work, left where anyone can check it. Every number below was
measured, not estimated, and every claim has a command next to it that
reproduces or disproves it.

Repository: <https://github.com/celikfana-lab/anubis-solver> · release **v1.2.0**

---

## 1. Real measurements on real hardware

The three GPU kernels were compiled for `sm_75`, run on a **Tesla T4** (Kaggle),
and optimised against that baseline. Before/after, same workload, verified
against the shipped reference vectors before any timing:

| kernel | shipped | optimised | gain | the actual change |
|---|---:|---:|---:|---|
| SHA-256 | ~1,500 MH/s | **~2,400 MH/s** | **1.4–1.8×** | block built in registers instead of a 96-byte local-memory array |
| HashX | 62.7 MH/s | **1,244 MH/s** | **19.9×** | the challenge program emitted as straight-line code instead of interpreted |
| Argon2id | 715 H/s | **960 H/s** | **1.34×** | 16-byte block copies, `prev^ref` kept in shared memory |

The SASS for all three ships in `src/sass/`, along with the jobs that produced
it. Two of those kernels are additionally **annotated instruction by instruction**
— 4,896 comments in total, and stripping the comments reproduces the original
`.sass` byte for byte.

Two results I keep because the measurement disagreed with my prediction:

- **ILP does not help SHA-256 here** (2,390 / 2,412 / 2,407 MH/s at 1/2/4 nonces
  per thread). The SM is issue-throughput-bound, not latency-bound. ILP=1 also
  uses 40 registers instead of 128, i.e. full occupancy.
- **My first JIT produced a wrong digest** — `imm` zero-extended where the
  interpreter sign-extends through `int32`. One mismatched word, caught by
  checking against the reference vector instead of trusting the generator.

## 2. Seven languages, one answer

`libanubis_solver.so` is reachable from seven languages, each with tests against
the real library, and **all of them return the same nonce and the same digest**
for the same challenge:

| | mechanism | checks |
|---|---|---:|
| Python | ctypes | — (the original) |
| Node | koffi FFI, no native addon | 11 |
| Go | cgo | 10 |
| C# | P/Invoke, no NuGet | 13 |
| R | `.Call` shim | 14 |
| Java | JNI, no jars, no preview flags | 15 |
| Assembly | `.include` macros, x86-64 `call` / AArch64 `bl` | runs on both |

The AArch64 demos were cross-compiled and executed under `qemu-aarch64` against
an aarch64 build of the library — and produce the same nonce as native x86-64,
so the two check each other rather than themselves.

```bash
./examples/run_all.sh      # 7 passed, 0 failed, 0 skipped
```

Each binding's file documents the FFI trap that actually cost time in that
language: koffi's Buffer-vs-string and out-pointer rules, C#'s UTF-8 string
marshalling hiding binary input, R's `.C()` discarding the return value, Java's
silently-matching-nothing JNI signatures.

## 3. A build that knows what it is building for

```bash
$ make config
1. GPU architecture
   detected : Tesla T4 (7.5 -> sm_75)
   SASS     : measured reference exists - 7 file(s) for sm_75
2. CPU architecture : x86_64
3. CPU features     : AVX2 yes, AVX-512F no, SHA-NI yes
   best SHA-256 path: src/cpu/shani.s (SHA-NI) + src/cpu/avx2.s
```

It writes `config.mk` and passes `-arch=` to nvcc — **which the build
previously never did**, so every CUDA build had silently taken nvcc's default
architecture.

## 4. The hardware half

`beyond/` is a Verilog project: a 365-engine Argon2id card with eight HBM3e
stacks, a three-machine die (Argon2id / HashX / SHA-256), SPI/QSPI/OSPI and UART
control, and a self-test ("doctor") that stresses every datapath and the memory
stacks on command. 19 testbenches pass.

Its headline numbers (70,122 h/s, 9.8 TB/s) are **cycle-accurate simulation at an
assumed 1 GHz** — not silicon, and no STA has been run. The 75 %-efficiency
derate is given alongside (46,582 h/s), because that is the honest figure.

## 5. A working tool, not a demo

`dsh-plugin/` adds `anubis_fetch`: a `web_fetch` that solves
[Anubis](https://github.com/TecharoHQ/anubis) challenges. Default engine is pure
Node — `node:crypto` plus a cookie jar, no Python, no native library, no
subprocess. It reads the challenge, solves it, passes it, keeps the cookie and
returns the page.

Against the live target it handled both policies the server actually serves
(`sha256` difficulty 16 and `metarefresh`), and the pure-JS proof of work was
checked against the C engine: both find the same nonce, the C engine accepts the
JS nonce, including the little-endian edge case.

---

## Verify it yourself, in about a minute

```bash
git clone https://github.com/celikfana-lab/anubis-solver && cd anubis-solver
make && make config

./examples/run_all.sh                 # seven languages, same digest
make -C beyond -j16 sim               # 19 hardware testbenches
node --test dsh-plugin/test.mjs       # the fetch tool, incl. a live solve

cd bindings/asm && make run && make run-arm   # assembly on x86-64 and AArch64
```

Reproduce the GPU numbers: `src/sass/kaggle_t4_sass.py`,
`kaggle_t4_hashx.py` and `kaggle_t4_argon2id.py` are the exact jobs that ran on
the T4; each prints the SASS, the register/spill report and the timings.

## What is *not* verified — read this before believing anything above

- **The GPU numbers are one shared cloud T4 per run.** Ratios are trustworthy
  (measured back-to-back in the same process); absolute MH/s moves between runs
  because of clock and contention. The shipped-kernel figures varied 1,348–1,749
  MH/s across runs for exactly that reason, which is why the optimised kernel's
  flat ~2,400 is the more useful number.
- **All chip numbers are simulation.** No synthesis-to-netlist timing, no silicon.
- **Nothing is wired into the library itself.** The optimised kernels live in
  `src/sass/` as measured references and are not compiled into
  `src/cuda/*.cu` — that would need a GPU to validate the library path end to end.
- **The JS engine coverage is no longer partial, but argon2id still is.**
  `tools/anubis_fetch.js` solves `fast`, `slow`, `sha256` and now `hashx` by
  itself (`hashx` is compiled to wasm for the challenge, in JavaScript);
  `argon2id` still goes through the Python driver or the C engine, because ~19 MiB
  of memory-hard work is not something to reimplement in JS for a client.
- **Some chip design choices were wrong and are documented as such** rather than
  quietly dropped — e.g. 484 engines at 2 contexts measured 1,592 B/cycle against
  a predicted ~9,800, and that anomaly is unexplained, so it appears in no table.
- This is one session. It produced a lot, and a long session also means the
  guard rails (rebase discipline, single-owner files, Lead review) did the work
  of keeping it consistent.

## The one-line summary

Given a repository, a live target and a bench, this session produced: measured
optimisations rather than claimed ones, seven independent bindings that agree
with each other, a build that knows its target, a working tool on top, and a
document that names its own unverified claims.
