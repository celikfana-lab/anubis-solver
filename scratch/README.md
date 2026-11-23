# SHA-256, Argon2id and HashX, in pure Scratch

`scratch/Scratch 3 Emulator.sb3` is a Scratch VM written in Scratch: 15,277
blocks emulating the thing that is running it. This directory is the same genre
applied to the proof-of-work kernels: the hashes Anubis asks a browser to
compute, written the same way, as blocks, with no JavaScript anywhere.

"Pure" means: no `js` escaping, no extension, no compiled-mode-only trick. Every
line the interpreter runs is a Scratch block you can see in the editor.

SHA-256 is done, verified, and it **solves real Anubis sha256 challenges**: the
project finds the nonce, and Anubis accepts the proof. Argon2id and HashX are
next; they share the builder and the two techniques below.

```
scratch/
├── gen_sha256.py            generator: SHA-256 -> .sb3
├── tools/
│   ├── sb3.py               minimal, dependency-free .sb3 writer
│   ├── run_sb3.mjs          headless run in the official scratch-vm
│   ├── profile_sb3.mjs      count every primitive the interpreter executes
│   ├── verify_sha256.py     test vectors against hashlib
│   └── bench_ops.py         per-statement cost of the interpreter
├── build/sha256.sb3         the project (23 KiB, open it in TurboWarp)
└── Makefile
```

## Open it

Load `build/sha256.sb3` in [TurboWarp](https://turbowarp.org) (or scratch.mit.edu),
press the green flag. It hashes the byte list `MSG`, which starts as `abc`, and
puts the hex digest in `OUT_HEX`. `DONE` flips to 1 when it finishes. Edit `MSG`
to hash something else; the flag can be pressed repeatedly.

## The two things Scratch does not have

### 1. Bitwise operators

Scratch gives you `+ - * / mod` and `floor`. That is all. There is no `xor`,
`and`, `<<`, `>>>`.

A 32-bit word fits in a double exactly (every integer below 2^53 does), so most
of SHA-256 is plain arithmetic, and every one of these is *exact* — no rounding,
because the divisors are powers of two:

| operation | in Scratch |
|---|---|
| `a + b mod 2^32` | `(a + b) mod 4294967296` |
| `rotr(x, n)` | `floor(x / 2^n) + (x mod 2^n) * 2^(32-n)` |
| `shr(x, n)` | `floor(x / 2^n)` |
| `not x` | `4294967295 - x` |

xor/and/or have no arithmetic closed form, so they become table lookups: split
the word into limbs, use the limb pair as an index into a 2^L x 2^L table, add
the results back with the right place value.

```
xor32(a,b) = sum over k of   XOR_T[((a >> Lk) mod 2^L) * 2^L + ((b >> Lk) mod 2^L)] * 2^(Lk)
```

L = 4 needs a 256-entry table and 8 lookups per word. L = 8 needs 65,536 entries
and 4 lookups. The tables are generated, so their size costs nothing but file
size: `AND_T` and `OR_T` exist because Ch is `(e and f) or ((not e) and g)` and
Maj is `(a and b) or (c and (a or b))`.

### 2. No return values

`procedures_call` is a *stack* block. Scratch custom blocks cannot return
anything, so putting one in an input slot runs it and yields `undefined`. This
was verified against the real VM before the generator was written: the callee
ran, its global held 42, the receiving variable was `undefined`.

So the port has no functions. A call is a statement that leaves its result in
the global `IRES`, and any expression containing a call is flattened into
statements with temporaries. That flattening is the whole reason this is a
generator (`Fn` in `gen_sha256.py`) instead of a hand-drawn project.

## What it measures

Run against the official `scratch-vm` (the interpreter under TurboWarp and
scratch.mit.edu), counted by `tools/profile_sb3.mjs`:

| | 4-bit limbs | 8-bit limbs |
|---|---|---|
| table entries | 3 x 256 | 3 x 65,536 |
| blocks in project | 1,343 | 1,175 |
| `project.json` | 277 KiB | 1,289 KiB |
| `.sb3` on disk | 24 KiB | 62 KiB |
| block executions / 64-byte block | 117,523 | 67,347 |
| cost per block execution | 0.66 us | 0.84 us |
| throughput, 4 KiB message | 3.0 KB/s | 5.1 KB/s |
| one 64-byte block, steady state | ~21 ms | ~12 ms |
| 3-byte message end to end | ~52 ms | ~41 ms |

Every statement costs about a microsecond (`tools/bench_ops.py`: 1.0-1.3 us for
a variable store or a list read, ~2 us extra for a custom block call). That is
the number that decides the design. Two consequences, both applied:

- **Bake the constants.** `rotr`, `shr` and `add32` are not procedures at all;
  they are nested reporters with the powers of two already folded in. A rotate
  costs no call and no temporary.
- **Unroll the limb loop.** Each limb is one `change IRES by item(...)*2^(Lk)`
  statement. Doing it with variables and a loop instead costs 25 statements per
  xor instead of 5, which is what the first version did.

The 3-byte case is slower than one block of steady-state work because V8 is
still warming up: 41 ms for `abc` versus 12 ms for each block of a 4 KiB run.

## Solving real Anubis challenges

Anubis's sha256 tier (the wasm kernel in `wasm/pow/sha256/src/lib.rs`) hashes
`challenge_raw || nonce`, where the challenge is **hex-decoded** first — the
client worker does `y(c(r))` before handing the bytes to the module — and the
nonce is 4 bytes, big-endian, or little-endian when the challenge's last byte is
`>= 0x80`. `difficulty` is a count of leading zero *bits* of the digest.

The server issues a 64-byte challenge, so the hashed input is 68 bytes: two
blocks, about 40 ms per attempt here. The project has a solver mode: if the
stage list `CHAL` is non-empty, the green flag rebuilds `CHAL || nonce`, hashes
it, checks the leading `DIFF` bits, and bumps `NONCE` until it fits — all in
blocks.

```bash
python3 tools/scratch_pow.py --port 8084     # fetch, solve, submit, re-fetch
```

Against a real Anubis v1.28.3, difficulty 12, 2026-11-23:

```
challenge: 64 raw bytes, difficulty 12, algorithm sha256, id 01a209f0-...
blocks found nonce 7581 after 7582 hashes (25.3 H/s, 300.1 s)
hash: 000e7eb3f4c65c64b53a4f31cb8268f34cd0063a97c21b8f9ee49990fd310d09
pass-challenge: HTTP 302
cookies: techaro.lol-anubis-auth-e0454d27, techaro.lol-anubis-cookie-verification-e0454d27
av log:  msg="challenge accepted"
```

and at difficulty 8, with the re-fetch through the gate:

```
blocks found nonce 84 after 85 hashes (26.1 H/s, 3.3 s)
pass-challenge: HTTP 302
re-fetch: HTTP 200, still challenged: False, 247 bytes
PASS: Anubis accepted a proof of work computed entirely in Scratch blocks
```

25 H/s is the number that matters, because the work is `2^difficulty` hashes:

| difficulty | expected hashes | 4-bit limbs (25 H/s) | 8-bit limbs (~41 H/s) |
|---|---|---|---|
| 8 | 256 | 10 s | 6 s |
| 12 | 4,096 | 2.7 min | 1.7 min |
| 16 | 65,536 | 44 min | 27 min |
| 21 | 2,097,152 | **23 h** | **14 h** |

So: yes, it runs Anubis sha256 challenges, for real — and at the difficulty
production Anubis uses for this tier (21, i.e. 2.1 million hashes) it takes most
of a day in the interpreter. That is the honest ceiling: the algorithm fits in
Scratch perfectly, the *throughput* is what a scratch interpreter cannot give
you. TurboWarp's compiled mode would cut that by a large factor; it is not
measured here.

## Test it

The project is checked against `hashlib` on 20 vectors, including the lengths
that break padding (55, 56, 57, 63, 64, 65, 119, 120), a multi-block message,
all 256 byte values, and random data:

```bash
python3 gen_sha256.py                       # -> build/sha256.sb3
node tools/run_sb3.mjs build/sha256.sb3 '[97,98,99]'
python3 tools/verify_sha256.py              # 20 vectors vs hashlib
python3 tools/verify_sha256.py --sb3 build/sha256_b8.sb3
python3 tools/bench_ops.py                  # where the microseconds go
```

`run_sb3.mjs` needs `scratch-vm` and `jszip`:

```bash
cd /tmp && npm i scratch-vm jszip
NODE_PATH=/tmp/node_modules node scratch/tools/verify_sha256.py
```

## Honest limits

- Verified in **scratch-vm**, the reference interpreter, which also validates the
  project against its own `sb3_definitions.json` schema. It has **not** been
  opened in the TurboWarp or scratch.mit.edu GUI editors; the blocks are the same
  blocks either way, but that check is not done.
- The KB/s figures in the table above are stock `scratch-vm` interpreter
  numbers, the floor. In TurboWarp the same project runs ~66x faster (1653 H/s
  measured by the user in a browser); see "Solving real Anubis challenges".
- The 65,536-entry lists make the editor's list monitor unusable. Functional,
  not pleasant. Use the 4-bit build if you want to read the project.
- Only SHA-256 so far. Argon2id needs a 32x32 -> 64-bit multiply, which Scratch's
  doubles cannot do directly (limbs, again); HashX is an interpreter, so that
  port is a different and larger problem.
- Solver mode assumes the challenge length Anubis currently uses (any length
  works; the nonce rule is implemented, the padding is not length-specific).
  The 23 h figure is an extrapolation from the measured 25.3 H/s, not a run.
