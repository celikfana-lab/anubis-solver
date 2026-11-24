# Evolution: where this began

Thirteen days of commits (`2026-11-11` → `2026-11-24`, 339 of them at the time
of writing) plus the two weeks of code before the repository existed. Dates are from `git log`, and each
chapter names the commits that carry it, so any claim here can be checked with
`git show`. Nothing in this file is a feature: it is the story of why the
features exist.

## 1. A `.so` in a small pirate tool (October 2026)

The engine did not start as a solver. It started as one file in a small pirate
tool, as a test: could a C hashing loop get a browser through an Anubis wall
without the page's own eight wasm workers? The answer was yes, and the leftover
is still on the maintainer's disk at
`alibaba/flixbaba-dump/flixbrute/firefox-anubis/`.

It contains no solver repository: a Firefox WebExtension, a 181-line
native-messaging host (`native/anubis_native.c`), and an `anubis.h` the host
shared with `flixbrute`. The extension cancelled `main.mjs` before it loaded,
replaced the challenge page with a black-whale screen, and handed the challenge
JSON over native messaging. On `git.ffmpeg.org` the C host took 0.30 s where the
page's own solver took 31 s. That ratio is the whole reason any of this exists.

## 2. Posted to GitHub with half of it missing

The first public posting was that extension. The add-on was public; the engine
behind it was a binary, so the interesting half — the hashing, the midstate, the
JIT — was not there. It was taken down, and the replacement is this repository.

The first commit here, `e10e626` on 2026-11-11, is the opposite: 1,239 lines of
`src/anubis_solver.c`, the AVX2 and SHA-NI assembly, the 2,275-line HashX port,
the Python CLI, and measured JSON for the CVE and the version matrix. Nothing is
missing this time, and that has been the rule since.

## 3. Two days of everything (`11-11` → `11-13`: 7, 78, 79 commits)

The first day added `SPEED.md` and the Vulkan compute backend (`218e5c7`:
"optional" because a laptop iGPU is not obviously a win). The second added CUDA
(`61fe7b6`), Level Zero, OpenCL, AVX-512, AArch64 NEON, the first public header,
the docs tree, and v1.1.0. The third added the T4 SASS kernels, six language
bindings, the wasm kernels, `betterAnusbis`, a documentation site, and v1.2.0.

That is not a schedule anyone should copy. It is what happens when the engine
already exists and only the packaging was missing.

## 4. The chip (`11-12` → `11-13`)

On day two, the same history contains an Argon2id engine in Verilog that solves a
real Anubis challenge (`2fa3f83`), on the way to a 365-engine card with eight
HBM3e stacks (`86aa39d`), a QEMU PCI device with a Linux driver (`card/`), and a
rendered die shot. It has never been fabricated. It is in the repository because
the question "what would this cost in silicon" has a numerical answer, and
because `SPEED.md` is more interesting when the top row is hardware nobody has.

## 5. "HashX and Argon2id can't run on a GPU" (`11-12` → `11-15`)

The maintainer asked Google Gemini whether the two memory-hard-ish tiers could
run on a GPU. The answer was that they could not, or that it would be very slow.
Half of that was wrong, and the half that was right is the point of the
repository — both rows below are measured, and both are in `SPEED.md`:

| claim | measurement | verdict |
|---|---|---|
| Argon2id on a GPU is slow | **20.7x** the 4-vCPU host at d8 (2x Tesla T4, `results/argon2id-cuda-t4.json`) | wrong |
| HashX on a GPU is slow | **8-12x** one CPU thread, program interpreted on the GPU | wrong |
| Argon2id scales with arithmetic | 3.8x **slower** than one CPU core on a TPU | right, for the reason it gave |

The one that came true did so for the reason that makes this project worth
running: Argon2id is memory-hard, so the dependency chain, not the multiplier
count, is the wall. Which is why `SPEED.md` publishes the losing rows next to the
winning ones.

## 6. Kaggle, age verification, and the TPU (`11-15` → `11-22`)

The TPU work starts at `6ee670f` (a PJRT probe and the Kaggle harness). Between
`11-15` and `11-20` the commit counts fall off a cliff — 3, 5, 5 — and that gap
is the cost of the hardware: an account, an age gate, a phone number, and a
notebook that dies at nine hours. The result was worth it on `11-22`
(`1c0ee64`): **700.2 MHash/s** SHA-256 and **284.6 MHash/s** HashX on one TPU
device, 84x and 29x one CPU core.

## 7. `tensor` and `tensor-v`: the tiers that are ours (`11-15` → `11-20`)

Every Anubis tier scales with integer throughput, the axis a CPU with good ILP
wins. `tensor` (`479d4f7`) is the one primitive where a GPU is actually faster:
one int8 GEMM whose digest is the proof. `tensor-v` (`5d464b0`) is the same GEMM
with the server's cost removed — the client commits to the output with a Merkle
root, the server samples 96 blocks from a secret, and a client that skipped a
fraction `f` of the matrix passes with probability `f^96`. Also in that week:
a bare-metal UEFI solver (`129bf2a`), because "no operating system" turned out
to be a smaller step than expected.

## 8. PyPI, and one `.so` (`11-21` → `11-22`)

`64c2ce3` published `libanubis-solver` to PyPI as an sdist and a manylinux
wheel, with trusted publishing for the next release. The `2.0.2 "shaoogle"`
release is the one-`.so` release: CUDA, Level Zero, Vulkan, OpenCL, the TPU and
the CPU in a single library that picks a backend at runtime and always keeps the
CPU as the fallback.

## 9. Scratch: SHA-256 in blocks (`11-23`)

Then came the joke that refused to be a joke. Scratch has no bitwise operators,
and its custom blocks cannot return values, so a SHA-256 has to be written with
limb tables and flattened temporaries. It works (`ffac6b5`, and it solves real
challenges end to end): **25 H/s** interpreted, **1,708 H/s** in TurboWarp, a
difficulty-20 challenge in 9m56s. It also removed the last third-party asset from
the project — the MIT Scratch Cat — and replaced it with the mascot.

The point of the exercise is in `SPEED.md`: the compiled path buys only 1.0-1.6x
over TurboWarp, and the tier is still 410,000x below the TPU kernel. "Compile
it" is not a strategy; it is a constant factor.

## 10. ROCm: the free test drive that was not (`11-23`)

After the TPU, the next obvious question was a Radeon. A web search turned up
Grando's "experience AMD ROCm on Radeon PRO" test drive, and the request was
sent on 2026-11-23 — one hand-written HIP kernel for Argon2id, a few GPU-hours,
results into the public benchmark. The answer, from Comino's sales desk the same
day:

> As your request is an evaluation without a planned procurement, unfortunately
> we cannot offer you test access at this time.

Which is a perfectly normal commercial policy and a completely fair answer, and
also the reason this repository has **no ROCm backend**: the free hardware is
for customers who are buying. The TPU path exists because Kaggle gives away
time; the ROCm path does not, because nobody gives away a W7900.

## 11. `meatrider`: the tier that pays you (`11-24`)

The last chapter is the first one that is about money. Every tier before it
charges the gate's operator in CPU time; `meatrider` (`03036d9`) charges the
client instead, in bitcoin, at a price that is what an Antminer S21 Pro would
earn doing the same hashes. Sixteen rungs from a femtocent to $1.33, which is
2.7 ASIC-hours and 73,000 browser-years.

It exists for the reason the whole repository exists in public: the maintainer
likes money and does not like subscriptions, so the tier is priced per request,
the address is the operator's (`654f916` added the receipt that lets a payer buy
their way past the ASIC rungs), and **no code path pays celikfana or the
project**. The honest limits are in the README next to the ladder: the gate does
not detect the payment, the operator mints the receipt, and nothing pays at all
unless an address is published.

## What it is now

- One `.so`, nine tiers (`fast`, `slow`, `sha256`, `argon2id`, `hashx`,
  `meatrider`, `tensor`, `tensor-v`, `metarefresh`), five backends plus a CPU
  fallback, a gate in one C file, and a browser path that needs no native code.
- 339 commits in thirteen days at the time of writing, every number in
  `SPEED.md` reproducible from a command printed next to it, and a
  `HALL_OF_SHAME.md` for the ones that were wrong — including this project's
  own.
- Started as a binary in a pirate tool. Ended as a published library that says
  exactly where the money goes.

## Read it yourself

```bash
git log --oneline --reverse | head -20     # the first day
git log --stat --reverse | less            # every change, with file counts
git log --date=short --pretty="%ad %s" | awk '{print $1}' | uniq -c   # the days
grep -n "Argon2id on a TPU" SPEED.md       # the claim that came true
grep -n "Argon2id on CUDA" SPEED.md        # the one that did not
git show e10e626 --stat                    # what "all the source" looked like
```
