# chip/ — SHA-256 and Argon2id proof of work in Verilog

Synthesizable RTL for the two Anubis challenge families: a SHA-256 core with a
nonce scanner (`fast`/`slow`/`sha256`), and a complete Argon2id datapath
(`argon2id`) that solves real challenges in simulation.

## Layout

```
rtl/
  sha256/     sha256_core.v       iterative SHA-256 block compressor, 1 round/cycle
              anubis_pow.v        nonce scanner on top of the core
  blake2b/    blake2b_core.v      BLAKE2b-512 compression, 2 cycles per round
              blake2b_stream.v    byte-streaming BLAKE2b (block buffer, t counter)
              h0.v                Argon2 H0
              h_prime.v           Argon2 H' (variable-length expansion)
  argon2/     argon2_fill.v       fill_block / BlaMka permutation
              argon2_index.v      index_alpha (reference block index)
              argon2_addr.v       data-independent address generator
              argon2_engine.v     a whole Argon2id hash: H0 -> fill -> tag
  hashx/      sipround.v          one SipHash round
              hashx_prf.v         SipHash-2-4 counter-mode PRF (nonce -> r[])
              hashx_exec.v        the 11-opcode HashX VM
              hashx_top.v         PRF, program, finalisation
  mem/        lpddr6_model.v      behavioural LPDDR6 model
              lpddr6_if.v         1 KiB block <-> 32-byte packet adaptor
  periph/     uart_tx.v           8N1 serial transmitter
              uart_log.v          console: banner, and a HIT line per solve
              axil_regs.v         BAR0 register file on AXI4-Lite (the PCIe side)

tb/           one testbench per unit; tb_anubis_solve.v is the end-to-end search
sim/          sim_top.v + sim_main.cpp, the Verilator harness
tools/        gen_*.py vector generators, verify_solve.py
vectors/      .hex vectors (generated on demand, except solve_challenge.hex)
build/        compiled testbenches and Verilator output (git-ignored)
```

Everything below runs from this directory: `$readmemh` picks up `vectors/`
with a relative path.

## Status

Everything below is verified in simulation against either the C core or a
reference implementation:

| module | state |
|---|---|
| `rtl/sha256/sha256_core.v` | **verified** — empty string, `"abc"`, the 56-byte two-block vector and a chained `digest → midstate` case all match the reference |
| `rtl/sha256/anubis_pow.v` | **verified** — 64 bytes of `a`, 4-byte big-endian nonce, difficulty 8 bits: finds nonce 83 with digest `008fa7f1…`, matching the reference |
| `rtl/argon2/argon2_fill.v` | **verified** — 128×64-bit BlaMka block permutation (8 column rounds + 8 row rounds, XOR-in/XOR-out) matches the Python reference on a 128-word block with `xor_en` asserted |
| `rtl/blake2b/blake2b_core.v` | **verified** — 2 cycles/round BLAKE2b-512 compression; empty message, 128×`a`, and a non-uniform block all match `hashlib` |
| `rtl/blake2b/blake2b_stream.v` | **verified** — byte-streaming BLAKE2b (128-byte block buffer, `flush`/`finish` handshake, `t` counter). 0, 3, 64, 112, 128 and 200-byte messages and a τ=32 digest match `hashlib` |
| `rtl/blake2b/h_prime.v` | **verified** — Argon2's H′ for τ = 1024 (31 chained calls), 96, 64 and 32, over X = 72 and X = 1024 bytes |
| `rtl/argon2/argon2_addr.v` | **verified** — the data-independent address generator: Z from (pass, lane, slice, m', t, y, counter), then A = G(0, G(0, Z)). 5 cases incl. counter 0…128 |
| `rtl/blake2b/h0.v` | **verified** — Argon2's H0: the parameter block, \|P\|, the password stream, the 8-byte salt and the empty K/X lengths, for \|P\| = 1, 26, 96 and T = 32, 64 |
| `rtl/argon2/argon2_index.v` | **verified** — `index_alpha` for one lane: 70 vectors across passes, slices and sizes, including the segment-entry cases |
| `rtl/argon2/argon2_engine.v` | **verified** — a whole Argon2id hash: H0 → lane seeding → two-pass fill over both addressing modes → H′(32) tag, bit-exact against `argon2-cffi` for three passwords |
| `rtl/hashx/hashx_prf.v` | **verified** — SipHash-2-4 counter-mode PRF; the ten rounds split 2/4/4 with the `0xee`/`0xdd` xors, matching `hashx_siphash24_ctr_state512` exactly |
| `rtl/hashx/hashx_exec.v` | **verified** — the HashX interpreter: 11 opcodes, 8 registers, one taken branch, and the quirk that BRANCH tests the high half of the last high-multiply |
| `rtl/hashx/hashx_top.v` | **verified** — a whole HashX hash, bit-exact against the C reference for 5 challenges at 512 instructions (533 cycles each) |
| `tb/tb_anubis_solve.v` | **solves** — nonce search on the chip with the Anubis hit rule (see below) |
| `tb/tb_hashx_solve.v` | **solves** — same for `hashx`: difficulty 8 in 229 nonces |

`make sim` runs every testbench (12 of them, ~1 minute plus the engine's 40k
cycles per hash). `make stream`, `make hprime`, `make h0` and `make blake2b`
run the layers on their own.

## Solving a challenge

`tb_anubis_solve.v` wires the engine to the real Anubis rule: the password is
the hex-decoded challenge, the salt is the nonce as a u64 (little-endian when
the last challenge byte is `>= 0x80`), and a hit needs `DIFF` leading zero bits
of the 32-byte tag.

```bash
cd chip
make solve DIFF=4 MAXN=32      # M_COST=64: searches nonces on the chip
```

Two solves are recorded in `../results/chip-solve-2026-11-12.json`:

| memory | difficulty | nonce | leading zeros | tag | how |
|---|---|---|---|---|---|
| 64 blocks | 4 | 18 | 7 | `019d8fec…` | `make solve`, 19 tries, Icarus |
| **19456 blocks** | **12** | **146** | **13** | `00043db9…` | 56 processes, Verilator, 388 s |

The second one is the real Anubis parameter set. Each of those tags is
byte-identical to `argon2-cffi`, so the chip solved the challenge rather than
just hashing something.

```
HIT nonce=18 (0x0000000000000012) leading_zero_bits=7 >= 4 after 19 tries
TAG 019d8fecf65e34c89847ccaf23209c36668261d396680ad3b8e3c96246106ed0
```

`tools/verify_solve.py` rechecks any solve:

```bash
tools/verify_solve.py <challenge_hex> <nonce> <tag_hex> [m_cost] [difficulty]
```

`M_COST` is only a parameter, and the same RTL runs the real 19456-block
parameters. Icarus needs half an hour for that, so use Verilator, which
compiles the RTL to C++ and is ~1000x faster here (2.5M cycles/s):

```bash
make vl64     # Verilator build at M_COST=64, then a 19-nonce search
make vlreal   # real parameters: one hash is 5.17M cycles, ~2.2 s
```

Measured on a 56-core Xeon:

| | Icarus | Verilator |
|---|---|---|
| 19 nonces at M_COST=64 | 174 s | 0.17 s |
| one hash at M_COST=19456 | ~18 min | 2.2 s |

`sim/sim_top.v` + `sim/sim_main.cpp` are the Verilator harness: a clocked FSM drives
`argon2_engine` (no delays, nothing to synthesise differently) and the C++ main
just toggles the clock and prints the tag.

```bash
iverilog -g2012 -Ptb_anubis_solve.M_COST=19456 -Ptb_anubis_solve.DIFF=5 \
  -Ptb_anubis_solve.NSTART=25 -Ptb_anubis_solve.MAXN=1 -o build/tbreal \
  tb/tb_anubis_solve.v rtl/argon2/argon2_engine.v rtl/argon2/argon2_index.v \
  rtl/argon2/argon2_addr.v rtl/argon2/argon2_fill.v rtl/blake2b/h_prime.v \
  rtl/blake2b/h0.v rtl/blake2b/blake2b_stream.v rtl/blake2b/blake2b_core.v
vvp build/tbreal          # ~36 minutes; `make vlreal` does it in 4 seconds
```

The bug that made it report nonce 275: `nblocks` was treated as a flag
("there is a second block") while the testbench meant it as the block count,
so every search hashed an extra all-zero block. It is now a 2-bit count
(`1` or `2`).

## Design

`sha256_core.v`

- 8×32-bit working state `a..h`, 16×32-bit message schedule ring `w[0..15]`.
- One round per clock: `W[r]` is generated on the fly for `r >= 16`
  (`σ1(W[r-2]) + W[r-7] + σ0(W[r-15]) + W[r-16]`) and stored in the ring, so
  the schedule never needs a 64-word memory.
- `midstate` is a full 8-word chaining value, so blocks can be chained without
  leaving the chip.
- Latency: 64 cycles per block (65 including handshake).

`anubis_pow.v`

- Host supplies the midstate after the full 64-byte prefix blocks and a padded
  block template with the nonce field zeroed, plus `nonce_word` (which 32-bit
  word of `block0` gets the nonce), `nonce_le`, `difficulty` (leading zero
  bits), `nonce_start` and `nblocks` (1 or 2).
- Per nonce: patch the nonce word, compress, optional second block, test the
  digest's leading bits; on a miss increment and retry.

## LPDDR6 memory

Argon2id is memory-bound (19 MiB per hash), so the chip needs a DRAM path.
LPDDR6 (JEDEC **JESD209-6**, published July 2025) is modelled here:

| property | LPDDR6 |
|---|---|
| data rate | 10,667 – 14,400 MT/s per pin |
| channel | 24 bit, split into two 12-bit sub-channels |
| burst | BL24: 288-bit burst = 256 data bits + 32 metadata bits |
| access granularity | 32-byte packet, 64-byte access = two packets |
| bandwidth | up to ~38.4 GB/s per die (2 channels) |

Sources: [JEDEC JESD209-6 announcement](https://www.notebookcheck.net/JEDEC-releases-LPDDR6-standard-data-rates-reach-14-400-MT-s.1055771.0.html),
[performance analysis (24-bit channels, BL24 = 288 bits, 32/64-byte accesses)](https://ieeexplore.ieee.org/document/11380413),
[channel architecture](https://www.eeworldonline.com/what-is-jesd209-6-and-why-is-it-important-for-edge-ai/).

What is in the tree:

| file | role |
|---|---|
| `rtl/mem/lpddr6_model.v` | behavioural DRAM model: 32-byte packets, configurable latency, byte/access counters |
| `rtl/mem/lpddr6_if.v` | adaptor between a 1 KiB Argon2 block and `NPKT` (default 32) 32-byte packet accesses |
| `tb/tb_lpddr6.v` | writes and reads back a 1 KiB block through the adaptor and checks it |

```
$ make build/tb_lpddr6 && vvp build/tb_lpddr6
write: 64 cycles, 1024 bytes
read: 864 cycles, 2048 bytes
tb_lpddr6: 1 KiB block round-trip OK through 32 x 32-byte packets
```

The adaptor issues one outstanding request at a time, so it is latency-bound in
simulation (~27 cycles/packet with a 24-cycle model latency). Real bandwidth
comes from pipelining across banks: at 14.4 GT/s a single 24-bit channel moves
`24 × 14.4 Gb/s = 43.2 GB/s`, two channels ~86 GB/s. Argon2id moves roughly
80 MB per hash (2 passes × 19 MiB, read+write), so the theoretical ceiling is
~1000 hashes/s at 86 GB/s and ~500 at one channel — before latency, refresh and
bank conflicts. Next step for the chip is a multi-bank, multi-outstanding
request scheduler on top of `lpddr6_if`.

## Simulate

Every command runs from this directory; artifacts land in `build/`.

```bash
cd chip
make sim        # all 11 testbenches (iverilog + vvp)
make solve      # on-chip nonce search, M_COST=64 (DIFF=4 MAXN=32 by default)
make synth      # yosys area estimate for sha256_core
make clean
```

Single units have shortcuts: `make pow`, `make argon`, `make blake2b`,
`make stream`, `make hprime`, `make h0`, `make addr`, `make index`,
`make engine`, `make hashx`. `make vectors` regenerates every `.hex` in
`vectors/`.

`make solve` searches argon2id nonces on the die, `make solve-hashx` does the
same for HashX (difficulty 8 in a couple of minutes of Icarus).

Verilator targets (see below for why they matter): `make vl64`, `make vlreal`.

Requires `iverilog` (Icarus Verilog), `python3` with `argon2-cffi` for the
engine vectors, and optionally `yosys` / `verilator`:

```bash
sudo apt-get install iverilog yosys verilator
pip install argon2-cffi
```

## Throughput

One block per 64 cycles. At an FPGA-friendly 200 MHz that is ~3.1 M blocks/s;
a 2-block message (nonce + padding) is ~1.5 M hashes/s per core. On an ASIC at
1 GHz it is ~15.6 M hashes/s per core, and the core is small enough that
hundreds fit on a die — which is exactly why memory-hard algorithms (Argon2id)
exist to blunt this.

## Host interfaces: PCIe and UART

Two blocks make the design a card rather than a testbench.

**PCIe.** The TLP and PHY layers are vendor hard IP (Xilinx XDMA, Intel HIP);
what you write is the AXI4-Lite slave that the host reaches through BAR0, and
that is `rtl/periph/axil_regs.v`:

| offset | | |
|---|---|---|
| 0x000 | R | ID, 32'hA0B15C01 |
| 0x004 | RW | CTRL: start, abort, algorithm |
| 0x008 | R | STATUS: busy, done, hit, leading zeros |
| 0x00C/0x010 | RW | NONCE low / high |
| 0x014 | RW | CHALLENGE_LEN |
| 0x018 | W | CHALLENGE_DATA at CH_INDEX*4, index auto-increments |
| 0x01C | RW | CH_INDEX |
| 0x040..0x05C | R | RESULT0..7, the 32-byte digest |

Writing CTRL with bit 0 set raises a one-cycle `start_pulse`. A larger program
load (the HashX table is up to 8 KiB) belongs on the IP's DMA stream, not
through the register window.

**UART.** `uart_log.v` prints a banner on start and one line per hit:

```
ANUBIS v1
HIT NONCE 0x000000123456789A LZ 13
```

Baud and clock are parameters (`CLK_HZ`, `BAUD`), so the same core works at
50 MHz/115200 on a board and at fast dividers in simulation.

Both are verified: `tb/tb_uart.v` decodes the serial line and checks the text,
`tb/tb_axil.v` drives BAR0 like a host and checks the register behaviour.
What is *not* wired yet is the card top that instantiates a register file, an
engine and the logger together - that also needs registers for the HashX keys
and program length.

## HashX

HashX is a program generator plus an interpreter, so the chip does the part
that runs once per nonce: `hashx_prf` turns the nonce into eight 64-bit
registers with SipHash-2-4, `hashx_exec` runs the generated program over them
(one instruction per cycle, 512 instructions, at most one taken branch), and
`hashx_top` finalises with two SipRounds and the key xors.

The program itself comes from software, exactly as it does for the CUDA and
Level Zero backends: `tools/gen_hashx_vectors.c` calls the C reference's
`hashx_init` / `hashx_export` / `hashx_hash` and stages
`(keys, op, dst, src, imm32, tag)` into `vectors/hx_vectors.hex`. Generating a
program is expensive and depends on the challenge, not the nonce, so it belongs
on the host.

```bash
make hashx          # 5 whole hashes against the C reference
make solve-hashx    # on-chip nonce search, difficulty 8 by default
```

```
tb_hashx_solve: 512 instructions, difficulty 8
HIT nonce=228 (0x00000000000000e4) leading_zero_bits=9 >= 8 after 229 tries
TAG 005cedf17531748e9789a1845ed97134c914ed68c45bcf8825dafbc683be4f80
```

## Scaling up: 24 engines, 48 hashes in flight, HBM3

Two modules answer "what if" without building silicon:

| file | role |
|---|---|
| `rtl/argon2/argon2_mpipe.v` | NENG engines, each carrying KCTX hashes, sharing one link. `fill_block` is a 133-cycle counter, so what it measures is whether the memory system keeps the engines busy |
| `rtl/mem/hbm3_model.v` | the link: 819 B/cycle, configurable latency, in-order service, byte accounting |
| `rtl/mem/hbm3e_mem.v` | eight HBM3e stacks: 8 x 1,228 B/cycle = 9.82 TB/s, routed by `block % 8`, with N request lanes and a response compaction network |

```bash
make mpipe        # 24 engines x 2 contexts vs HBM3, ~1 minute of Icarus
```

```
engines 59, contexts/engine 2 (118 in flight), HBM3 819 B/cycle, 350 cyc latency
  steady state: 12000 blocks in 60582 cycles (5.05 cycles/block, 297.86 per engine)
  link: 812.7 B/cycle (813 GB/s) of 819
  throughput: 5090 hashes/s at 1 GHz
```

59 engines is where the link runs out (813 of 819 GB/s). 64 engines reach
5,870 hashes/s and 96 reach 5,881 - no gain, 33 idle engines. At 75% link
efficiency, which is what random 1 KiB blocks costing a row activate each
actually deliver, the same 59 engines give 4,406 hashes/s.

Two bugs this sweep caught in the model itself: the request arbiter advanced
its ring pointer while idle and de-synchronised from demand (up to 38% loss at
36 engines), and every context started at block 0 so the window only ever
covered pass 0. Both are fixed; the curve is monotonic now.

`tools/perf_model.py` predicts 2370 hashes/s for the same configuration, and
says why the knobs behave as they do:

| configuration @ 1 GHz | hashes/s |
|---|---|
| 24 engines, HBM3 (331 GB/s) | 2,074 |
| 48 engines, HBM3 (662 GB/s) | 4,151 |
| **59 engines, HBM3 (813 GB/s)** | **5,090** |
| 64 engines, HBM3 (saturated) | 5,870 |
| 59 engines, HBM3 at 75% efficiency | 4,406 |
| 24 engines on LPDDR6 (86 GB/s) | 617, bandwidth-bound |

For scale: the 2x Tesla T4 measured elsewhere in this repo do 1759 Argon2id
hashes/s, so this configuration is ~1.35x faster than the pair - and still
~3x behind an estimate for an RTX 4090, because at 24 engines it is a DRAM
bandwidth contest.

## Scaling further: eight HBM3e stacks

One HBM3 stack runs out at ~40 engines. `rtl/mem/hbm3e_mem.v` replaces it with
eight HBM3e stacks (9.6 Gb/s/pin x 1024 bits = 1,228.8 GB/s each, 9.82 TB/s
total), reusing the same per-stack link model behind a router that sends
`stack = block % 8`. Only the selected stack can backpressure a request.

```bash
make hbm3e-capacity   # 8 links alone, and the one-port limit
make hbm3e-mpipe MP_NENG=365 MP_KCTX=3 MP_NPORT=3 MP_NRESP=3 MP_CYC=133
```

```
per-stack B/cycle: 1228.0 x8
aggregate: 9824.0 B/cycle = 9824 GB/s at 1 GHz
MPIPE NENG=365 KCTX=3 CYC=133 ... bpc=9801.52 (99.8% of 9824) reqport=2.740
```

Two things are easy to get wrong and both were:

* **The request port, not the DRAM, is the wall.** At most one request per cycle
  at Argon2's 3,584-byte average block is 3,584 B/cycle, so a single-port design
  uses 36% of the memory it paid for (measured: 3,575 B/cycle, 25,699 hashes/s,
  flat from 177 engines upward). Three lanes reach 9,801 B/cycle and 70,282
  hashes/s. A lane is per engine (`engine % 3`) with its own rotating arbiter.
* **`ready` must not depend on `valid`.** Gating the memory's ready on the
  requester's valid deadlocks any master that waits for ready first — it produced
  0 B/cycle with 2,000 of 2,000 requests "accepted". The per-stack lane pointer
  also has to be reset, or the request path is X and every stack quietly rejects
  everything while ready still reads high.

Contexts, not engines, hide the latency: a block costs `max(133, 350/K)` engine
cycles, so K=2 floors at 175 and K=3 reaches the datapath's 133. Filling 9.82 TB/s
therefore needs 484 engines at K=2 but only 365 at K=3 — the difference is DRAM,
not silicon.

## Notes / next steps

- Argon2id is complete end to end: `blake2b_core` → `blake2b_stream` → `h0` /
  `h_prime`, `argon2_index`, `argon2_addr`, `argon2_fill` and `argon2_engine`,
  with the block memory inside the engine. `tb_anubis_solve.v` searches nonces
  and finds one that satisfies the Anubis difficulty.
- What the chip does not have yet is the *memory interface*: `argon2_engine`
  keeps its 1 KiB blocks in a flop array, which is fine for 64 blocks and
  hopeless for 19456. `argon2_mpipe` + `hbm3_model` model the scaled system
  (24 engines, 48 hashes in flight, HBM3) but stand in a counter for
  `fill_block`; wiring the real engine to that port is the remaining work.
- The nonce loop lives in the testbench; a real product would put the leading
  zero counter and the nonce register on the die.
- For `fast`/`slow` (decimal nonce) the padding position depends on the nonce
  length; that needs a byte-assembly front end instead of the fixed-word patch.
- A pipelined version (one round per stage, 64-stage) would raise throughput
  ~64× at the cost of latency and area.
