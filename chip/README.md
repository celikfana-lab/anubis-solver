# chip/ — SHA-256 proof-of-work core in Verilog

A synthesizeable SHA-256 compression core plus a proof-of-work nonce scanner,
written for the Anubis `sha256` (WebAssembly) challenge family.

```
sha256_core.v        iterative SHA-256 block compressor, one round per cycle
anubis_pow.v         nonce scanner on top of the core
argon2_fill.v        Argon2id fill_block (BlaMka) unit — verified
blake2b_core.v       BLAKE2b-512 compression core — WIP (wrong digest)
gen_argon_vectors.py generates prev/ref/dst/expected vectors for the Argon2 tb
tb_sha256.v          known-answer tests (4 vectors, incl. a chained 2-block case)
tb_pow.v             end-to-end PoW test (nonce 83, difficulty 8 bits)
tb_argon2_fill.v     fill_block test against the reference vector (WIP)
Makefile             make sim / make pow / make argon / make synth
```

## Status

Everything below is verified in simulation against either the C core or a
reference implementation:

| module | state |
|---|---|
| `sha256_core.v` | **verified** — empty string, `"abc"`, the 56-byte two-block vector and a chained `digest → midstate` case all match the reference |
| `anubis_pow.v` | **verified** — 64 bytes of `a`, 4-byte big-endian nonce, difficulty 8 bits: finds nonce 83 with digest `008fa7f1…`, matching the reference |
| `argon2_fill.v` | **verified** — 128×64-bit BlaMka block permutation (8 column rounds + 8 row rounds, XOR-in/XOR-out) matches the Python reference on a 128-word block with `xor_en` asserted |
| `blake2b_core.v` | **verified** — 2 cycles/round BLAKE2b-512 compression; empty message, 128×`a`, and a non-uniform block all match `hashlib` |
| `blake2b_stream.v` | **verified** — byte-streaming BLAKE2b (128-byte block buffer, `flush`/`finish` handshake, `t` counter). 0, 3, 64, 112, 128 and 200-byte messages and a τ=32 digest match `hashlib` |
| `h_prime.v` | **verified** — Argon2's H′ for τ = 1024 (31 chained calls), 96, 64 and 32, over X = 72 and X = 1024 bytes |
| `argon2_addr.v` | **verified** — the data-independent address generator: Z from (pass, lane, slice, m', t, y, counter), then A = G(0, G(0, Z)). 5 cases incl. counter 0…128 |
| `h0.v` | **verified** — Argon2's H0: the parameter block, \|P\|, the password stream, the 8-byte salt and the empty K/X lengths, for \|P\| = 1, 26, 96 and T = 32, 64 |

`make sim` runs every testbench. `make stream`, `make hprime`, `make h0` and
`make blake2b` run the BLAKE2b layers on their own.

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
| `lpddr6_model.v` | behavioural DRAM model: 32-byte packets, configurable latency, byte/access counters |
| `lpddr6_if.v` | adaptor between a 1 KiB Argon2 block and `NPKT` (default 32) 32-byte packet accesses |
| `tb_lpddr6.v` | writes and reads back a 1 KiB block through the adaptor and checks it |

```
$ make tb_lpddr6 && vvp tb_lpddr6
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

```bash
cd chip
make sim      # verified core vectors (iverilog + vvp)
make pow      # WIP PoW wrapper test
make synth    # yosys area estimate for sha256_core
```

Requires `iverilog` (Icarus Verilog) and optionally `yosys`:

```bash
sudo apt-get install iverilog yosys
```

## Throughput

One block per 64 cycles. At an FPGA-friendly 200 MHz that is ~3.1 M blocks/s;
a 2-block message (nonce + padding) is ~1.5 M hashes/s per core. On an ASIC at
1 GHz it is ~15.6 M hashes/s per core, and the core is small enough that
hundreds fit on a die — which is exactly why memory-hard algorithms (Argon2id)
exist to blunt this.

## Notes / next steps

- The BLAKE2b stack is done: `blake2b_core` → `blake2b_stream` → `h0` /
  `h_prime`, i.e. H0, the 1 KiB lane seeding and the final tag all verify
  against `hashlib`/`argon2-cffi` inputs.
- Then the Argon2id top level: `index_alpha` (the reference block index),
  the two-pass fill loop and a 19 MiB memory port (the LPDDR6 model is ready
  for it). The address generator for pass 0 slices 0–1 is done.
- For `fast`/`slow` (decimal nonce) the padding position depends on the nonce
  length; that needs a byte-assembly front end instead of the fixed-word patch.
- A pipelined version (one round per stage, 64-stage) would raise throughput
  ~64× at the cost of latency and area.
