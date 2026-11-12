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

Both modules are verified in simulation:

| module | state |
|---|---|
| `sha256_core.v` | **verified** — empty string, `"abc"`, the 56-byte two-block vector and a chained `digest → midstate` case all match the reference |
| `anubis_pow.v` | **verified** — 64 bytes of `a`, 4-byte big-endian nonce, difficulty 8 bits: finds nonce 83 with digest `008fa7f1…`, matching the reference |
| `argon2_fill.v` | **verified** — 128×64-bit BlaMka block permutation (8 column rounds + 8 row rounds, XOR-in/XOR-out) matches the Python reference on a 128-word block with `xor_en` asserted |
| `blake2b_core.v` | **WIP** — 2 cycles/round BLAKE2b-512 compression core. The 24-cycle FSM runs and produces a digest, but it does not match the reference vectors yet (`make blake2b` fails) |

`make sim` runs the three verified testbenches; `make blake2b` runs the WIP
BLAKE2b core test.

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

- Wire the verified `fill_block` unit into a full Argon2id engine: it still
  needs the BLAKE2b core (H0, H′, final tag), the address generator and a
  19 MiB memory port.
- For `fast`/`slow` (decimal nonce) the padding position depends on the nonce
  length; that needs a byte-assembly front end instead of the fixed-word patch.
- A pipelined version (one round per stage, 64-stage) would raise throughput
  ~64× at the cost of latency and area.
