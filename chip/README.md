# chip/ — SHA-256 proof-of-work core in Verilog

A synthesizeable SHA-256 compression core plus a proof-of-work nonce scanner,
written for the Anubis `sha256` (WebAssembly) challenge family.

```
sha256_core.v   iterative SHA-256 block compressor, one round per cycle
anubis_pow.v    nonce scanner on top of the core (WIP, see Status)
tb_sha256.v     known-answer tests (4 vectors, incl. a chained 2-block case)
tb_pow.v        end-to-end PoW test (currently failing, see Status)
Makefile        make sim / make pow / make synth
```

## Status

| module | state |
|---|---|
| `sha256_core.v` | **verified** — empty string, `"abc"`, the 56-byte two-block vector and a chained `digest → midstate` case all match the reference |
| `anubis_pow.v` | **not yet correct** — the wrapper patches the nonce into the block template and runs the core, but it accepts nonces whose digest does not actually have the required leading zero bits (it reports nonce 275 for a case where the reference answer is 83). The core itself produces the right digest for the same midstate/block in simulation, so the fault is in the wrapper's control/data path. |

`make sim` runs only the verified core test; `make pow` runs the WIP wrapper
test (expected to fail).

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

- Fix the `anubis_pow` control path (the wrapper's digest and the reported
  nonce disagree; the core is proven by `tb_sha256`).
- For `fast`/`slow` (decimal nonce) the padding position depends on the nonce
  length; that needs a byte-assembly front end instead of the fixed-word patch.
- A pipelined version (one round per stage, 64-stage) would raise throughput
  ~64× at the cost of latency and area.
