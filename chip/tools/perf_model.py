#!/usr/bin/env python3
"""Argon2id throughput model for a scaled-up version of chip/rtl/argon2.

Grounded in the measured RTL: one engine takes 10,126,531 cycles for a real
Anubis hash (m=19456, t=2), i.e. 260.2 cycles per 1 KiB block over 38,912
blocks. Each block touches prev (read), ref (read), dst (read, pass 1 only)
and cur (write) - 3 KiB on pass 0, 4 KiB on pass 1.

Three limits are modelled:
  compute   engines * clock / cycles_per_block
  bandwidth bytes_per_block / link bandwidth
  latency   each engine exposes one dependent read per block (the ref index
            depends on the block just computed), hidden only by interleaving
            several hashes on that engine

Run:  python3 tools/perf_model.py
"""
CYCLES_PER_HASH = 10_126_531
BLOCKS = 19456 * 2            # t=2 passes
CPB = CYCLES_PER_HASH / BLOCKS  # 260.2 cycles per block
BYTES_P0 = 3 * 1024           # prev + ref + write
BYTES_P1 = 4 * 1024           # + dst for the xor-in


def throughput(engines, clock_hz, bw_Bps, latency_s, contexts=1):
    """Return (hashes/s, bottleneck, in_flight_GiB, bytes_in_flight_KB)."""
    blocks_per_s_compute = engines * clock_hz / CPB

    # average bytes per block over the two passes
    bytes_per_block = (BYTES_P0 + BYTES_P1) / 2
    blocks_per_s_bw = bw_Bps / bytes_per_block

    # latency: with K hashes interleaved on one engine, the waiting hash's
    # memory access overlaps K-1 blocks of work, so an engine can hide up to
    # K * CPB of latency. Standard multithreading model: one block costs
    # max(CPB, latency / K).
    block_cycles = max(CPB, latency_s * clock_hz / contexts)
    blocks_per_s_lat = engines * clock_hz / block_cycles

    rate = min(blocks_per_s_compute, blocks_per_s_bw, blocks_per_s_lat)
    if rate == blocks_per_s_compute:
        why = "compute"
    elif rate == blocks_per_s_bw:
        why = "bandwidth"
    else:
        why = "latency"
    hashes = rate / BLOCKS
    # resident memory is the in-flight hash contexts, not the rate
    in_flight_gib = engines * contexts * 19456 * 1024 / 2**30
    # little's law: bytes the link must hold to run at this rate
    bytes_in_flight_kb = rate * bytes_per_block * latency_s / 1024
    return hashes, why, in_flight_gib, bytes_in_flight_kb


LINKS = [
    ("LPDDR6 one channel", 43e9),
    ("LPDDR6 die (2 chan)", 86e9),
    ("DDR5-6400 2ch", 102e9),
    ("GDDR6X 384-bit", 1008e9),
    ("HBM2e stack", 460e9),
    ("HBM3 stack", 819e9),
]


def main():
    print(f"{CYCLES_PER_HASH:,} cycles/hash, {CPB:.1f} cycles per 1 KiB block\n")
    print("24 engines @ 1 GHz, 350 ns latency, K hashes interleaved per engine")
    print(f"{'K':>3} {'in flight':>10} {'hashes/s':>10} {'bound by':>10} "
          f"{'live mem':>9}")
    for k in (1, 2, 3, 4, 8, 21):
        h, why, mem, _ = throughput(24, 1e9, 460e9, 350e-9, k)
        print(f"{k:>3} {24*k:>10} {h:>10.0f} {why:>10} {mem:>8.2f}G")
    print()
    print("24 engines @ 1 GHz, K=3 (72 hashes in flight), by memory")
    print(f"{'link':>22} {'hashes/s':>10} {'bound by':>10} {'needed KB':>10}")
    for name, bw in LINKS:
        h, why, mem, kb = throughput(24, 1e9, bw, 350e-9, 3)
        print(f"{name:>22} {h:>10.0f} {why:>10} {kb:>9.0f}K")
    print()
    print("scaling engines on HBM3 (819 GB/s), 1 GHz, K=3")
    print(f"{'engines':>8} {'hashes/s':>10} {'bound by':>10}")
    for n in (6, 12, 24, 48, 96):
        h, why, mem, _ = throughput(n, 1e9, 819e9, 350e-9, 3)
        print(f"{n:>8} {h:>10.0f} {why:>10}")
    print()
    ref = [("CPU 1 thread", 73), ("2x Tesla T4 (measured)", 1758.6),
           ("1x T4", 879), ("RTX 4090 (est, bandwidth-bound)", 7000),
           ("H100 (est, bandwidth-bound)", 20000)]
    print("for reference")
    for name, v in ref:
        print(f"{name:>32} {v:>10.0f} hashes/s")


if __name__ == "__main__":
    main()
