#!/usr/bin/env python3
"""Argon2id throughput model for a scaled-up version of beyond/rtl/argon2.

Grounded in the measured RTL: one engine takes 5,165,657 cycles for a real
Anubis hash (m=19456, t=2), i.e. 132.76 cycles per 1 KiB block over 38,912
blocks. Before the one-cycle write-back landed it was 10,126,531 cycles
(260.2 cycles per block); the write-back is what halved that per-block cost,
and 5,165,657 is the measured post-change number (`make vlreal`, real RTL,
real Argon2). Each block touches prev (read), ref (read), dst (read, pass 1
only) and cur (write) - 3 KiB on pass 0, 4 KiB on pass 1, 3,584 B on average.

Memory: HBM3e is 9.6 Gb/s/pin x 1024 bit / 8 = 1228.8 GB/s per stack. At a
1 GHz core clock that is 1228.8 B/cycle; BPC_STACK = 1228 is used here (0.07%
conservative). NSTACK stacks give NSTACK * BPC_STACK B/cycle, i.e. 9,824
B/cycle = 9.82 TB/s for eight of them.

Four limits are modelled:
  compute   engines * clock / cycles_per_block
  bandwidth bytes_per_block / link bandwidth
  latency   each engine exposes one dependent read per block (the ref index
            depends on the block just computed), hidden only by interleaving
            several hashes on that engine
  port      one memory request per cycle; a request is one block (3,072 B on
            pass 0, 4,096 B on pass 1), so the client port caps a single-port
            engine at 3,584 B/cycle however much bandwidth sits behind it.
            This is what the eight-stack RTL measurement hits, and why
            req_lanes matters: 9,824 / 3,584 = 2.74 request lanes are needed
            to use eight HBM3e stacks.

Checked against cycle-accurate RTL, not assumed:
  * tb/tb_mpipe.v, 24 engines x 2 contexts, one 819 B/cycle HBM3 link at the
    default CYC_BLOCK=133: measured 176.50 cycles/engine/block = 3,494
    hashes/s. The model says max(132.76, 350/2) = max(CPB, LAT/K) = 175, so the
    engine is latency-bound here, not compute-bound - the extra 1.5 cycles are
    the request handshake. With CYC_BLOCK=260 the same bench measured 260.00
    exactly (2,372 hashes/s), i.e. compute-bound and zero memory stalls.
  * tb/tb_hbm3e_x8.v, eight HBM3e stacks: each of the eight links sustains
    1,228 B/cycle and the eight together 9,824 B/cycle (measured, exact, one
    request port per stack); through a single request port the same subsystem
    measures 4,096 B/cycle (4.096 TB/s), and argon2_mpipe's 3,072/4,096 B
    traffic plateaus at 3,584 B/cycle (3.584 TB/s, ~25.7 k hashes/s at 1 GHz).
  * the same bench at NENG=365, KCTX=3, NPORT=3: 365 engines saturate all eight
    stacks (2.74 blocks/cycle, 99.8% of 9,824 B/cycle) at 133 cycles per engine
    per block, which is 70,426 hashes/s at 1 GHz. KCTX=2 needs 484 engines for
    the same rate because the floor is LAT/2 = 175, and adding engines past the
    saturation point buys nothing.

Run:  python3 tools/perf_model.py
"""
CYCLES_PER_HASH = 5_165_657
BLOCKS = 19456 * 2                      # t=2 passes
CPB = CYCLES_PER_HASH / BLOCKS          # 132.76 cycles per block
BYTES_P0 = 3 * 1024                     # prev + ref + write
BYTES_P1 = 4 * 1024                     # + dst for the xor-in
BYTES_PER_BLOCK = (BYTES_P0 + BYTES_P1) / 2
BYTES_PER_HASH = BLOCKS * BYTES_PER_BLOCK   # 139.46 MB

BPC_STACK = 1228        # HBM3e B/cycle at 1 GHz (1228.8 rounded down 0.07%)
NSTACK = 8
REQ_LANES = 1           # argon2_mpipe presents one memory request per cycle


def throughput(engines, clock_hz, bw_Bps, latency_s, contexts=1, req_lanes=REQ_LANES):
    """Return (hashes/s, bottleneck, in_flight_GiB, bytes_in_flight_KB)."""
    blocks_per_s_compute = engines * clock_hz / CPB
    blocks_per_s_bw = bw_Bps / BYTES_PER_BLOCK
    # one request per cycle, one block per request
    blocks_per_s_port = req_lanes * clock_hz

    # latency: with K hashes interleaved on one engine, the waiting hash's
    # memory access overlaps K-1 blocks of work, so an engine can hide up to
    # K * CPB of latency. Standard multithreading model: one block costs
    # max(CPB, latency / K).
    block_cycles = max(CPB, latency_s * clock_hz / contexts)
    blocks_per_s_lat = engines * clock_hz / block_cycles

    rate, why = min(
        (blocks_per_s_compute, "compute"),
        (blocks_per_s_bw, "bandwidth"),
        (blocks_per_s_lat, "latency"),
        (blocks_per_s_port, "request port"),
    )
    hashes = rate / BLOCKS
    # resident memory is the in-flight hash contexts, not the rate
    in_flight_gib = engines * contexts * 19456 * 1024 / 2**30
    # little's law: bytes the link must hold to run at this rate
    bytes_in_flight_kb = rate * BYTES_PER_BLOCK * latency_s / 1024
    return hashes, why, in_flight_gib, bytes_in_flight_kb


def link_bpc(nstack=NSTACK, bpc_stack=BPC_STACK):
    """Aggregate bytes/cycle at 1 GHz for nstack HBM3e stacks."""
    return nstack * bpc_stack


def engines_to_fill(bytes_per_cycle, cycles_per_block):
    """Blocks/cycle needed to fill the link, times cycles/block per engine."""
    return bytes_per_cycle / BYTES_PER_BLOCK * cycles_per_block


LINKS = [
    ("LPDDR6 one channel", 43e9),
    ("LPDDR6 die (2 chan)", 86e9),
    ("DDR5-6400 2ch", 102e9),
    ("GDDR6X 384-bit", 1008e9),
    ("HBM2e stack", 460e9),
    ("HBM3 stack", 819e9),
    ("HBM3e stack", BPC_STACK * 1e9),
    ("8x HBM3e", link_bpc() * 1e9),
]


def main():
    print(f"{CYCLES_PER_HASH:,} cycles/hash, {CPB:.2f} cycles per 1 KiB block")
    print(f"{BLOCKS:,} blocks/hash, {BYTES_PER_HASH/1e6:.1f} MB moved/hash\n")

    print("24 engines @ 1 GHz, 350 ns latency, one 819 B/cycle HBM3 link")
    print(f"{'K':>3} {'in flight':>10} {'hashes/s':>10} {'bound by':>12} "
          f"{'live mem':>9}")
    for k in (1, 2, 3, 4, 8, 21):
        h, why, mem, _ = throughput(24, 1e9, 819e9, 350e-9, k)
        print(f"{k:>3} {24*k:>10} {h:>10.0f} {why:>12} {mem:>8.2f}G")
    print()

    print("24 engines @ 1 GHz, K=3 (72 hashes in flight), by memory")
    print(f"{'link':>22} {'hashes/s':>10} {'bound by':>12} {'needed KB':>10}")
    for name, bw in LINKS:
        h, why, mem, kb = throughput(24, 1e9, bw, 350e-9, 3)
        print(f"{name:>22} {h:>10.0f} {why:>12} {kb:>9.0f}K")
    print()

    print(f"{NSTACK} x HBM3e at 1 GHz: {link_bpc()} B/cycle = "
          f"{link_bpc()/1000:.2f} TB/s aggregate")
    print(f"  per stack {BPC_STACK} B/cycle ({BPC_STACK/1000:.2f} TB/s), "
          f"rounded down 0.07% from 1228.8")
    ceiling = link_bpc() * 1e9 / BYTES_PER_HASH
    print(f"  {BYTES_PER_HASH/1e6:.1f} MB per hash -> {ceiling:,.0f} hashes/s at 1 GHz")
    print(f"  capacity: {NSTACK} x 16 GiB = {NSTACK*16} GiB bought for bandwidth; "
          f"Argon2id needs 19 MiB resident (m=19456 KiB)")
    print()

    print("engines needed to fill it: "
          f"{link_bpc()}/{BYTES_PER_BLOCK:.0f} = "
          f"{link_bpc()/BYTES_PER_BLOCK:.2f} blocks/cycle")
    for label, cpb in (("133 (write-back, rounded up)", 133),
                       ("260 (old per-block cost)", 260)):
        print(f"  x {label:>29} = {engines_to_fill(link_bpc(), cpb):>6.0f} engines")
    print()

    print("request-port limit (one request/cycle, 3,584 B average per request)")
    for lanes in (1, 2, 3, 4):
        b = lanes * BYTES_PER_BLOCK
        h = min(b, link_bpc()) * 1e9 / BYTES_PER_HASH
        note = "  link-bound: the 9.82 TB/s ceiling is reached" if b >= link_bpc() else ""
        print(f"  {lanes} lane(s) -> {b:>6.0f} B/cycle = {b/1000:.2f} TB/s -> "
              f"{h:>7,.0f} hashes/s{note}")
    print("  (1 lane is argon2_mpipe as written: 1.000 request/cycle, which the")
    print("   8-stack RTL sweep confirms; 3 lanes are needed for 9.82 TB/s)")
    print()

    print("scaling engines on 8 x HBM3e (9,824 B/cycle), 1 GHz, K=3, one port")
    print(f"{'engines':>8} {'hashes/s':>10} {'bound by':>12}")
    for n in (59, 118, 236, 365, 472, 713, 1426):
        h, why, _, _ = throughput(n, 1e9, link_bpc()*1e9, 350e-9, 3)
        print(f"{n:>8} {h:>10.0f} {why:>12}")
    print("  (one port: the engine count stops buying throughput at 1 block/cycle;")
    print("   with 3 lanes the same table would run to the 9.82 TB/s link ceiling)")
    print()

    print("scaling engines on HBM3 (819 GB/s), 1 GHz, K=3")
    print(f"{'engines':>8} {'hashes/s':>10} {'bound by':>12}")
    for n in (6, 12, 24, 48, 96):
        h, why, mem, _ = throughput(n, 1e9, 819e9, 350e-9, 3)
        print(f"{n:>8} {h:>10.0f} {why:>12}")
    print()
    ref = [("CPU 1 thread", 73), ("2x Tesla T4 (measured)", 1758.6),
           ("1x T4", 879), ("RTX 4090 (est, bandwidth-bound)", 7000),
           ("H100 (est, bandwidth-bound)", 20000)]
    print("for reference")
    for name, v in ref:
        print(f"{name:>32} {v:>10.0f} hashes/s")


if __name__ == "__main__":
    main()
