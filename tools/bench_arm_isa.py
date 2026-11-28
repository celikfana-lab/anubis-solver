#!/usr/bin/env python3
"""Compare the aarch64 kernels on one machine: crypto extension vs SVE2.

    python3 tools/bench_arm_isa.py            # default reps
    python3 tools/bench_arm_isa.py --reps 20

The measurement is a small C program, not ctypes: one Python/ctypes call costs
microseconds, which is ~10x the kernel itself, so a Python loop would measure
the FFI boundary. The C harness calls the exported kernel symbols in a tight
loop (`sha256_compress_sve2`, `sha256_block_neon`) and `anubis_solve_bits()`
for the end-to-end row, and runs twice: with the SVE2 batch path off (the
default on arm64, where neon.s's sha256h wins) and with ANUBIS_SVE2=1.

Numbers from GitHub's `ubuntu-24.04-arm` runner (Cobalt 100 / Neoverse N2) are
in SPEED.md; qemu-user reproduces the parity (`tests/test_cpu_sve2.py`) but
not the timings.
"""

import argparse
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BENCH_C = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern long sha256_sve2_width(void);
extern void sha256_compress_sve2(const uint32_t mid[8], const uint8_t tails[][64],
                                 uint8_t out[][32]);
extern void sha256_block_neon(uint32_t state[8], const uint8_t block[64]);
extern int anubis_solve_bits(const char *challenge_hex, int difficulty, int threads,
                             double budget_ms, uint32_t *out_nonce,
                             char *out_hex, double *out_ms);

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    int reps = argc > 1 ? atoi(argv[1]) : 10;
    long iters = 100000;
    long lanes = sha256_sve2_width();
    uint32_t mid[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    static uint8_t tails[16][64], out[16][32];

    for (long l = 0; l < lanes; l++) {
        char s[8];
        int n = snprintf(s, sizeof s, "%ld", l);
        memset(tails[l], 0, 64);
        memcpy(tails[l], s, (size_t)n);
        tails[l][n] = 0x80;
        uint64_t bits = (uint64_t)(64 + n) * 8;
        for (int i = 0; i < 8; i++) tails[l][56 + i] = (uint8_t)(bits >> (8 * (7 - i)));
    }

    sha256_compress_sve2((const uint32_t *)mid, (const uint8_t (*)[64])tails, out);
    double t0 = now();
    for (long i = 0; i < iters; i++)
        sha256_compress_sve2((const uint32_t *)mid, (const uint8_t (*)[64])tails, out);
    double dt = now() - t0;
    double sve2_ns = dt * 1e9 / (iters * (double)lanes);

    uint32_t st[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    sha256_block_neon(st, tails[0]);
    t0 = now();
    for (long i = 0; i < iters * lanes; i++) sha256_block_neon(st, tails[0]);
    dt = now() - t0;
    double neon_ns = dt * 1e9 / (iters * (double)lanes);

    char hex[129];
    for (int i = 0; i < 64; i++) snprintf(hex + 2 * i, 3, "%02x", i);
    double total = 0;
    int solves = 0;
    for (int r = 0; r < reps; r++) {
        uint32_t nonce = 0;
        char dg[65];
        double ms = 0;
        if (anubis_solve_bits(hex, 20, 1, 60000.0, &nonce, dg, &ms) == 0) {
            total += ms;
            solves++;
        }
    }
    double mhs = solves ? (1048576.0 * solves) / (total / 1000.0) / 1e6 : 0.0;

    printf("%ld %ld %ld %.1f %.1f %.2f %.1f %s\n", lanes, iters, solves,
           sve2_ns, neon_ns, total / (solves ? solves : 1), mhs,
           getenv("ANUBIS_SVE2") ? "on" : "off");
    return 0;
}
'''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reps", type=int, default=10, help="solves per timing row (default 10)")
    args = ap.parse_args()

    if platform.machine() not in ("aarch64", "arm64"):
        print("skip: this benchmarks the aarch64 kernels; run it on arm64 hardware "
              "(or in the arm64 CI job). For parity under emulation see tests/test_cpu_sve2.py")
        return 0

    lib = ROOT / "libanubis_solver.so"
    if not lib.exists():
        print("error: %s is not built; run `make` first" % lib, file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "bench_arm_isa.c"
        exe = Path(tmp) / "bench_arm_isa"
        src.write_text(BENCH_C)
        cc = os.environ.get("CC", "cc")
        subprocess.run([cc, "-O2", "-o", str(exe), str(src), "-L" + str(ROOT),
                        "-lanubis_solver", "-Wl,-rpath," + str(ROOT)], check=True)
        rows = []
        for env_extra in ({}, {"ANUBIS_SVE2": "1"}):
            env = dict(os.environ, **env_extra)
            out = subprocess.run([str(exe), str(args.reps)], check=True, env=env,
                                 capture_output=True, text=True).stdout.split()
            rows.append(out)

    print("aarch64 kernels (one thread, %d solves per row):" % args.reps)
    print()
    print("| path | per candidate | `sha256` b20 |")
    print("|---|---:|---:|")
    labels = {"off": "neon.s + sha256h (default)", "on": "sve2.s batch (ANUBIS_SVE2=1)"}
    for row in rows:
        lanes, _iters, solves, sve2_ns, neon_ns, avg_ms, mhs, sve2_on = row
        if sve2_on == "on":
            print("| %s, %s lanes | %.0f ns | %.1f MH/s |" %
                  (labels["on"], lanes, float(sve2_ns), float(mhs)))
        else:
            print("| %s | %.0f ns | %.1f MH/s |" %
                  (labels["off"], float(neon_ns), float(mhs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
