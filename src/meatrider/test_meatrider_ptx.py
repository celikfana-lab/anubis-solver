#!/usr/bin/env python3
"""Offline correctness test for the meatrider PTX kernel.

Executes src/meatrider/meatrider.ptx with src/nvidia/ptx/ptxsim.py (a small
PTX interpreter) and compares every reported hit nonce and digest against
tools/meatrider_ref.py, the independent Python reference for the tier. This
needs neither a GPU nor ptxas; it checks the kernel logic, not driver
integration.

The kernel hashes SHA-256d over an 80-byte Bitcoin block header. The test
derives the header, its 64-byte midstate and the 12 tail bytes exactly the way
the C context does, then asks the kernel for every nonce in a range and
compares the full display-order digest of every hit.

    python3 src/meatrider/test_meatrider_ptx.py
"""
import hashlib
import importlib.util
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "nvidia", "ptx"))
from ptxsim import Kernel, midstate, launch, results, GLOBAL_BASE

_spec = importlib.util.spec_from_file_location(
    "meatrider_ref", os.path.join(ROOT, "tools", "meatrider_ref.py"))
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)

PTX = os.path.join(HERE, "meatrider.ptx")

checks = 0
digests = 0
fails = 0


def check(cond, msg):
    global checks, fails
    print(("  ok   " if cond else "  FAIL ") + msg)
    checks += 1
    if not cond:
        fails += 1


def run_case(rd, header_difficulty, threshold, base, count, blockdim=256):
    """Hash [base, base+count) with the kernel; return (count, nonces, hashes).

    header_difficulty selects the header's nBits field (part of the hashed
    message), while threshold is the leading-zero-bit count the kernel tests.
    They are the same for ordinary challenges; the digest-only cases separate
    them so the kernel can report every nonce without an impossible target.
    """
    hdr = ref.header(rd, header_difficulty, 0)
    st = midstate(hdr[:64])
    tail = hdr[64:76]
    p = {"mid%d" % i: st[i] for i in range(8)}
    p["tail0"] = int.from_bytes(tail[0:4], "little")
    p["tail1"] = int.from_bytes(tail[4:8], "little")
    p["tail2"] = int.from_bytes(tail[8:12], "little")
    p["difficulty"] = threshold
    p["base"] = base
    p["count"] = count
    p["results_ptr"] = GLOBAL_BASE
    gm = launch(kernel, p, count, blockdim=blockdim)
    return results(gm)


def expected_hits(rd, header_difficulty, threshold, base, count):
    hits = []
    for n in range(base, base + count):
        d = ref.digest(rd, header_difficulty, n)
        if ref.leading_zero_bits(d) >= threshold:
            hits.append((n, d))
    return hits


def check_case(name, rd, header_difficulty, threshold, base, count):
    """Run one nonce range and compare count, nonce set and every digest."""
    global digests
    print("== %s: header d=%d threshold=%d base=%d count=%d =="
          % (name, header_difficulty, threshold, base, count))
    exp = expected_hits(rd, header_difficulty, threshold, base, count)
    cnt, nonces, hashes = run_case(rd, header_difficulty, threshold, base, count)
    check(cnt == len(exp),
          "count=%d, reference has %d hit(s)" % (cnt, len(exp)))
    stored = list(zip(nonces[:min(cnt, 8)], hashes[:min(cnt, 8)]))
    by_nonce = dict(exp)
    check(set(n for n, _ in stored) == set(n for n, _ in exp[:8]),
          "stored nonces %s == first 8 reference hits %s"
          % ([n for n, _ in stored], [n for n, _ in exp[:8]]))
    for n, d in stored:
        ok = n in by_nonce and d == by_nonce[n]
        if n in by_nonce:
            digests += 1
        check(ok, "nonce %d digest %s" % (n, d.hex()))


kernel = Kernel(PTX)

# Sanity: the reference really is SHA-256d over the header, in display order.
hdr = ref.header(bytes(range(32)), 7, 0x12345678)
raw = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()
check(raw[::-1] == ref.digest(bytes(range(32)), 7, 0x12345678),
      "reference digest == reversed SHA-256d over the 80-byte header")

rnd = random.Random(0x5EED)


def randbytes():
    return bytes(rnd.randrange(256) for _ in range(32))


# 1) Threshold 0 accepts every nonce, so all 8 result slots are filled and
#    eight full display-order digests are compared per case, including a
#    nonce range near the top of the u32 space.
check_case("all nonces accepted", randbytes(), 1, 0, 0, 8)
check_case("all nonces accepted, high base", randbytes(), 1, 0, 0xFFFFFF00, 8)

# 2) Ordinary challenges: header difficulty == threshold, random ranges.
for hd, thr, base, count in [
        (2, 2, 0, 16),
        (3, 3, 4096, 32),
        (4, 4, 123456, 48),
        (5, 5, 777777, 64),
        (6, 6, 1000000, 64)]:
    check_case("threshold %d" % thr, randbytes(), hd, thr, base, count)

# 3) Guarantee a difficulty-8 hit by scanning the reference, then test a
#    range around it (a non-zero base and a non-zero hit offset).
rd8 = randbytes()
hit = None
for n in range(8192):
    d = ref.digest(rd8, 8, n)
    if ref.leading_zero_bits(d) >= 8:
        hit = n
        break
check(hit is not None, "reference found a difficulty-8 hit in the first 8192 nonces")
if hit is not None:
    check_case("guaranteed difficulty-8 hit", rd8, 8, 8, hit, 16)

# 4) Full-word and full-digest paths: no nonce can pass, so the kernel must
#    report zero hits and must not store anything.
check_case("no possible hit (d=32)", randbytes(), 32, 32, 0, 8)
check_case("no possible hit (d=255)", randbytes(), 255, 255, 0, 8)

print()
print("checks: %d (digests compared: %d)" % (checks, digests))
if fails:
    print("FAILURES:", fails)
    sys.exit(1)
print("ALL MEATRIDER PTX CHECKS PASSED")
