#!/usr/bin/env python3
"""Check the hits that src/i915raw/i915_replay.c reads back from the GPU.

The replay prints one `tail <hex>` line (the 44 message bytes) and one
`hit <nonce> <digest>` line per reported hit.  This recomputes every digest
with hashlib and checks the difficulty test, so a wrong answer on the GPU
cannot pass as a solve.

    ./build/i915-replay --dump /tmp/i915dump --upto 8 --solve 16 --bench 1 \\
        | python3 src/i915raw/verify_solve.py --difficulty 16

Anubis encodes the nonce little-endian at the front of the block (that is what
`w[0] = bswap(nonce)` in the kernel means), so the check uses
`nonce.to_bytes(4, "little") + tail`.
"""
import argparse
import hashlib
import re
import sys

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--difficulty", type=int, required=True)
    ap.add_argument("--base", type=int, default=0, help="expected scan base")
    ap.add_argument("--count", type=int, default=None, help="expected scan length")
    args = ap.parse_args()

    tail = None
    hits = []
    total = None
    for line in sys.stdin:
        line = line.strip()
        m = re.match(r"^tail ([0-9a-f]+)$", line)
        if m:
            tail = bytes.fromhex(m.group(1))
            continue
        m = re.match(r"^hits (\d+)$", line)
        if m:
            total = int(m.group(1))
            continue
        m = re.match(r"^hit (\d+) ([0-9a-f]{64})$", line)
        if m:
            hits.append((int(m.group(1)), m.group(2)))

    if tail is None or len(tail) != 44:
        print("FAIL: no 44-byte tail in the input", file=sys.stderr)
        return 1
    if not hits:
        print("FAIL: no hits reported", file=sys.stderr)
        return 1

    ok = 0
    for nonce, reported in hits:
        digest = hashlib.sha256(nonce.to_bytes(4, "little") + tail).hexdigest()
        zeros = 32 - int(digest, 16).bit_length() + (0 if int(digest, 16) == 0 else 0)
        zeros = 8 * 32 - int(digest, 16).bit_length()
        good = digest == reported and zeros >= args.difficulty
        if args.count is not None:
            good = good and args.base <= nonce < args.base + args.count
        ok += good
        print("%s nonce %-9d clz %2d  %s" % ("PASS" if good else "FAIL",
                                             nonce, zeros, digest))
    print("%d/%d hits verified (total reported: %s, difficulty %d)"
          % (ok, len(hits), total, args.difficulty))
    return 0 if ok == len(hits) else 1


if __name__ == "__main__":
    sys.exit(main())
