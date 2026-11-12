#!/usr/bin/env python3
"""Vectors for chip/tb_argon2_index.v: index_alpha, single lane."""
import random
import sys

M64 = (1 << 64) - 1


def index_alpha(p, s, idx, prand, lane_len, seg):
    """Argon2 reference index_alpha with same_lane = 1 (p = 1)."""
    if p == 0:
        size = idx - 1 if s == 0 else s * seg + idx - 1
    else:
        size = lane_len - seg + idx - 1
    rel = (prand * prand) >> 32
    rel = (size - 1 - ((size * rel) >> 32)) & 0xFFFFFFFF
    start = 0 if p == 0 else (0 if s == 3 else (s + 1) * seg)
    return (start + rel) % lane_len


CASES = []
random.seed(7)
for p, s, idx in [(0, 0, 2), (0, 0, 3), (0, 1, 0), (0, 2, 100), (0, 3, 4863),
                  (1, 0, 0), (1, 1, 7), (1, 2, 4863), (1, 3, 0), (1, 0, 2)]:
    CASES.append((p, s, idx, random.getrandbits(32), 19456, 4864))
for _ in range(60):
    lane_len = random.choice([64, 128, 1024, 19456, 65536])
    seg = lane_len // 4
    p = random.randint(0, 2)
    s = random.randint(0, 3)
    idx = random.randint(0, seg - 1)
    CASES.append((p, s, idx, random.getrandbits(32), lane_len, seg))


def main(path="vectors/index_vectors.hex"):
    out = []
    for p, s, idx, prand, lane_len, seg in CASES:
        out.append("%08x%08x" % (p, s))      # 0
        out.append("%08x%08x" % (idx, prand))
        out.append("%08x%08x" % (lane_len, seg))
        out.append("%08x" % index_alpha(p, s, idx, prand, lane_len, seg))
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {path}: {len(CASES)} cases", file=sys.stderr)


if __name__ == "__main__":
    main()
