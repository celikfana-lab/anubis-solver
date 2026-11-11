#!/usr/bin/env python3
"""Show the GPU / CPU-affinity setup, optionally solve one challenge on the GPU.

    python3 examples/gpu.py
    python3 examples/gpu.py --solve

Without Vulkan the solver silently uses the CPU paths, so this is safe to run
anywhere. `--solve` only attempts a challenge the GPU is actually used for.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisChallenge, AnubisSolver


def main(argv: list[str]) -> int:
    solver = AnubisSolver()

    print(f"threads:   {solver.threads}")
    print(f"affinity:  {solver.affinity}")
    print(f"gpu:       {solver.gpu or 'none (CPU only)'}")

    if "--solve" not in argv:
        print("\npass --solve to run a `fast` challenge on the GPU")
        return 0

    if solver.gpu is None:
        print("\nno Vulkan device; nothing to demonstrate")
        return 0

    # `fast` at difficulty 6 is above the GPU dispatch threshold, so this runs
    # on the GPU (and is re-verified on the CPU before it is returned).
    payload = {
        "challenge": {"id": "gpu-example", "randomData": "cd" * 64},
        "rules": {"algorithm": "fast", "difficulty": 6},
    }
    challenge = AnubisChallenge.from_payload(payload)
    t0 = time.time()
    solution = solver.solve(challenge)
    wall = (time.time() - t0) * 1000.0
    print(f"\nsolved difficulty 6 in {solution.elapsed_ms:.1f} ms "
          f"(wall {wall:.1f} ms), nonce={solution.nonce}")

    # Override knobs, for reference:
    #   ANUBIS_NO_VULKAN=1          always CPU
    #   ANUBIS_VULKAN_DEVICE=NAME   pick a device (substring match)
    #   ANUBIS_VULKAN_MIN_WORK=N    lower/raise the dispatch threshold
    #   ANUBIS_CPU_AFFINITY=off     stop pinning workers to the P-cores
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
