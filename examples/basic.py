#!/usr/bin/env python3
"""Solve an Anubis challenge and fetch a page.

    python3 examples/basic.py http://127.0.0.1:8923

The client handles the whole flow: it loads the page, parses the embedded
challenge, solves the proof of work (CPU or Vulkan GPU), and retries the
request with the auth cookie.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisClient


def main(argv: list[str]) -> int:
    url = argv[0] if argv else "http://127.0.0.1:8923"

    with AnubisClient(url, threads=None) as client:
        print(f"target:   {url}")
        print(f"threads:  {client.solver.threads}  (affinity: {client.solver.affinity})")
        print(f"gpu:      {client.solver.gpu or 'none'}")

        resp = client.get("/")
        print(f"status:   {resp.status_code}")
        print(f"body:     {len(resp.text)} bytes")

        for sol in client.solutions:
            print(
                f"solved:   {sol.algorithm} difficulty={sol.difficulty} "
                f"nonce={sol.nonce} in {sol.elapsed_ms:.1f} ms"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
