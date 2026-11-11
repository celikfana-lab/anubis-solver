#!/usr/bin/env python3
"""Use curl_cffi so the TLS/JA3 fingerprint matches the User-Agent.

    pip install curl_cffi
    python3 examples/impersonate.py https://example.com

Some Anubis deployments weigh the client's TLS fingerprint. curl_cffi ships
browser TLS stacks; pass `impersonate` and the client keeps the profile's
User-Agent consistent with it.
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from curl_cffi import requests as curl_requests
except ImportError:  # pragma: no cover - explicit dependency message
    raise SystemExit("this example needs curl_cffi: pip install curl_cffi") from None

from anubis_solver import AnubisClient


def main(argv: list[str]) -> int:
    url = argv[0] if argv else "http://127.0.0.1:8923"
    profile = argv[1] if len(argv) > 1 else "chrome"

    session = curl_requests.Session(impersonate=profile)
    with AnubisClient(url, session=session) as client:
        resp = client.get("/")
        print(f"{url} -> {resp.status_code} ({len(resp.text)} bytes)")
        for sol in client.solutions:
            print(f"solved {sol.algorithm} d{sol.difficulty} in {sol.elapsed_ms:.1f} ms")

        # The same session can keep making requests with the auth cookie.
        again = client.get("/")
        print(f"reuse  -> {again.status_code}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
