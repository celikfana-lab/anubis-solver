#!/usr/bin/env python3
"""Load-test an Anubis-protected endpoint that you own.

Every request goes through the normal client flow: fetch, solve the
proof-of-work, submit `pass-challenge`, fetch again. This measures how much
request pressure one machine can generate against an Anubis instance it
controls; it is not a packet flood and does not touch anything but the URL you
pass.

Safety rails: the host must be private/loopback, `--i-own-this-host` is
mandatory, and duration/concurrency are capped. Use it on infrastructure you
own or are authorised to test.

    python3 tools/stress_test.py --url http://192.168.1.15:8923 \
        --duration 30 --concurrency 32 --i-own-this-host
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import statistics
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anubis_solver import AnubisClient  # noqa: E402

MAX_DURATION = 300.0
MAX_CONCURRENCY = 256


def is_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if not (addr.is_private or addr.is_loopback):
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True, help="base URL, e.g. http://host:8923")
    ap.add_argument("--path", default="/", help="path to request (default /)")
    ap.add_argument("--duration", type=float, default=30.0, help="seconds (max 300)")
    ap.add_argument("--concurrency", type=int, default=16, help="workers (max 256)")
    ap.add_argument("--threads", type=int, default=1, help="solver threads per worker")
    ap.add_argument("--impersonate", default=None, help="curl_cffi profile")
    ap.add_argument("--allow-remote", action="store_true",
                    help="allow a non-private target (you must own it)")
    ap.add_argument("--keep-session", action="store_true",
                    help="reuse the TCP session but drop cookies each request "
                         "(default for throughput)")
    ap.add_argument("--reuse-client", action="store_true",
                    help="keep one session per worker (default: fresh client "
                         "per request, so every request gets a challenge)")
    ap.add_argument("--i-own-this-host", action="store_true",
                    help="required acknowledgement that you own the target")
    args = ap.parse_args()

    if not args.i_own_this_host:
        print("refusing to run: pass --i-own-this-host (target must be yours)",
              file=sys.stderr)
        return 2
    host = urlparse(args.url).hostname or ""
    if not is_private(host) and not args.allow_remote:
        print(f"refusing to run against non-private host {host!r} "
              "(use --allow-remote if you own it)", file=sys.stderr)
        return 2
    duration = max(1.0, min(MAX_DURATION, args.duration))
    workers = max(1, min(MAX_CONCURRENCY, args.concurrency))

    print(f"target {args.url}{args.path} | workers {workers} | "
          f"duration {duration:.0f}s | solver threads {args.threads}", flush=True)

    stop = threading.Event()
    lock = threading.Lock()
    stats = {"requests": 0, "solves": 0, "errors": 0, "lat": []}
    codes: dict[int, int] = {}

    def worker(wid: int) -> None:
        local_lat = []
        req = solve = err = 0
        reuse = None
        seen = 0
        while not stop.is_set():
            t0 = time.perf_counter()
            client = reuse
            try:
                if client is None:
                    client = AnubisClient(args.url, threads=args.threads,
                                          impersonate=args.impersonate)
                resp = client.get(args.path)
                dt = (time.perf_counter() - t0) * 1000.0
                local_lat.append(dt)
                req += 1
                total_sol = len(client.solutions)
                solve += total_sol - seen
                seen = total_sol
                with lock:
                    codes[resp.status_code] = codes.get(resp.status_code, 0) + 1
                if args.reuse_client or args.keep_session:
                    reuse = client
                    if not args.reuse_client:
                        client.session.cookies.clear()
                else:
                    client.close()
            except Exception:
                err += 1
                try:
                    client.close()
                except Exception:
                    pass
        with lock:
            stats["requests"] += req
            stats["solves"] += solve
            stats["errors"] += err
            stats["lat"].extend(local_lat)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(workers)]
    t_start = time.perf_counter()
    for t in threads:
        t.start()

    last = 0.0
    while time.perf_counter() - t_start < duration:
        time.sleep(1.0)
        elapsed = time.perf_counter() - t_start
        with lock:
            req = stats["requests"]
        if elapsed - last >= 2.0:
            last = elapsed
            print(f"  {elapsed:5.1f}s  {req / elapsed:7.1f} req/s", flush=True)
    stop.set()
    for t in threads:
        t.join(timeout=30.0)
    elapsed = time.perf_counter() - t_start

    with lock:
        req, solve, err, lat = (stats["requests"], stats["solves"],
                                stats["errors"], stats["lat"])
    lat = sorted(lat)
    def pct(p: float) -> float:
        return lat[min(len(lat) - 1, int(len(lat) * p))] if lat else 0.0

    print("\nresults")
    print(f"  duration          {elapsed:.1f} s")
    print(f"  requests          {req}  ({req / elapsed:.1f} req/s)")
    print(f"  challenges solved {solve}  ({solve / elapsed:.1f} solves/s)")
    print(f"  errors            {err}")
    print(f"  status codes      {dict(sorted(codes.items()))}")
    print(f"  latency p50/p95   {pct(0.50):.1f} / {pct(0.95):.1f} ms")
    return 0 if req > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
