#!/usr/bin/env python3
"""Scrape an Anubis-protected documentation site with the Python library.

Every page behind https://anubis.techaro.lol/docs/ is guarded by Anubis, so a
plain ``requests`` crawl gets a challenge page instead of a document. This demo
uses :class:`anubis_solver.AnubisClient`, which detects the challenge, solves
the proof of work locally (hand-written SHA-NI/AVX kernels in
``libanubis_solver.so``) and keeps the auth cookie so the rest of the crawl is
ordinary HTTP.

    python3 demo/scrape_docs.py --max-pages 40 --out html

The crawl is deliberately small and slow: one request at a time, a delay
between them, and a page cap. It is a demonstration of the solver, not a
harvester.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

try:
    from anubis_solver import AnubisClient, HAVE_CURL_CFFI
except ImportError:  # pragma: no cover
    sys.exit("pip install libanubis-solver   # the import name is anubis_solver")


class LinkExtractor(HTMLParser):
    """Collects hrefs; nothing else. stdlib beats a dependency here."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.links.append(value)
                return


def normalise(url: str) -> str:
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/") and "." not in path.rsplit("/", 1)[-1]:
        path += "/"          # /docs/admin -> /docs/admin/
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def output_path(out: Path, url: str) -> Path:
    parsed = urlparse(url)
    path = parsed.path.lstrip("/")
    if not path or path.endswith("/"):
        path += "index.html"
    elif "." not in path.rsplit("/", 1)[-1]:
        path += "/index.html"
    return out / path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="https://anubis.techaro.lol",
                    help="site origin (default: %(default)s)")
    ap.add_argument("--root", default="/docs/", help="path prefix to stay inside")
    ap.add_argument("--out", default="html", type=Path, help="output directory")
    ap.add_argument("--max-pages", default=40, type=int, help="stop after N pages")
    ap.add_argument("--delay", default=0.4, type=float, help="seconds between requests")
    ap.add_argument("--impersonate", default=None,
                    help="curl_cffi profile, e.g. chrome (needs libcurl-impersonate)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    base = args.base.rstrip("/")
    start = normalise(base + args.root)
    prefix = args.root if args.root.startswith("/") else "/" + args.root
    origin = urlparse(base).netloc
    out = args.out if args.out.is_absolute() else Path.cwd() / args.out
    out.mkdir(parents=True, exist_ok=True)

    solves = {"n": 0}
    client = AnubisClient(base_url=base, impersonate=args.impersonate)
    original_solve = client._solve_and_pass  # count what the client does for us

    def counting_solve(url, challenge):      # noqa: ANN001
        solves["n"] += 1
        if not args.quiet:
            print(f"    challenge: {challenge.algorithm} d{challenge.difficulty} "
                  f"-> solved ({solves['n']})")
        return original_solve(url, challenge)

    client._solve_and_pass = counting_solve  # type: ignore[method-assign]

    seen: set[str] = {start}
    queue: deque[str] = deque([start])
    pages = bytes_written = errors = 0
    t0 = time.monotonic()

    try:
        while queue and pages < args.max_pages:
            url = queue.popleft()
            try:
                resp = client.get(url)
            except Exception as exc:                      # noqa: BLE001
                errors += 1
                print(f"[error] {url}: {exc}", file=sys.stderr)
                continue

            if resp.status_code != 200:
                errors += 1
                print(f"[{resp.status_code}] {url}", file=sys.stderr)
                continue
            if "text/html" not in resp.headers.get("content-type", "text/html"):
                continue

            dest = output_path(out, url)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(resp.text, encoding="utf-8", errors="replace")
            pages += 1
            bytes_written += len(resp.content)
            if not args.quiet:
                rel = dest.relative_to(out)
                print(f"[{pages:>3}/{args.max_pages}] {len(resp.content):>7} B  {rel}")

            parser = LinkExtractor()
            parser.feed(resp.text)
            for href in parser.links:
                nxt = normalise(urljoin(url, href))
                parsed = urlparse(nxt)
                if parsed.netloc != origin or not parsed.path.startswith(prefix):
                    continue
                if nxt in seen:
                    continue
                seen.add(nxt)
                queue.append(nxt)

            time.sleep(args.delay)
    finally:
        client.close()

    elapsed = time.monotonic() - t0
    print()
    print(f"pages      : {pages}")
    print(f"bytes      : {bytes_written:,}")
    print(f"solves     : {solves['n']}  "
          f"({pages / max(solves['n'], 1):.1f} pages per solve)")
    print(f"errors     : {errors}")
    print(f"queued     : {len(queue)} left")
    print(f"elapsed    : {elapsed:.1f}s")
    print(f"output     : {out}")
    print(f"tls        : {'curl_cffi impersonation' if HAVE_CURL_CFFI and args.impersonate else 'plain requests'}")
    return 0 if pages else 1


if __name__ == "__main__":
    raise SystemExit(main())
