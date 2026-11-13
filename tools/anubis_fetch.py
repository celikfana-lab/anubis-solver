#!/usr/bin/env python3
"""anubis_fetch.py — fetch a URL through Anubis, solving the challenge locally.

    python3 tools/anubis_fetch.py https://anubis.techaro.lol/ --json
    python3 tools/anubis_fetch.py URL --text-only --max-chars 4000

This is the engine behind the `anubis_fetch` tool in the DSH plugin
(`dsh-plugin/`), and it is useful on its own: the same AnubisClient the Python
library exposes, with the result as JSON instead of a requests.Response.

Exit status: 0 fetched, 1 fetch failed, 2 the challenge could not be solved.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import anubis_solver  # noqa: E402

UA_CHROME = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_TAG = re.compile(r"<[^>]+>")
_SCRIPT = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)
_WS = re.compile(r"[ \t\r\f\v]+")
_BLANK = re.compile(r"\n{3,}")


def html_to_text(html: str) -> str:
    """Strip tags to readable text. Deliberately crude: no DOM, no dependencies."""
    body = _SCRIPT.sub(" ", html)
    body = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>|</tr>", "\n", body)
    body = _TAG.sub("", body)
    body = (
        body.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    body = _WS.sub(" ", body)
    body = "\n".join(line.strip() for line in body.splitlines())
    return _BLANK.sub("\n\n", body).strip()


def title_of(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    return _TAG.sub("", m.group(1)).strip() if m else ""


def fetch(url: str, *, threads: int | None = None, timeout: float = 30.0,
          impersonate: str | None = None, max_chars: int = 100_000,
          text_only: bool = False) -> dict:
    """GET a URL, solving any Anubis challenge, and return a JSON-able dict."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"not an http(s) URL: {url!r}")
    base = f"{parts.scheme}://{parts.netloc}"
    client = anubis_solver.AnubisClient(
        base,
        user_agent=UA_CHROME,
        timeout=timeout,
        threads=threads,
        impersonate=impersonate,
    )
    resp = client.get(url)

    body = resp.text
    content_type = resp.headers.get("content-type", "")
    is_html = "html" in content_type.lower() or body.lstrip()[:1] == "<"
    text = html_to_text(body) if is_html else body

    solutions = list(getattr(client, "solutions", []) or [])
    challenge = None
    if solutions:
        last = solutions[-1]
        challenge = {
            "algorithm": getattr(last, "algorithm", ""),
            "difficulty": getattr(last, "difficulty", 0),
            "nonce": getattr(last, "nonce", None),
            "response": getattr(last, "response", ""),
            "elapsedMs": round(float(getattr(last, "elapsed_ms", 0.0)), 3),
            "rounds": len(solutions),
        }

    # is what came back still a challenge page? then the solve did not take
    still_challenged = "anubis_challenge" in body and len(body) < 40_000

    out = {
        "url": url,
        "finalUrl": str(resp.url),
        "statusCode": int(resp.status_code),
        "contentType": content_type,
        "title": title_of(body) if is_html else "",
        "challenge": challenge,
        "stillChallenged": bool(still_challenged),
        "slow": float(getattr(resp, "elapsed", 0).total_seconds()) if getattr(resp, "elapsed", None) else None,
        "truncated": False,
        "content": text,
    }
    if text_only:
        out.pop("content", None)
    else:
        if len(out["content"]) > max_chars:
            out["content"] = out["content"][:max_chars]
            out["truncated"] = True
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true", help="emit JSON (default)")
    ap.add_argument("--text-only", action="store_true", help="omit the body")
    ap.add_argument("--max-chars", type=int, default=100_000)
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--impersonate", default=None,
                    help="browser TLS fingerprint via curl_cffi (chrome, firefox, ...)")
    args = ap.parse_args(argv)

    try:
        result = fetch(args.url, threads=args.threads, timeout=args.timeout,
                       impersonate=args.impersonate, max_chars=args.max_chars,
                       text_only=args.text_only)
    except anubis_solver.UnsupportedAlgorithm as exc:
        print(json.dumps({"url": args.url, "error": f"unsupported algorithm: {exc}"}), flush=True)
        return 2
    except Exception as exc:  # noqa: BLE001 - the caller wants a status, not a traceback
        print(json.dumps({"url": args.url, "error": str(exc),
                          "trace": traceback.format_exc(limit=2)}), flush=True)
        return 1

    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
