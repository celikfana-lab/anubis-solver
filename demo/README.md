# demo: scrape an Anubis-protected docs site

A crawler that would be useless without the solver: `https://anubis.techaro.lol/docs/`
sits behind Anubis, so a plain `requests` GET returns the challenge page instead of
a document. `scrape_docs.py` swaps in `anubis_solver.AnubisClient`, which solves the
proof of work locally (in `libanubis_solver.so`, the hand-written SHA-NI/AVX kernels)
and keeps the auth cookie for the rest of the crawl.

```bash
pip install libanubis-solver
python3 demo/scrape_docs.py --max-pages 40 --out html
```

## What one run looks like

```
    challenge: sha256 d16 -> solved (1)
[  1/6]   26138 B  docs/index.html
[  2/6]   95418 B  docs/admin/botstopper/index.html
...
pages      : 6
bytes      : 204,250
solves     : 1  (6.0 pages per solve)
errors     : 0
elapsed    : 3.9s
```

The `pages per solve` line is the point. Anubis issues one cookie per solved
challenge, and the cookie is what the crawl amortises: **one 11 ms hash solve buys
every page until the cookie expires.** A crawler that pays one proof of work per
page is not paying anything at all.

## Flags

| flag | default | meaning |
|---|---|---|
| `--base` | `https://anubis.techaro.lol` | site origin |
| `--root` | `/docs/` | path prefix to stay inside; off-origin links are dropped |
| `--out` | `html` | output dir, mirrors the URL path (`docs/admin/x/` -> `html/docs/admin/x/index.html`) |
| `--max-pages` | `40` | hard cap |
| `--delay` | `0.4` | seconds between requests |
| `--impersonate` | none | `curl_cffi` profile (`chrome`, ...) if libcurl-impersonate is installed |
| `--quiet` | off | only the summary |

## It is deliberately slow

One request at a time, 0.4 s apart, and a page cap, because the point is to show
the solver working, not to hammer somebody's docs. If you want the full site, raise
`--max-pages` and leave `--delay` alone.

Output goes to `html/`, which is gitignored.
