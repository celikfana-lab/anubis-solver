# web/ — documentation for humans

Published at **https://celikfana-lab.github.io/anubis-solver/** by
[`.github/workflows/pages.yml`](../.github/workflows/pages.yml), which lints the
site and then uploads this directory as the Pages artifact.

A small static site: an overview, a beginner walkthrough, a per-algorithm
reference, a comparison against Anubis, the benchmark tables, and a page about
the claims that measurement proved wrong.

```bash
cd web
make serve      # http://127.0.0.1:8090/
make check      # links, ids, tag balance, then layout at 390 and 1280 px
```

No build step, no framework, no CDN at runtime. Six HTML files, one
`style.css`, and everything else is a link into the repository. That is
deliberate: a documentation site that needs `npm install` to read is a
documentation site that will be out of date, and this one has to be readable
over SSH on a machine with only Python.

## Pages

| file | what it is for |
|---|---|
| `index.html` | what the project is, the two headline results, where to start |
| `beginner.html` | Anubis from zero: what a gate is, the vocabulary, build, first solve, real errors |
| `algorithms.html` | the six algorithms, what a difficulty unit means for each, how to choose |
| `comparison.html` | betterAnusbis vs Anubis, including what Anubis does better |
| `benchmarks.html` | every measured table and the protocol behind it |
| `mistakes.html` | six claims that did not survive re-measurement, and why |

## Rules for editing

1. **Numbers come from the repository.** Every figure on these pages is in
   [`../SPEED.md`](../SPEED.md), `../wasm/README.md` or a page of `../docs/`, with
   a reproduce command. If you change a number in the code, change it in three
   places or the checks will not catch you — the site is cross-checked by eye and
   by `make check`, not by a number generator.
2. **Say which artefact.** "The fill core", "the module" and "the search loop" are
   different claims. Conflating them is exactly mistake 4 on `mistakes.html`.
3. **Ratios within a run, not absolutes across runs.** This machine drifts ~30%,
   so a table that mixes two sessions is a table that lies slightly.
4. **The navigation is duplicated on every page.** Adding a page means adding it
   to the nav on all six, plus `check.py`'s reachability test will tell you if
   you missed one.
5. **No remote subresources.** `check.py` fails the build if a `<link>`, `<img>`
   or `<script src>` points at another origin.

## Checks

`check.py` (Python only, ~200 lines):

- every local `href` resolves to a file that exists
- every `#fragment` matches an `id` in the target page
- duplicate ids, unclosed tags, exactly one non-empty `<h1>` per page
- every page is reachable from every page's navigation
- `style.css` is linked, and nothing pulls a subresource from the network

`check-layout.mjs` (needs Chrome, driven over the DevTools protocol with Node's
built-in WebSocket):

- no page scrolls horizontally at 390 px or 1280 px
- no element sticks out of the viewport, except the skip link and children of a
  deliberately scrollable table box

Both are wired into `make check`. A screenshot of the top of a page cannot catch
a table that slides sideways on a phone; that check can.

## Design notes

- Light and dark via `prefers-color-scheme`; `color-scheme` is declared so form
  controls and scrollbars follow.
- System font stack, no webfonts: nothing to block on, nothing to license.
- `tabular-nums` on numbers so columns of figures line up.
- One accent colour, used for links, the active nav item, and table hover only.
- Print styles drop the chrome and unclip the table boxes, because these pages
  are the sort of thing people print.
