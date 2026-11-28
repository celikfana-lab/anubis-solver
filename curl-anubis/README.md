# curl-anubis

`curl`, with Anubis support. It is curl — the same binary, the same flags, the
same output — with one addition: when the response turns out to be Anubis's
proof-of-work interstitial, it solves the challenge and asks for the page again,
so what lands on stdout is the page you asked for instead of the gate.

```console
$ curl https://gitlab.gnome.org/            # the interstitial, 108 KB of it
$ ./curl-anubis https://gitlab.gnome.org/    # the page
```

Only the Anubis layer is handled. It does not execute JavaScript, render a DOM,
rotate IPs, or touch any other anti-bot system: Anubis inspects no canvas, no
WebGL and no fingerprint, it only wants a nonce, so the nonce is what this
computes.

## How it works

1. The first bytes of a response body are held back until we know whether they
   are a challenge page. If they are not, they are written out immediately and
   nothing else happens; the cost on a normal site is a 16 KiB memory buffer and
   nothing else.
2. When it is a challenge, the `<script id="anubis_challenge">` JSON gives the
   algorithm, the difficulty and the random data. The challenge is solved by
   [`libanubis_solver`](..) in native code — 0.2 ms at Anubis's usual difficulty,
   and 0.1 s even at difficulty 20.
3. The answer URL that Anubis documents on the page itself
   (`/.within.website/x/cmd/anubis/api/pass-challenge`) is fetched with the
   verification cookie, the auth cookie it sets goes into the transfer's own
   cookie jar, and the original request is simply performed again — through
   curl's normal retry path, so `-o`, `-i`, `-w`, `-X`, `-d`, cookie jars and
   multiplexing all keep behaving as they always did.

A site that is not behind Anubis never sees a second request. A site that is
sees exactly one extra request: the one that answers the challenge.

## Options

| option | |
|---|---|
| `--anubis` | answer Anubis challenges (default: on) |
| `--no-anubis` | plain curl behaviour, for comparison or debugging |
| `--anubis-max-retries N` | how many challenges to answer before giving up and showing the page (default: 3) |

`-A` always wins over the browser User-Agent that `--anubis` sends by default,
which exists because plenty of deployments deny `curl/…` outright before they
ever issue a challenge.

Everything else is curl. `curl-anubis --help` lists the other several hundred
options, `--version` prints the curl version, and `-v` shows the solve:

```console
$ ./curl-anubis -v https://example-anubis-site/ 2>&1 | grep anubis
* anubis: solved the sha256 challenge at difficulty 4 in 0.3 ms (nonce 40), retrying
```

## Cookies, and not solving twice

Anubis's pass is a cookie, so curl's own cookie options are the persistence layer
and there is nothing new to learn:

```console
$ ./curl-anubis -c jar.txt https://site/     # solves, writes the jar
$ ./curl-anubis -b jar.txt https://site/     # reuses it: no challenge, no solve
```

The auth cookie reaches the jar because the answer to the challenge is injected
into the transfer's own cookie store, so `-c` records it like any other cookie
(HttpOnly, with whatever expiry the gate chose — 7 days by default). `-b` hands
it back on the next run, and the gate serves the page before a challenge is ever
issued.

Three details that matter for a scraper:

- **One solve per process per host is the normal case.** One invocation with
  several URLs on the same host solves once and reuses the cookie for the rest,
  because curl's handles share a cookie store. `curl-anubis -c jar.txt $(cat
  urls.txt) -O` therefore costs one challenge per host, not one per URL.
- **A stale or foreign cookie is solved again, not obeyed.** An expired entry, a
  corrupted token, or a jar from another host gets challenged again and answered;
  the test suite runs exactly that case rather than trusting it.
- **The jar is written at exit**, so a killed process persists nothing. That is
  curl's behaviour and it is the right one.

## Building

```console
$ ./build.sh                     # curl source from ../../curl, engine from ..
$ CURL_SRC=/path/to/curl ./build.sh
$ ./build.sh --curl-src ./curl --engine /path/to/anubis-solver
```

The script copies the curl tree into `build/`, applies
`patches/curl-anubis.patch`, runs `autoreconf`/`configure`/`make`, and leaves
the binary at `build/curl-anubis`. The engine is linked by path with an rpath,
so nothing needs installing to run it from here; moving the binary elsewhere
needs `libanubis_solver.so` findable (install it, or set `LD_LIBRARY_PATH`).

The patch is written against curl **8.23.1-DEV** (commit `23256cf`). It touches
the tool only — `src/tool_anubis.[ch]` are new, and `tool_cb_wrt.c`,
`tool_operate.c/h`, `tool_cfgable.c/h`, `tool_getparam.c/h`, `config2setopts.c`,
`Makefile.inc` and `Makefile.am` get small edits. libcurl is untouched, so a
patched curl behaves like any other curl for every other protocol and option.

## Testing

```console
$ ./test.sh
```

It starts a static backend, puts `betterAnusbis` in front of it, and checks that
plain `curl` gets the interstitial while `curl-anubis` gets the page: with `-o`,
with `-d` POSTs, with `--no-anubis`, with `-i`, on a site that is not protected
at all (byte-identical output to plain curl), and with the challenge counted in
the gate's log so a second request is not silently doubling up — and the cookie
round trip: `-c` writes, `-b` reuses without a second solve, a stale jar is
solved again.

## What it costs

Measured against `betterAnusbis` 2.50 on one core, this machine, three runs each:

| difficulty | expected hashes | solve |
|---|---:|---:|
| 4 (Anubis default) | 16 | 0.2 – 0.3 ms |
| 8 | 256 | 0.2 – 0.4 ms |
| 12 | 4,096 | 0.2 – 1.9 ms |
| 16 | 65,536 | 0.7 – 2.1 ms |
| 20 | 1,048,576 | 30 – 106 ms |

Live deployments, same binary: `trac.ffmpeg.org` (the `fast` tier, difficulty 2)
is solved in **0.7 ms** and one extra request; `anubis.techaro.lol` is a
`metarefresh` gate, which is not a proof of work at all — the tool waits the 2
seconds that gate asks for, answers, and comes back with the page.

The only request this adds is the answer to the challenge, and only when the
response actually was one. A site that is not behind Anubis sees exactly the
requests plain curl would make.

## What it does not do

- **No JavaScript, no DOM.** Sites that build their content in the browser still
  come back as a shell. This is a scraper, not a browser, and that is the point.
- **Unsupported challenge types.** `sha256`, `hashx`, `argon2id`, `fast`/`slow`
  and `metarefresh` are implemented. `meatrider`, `tensor`, `tensor-v` and
  `preact` are not: the tool says so — by name, on stderr — and shows you the
  page it got. A `HEAD` request is also unsolvable by nature: the gate sends a
  challenge body to `GET` only, so `-I` returns the interstitial's headers like
  plain curl does.
- **No IP reputation.** If a deployment denies your address, or another anti-bot
  system is in front of it, this changes nothing. That is what a proxy is for.
- **It does not hide.** `--anubis` sends a browser User-Agent. It does not spoof
  a TLS or HTTP/2 fingerprint; if a deployment is fingerprinting, that is a
  different tool ([curl-impersonate](https://github.com/lwthiker/curl-impersonate)
  and this project's own fetch layer exist for that).
