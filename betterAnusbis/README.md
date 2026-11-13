# betterAnusbis

An Anubis-compatible proof-of-work gate in **one C file**. It issues the same
challenges, on the same routes, with the same JSON and the same cookie name — so
every existing Anubis client, including ours, works against it unchanged — and it
does it without a policy language, a config file, or a build chain.

```bash
make                                   # one cc invocation
./betterAnusbis --target http://127.0.0.1:3000
```

That is the whole setup. Then open `http://127.0.0.1:8080/`: the challenge page
solves itself and you land on your backend.

```
$ ./betterAnusbis --target http://127.0.0.1:3000 --algorithm sha256 --difficulty 12
[betterAnusbis] betterAnusbis 1.10.0 listening on :8080 -> http://127.0.0.1:3000 (sha256, difficulty 12)
[betterAnusbis] open http://127.0.0.1:8080/ and the challenge page solves it for you
```

## What "the same thing" means here

Anubis's job, reduced to one rule: every request is challenged, the client solves
it, the server verifies, sets a signed cookie, and proxies the request. That is
what this implements — **all six algorithms**, with verification done by
`libanubis_solver.so`, the same engine the CLI and the Firefox extension solve
with. Server and client cannot disagree about a primitive because it is the same
code.

`./test-all-algorithms.sh` — each line asserts the protected page came back, not
just that a challenge was issued:

```
  fast         difficulty 4   via node    PASS
  slow         difficulty 4   via node    PASS
  sha256       difficulty 12  via node    PASS
  metarefresh  difficulty 1   via node    PASS
  argon2id     difficulty 4   via python  PASS
  hashx        difficulty 4   via python  PASS

6 passed, 0 failed
```

And it actually rejects things:

| probe | answer |
|---|---|
| no cookie | 200 + challenge page |
| tampered `response` | **403** |
| forged challenge id | **403** |
| forged/re-signed cookie | **401** from `/api/check` |
| correct solve | 302 + cookie, then the real page |

## Compatibility with Anubis, on purpose

| piece | value |
|---|---|
| challenge JSON | `<script id="anubis_challenge" type="application/json">` with `rules` + `challenge` exactly as Anubis emits it |
| pass route | `/.within.website/x/cmd/anubis/api/pass-challenge?id=&response=&nonce=&redir=&elapsedTime=` |
| other routes | `.../api/check` (200/401), `.../api/ping` |
| cookie | `techaro.lol-anubis-auth`, a JWT HS256 with Anubis's claims (`challenge`, `method`, `policyRule`, `action`, `iat`, `exp`) |
| test cookie | `techaro.lol-anubis-cookie-verification` |
| metarefresh | no hashing: wait `difficulty × 800 ms`, echo `?challenge=<randomData>` — the same two checks as `lib/challenge/metarefresh/metarefresh.go` |

## Two design decisions worth knowing

**No server-side state.** The challenge id *is* the challenge:
`<hex randomData>.<unix time issued>`. Verification becomes a pure function, memory
is bounded by nothing, and there is no ledger to reap. The cost: a *solved*
challenge can be replayed inside the cookie window, because there is no "spent"
flag. Anubis keeps state and refuses replays; this trades that for simplicity, and
if you need the ledger the id scheme is where to add it.

**No policy engine.** Anubis's bot rules, weighting, GeoIP, honeypot and bench
machinery are what make it a general gatekeeper; they are also what makes it need
a YAML file. Here there is one rule, set on the command line. If you need per-path
or per-user-agent rules, use Anubis — this is the "just put a wall here" tool.

## Options

```
--listen ADDR:PORT     where to listen (default :8080)
--target URL           the backend to protect (required)
--algorithm NAME       fast, slow, sha256, argon2id, hashx or metarefresh (default sha256)
--difficulty N         bits for sha256/argon2id/hashx, nibbles for fast/slow (default 4)
--cookie-prefix NAME   cookie prefix (default techaro.lol-anubis)
-v, --verbose          log every request
```

Difficulty 4 is a good default for a human-facing site (a few milliseconds of
work); 12–16 is a wall worth having against a script.

## The honeypot, ported from Anubis

`internal/honeypot/naive` is one of Anubis's better ideas, so this does the same
thing, with the same markup:

1. Every challenge page carries a link inside `<script type="ignore">` — a browser
   never renders it, a crawler that scrapes `href`s finds it:

   ```html
   <script type="ignore"><a href="/.within.website/x/cmd/anubis/api/honeypot/<id>/init">Don't click me</a></script>
   ```

2. Following it marks the network (IPv4 `/24`, IPv6 `/64`) as a crawler and starts
   a **tarpit**: the server sleeps `min(hits², 1000)` ms before answering — Anubis's
   exact curve — and the answer is a generated index page with 36 more trap links,
   so a crawler that follows links keeps walking and keeps waiting.

3. Hits are logged (`--honeypot-log FILE`) and, once a network passes 25 hits in the
   one-hour window, its challenges get harder: **difficulty + 8 bits**. Anubis raises
   a policy weight by 30 and lets its thresholds decide; with a single rule here,
   +8 bits is the equivalent wall.

Measured, from `./test-all-algorithms.sh`:

```
  trap link hidden in <script type="ignore"> PASS
  tarpit ramps with hit count                PASS  (0.002225s -> 0.101272s)
  maze page links further in                 PASS
  trap hits are logged                       PASS  (10 hits logged)
  flagged network gets a harder challenge    PASS  (4 -> 12)
```

`--no-honeypot` turns it off. Nothing about it is visible to a normal user, and a
normal solve still passes with it on.

### What differs from Anubis's

- **Filler text is generated, not spintax.** Anubis fills its maze from
  `spintext.txt` templates to read like real pages; this emits fixed-but-varied
  index text. A crawler cannot tell the difference; a human reading over the
  crawler's shoulder could.
- **State is in memory**, a 4096-bucket table with a one-hour window, so it resets
  with the process. Anubis stores it in its backends and can share it across
  replicas.
- **No `honeypot/network` policy rule** — there is no policy engine — so the flag is
  the difficulty bump above rather than a weight the rules interpret.

## The browser solves every algorithm, with no native code

The page loads **our own wasm kernels** from the server itself
(`/.within.website/x/cmd/anubis/api/static/anubis/<name>.wasm`, `--web DIR`) and
drives them through the same ABI Anubis's modules use — `data_ptr`,
`set_data_length`, `anubis_work`, `result_hash_*`:

| algorithm | kernel | size | digest vs Anubis's own module |
|---|---|---:|---|
| `sha256` | `sha256_pow_batch.wasm` (four nonces wide) | 38.7 KB | exact, and **1.8-2.1x faster** |
| `argon2id` | `argon2id_pow.wasm` (vendored reference, m=19456 t=2 p=1) | 16.6 KB | **identical** |
| `hashx` | `hashx_pow.wasm` (our interpreter, LGPL part of this repo) | 16.7 KB | **identical** |

`fast`, `slow` and `metarefresh` are solved inline in JS, so a page needs no
network round trip for the cheap algorithms.

Verified end to end through the served kernels: `hashx` solves in milliseconds and
`argon2id` in seconds — Argon2id is ~160 ms per hash here because this compiles the
*reference* fill rather than a SIMD-optimised one, which is slower than Anubis's
Rust build and is stated rather than hidden.

## Policy

`--policy FILE`, one rule per line, first match wins:

```
allow     path prefix /health          # never challenge this
allow     net 10.0.0.0/8               # the office is trusted
deny      ua contains AhrefsBot        # well-known bad crawler
challenge ua contains curl difficulty 16
default   challenge difficulty 4
```

Selectors: `ua`, `path`, `header:<name>`, `net` (IPv4 CIDR). Matches: `contains`,
`prefix`, `is`. Actions: `allow` (proxy straight through), `deny` (403),
`challenge` (with an optional per-rule `difficulty`).

Measured on the running server: `AhrefsBot` → 403, `curl` UA → difficulty 16,
anyone else → difficulty 4, `/health` → proxied with no challenge at all.

**No regular expressions.** A policy *language* is the thing this project exists to
avoid; literal matching covers what a site owner actually writes.

## State verification

Challenges are kept server-side (`ch_table`, 4096 entries, expiring with the cookie
window) and **retired on use**, so a solved challenge cannot be replayed:

```
  first pass:  302 (redirect + cookie)
  replay:      403 betterAnusbis: that challenge was already used
```

`GET .../api/state` reports the counters (`issued`, `accepted`, `replayed`,
`expired`). `--stateless` restores the old stateless id encoding — the trade is in
the design notes above.

## HTTPS

```bash
./betterAnusbis --target https://backend.internal --tls-cert cert.pem --tls-key key.pem
```

The listener speaks TLS 1.2+ with your certificate, and the backend hop can be TLS
too (verified against the system trust store; `--target-insecure` exists for a
self-signed internal backend and says so when it uses it). Verified: HTTPS
challenge page, full solve and pass over TLS, and plain HTTP to the TLS port fails
the handshake as it should.

## What it costs

Measured from `/proc` while serving 300 challenge pages and 40 pass-challenge
exchanges (`python3 tools/bench-server-resources.py` in the repository root):

| | idle RSS | threads | CPU per page | CPU per verification |
|---|---:|---:|---:|---:|
| Anubis v1.28.3 (Go) | 44-46 MB | 17-19 | 870-900 µs | 2.3-2.8 ms |
| **betterAnusbis** | **2.1 MB** | **1** | **470-500 µs** | **1.25 ms** |

**~21x less RAM and about half the CPU**, and neither grows under load: RSS after 300
pages equals idle RSS and peak RSS never moved. The verification row is the engine
difference — Anubis re-checks through its wasm module via wazero, this calls
`libanubis_solver.so`.

## What it does not do

- **No TLS.** Terminate TLS in front of it (nginx, caddy, stunnel) and it will
  happily sit behind it; `--target https://` would need a TLS client, which this
  does not implement, so targets are `http://`.
- **No policy**: one rule for everything, no user-agent matching, no weighting.
- **No imprint page, no `make-challenge` API.** `pass-challenge`, `check`, `ping`
  and the honeypot are implemented.
- **No TLS listener, no HTTP/2, no keep-alive.** It reads one request, answers it
  and closes — which is fine behind a real reverse proxy and keeps this readable.
- **The in-page solver covers `fast`, `slow`, `sha256` and `metarefresh`.** For
  `argon2id` and `hashx` the page says so and points at the CLI or the extension;
  the server verifies all six either way.

## Why C, and why it is easier

| | Anubis | betterAnusbis |
|---|---|---|
| build | Go toolchain, multi-package | `make`, one file, one `cc` line |
| config | policy YAML + flags + rules to learn | flags on the command line |
| dependency | its own runtime and rule data | `libanubis_solver.so` (this repo) |
| surface | policy engine, honeypot, bench, imprint | the gate |
| binary | ~60 MB | ~100 KB |

Not a fair fight in features — Anubis is a product and this is the 20 % of it that
a site owner actually configures. That is the point: `--target` and you are done.

## Testing

```bash
./test-all-algorithms.sh      # all six algorithms, needs a backend on :8002
```

It starts a backend itself if one is not running and kills/restarts betterAnusbis
per algorithm. `wasm/live-server.md` in the parent repository has a policy file for
the real Anubis if you want to compare side by side.

---

Built with [DeepSeek V4.1 Flash](https://huggingface.co/deepseek-ai/DeepSeek-V4.1-Flash-1017)
running [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness),
per the repository's MIT + attribution license.
