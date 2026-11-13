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
[betterAnusbis] betterAnusbis 1.15.0 listening on :8080 -> http://127.0.0.1:3000 (sha256, difficulty 12)
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

honeypot
  trap link hidden in <script type="ignore"> PASS
  tarpit ramps with hit count                PASS  (0.0035s -> 0.1013s)
  maze page links further in                 PASS
  trap hits are logged                       PASS  (10 hits logged)
  flagged network gets a harder challenge    PASS  (4 -> 12)

11 passed, 0 failed
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
- **No `honeypot/network` policy rule.** The policy file takes `allow`, `deny` and
  `challenge` (on user agent, path, header or network); a network the honeypot has
  already flagged gets its difficulty bump from the trap table, not from a rule,
  and a rule cannot express a weight the way Anubis's rules can.

## The browser solves every algorithm, with no native code

The page loads **our own wasm kernels** from the server itself
(`/.within.website/x/cmd/anubis/api/static/anubis/<name>.wasm`, `--web DIR`) and
drives them through the same ABI Anubis's modules use — `data_ptr`,
`set_data_length`, `anubis_work`, `result_hash_*`. `hashx` is the exception: its
program depends on the challenge, so the page compiles the module itself from the
challenge bytes and only falls back to fetching the interpreter.

| algorithm | kernel | size | digest vs Anubis's own module |
|---|---|---:|---|
| `sha256` | `sha256_pow_batch.wasm` (four nonces wide) | 38.7 KB | exact, and **1.8-2.1x faster** |
| `argon2id` | `argon2id_pow.wasm` (our register-resident fill, m=19456 t=2 p=1) | 13.9 KB | **exact, and 1.02-1.05x faster** |
| `hashx` | compiled in the page from the challenge (`hashx_jit.mjs`), falling back to `hashx_pow.wasm` | 10.4 KB / 14.9 KB | **exact, and 7-8x faster** |

`hashx` also shows what it costs. The page compiles the challenge's program,
then scans nonces in windows of 262,144 and drives a progress bar that says
**slowing you down!** with the measured MHash/s and an estimate of the time
left. The number is measured, not guessed: the rate is the nonces actually
hashed divided by the elapsed time, and a difficulty-28 challenge on one laptop
core runs at about 2.8 MHash/s.

`fast`, `slow` and `metarefresh` are solved inline in JS, so a page needs no
network round trip for the cheap algorithms, and `hashx` needs none either because
it builds its kernel in the page.

Verified end to end through the served kernels, and measured head to head against
Anubis's own modules (one hash per call, warm):

| kernel | ours | Anubis's | verdict |
|---|---:|---:|---|
| `hashx` (compiled in the page) | 0.34 µs/hash | 2.73 µs/hash | **7.9x faster** |
| `hashx` (interpreter fallback) | 2.31 µs/hash | 2.73 µs/hash | **1.18x faster** |
| `argon2id` | 65-75 ms/hash | 68-76 ms/hash | **1.02-1.05x faster** |

The digests are identical, and both are now faster. Argon2id got there in two
steps: the module had been built with `-ffreestanding`, which turns every 1 KiB
block copy into a call to a byte-at-a-time `memcpy` (2.0x, and the whole of the
"161 ms"), and the fill loop was then rewritten to keep each round in registers
(`wasm/argon2_fill_fast.c`, another 1.25x).
`SPEED.md#argon2id-in-wasm-why-it-was-2x-slower-and-what-fixed-it` has the
measurements, including the flag variants that did not work.

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

- **No HTTP/2 and no keep-alive.** It reads one request, answers it and closes,
  which is fine behind a reverse proxy and keeps the listener readable. TLS itself
  is there (`--tls-cert`/`--tls-key`, and `--target https://` with
  `--target-insecure` for a self-signed backend).
- **No imprint page and no `make-challenge` API.** `pass-challenge`, `check`,
  `ping`, the state endpoint and the honeypot are implemented.
- **Policy is a flat file, not a language.** `allow`/`deny`/`challenge` on user
  agent, path, header or network, first match wins. No weights, no expressions,
  no per-rule difficulty beyond what the line says.
- **`--stateless` gives up replay protection.** By default an issued challenge is
  consumed once; that table is what makes a second submission fail.

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
