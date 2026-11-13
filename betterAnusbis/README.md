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

## What it does not do

- **No TLS.** Terminate TLS in front of it (nginx, caddy, stunnel) and it will
  happily sit behind it; `--target https://` would need a TLS client, which this
  does not implement, so targets are `http://`.
- **No policy**: one rule for everything, no user-agent matching, no weighting.
- **No honeypot, no imprint page, no `make-challenge` API.** `pass-challenge`,
  `check` and `ping` are implemented.
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
