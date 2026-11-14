# betterAnusbis

**1.50.1 "headslam"**

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
[betterAnusbis] betterAnusbis 1.50.1 listening on :8080 -> http://127.0.0.1:3000 (sha256, difficulty 12)
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
| client IP | `X-Forwarded-For` flattened right-to-left, CGNAT and link-local hops always dropped, RFC1918 unless `--no-xff-strip-private`; `--custom-real-ip-header` reads a proxy-specific header, `--use-remote-address` ignores them all |
| redirect | `redir=` restricted to this host or `--redirect-domains`, with the same four-wildcard glob limit as `REDIRECT_DOMAINS` |
| subpath | `--base-prefix` / `--strip-base-prefix`, same pair as `cmd/anubis` |
| request shape | a path with a `.` or `..` segment is refused with 400 before anything else, and repeated slashes are collapsed for rule matching, as `lib/policy/checker.go:192-231` does |
| health | `--healthcheck` GETs `/healthz` on the metrics listener and exits 0 or 1, for a supervisor that knows nothing about this program |
| metrics | `anubis_challenges_issued`, `anubis_challenges_validated`, `anubis_failed_validations`, `anubis_proxied_requests_total`, `anubis_policy_results` with upstream's names and fewer labels (no ASN), plus `/healthz`; `--metrics-bind` puts them on their own listener |
| token binding | the JWT carries a `restrict` claim holding the client address, the way `--jwt-restriction-header` does; a stolen cookie is useless from another address. Tokens minted before this existed carry no claim and keep working |
| policy file | `--policy data/botPolicies.yaml` reads Anubis's own schema: `bots[]` with `user_agent_regex`, `path_regex`, `headers_regex`, `remote_addresses`, `expression`, `challenge{algorithm,difficulty}`, `weight.adjust`, `import:` including the `(data)/` macro, plus `thresholds[]`, `status_codes` and `honeypot.enabled`. Anubis's default-allow semantics come with it: a request that matches no rule and no threshold is allowed |

## Two design decisions worth knowing

**The id carries the challenge.** `<hex randomData>.<unix time issued>` means
verification is a pure function of the request, so a challenge can be checked
without a lookup. On top of that there is a fixed-size spent-challenge table
(4096 slots, one hour) that makes a second submission fail, which is Anubis's
`spent` flag with a bounded amount of memory. `--stateless` turns the table off
and accepts that a solved challenge can be replayed inside its window.

**Policy is a small rule file, not a language.** One `allow`/`deny`/`challenge`
per line on user agent, path, header or IPv4 network, first match wins, optional
`difficulty` per rule. No CEL, no weights, no thresholds, no GeoIP, no regex.
Anubis's policy engine is what makes it a general gatekeeper; if you need
`expression:` with `all`/`any` over headers, use Anubis. This is the "just put a
wall here" tool that still knows your `.well-known` and your RSS reader.

## Options

`--help` is the authority; this is the map. Values are parsed once, so
`--flag=value` and `--flag value` both work, and every boolean takes
`--no-flag` or `--flag=false` (`--cookie-secure=false`, `--no-cookie-secure`).

```
where to listen, what to protect
  --listen ADDR:PORT         default :8080
  --target URL               required
  --target-sni NAME          TLS name for the backend, "auto" = the Host header
  --target-host NAME         Host header for the backend
  --target-insecure          do not verify the backend certificate
  --base-prefix PATH         serve under a subpath, e.g. /anubis
  --strip-base-prefix        strip that prefix before the backend sees it

the challenge
  --algorithm NAME           fast, slow, sha256, argon2id, hashx, metarefresh
  --difficulty N             bits for sha256/argon2id/hashx, nibbles for fast/slow
  --challenge-status N       status for the challenge page (default 200)
  --deny-status N            status for a policy deny (default 200, see below)
  --serve-robots-txt         answer /robots.txt with Disallow: /
  --debug-benchmark-js       challenge every request, for measuring a client

cookies
  --cookie-prefix NAME       default techaro.lol-anubis
  --dynamic-cookie-suffix[=B]  hash the cookie settings into the name (default on)
  --cookie-domain DNS        Domain=
  --cookie-expiration-time S Max-Age and JWT exp, 0 = session cookie (604800)
  --cookie-secure[=B]        default: on exactly when we serve TLS
  --cookie-http-only[=B]     default on
  --cookie-same-site S       default, lax, strict, none (default lax)
  --cookie-partitioned[=B]   CHIPS, only emitted with Secure (default on)

who the client is
  --custom-real-ip-header H  e.g. CF-Connecting-IP
  --use-remote-address       ignore X-Forwarded-For and the custom header
  --no-xff-strip-private     keep RFC1918 hops from X-Forwarded-For

where a solved client may be sent
  --redirect-domains LIST    comma list of hosts, glob, four stars max

the token
  --jwt-restriction-header H  bind the cookie to the client address (default
                              X-Real-IP); pass "" to turn the binding off
  --secret-file PATH          keep the signing key here (0600, created on first
                              run); without it the key is random per process
  --secret-hex HEX            the same key inline, 64 hex characters

policy, honeypot, assets, TLS, metrics
  --policy FILE              Anubis's botPolicies.yaml, or this gate's own rules
  --data-dir DIR             where (data)/... imports resolve (default data)
  --honeypot-log FILE  --web DIR  --tls-cert/--tls-key  --metrics-bind ADDR:PORT
  --no-honeypot  --stateless  --healthcheck  --slog-level LEVEL
  --bind-network tcp|unix  --socket-mode 0770  --metrics-bind-network tcp|unix
  --difficulty-in-jwt  --webmaster-email ADDR  --preserve-referer-query-param
  --target-disable-keepalive (accepted; this gate always closes)
  --geoip-country PATH  --geoip-asn PATH  --geoip-lookup IP  --dnsbl
  --og-passthrough  --og-expiry-time SECS  --og-override "og:title=..."
  --og-cache-consider-host               key the cache on host and path
  --challenge-extension css-load
  --store file:PATH      keep the challenge ledger and honeypot counters
  (upstream's --bind, --policy-fname and --target-insecure-skip-verify are
   accepted as aliases)
```

Every flag is also an environment variable, upper case with dashes as
underscores: `--cookie-same-site` is `COOKIE_SAME_SITE`, `--listen` is `LISTEN`.
A flag on the command line wins over the environment, so a container can carry
its configuration in `environment:` and still be overridden by hand. This is
the same mapping upstream's `flagenv` gives its flags.

Difficulty 4 is a good default for a human-facing site (a few milliseconds of
work); 12–16 is a wall worth having against a script.

### Three places the defaults differ from Anubis, on purpose

| | Anubis | here | why |
|---|---|---|---|
| cookie attributes | `Secure` and `SameSite=None` by default | `Secure` only when we serve TLS, `SameSite=Lax` | a Secure cookie handed out over plain HTTP is dropped, and this gate is usually on loopback behind a TLS terminator. `--cookie-secure --cookie-same-site none` gives the upstream behaviour verbatim |
| `redir=` | any domain unless `REDIRECT_DOMAINS` is set | this host only unless `--redirect-domains` says otherwise | the challenge endpoint is otherwise a redirector for anyone who can hand you a pre-solved link |
| deny | 200 with a page | 200 with a page, `--deny-status 403` for the honest answer | 200 is what Anubis ships, and what makes a scraper think it won |
| metrics | binds `:9090` for you | off unless `--metrics-bind` is given | those counters describe your traffic and nothing authenticates the reader. Anubis opens the port for you; that is a convenience, and it is not free |

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
allow     path prefix /health                    # never challenge this
allow     net 10.0.0.0/8                         # the office is trusted
allow     net 2001:db8::/32                      # both address families
deny      ua matches (AhrefsBot|SemrushBot)      # POSIX extended regex
challenge ua contains curl difficulty 16
challenge ua matches ^python-requests algorithm argon2id difficulty 4
default   challenge difficulty 4
```

Selectors: `ua`, `path`, `header:<name>`, `net` (IPv4 or IPv6 CIDR). Matches:
`contains`, `prefix`, `is` (literal, case sensitive) and `matches` (POSIX
extended regular expression, compiled at load; a pattern that does not compile
is logged and the rule ignored rather than taking the gate down). Actions:
`allow` (proxy straight through), `deny` (status from `--deny-status`),
`challenge` (with an optional per-rule `difficulty` and `algorithm`).

A per-rule `algorithm` needs the spent-challenge table to remember it, so it is
ignored with a warning under `--stateless`.

**Regex is opt-in per rule.** The literal matchers stay the default because a
pattern nobody can read is a policy nobody can audit, and because `matches`
cannot express a reviewable "allow the office" the way `net` can. Patterns
cannot contain spaces, since a rule line is whitespace separated.

Measured on the running server: `AhrefsBot` → denied, `curl` UA → difficulty
16, anyone else → difficulty 4, `/health` → proxied with no challenge at all.

### Anubis's own policy file

`--policy` detects the format by looking at the file: a top-level `bots:` or a
bare `- ` list is Anubis's schema, a line starting with `allow`/`deny`/
`challenge`/`default` is ours. Pointing it at the real `data/botPolicies.yaml`
loads that file's import graph:

```
[betterAnusbis] policy: 41 rule(s) and 5 threshold(s) read from the Anubis format,
                6 conditional, 6 range-restricted, 2359 CIDR(s). A request that
                matches nothing is allowed, as Anubis does
```

The shipped policy then behaves the way its author meant:

| request | decision |
|---|---|
| `curl/8.5.0` | allowed (weight 0 hits `minimal-suspicion`) |
| Firefox UA | fast challenge at difficulty 2 (the `generic-browser` rule weighs +10) |
| `ChatGPT-User` | denied (the AI client rule) |
| Googlebot from `66.249.64.5` | allowed (`remote_addresses` matches) |
| Googlebot from anywhere else | fast at 2, not allowed: the UA alone proves nothing |
| `X-Firefox-Ai: 1` | metarefresh at difficulty 1 (weight 5) |
| no `User-Agent` at all | denied (`rfc-violations`) |
| `/robots.txt` | allowed, proxied |

What is honoured: `ALLOW`/`DENY`/`CHALLENGE`/`WEIGH`, rule order, the weight
accumulation, `thresholds` with the arithmetic subset of CEL (`weight <= 0`,
`all:`/`any:`), `remote_addresses` as IPv4 and IPv6 CIDR, `headers_regex`,
`expression` in its shipped forms (`"H" in headers`, `userAgent.contains`,
`path.startsWith`, `headers["H"].matches`, `host`, `load_1m`/`load_15m`),
`status_codes`, `honeypot.enabled`, and `import:` including `(data)/`.

`geoip.countries` and `asns.match` work when `--geoip-country` and `--geoip-asn`
point at MaxMind databases: the reader is this project's own, validated against
MaxMind's test files checked in under `tools/geoip-testdata`, and
`--geoip-lookup IP` prints what it thinks about an address. `dnsbl: true` is
honoured too, through DroneBL, cached for a day.

**The file also configures the gate.** `store`, `metrics`, `geoip`, `openGraph`,
`impressum`, `logging`, `dns_ttl`, `status_codes`, `honeypot` and `dnsbl` are
read from the same document as the rules, so an Anubis deployment's config
travels rather than being retyped as flags. Flags win where both are given. What
is still missing there is said out loud: a `bbolt`, `valkey` or `s3api` store is
named as unimplemented (the ledger stays in memory), as are the metrics
listener's `tls`/`basic_auth` and `pprof`, and `botstopper` is enterprise.

What is reported and skipped, by name, at load: `geoip` and `asns` matchers when
no database is configured, and `verifyFCrDNS` in shapes the evaluator cannot
read. Nothing is silently reinterpreted: a rule that cannot be evaluated logs
"will never match" rather than quietly matching everything or nothing.

Two translation notes, both reported when they happen: POSIX ERE has no
non-capturing groups or `\d`, so `(?:` becomes `(`, `\d` becomes `[0-9]`, and a
pattern wrapped in `(?i:...)` is compiled case-insensitively as a whole (POSIX
has no partial folding). A pattern that still will not compile is logged with
`regerror`'s words and its rule skipped.

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

## WebSocket

An upgrade is tunnelled, not answered. If the request carries
`Connection: Upgrade` and `Upgrade: websocket` (or `h2c`), the gate forwards the
request as written, relays the backend's `101` and its headers, and then stops
being an HTTP client: two sockets, one pipe, spliced with `poll()` until either
end closes or nothing has been said for five minutes.

A browser cannot solve a challenge from inside a WebSocket, so an upgrade has to
get through one of the two ways any proxied WebSocket does:

- a rule that allows the path, e.g. `allow path prefix /ws` (or a
  `path_regex` in an Anubis policy), or
- the auth cookie from a challenge the browser already passed, sent in the
  handshake like any other header.

Anything else gets the challenge page, which is the same thing Anubis does.

Two honest limits: closing either end closes both, so a half-close is not
forwarded; and the idle timeout is a fixed five minutes, not configurable yet.

## Inspecting a running gate

`kill -HUP <pid>` prints the effective settings, as parsed and validated, plus
the counters: challenge issued/accepted/replayed/expired, trap hits, flagged
networks. `--metrics-bind 127.0.0.1:9090` exposes the same numbers in Prometheus
form, and `GET /healthz` on that port answers `OK`.

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

- **No HTTP/2, and the client side has no keep-alive.** The gate reads one
  request, answers it with `Connection: close` and closes, which keeps the
  listener readable. TLS itself is there (`--tls-cert`/`--tls-key`, and
  `--target https://` with `--target-insecure` for a self-signed backend).
- **The origin does get keep-alive.** Its connections are pooled and reused when
  the response was framed (Content-Length, chunked, or no body), idle for up to
  a minute, with one retry when a pooled connection turns out to be dead.
  `--target-disable-keepalive` turns it off. Three proxied requests cost one
  connection with the pool, three without it.
- **OpenGraph works for the challenge page, not for every page.** `--og-passthrough`
  fetches the protected page once, keeps its `og:` and description tags for
  `--og-expiry-time` and puts them on the challenge page, so a link preview says
  what the page is about. `--og-override "og:title=...;og:description=..."`
  replaces them without fetching anything.
- **`--challenge-extension css-load`** carries a stylesheet link on the challenge
  page and refuses a pass-challenge until the browser has fetched it, which is
  what the upstream extension does. `headless` exists only in the enterprise
  build, so asking for it logs that and checks nothing.
- **One store backend: a file.** `--store file:PATH` snapshots the challenge
  ledger and the honeypot counters every five seconds, on `SIGTERM`, and loads
  them at startup, so a restart no longer forgets which challenges were issued
  or which networks were annoying. It is a snapshot, not a journal: a crash
  loses up to five seconds, and nothing coordinates two processes writing the
  same file. Upstream's bbolt, valkey and S3 backends exist to share state
  between replicas, which this does not do.
- **No bbolt, valkey or S3 backends.** `pass-challenge`,
  `check`, `ping`, the state endpoint, the honeypot, `robots.txt`, the
  Prometheus `/metrics`, impressum, localization and the challenge extensions
  are implemented or documented above. The store backends (bbolt, valkey, S3)
  and OpenGraph passthrough are the last two things on the parity list;
  `PARITY.md` is the full gap list with file references.
- **Two policy formats, neither of them a CEL engine.** Our own flat rules
  (literal or regex matchers, first match wins) and Anubis's `botPolicies.yaml`
  (rules, weights, thresholds, imports). The expression evaluator covers the
  forms the shipped policies use, not CEL: no GeoIP countries, no ASN matching,
  no `verifyFCrDNS`, and no arbitrary CEL you invent. Everything it cannot
  evaluate is named in the log at startup.
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
python3 test_parity.py        # the flags taken from cmd/anubis, checked on the wire
```

`test-all-algorithms.sh` starts a backend itself if one is not running and
kills/restarts betterAnusbis per algorithm. `test_parity.py` starts both sides
itself and asserts what the HTTP response says: status lines, every Set-Cookie
attribute, the Location header after a blocked redirect, the counters a scrape
returns, the headers the backend received after XFF flattening, and the decision
the shipped `data/botPolicies.yaml` produces for nine probe requests, and a real
WebSocket upgrade: the 101, its `Sec-WebSocket-Accept`, and a frame echoed byte
for byte through the tunnel. 103 checks, no logs read. The Anubis policy checks skip themselves when the upstream data
directory is not there; set `ANUBIS_DATA_DIR` to point at one. `wasm/live-server.md` in the parent repository has a policy file for
the real Anubis if you want to compare side by side.

---

Built with [DeepSeek V4.1 Flash](https://huggingface.co/deepseek-ai/DeepSeek-V4.1-Flash-1017)
running [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness),
per the repository's MIT + attribution license.
