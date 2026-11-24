<p align="center">
  <img src="mascot/anubis_mascot_happy.png" height="230" alt="the Anubis mascot">
  &nbsp;&nbsp;&nbsp;<b>➜</b>&nbsp;&nbsp;&nbsp;
  <img src="mascot/anti-anti-ai.png" height="230" alt="the betterAnusbis mascot">
</p>

<p align="center">
  anubis mascot made by CELPHASE , anubis-solver mascot made by Chatgpt , everything else written by DeepSeek V4.1 flash running on Deepseek Harness (DSH)
</p>

---

# Moving from Anubis to betterAnusbis

> **2.50 "mule"** is the version this guide describes. Since 2.0.0 the C
> services moved the fetch layer into `libanubis_solver.so`, the fetch layer can
> present a browser TLS fingerprint through a `dlopen()`ed libcurl-impersonate,
> and `LICENSE` section 4 requires the DeepSeek logo and credit line on the die
> and package marking of any chip built from `beyond/`. The binaries in the
> 2.0.2 release are rebuilt with those changes, and the MSI licence page shows
> the new text.

You are not rewriting anything. Your Anubis config file is the config file. Your
reverse proxy changes one line. Your users notice that the challenge page is
prettier and nothing else.

This guide assumes you can start a program and edit an nginx/Caddy config. If
you cannot yet, the README's first three paragraphs are enough to get there.

## What you need

- A Linux box (or macOS; the gate is plain C), **or** Windows 10/11 x86-64
- On Linux: `cc`, `make`, and OpenSSL's headers: `apt install build-essential libssl-dev`
  / `dnf install gcc make openssl-devel` / `apk add build-base openssl-dev`
- On Windows: nothing to build — the release ships `betterAnusbis.exe` +
  `anubis_solver.dll` as a zip and as an MSI. Building from source is a
  mingw-w64 cross build (`betterAnusbis/win32/build-windows.sh`); the recipe is
  in [RELEASING.md](RELEASING.md)
- Your existing `botPolicies.yaml` and the `data/` directory next to it
- About five minutes

## 1. Build it

```bash
git clone https://github.com/celikfana-lab/anubis-solver
cd anubis-solver
make                      # the solver library: libanubis_solver.so
cd betterAnusbis
make                      # the gate: one cc invocation, one binary
./betterAnusbis --version
# 2.50 "mule"
```

That is the whole build. No Go toolchain, no container, no `go mod download`.

On Windows you take a release artifact instead — same version string, same
flags, no compiler:

```powershell
# the MSI installs under Program Files\betterAnusbis and adds it to PATH;
# open a new terminal afterwards so PATH is picked up
msiexec /i betterAnusbis-2.50-x86_64-windows.msi

# or unzip and run from the folder (keep the .exe and the .dll together)
.\betterAnusbis.exe --version
# 2.0.2 "shaoogle"
```

The Windows pair comes from the same `betterAnusbis.c`; what it leaves out and
why is in [Running it on Windows](#running-it-on-windows) below.

## 2. Start it next to Anubis, not instead of it

Put it on another port and point it at the same backend. Use **your existing
policy file**:

```bash
./betterAnusbis \
  --listen 127.0.0.1:8081 \
  --target http://127.0.0.1:3000 \
  --policy /etc/anubis/botPolicies.yaml \
  --data-dir /etc/anubis/data \
  --secret-file /etc/betterAnusbis/secret.key \
  --web /opt/anubis-solver/wasm \
  --metrics-bind 127.0.0.1:9091
```

`--web` is where the browser's WASM kernels live (`sha256_pow_batch.wasm` and
friends, built by `wasm/make`). Point it at the repository's `wasm/` directory
or wherever you installed them. Without it, `sha256` still works but the browser
falls back to plain JavaScript, and `argon2id`/`hashx` cannot run at all. The
release archives do not bundle the kernels: on Windows, point `--web` at a
source checkout's `wasm/` directory (or copy its files next to the binary).

The startup log tells you exactly what it understood:

```
policy: 41 rule(s) and 5 threshold(s) read from the Anubis format,
        6 conditional, 6 range-restricted, 2711 CIDR(s).
        A request that matches nothing is allowed, as Anubis does
```

If a line says something is ignored, that line is the truth: either it is an
enterprise feature (`botstopper`). It will not fail silently.

> **Why `--secret-file`?** Without it the signing key is random per run, so
> every restart logs every client out. Anubis keeps its key on disk; give this
> gate one too. It is created `0600` if missing.

## 3. Check it like a user

```bash
# the challenge page, from the gate's own port
curl -i http://127.0.0.1:8081/

# a browser is the real test: open it and watch yourself land on the backend
xdg-open http://127.0.0.1:8081/   # Linux
start http://127.0.0.1:8081/      # Windows (Command Prompt or PowerShell)

# metrics and the health endpoint
curl -s http://127.0.0.1:9091/healthz     # ok
curl -s http://127.0.0.1:9091/metrics | head

# what the geoip reader thinks, if you configured databases
./betterAnusbis --geoip-lookup 8.8.8.8 --geoip-country /etc/geoip/GeoLite2-Country.mmdb
```

Then compare decisions with Anubis for a few user agents. `-v` logs every
request, and both gates print the same vocabulary:

```bash
./betterAnusbis ... -v
# [betterAnusbis] 1.2.3.4 GET / 200 policy=challenge weight=10
```

## 4. Cut over

Only the reverse proxy's upstream changes. For nginx:

```nginx
upstream anubis {
    server 127.0.0.1:8080;      # was Anubis, now betterAnusbis
    keepalive 16;
}

location / {
    proxy_pass http://anubis;
    proxy_http_version 1.1;
    proxy_set_header Connection "";        # let the keepalive pool work
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Reload the proxy (`nginx -s reload`). Nobody is logged out mid-flight, but
**every client will solve one challenge after the swap**, because Anubis's
tokens and this gate's tokens are signed differently. That is one extra page
load per client, once.

## 5. Rollback

Point the upstream back at Anubis's port and reload. The two gates do not share
state, so nothing about the rollback is delicate.

## Running it on Windows

The same gate, the same flags, the same policy file. What changes is the
packaging and a handful of things Win32 does not have:

- **The pair must stay together.** `betterAnusbis.exe` imports
  `anubis_solver.dll` by name, so both files have to be in the same directory.
  The MSI opens on a license page (our MIT + attribution text, the
  anti-anti-ai mascot); tick *I accept* and **Install** proceeds. It puts the
  files under `Program Files\betterAnusbis` and adds that directory to the
  machine `PATH`; the zip is enough if you would rather not install. Silent
  installs (`msiexec /i ... /qn`) skip the license page.
- **No Visual C++ runtime needed.** Everything except `anubis_solver.dll` is
  linked statically, and that DLL only needs the system libraries.
- **Windows 10/11 x86-64.** `--bind-network unix` additionally needs Windows 10
  1803+ for AF_UNIX; the normal TCP listener does not.
- **The WASM kernels are not in the zip/MSI.** The browser-side files
  (`sha256_pow_batch.wasm`, `argon2id_pow.wasm`, `hashx_pow.wasm`,
  `tensor_pow.wasm`) live in the
  repository's `wasm/` directory; point `--web` there. Without them `sha256`
  falls back to JavaScript and `argon2id`/`hashx` cannot be solved in the
  browser — which is the same rule as on Linux, the archives just do not carry
  the files.
- **HTTP/1.1 only in the release build.** nghttp2 and nghttp3/QUIC are optional
  at build time everywhere and are not linked into the shipped Windows pair;
  `--http2` says so at startup. Build from source with those libraries if you
  need h2/h3.
- **HashX runs the interpreter, and the SHA-NI/AVX2 kernels are not linked.**
  The Windows build takes the portable C paths (the hand-written kernels are
  ELF assembly and the HashX JIT is System V ABI), so a `hashx` challenge costs
  noticeably more CPU there. `sha256`, `fast` and `slow` are the cheap choices
  on both platforms; raise `hashx` difficulty with that in mind.
- **TLS trusts the Windows certificate store** through OpenSSL's winstore
  support. Set `SSL_CERT_FILE` to a PEM bundle to point the backend hop at one
  explicitly; `--tls-cert`/`--tls-key` for the listener are unchanged.
- **No SIGHUP.** The settings dump that `kill -HUP` prints on Linux has no
  Windows equivalent; scrape `/metrics` (with `--metrics-bind`) or restart.
  Ctrl+C / Ctrl+Break take the place of SIGINT/SIGTERM and flush a `file:` or
  `bbolt:` store on the way out.

Start it by hand:

```powershell
# from an MSI install (already on PATH) or the unzipped folder
betterAnusbis.exe --listen 127.0.0.1:8081 --target http://127.0.0.1:3000 `
  --policy C:\ProgramData\anubis\botPolicies.yaml `
  --data-dir C:\ProgramData\anubis\data `
  --secret-file C:\ProgramData\betterAnusbis\secret.key `
  --web C:\anubis-solver\wasm `
  --metrics-bind 127.0.0.1:9091
```

For a real service, Task Scheduler (run at startup, restart on failure) or NSSM
both work: give them the full path to `betterAnusbis.exe`, a working directory,
and `stderr` redirected to a file or a logging agent — Windows has no syslog for
the gate to write to. The first time the TCP listener opens, Windows Firewall
may ask; if the reverse proxy runs on the same host, loopback access is all it
needs.

Paths with spaces need quotes. `--secret-file` is created if it is missing, as
on Linux; keep it out of a synchronised profile, because two machines sharing
one signing key is fine but two instances fighting over one file-backed
challenge store is not.

## The config file already travels

Since 1.50.1 the policy file configures the gate, not just the rules. These
blocks are read from the same document:

| block | what it sets |
|---|---|
| `bots`, `thresholds`, `import:`, `(data)/` | the rules, as in Anubis |
| `status_codes` | the `CHALLENGE` and `DENY` statuses |
| `honeypot` | the trap link, the tarpit, the IP log |
| `dnsbl` | DroneBL checks, and `dns_ttl` for how long an answer is kept |
| `store` | `memory`, or `file` with `parameters.path` |
| `metrics` | `enabled`, `bind` |
| `geoip` | `country.path`, `asn.path` |
| `openGraph` | `enabled`, `considerHost`, `expiryTime`, `override` |
| `impressum` | `enabled`, `footer` |
| `logging` | `level` |

Command-line flags win over the file, so you can override a shared policy
without editing it.

**Flags:** every Anubis flag has a home here, and three of upstream's names are
accepted as aliases so a copied compose file starts:
`--bind`→`--listen`, `--policy-fname`→`--policy`,
`--target-insecure-skip-verify`→`--target-insecure`. Every flag is also an
environment variable (`--cookie-same-site` is `COOKIE_SAME_SITE`).

**Not here:** the metrics listener's TLS and basic auth,
`--cookie-dynamic-domain`, and six locales of Anubis's thirty-one. All four
store backends are here: `--store file:PATH`, `bbolt:PATH`,
`valkey:redis://HOST:PORT/DB`, and `s3api:BUCKET` with the AWS environment
credentials upstream's SDK uses.
HTTP/2 is here (ALPN `h2`, plus `h2c` prior knowledge on a plain listener), and
HTTP/3 over QUIC is an extra this gate has and upstream does not — both are
optional at build time and on by default only for HTTP/2.

## Making clients fast

The client is a browser on somebody's phone. Its work is the challenge, and the
challenge is the only thing this gate asks of it.

**Leave the difficulty low.** It doubles the client's work for every step:
each `+1` on `sha256` is twice as many hashes, each `+1` on `fast`/`slow` is
sixteen times as many. Difficulty 4 on `sha256` is around sixteen attempts, which
is a few milliseconds. Difficulty 8 is a visible pause on a cheap phone, and
difficulty 12 is a joke that stops being funny on battery.

```bash
--algorithm sha256 --difficulty 4     # the default, and the right default
```

**Pick the cheapest algorithm that stops your bots.** `sha256` is the lightest
on a browser: one WASM hash loop, no memory. `argon2id` and `hashx` are much
heavier on purpose; they cost mobile CPUs and battery, so raise them only when
you have a reason. `tensor` is the fourth option and the only one that is not a
hash: difficulty *d* means a matrix of `N = 64*clamp(d,2,16)`, so `--difficulty 8`
is a 512x512x512 int8 product (about 40 ms in wasm, 0.4-0.7 s in JavaScript,
20 ms to verify). It is the tier to reach for when you specifically want a
browser that can run WebNN or wasm SIMD, and the only one whose proof is
deterministic rather than a nonce search.

`tensor-v` is the same product with a cheaper server check: the browser commits
to the result and opens the 96 blocks the gate samples, so verification is a few
milliseconds instead of 20-130 ms. It needs the bundled challenge page (the
two-request commit/audit flow is in its JavaScript); stock Anubis solvers cannot
solve it. Use `tensor` if you need the classic one-request digest, `tensor-v` if
gate CPU is the constraint.

**Keep the cookie settings stable.** `--dynamic-cookie-suffix` (on by default)
puts a hash of your cookie settings in the cookie's *name*. Change a cookie flag
and every client solves again. Decide the settings once, then leave them.

**Give cookies a real lifetime.** `--cookie-expiration-time 604800` (seven days,
the default) means a returning visitor does not solve again for a week. Zero
makes it a session cookie and buys you a re-solve every browser restart.

**Do not bind cookies to addresses if you have mobile users.** The
`--jwt-restriction-header` default ties the cookie to the client's IP, which is
Anubis's default too. A phone hopping between Wi-Fi and LTE changes address and
solves again. If your threat model tolerates it:

```bash
--jwt-restriction-header ""      # no address binding
```

**Do not put DNS lookups in the hot path unless you want them.** `dnsbl: true`
asks DroneBL about each *new* address once and caches the answer for `dns_ttl`.
With a slow resolver that is a visible first-request delay. If you enable it,
point `/etc/resolv.conf` at a local cache.

**GeoIP costs microseconds.** A MaxMind lookup per request is cheap; the
databases are memory-mapped once at startup. Leave it on if you use it.

**Serve the kernels locally.** The challenge page is one HTML document with
inline CSS and JS, and its WASM kernels come from the gate's own static route
(`--web`). There are no fonts, no images and no third-party requests, so the
page cannot be slower than the gate. `sha256` in WASM is the fast path; pure
JavaScript is the fallback and is several times slower on a phone. The fallback
is automatic when WebAssembly is unavailable, and `#pure-js` on the challenge
URL forces it (the fragment is never sent to the server).

## Making the gate fast

- **Keep-alive to the backend is on by default.** Three proxied requests cost
  one connection. If the backend is fussy about that, `--target-disable-keepalive`
  sends `Connection: close` instead.
- **The gate is one thread per client connection.** It is cheap (a PoW check is
  microseconds) but it is not `epoll`; if you expect more than a few thousand
  concurrent sockets, put it behind a proxy that queues, which you were going to
  do anyway.
- **`--stateless` is faster and weaker.** It skips the challenge ledger, which
  means an issued challenge can be replayed, and it makes
  `--challenge-extension css-load` impossible (the gate refuses to start with
  both, rather than pretending to check). Use it only if you know that.
- **Unix sockets** for both listeners: `--bind-network unix --listen
  /run/anubis.sock --socket-mode 0770`. On Windows that needs Windows 10 1803+
  (AF_UNIX); on older versions keep the TCP listener.
- **Metrics are off unless you bind them.** Anubis binds `:9090` for you, which
  hands your traffic numbers to anyone who can reach it; this gate makes you ask.

## Troubleshooting

| symptom | cause and fix |
|---|---|
| `502 Bad Gateway` | the target is unreachable or not HTTP. Check `--target`, then `curl` it yourself. |
| every restart logs everyone out | no `--secret-file` (or `--secret-hex`). The key must survive restarts. |
| the cookie is set but not sent back | `--cookie-domain` does not match the host the browser sees, or you are on plain HTTP with `--cookie-secure=1`. |
| a policy edit logs everyone out | by design: the token names the policy it was minted under, so a changed policy invalidates it. Anubis invalidates per rule; this gate does it wholesale, in the safe direction. |
| `/metrics` 404s | metrics are off until `--metrics-bind` (or the `metrics.bind` block) says where to put them. |
| the gate says a rule "will never match" | the expression uses something outside the CEL subset; the message names the rule. |
| `--bind-network unix` fails | the socket's directory must exist and be writable; the mode comes from `--socket-mode`. On Windows this also needs Windows 10 1803+ for AF_UNIX. |
| `anubis_solver.dll was not found` (Windows) | the .exe and the .dll were separated. Keep them in one directory, or install the MSI. |
| `fixme:msi:internal_ui_handler` when installing under Wine | Wine's MSI UI is incomplete, the install finishes anyway. `wine msiexec /i betterAnusbis-2.50-x86_64-windows.msi /qn` does the same quietly; on real Windows, double-clicking the MSI shows the normal progress UI. |
| no `kill -HUP` on Windows | there is no SIGHUP; scrape `/metrics` (`--metrics-bind`) or restart. Ctrl+C flushes a `file:`/`bbolt:` store. |
| browser cannot solve `argon2id`/`hashx` | `--web` does not point at the WASM kernels; the release archives do not include them, use a source checkout's `wasm/` directory. |
| HTTPS target certificate fails (Windows) | point `SSL_CERT_FILE` at a PEM bundle, or rely on the Windows certificate store where OpenSSL's winstore support is available. |
| Windows Firewall prompts on first start | expected: the listener binds a TCP port. Allow loopback (or the proxy's address) only. |

## Known differences

In the order you are likely to hit them:

1. **Six locales of thirty-one.** English, Dutch, German, French, Spanish,
   Italian. Everything else gets English.
2. **One re-solve per client** on the swap, and per policy edit afterwards.
3. **Simpler store clients than the upstream SDKs.** Valkey has no
   cluster/Sentinel discovery; S3 uses static credentials from the environment
   (no IMDS, profile chain, assume-role, or SDK retry/keep-alive layer), and one
   HTTP connection per operation. file/bbolt share nothing between replicas;
   valkey and S3 are the multi-instance backends.
4. **WebSockets are HTTP/1.1 only.** HTTP/2 extended CONNECT and HTTP/3
   datagram tunnels are not implemented, so an h2/h3 client gets 400 for
   CONNECT; browsers use h1 for `ws://` regardless.
5. **No CEL engine** beyond the expressions Anubis's own policies use; anything
   else is reported by rule name at startup.
6. **`botstopper` and the headless extension** are enterprise features and are
   reported as such, not imitated.

The full, file-by-file account of every gap on both sides is
[`betterAnusbis/PARITY.md`](betterAnusbis/PARITY.md), and the security review
that came out of reading the gate against upstream is
[`betterAnusbis/SECURITY-REVIEW.md`](betterAnusbis/SECURITY-REVIEW.md).
