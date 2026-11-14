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

You are not rewriting anything. Your Anubis config file is the config file. Your
reverse proxy changes one line. Your users notice that the challenge page is
prettier and nothing else.

This guide assumes you can start a program and edit an nginx/Caddy config. If
you cannot yet, the README's first three paragraphs are enough to get there.

## What you need

- A Linux box (or macOS; the gate is plain C)
- `cc`, `make`, and OpenSSL's headers: `apt install build-essential libssl-dev`
  / `dnf install gcc make openssl-devel` / `apk add build-base openssl-dev`
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
# 1.50.1 "headslam"
```

That is the whole build. No Go toolchain, no container, no `go mod download`.

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
falls back to plain JavaScript, and `argon2id`/`hashx` cannot run at all.

The startup log tells you exactly what it understood:

```
policy: 41 rule(s) and 5 threshold(s) read from the Anubis format,
        6 conditional, 6 range-restricted, 2711 CIDR(s).
        A request that matches nothing is allowed, as Anubis does
```

If a line says something is ignored, that line is the truth: either it is an
enterprise feature (`botstopper`) or a store backend this gate does not have
(`bbolt`, `valkey`, `s3api`). It will not fail silently.

> **Why `--secret-file`?** Without it the signing key is random per run, so
> every restart logs every client out. Anubis keeps its key on disk; give this
> gate one too. It is created `0600` if missing.

## 3. Check it like a user

```bash
# the challenge page, from the gate's own port
curl -i http://127.0.0.1:8081/

# a browser is the real test: open it and watch yourself land on the backend
xdg-open http://127.0.0.1:8081/     # or just click it

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

## The config file already travels

As of 1.50.1 the policy file configures the gate, not just the rules. These
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

**Not here:** `bbolt`/`valkey`/`s3api` stores, the metrics listener's TLS and
basic auth, `--cookie-dynamic-domain`, HTTP/2, and six locales of Anubis's
thirty-one.

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
you have a reason.

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
JavaScript is the fallback and is several times slower on a phone.

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
  /run/anubis.sock --socket-mode 0770`.
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
| `--bind-network unix` fails | the socket's directory must exist and be writable; the mode comes from `--socket-mode`. |

## Known differences

In the order you are likely to hit them:

1. **Six locales of thirty-one.** English, Dutch, German, French, Spanish,
   Italian. Everything else gets English.
2. **One re-solve per client** on the swap, and per policy edit afterwards.
3. **No bbolt, valkey or S3 store.** `--store file:PATH` survives restarts but
   shares nothing between replicas.
4. **No HTTP/2.** Terminate TLS at your proxy, which speaks HTTP/1.1 to the gate.
5. **No CEL engine** beyond the expressions Anubis's own policies use; anything
   else is reported by rule name at startup.
6. **`botstopper` and the headless extension** are enterprise features and are
   reported as such, not imitated.

The full, file-by-file account of every gap on both sides is
[`betterAnusbis/PARITY.md`](betterAnusbis/PARITY.md), and the security review
that came out of reading the gate against upstream is
[`betterAnusbis/SECURITY-REVIEW.md`](betterAnusbis/SECURITY-REVIEW.md).
