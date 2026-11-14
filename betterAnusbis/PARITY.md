# PARITY: betterAnusbis against TecharoHQ/anubis

Scope: upstream Go tree at `/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis` (read only), our gate at
`anubis-solver/betterAnusbis/betterAnusbis.c` (read only for this audit).

Method: read the sources named in each row. No build, no execution, no commits. Every claim carries `file:line`.
Where a claim could not be checked it says **unverified**.

Snapshots. Upstream: working tree as of 2026-11-14 09:59, git revision not read (**unverified**).
Ours: `betterAnusbis.c` md5 `768d0c966353ebc54afd13405bbda9e8`, 3705 lines, mtime 2026-11-14 10:09:04 +0100. This is
the final snapshot for the CLI surface; the file was still growing during the audit (2820 lines at 09:59), and all our
line numbers below are from this blob. Every one is preceded by a symbol name, so `grep` finds it if a later edit shifts it.

Counts. 49 upstream flags (`grep -c '= flag\.' cmd/anubis/main.go`): 7 already have an equivalent here, 18 are ported in
this commit, 24 remain missing (20 functional, 4 deprecated no-ops). 45 behavioural gaps without a flag. 10
recommendations. 16 deliberate divergences.

---

## 1. What betterAnusbis already has

| area | upstream equivalent | ours | note |
|---|---|---|---|
| Challenge algorithms `fast`, `slow` | `lib/challenge/proofofwork/proofofwork.go:21-22` | `verify_answer` dispatches to nibble verification, `betterAnusbis.c:385-403` | difficulty is leading hex nibbles on both sides |
| `sha256`, `argon2id`, `hashx` | `lib/challenge/wasm/wasm.go:21-23` | `verify_answer`, `betterAnusbis.c:389-397` | difficulty is leading zero bits on both sides, confirmed by `docs/docs/admin/configuration/challenges/wasm.mdx:23` |
| `metarefresh` | `lib/challenge/metarefresh/metarefresh.go:60-73` (wait `difficulty*800ms`, echo the challenge) | `betterAnusbis.c:2990-3031` | ours measures the wait from the unix second inside the id, so 1 s granularity; upstream uses `IssuedAt` |
| Challenge JSON `<script id="anubis_challenge" type="application/json">` | `web/index.templ:60-65`, struct at `lib/challenge/challenge.go:6-16` | `challenge_page`, `betterAnusbis.c:2624-2696` | field set matches except `issuedAt` encoding, see the JSON divergence in section 5 |
| `pass-challenge` contract (`id`, `response`, `nonce`, `redir`, `elapsedTime`) | `lib/anubis.go:615-812` | `betterAnusbis.c:2947-3090` | ours reads and ignores `elapsedTime` (`:2954`); upstream requires it for `fast`/`slow` (`proofofwork.go:55-72`) |
| `check` route (status only) | `lib/config.go:214`, `lib/anubis.go:277-279` | `betterAnusbis.c:2905-2908` | ours answers `ok`/401; upstream proxies the target and returns its status |
| Auth cookie name and JWT claims `challenge`, `method`, `policyRule`, `action`, `iat`, `exp` | `anubis.go:29`, `lib/anubis.go:765-778` | `sign_token`, `betterAnusbis.c:274-306` | claim names match, signing does not, see the JWT signing divergence in section 5 |
| Cookie verification cookie | `lib/http.go:338-344`, `lib/anubis.go:639-648` | `challenge_page`, `betterAnusbis.c:2691` | ours sets it but never requires it, see the last-but-one divergence row in section 5 |
| Spent-challenge ledger (`spent`) | `lib/anubis.go:676-677`, `:746` | `ch_issue`/`ch_take`, `betterAnusbis.c:444-476` | in memory, 4096 buckets, one use; `--stateless` turns it off |
| Policy semantics `allow`/`deny`/`challenge` on UA, path, header, IP | `lib/config/config.go:37-44`, `lib/policy/checker.go:70-230` | `policy_load`/`policy_decide`, `betterAnusbis.c:2765-2833` | literal matching, no regex; IPv4 CIDR only, see the IPv6 row in section 5 |
| Honeypot trap link, tarpit, maze | `internal/honeypot/naive/naive.go:219-278`, wired at `lib/config.go:217-236` | `hp_tarpit`/`honeypot_maze`, `betterAnusbis.c:638-700`, route at `:3092` | same `min(hits^2, 1000)` ms curve (`naive.go:257`) |
| Honeypot network flag at 25 hits | `internal/honeypot/naive/naive.go:180` | `flag_threshold = 25`, `betterAnusbis.c:116`, applied `:3139-3145` | ours raises difficulty 8 bits instead of adding weight 30, see the honeypot divergence in section 5 |
| Reverse proxy with target Host/SNI/insecure knobs | `cmd/anubis/main.go:140-217` | `proxy_request`/`target_connect`, `betterAnusbis.c:1290-1394` | ours buffers the whole response and closes, see the WebSocket row in section 3 |
| TLS on the listener | none; upstream serves plain HTTP (`internal/http_server.go:8-15`) | `--tls-cert`/`--tls-key`, `betterAnusbis.c:3272-3348` | an addition, not parity |
| `status_codes.CHALLENGE` and `status_codes.DENY` | `lib/config/config.go:285-306`, defaults 200 at `:388-392` | `challenge_status`/`deny_status`, used at `betterAnusbis.c:2693` and `:3131` | now defaults to 200/200 like upstream, see the DENY status divergence in section 5 |
| `base-prefix` routing | `lib/http.go:458-473`, `lib/config.go:153` | `betterAnusbis.c:2877-2886` | see 1.1 |
| Difficulty units per algorithm | nibbles `proofofwork.go:88-101`, bits `lib/challenge/wasm/wasm.go:98-100` | `verify_answer`, `betterAnusbis.c:389-397` | matches |

### 1.1 Ported in this commit (final)

| flag or feature | upstream default | upstream file:line | our evidence |
|---|---|---|---|
| `--cookie-domain` | `""` | `cmd/anubis/main.go:48` | `cookie_domain`, `betterAnusbis.c:85`, applied `:865-866` |
| `--cookie-secure` | `true` | `cmd/anubis/main.go:58` | `cookie_secure`, default -1 = on iff TLS, `:86`, `:848` |
| `--cookie-http-only` | `false` | `cmd/anubis/main.go:59` | `cookie_http_only`, default 1, `:87`, `:870` |
| `--cookie-same-site` | `None` | `cmd/anubis/main.go:60` | `cookie_same_site`, default `lax`, `:88`, `:855` |
| `--cookie-partitioned` | `true` | `cmd/anubis/main.go:52` | `cookie_partitioned`, `:89`, `:872` |
| `--cookie-expiration-time` | `7*24h` (`anubis.go:48`) | `cmd/anubis/main.go:50` | `cookie_ttl`, `:90`, claim exp `:290` |
| `--base-prefix` | `""` | `cmd/anubis/main.go:44` | `base_prefix`, `:91`, route rewrite `:2877-2886` |
| `--strip-base-prefix` | `false` | `cmd/anubis/main.go:70` | `strip_base_prefix`, `:92`, `:2886` |
| `--custom-real-ip-header` | `""` | `cmd/anubis/main.go:87` | `real_ip_header`, `:93`, `client_address` `:954-975` |
| `--use-remote-address` | `false` | `cmd/anubis/main.go:77` | `use_remote_address`, `:94`, `:956` |
| `--xff-strip-private` | `true` | `cmd/anubis/main.go:86` | `xff_strip_private`, `:95`, `:988` |
| `--redirect-domains` | `""` (any domain allowed) | `cmd/anubis/main.go:68` | `redirect_domains` + glob, `:96`, `glob_match` `:1008`, `safe_redirect` `:1050-1087` |
| `status_codes` equivalent | 200/200 | `lib/config/config.go:388-392` | `--challenge-status`, `--deny-status`, fields `:97-98`, args `:3369-3370` |
| `--serve-robots-txt` | `false` | `cmd/anubis/main.go:66` | `serve_robots_txt`, `:99`, route `:2899` |
| `--target-sni` (`auto` included) | `""` | `cmd/anubis/main.go:72`, `:213-231` | `target_sni`, `:100`, `:1314` |
| `--target-host` | `""` | `cmd/anubis/main.go:73` | `target_host_hdr`, `:101`, `:1344-1345` |
| `--debug-benchmark-js` | `false` | `cmd/anubis/main.go:78`, `:357-364` | `debug_benchmark_js`, `:102`, `:2897` |
| `--jwt-restriction-header` | `X-Real-IP` | `cmd/anubis/main.go:92`, `lib/anubis.go:417-420`, `:768-778` | `jwt_restrict_hdr`, `:104`, claim minted `:283-284`, enforced `:346-353`; semantics differ, see the JWT restriction divergence in section 5 |
| `--metrics-bind` | `:9090` | `cmd/anubis/main.go:63`, `lib/metrics/metrics.go:46-60` | `metrics_bind`, `:103`, args `:3396`, listener `:3650-3675`; default off, see the metrics divergence in section 5 |
| X-Forwarded-For flattening | `internal/headers.go:115-220` | same | `client_address` walks right to left, skips private/loopback/link-local/CGNAT, `:954-1000` |
| Wildcard redirect allow list | `lib/http.go:41-56` + `internal/glob/glob.go:12-60` | same | `glob_match` capped at 4 stars, `:1008-1025` |

Two non-flag items also landed. The parser is now table driven (`args[]`, `betterAnusbis.c:3364-3398`; `parse_args`,
`:3400`) and accepts `--flag=value`, `--flag value`, `--no-flag` and `--flag=false` for every boolean. SIGHUP now
actually prints the effective settings (`print_settings`, `:3487`, installed at `:3604`), which the help text had
promised while the handler did nothing.

One parity detail worth keeping: the metric names match upstream, `anubis_challenges_issued`,
`anubis_challenges_validated`, `anubis_failed_validations`, `anubis_proxied_requests_total`, and
`anubis_policy_results` (`betterAnusbis.c:1154-1220` against `lib/anubis.go:70-99`, `lib/policy/policy.go:41-43`), so
existing dashboards keep the series they query. Label sets differ: upstream adds `asn` and `asn_description` to most of
them and has `anubis_requests_by_asn_total` and `anubis_dronebl_hits`; ours has `anubis_honeypot_hits_total`,
`anubis_honeypot_networks_flagged`, `anubis_challenges_replayed_total`, `anubis_challenges_expired_total` and
`betteranusbis_build_info` instead (`betterAnusbis.c:1203-1217`).

---

## 2. Missing CLI surface

49 flags are defined at `cmd/anubis/main.go:44-94`. Already equivalent here, under our own name:
`--bind` is `--listen` (a different default), `--target` is `--target` (we require it, upstream defaults to
`http://localhost:3923`, `main.go:71`), `--difficulty` is `--difficulty`, `--cookie-prefix` is `--cookie-prefix`,
`--policy-fname` is `--policy` (same intent, different file format), `--target-insecure-skip-verify` is
`--target-insecure`, `--version` is `-V`.

The 24 that are missing:

| flag | upstream default | what it does | port cost | notes |
|---|---|---|---|---|
| `--bind-network` | `tcp` | network family for the listener (`unix`, `tcp`) | trivial | needs `AF_UNIX` and socket mode handling; pairs with `--socket-mode` |
| `--cookie-dynamic-domain` | `false` | sets cookie `Domain` to the eTLD+1 of the request host | moderate | needs a public suffix list to do it properly (`lib/http.go:148-152`) |
| `--dynamic-cookie-suffix` | `true` | appends a hash of cookie settings to the cookie name | trivial | 8 hex chars from a hash of the settings (`lib/http.go:118-127`) |
| `--difficulty-in-jwt` | `false` | adds a `difficulty` claim to the JWT | trivial | diagnostics only (`lib/anubis.go:775-777`) |
| `--use-simplified-explanation` | `true` | deprecated, no effect | trivial | accept and ignore; upstream logs a warning (`main.go:425-427`) |
| `--forced-language` | `""` | overrides `Accept-Language` for page strings | big | useless until localization exists; value is stored at `anubis.go:69` |
| `--hs512-secret` | `""` | HS512 signing key instead of ed25519 | trivial | we already sign HS256 with a random key; persisting it is the real win |
| `--ed25519-private-key-hex` | `""` | ed25519 seed as hex, for JWTs | big | would need Ed25519 in C or a different signature scheme |
| `--ed25519-private-key-hex-file` | `""` | the same seed from a file | big | same |
| `--metrics-bind-network` | `tcp` | network family for the metrics listener | trivial | `lib/metrics/metrics.go:82-90`; our metrics listener is TCP only |
| `--socket-mode` | `0770` | permissions for unix sockets | trivial | `internal/setuplistener.go:41` |
| `--slog-level` | `INFO` | log level (`DEBUG`, `INFO`, `WARN`, `ERROR`) | trivial | we have `-v` only, no levels |
| `--target-disable-keepalive` | `false` | no connection reuse to the backend | trivial | we are already always-closing (`Connection: close`, `betterAnusbis.c:1370`) |
| `--healthcheck` | `false` | GET `/healthz` and exit 0/1 | trivial | `main.go:110-122`, `:251-257`; the endpoint now exists, the flag does not |
| `--og-passthrough` | `false` | copy `og:` tags from the protected page onto the challenge page | moderate | `main.go:79-81`, `lib/http.go:329-336` |
| `--og-expiry-time` | `24h` | OG tag cache TTL | trivial | only with OG enabled |
| `--og-cache-consider-host` | `false` | include the Host in the OG cache key | trivial | `main.go:81` |
| `--extract-resources` | `""` | write embedded static files to a directory | n/a | we embed nothing; not applicable |
| `--webmaster-email` | `""` | contact shown on the reject page for appeals | trivial | `lib/http.go:448` |
| `--public-url` | `""` | external URL for forwardAuth 307 redirects | moderate | subrequest mode, `lib/http.go:288-301`, `:398-428` |
| `--thoth-insecure` | `false` | deprecated, Thoth removed | n/a | accept and warn, as upstream does (`main.go:304-306`) |
| `--thoth-url` | `""` | deprecated, ignored | n/a | same |
| `--thoth-token` | `""` | deprecated, ignored | n/a | same |
| `--preserve-referer-query-param` | `false` | adds `utm_source`/`utm_medium` from the original Referer | trivial | `lib/anubis.go:812-853` |

Flags with no upstream counterpart, kept as extras: `--algorithm`, `--no-honeypot`, `--honeypot-log`, `--stateless`,
`--web`, `--tls-cert`, `--tls-key`, `--challenge-status`, `--deny-status`, `--policy`.

### Environment variables upstream reads

`flagenv.Parse()` runs before `flag.Parse()` (`cmd/anubis/main.go:236-237`), so every flag above is also an environment
variable named by uppercasing the flag and turning `-` (and `.`) into `_`; a flag given on the command line wins over the
environment (`flagenv@v0.0.0-20160425205200/flagenv.go:44-50`). `godotenv` also autoloads a `.env` file (`main.go:39`).
The 49 names, therefore:

```
BASE_PREFIX BIND BIND_NETWORK DIFFICULTY COOKIE_DOMAIN COOKIE_DYNAMIC_DOMAIN COOKIE_EXPIRATION_TIME
COOKIE_PREFIX COOKIE_PARTITIONED DYNAMIC_COOKIE_SUFFIX DIFFICULTY_IN_JWT USE_SIMPLIFIED_EXPLANATION
FORCED_LANGUAGE HS512_SECRET COOKIE_SECURE COOKIE_HTTP_ONLY COOKIE_SAME_SITE ED25519_PRIVATE_KEY_HEX
ED25519_PRIVATE_KEY_HEX_FILE METRICS_BIND METRICS_BIND_NETWORK SOCKET_MODE SERVE_ROBOTS_TXT POLICY_FNAME
REDIRECT_DOMAINS SLOG_LEVEL STRIP_BASE_PREFIX TARGET TARGET_SNI TARGET_HOST TARGET_INSECURE_SKIP_VERIFY
TARGET_DISABLE_KEEPALIVE HEALTHCHECK USE_REMOTE_ADDRESS DEBUG_BENCHMARK_JS OG_PASSTHROUGH OG_EXPIRY_TIME
OG_CACHE_CONSIDER_HOST EXTRACT_RESOURCES WEBMASTER_EMAIL VERSION PUBLIC_URL XFF_STRIP_PRIVATE
CUSTOM_REAL_IP_HEADER THOTH_INSECURE THOTH_URL THOTH_TOKEN JWT_RESTRICTION_HEADER PRESERVE_REFERER_QUERY_PARAM
```

One more, indirect: the geoip auto update block reads the variable *named by* `license_key_env`
(`lib/config/geoip_databases.go:173`, `:217`), so the variable name is operator-chosen rather than fixed.

---

## 3. Missing behaviour with no flag

Rows for XFF flattening, `custom-real-ip-header`, `redirect-domains`, `base-prefix`, `status_codes`,
`serve-robots-txt`, `/metrics` + `/healthz` and the JWT restriction claim are in 1.1 because they are ported now,
not missing.

| feature | upstream file:line | semantics | port cost | why a self-hoster would care |
|---|---|---|---|---|
| Policy file format (YAML/JSON) | `lib/config/config.go:308-321`, decoded at `:387-406` | one document with `bots[]` plus `thresholds`, `status_codes`, `store`, `dnsbl`, `dns_ttl`, `logging`, `metrics`, `honeypot`, `geoip`, `impressum`, `openGraph` | big | every existing deployment has one; without it a swap means rewriting the rules by hand |
| Rule condition fields | `lib/config/config.go:58-60` | `user_agent_regex`, `path_regex`, and a `headers_regex` map; all present conditions must match | moderate | this is how real configs say "this bot, those paths" |
| `expression` (CEL) | `lib/config/config.go:61`, `lib/policy/celchecker.go`, `lib/policy/expressions/environment.go:24-40` | CEL over `remoteAddress`, `headers`, `path`, `method`, `load_1m/5m/15m`, plus `reverseDNS`, `lookupHost`, `verifyFCrDNS` | not worth it | rare in small configs, but when present it is a hard blocker; a C CEL interpreter is a project of its own |
| `import:` statements | `lib/config/config.go:264-283`, `lib/config/import.go:26-45` | pull a YAML snippet from a path or from the embedded `(data)/` tree, glob supported | big | upstream's own default policy is built out of 8 imports (`data/botPolicies.yaml:14-52`); sharing fragments depends on it |
| `WEIGH` action | `lib/config/config.go:42`, `:192-194`, `lib/anubis.go:894-898` | adds `weight.adjust` to a running weight; first terminal action wins | moderate | the default policy expresses suspicion as weight, not as deny |
| Thresholds | `lib/config/threshold.go:19-32`, `lib/anubis.go:903-930` | CEL expression over `weight` picks the final action and challenge; default rule is `weight > 0` -> CHALLENGE `fast` | moderate for a numeric subset | without it `WEIGH` does nothing; the two are one feature |
| Per-rule challenge algorithm/difficulty | `lib/config/config.go:212-217` | `challenge: {algorithm, difficulty, report_as, extensions}` per rule and per threshold | trivial | the same site wants `fast` for pages and `argon2id` for APIs; we only have one global algorithm |
| `remote_addresses` | `lib/config/config.go:71`, `lib/policy/checker.go:22-65` | CIDR list on `X-Real-IP`, IPv4 and IPv6 via a prefix table | trivial | the classic "allow the office / VPN" rule; our IPv6 half is a stub, see the IPv6 row in section 5 |
| `remote_addresses_url` | `lib/config/config.go:72`, `lib/policy/remote_addresses_url.go:44-90` | fetch a JSON prefix list over HTTP, refresh every 24 h, 5 retries | big | cloud range feeds and blocklists that change weekly |
| GeoIP countries | `lib/config/geoip.go:26-36`, `lib/geoip/checker.go:59-95` | MaxMind country DB, `country_field` can be `country` or `registered_country` | big | blocking by jurisdiction; needs an mmdb reader |
| ASN matching | `lib/config/asn.go:14-30`, `lib/geoip/checker.go:14-50` | AS number from a MaxMind ASN DB | big | the only reliable way to block one cloud provider without a UA list |
| GeoIP databases and auto update | `lib/config/geoip_databases.go:58-120`, `lib/geoip/update.go` | paths for `GeoLite2-ASN`/`-Country`, licence key via env, 24 h refresh, 1 h minimum | big, not worth it | keeps the two rows above current; skip unless needed |
| DNSBL | `lib/anubis.go:490-521`, `internal/dnsbl/dnsbl.go:88-101` | reverse-IP lookup at `dnsbl.dronebl.org`, 24 h cache in the store, DENY on a non-zero answer | moderate | a free reputation feed with no data file to ship; needs a DNS client with NXDOMAIN detection |
| DNS TTL cache | `lib/config/config.go:484-505` | forward/reverse DNS cache TTLs, default 300 s | big | only matters for the CEL DNS functions |
| Store backends | `lib/store/all/all.go:6-10`, `lib/config/store.go:15-27` | `memory`, `bbolt`, `valkey`, `s3api` behind one interface | big | shared challenge/honeypot state across replicas and restarts; we are memory only |
| Metrics policy block | `lib/config/metrics.go:33-41`, `lib/metrics/metrics.go:34-40` | TLS with client CA, basic auth, `pprof` when debug, unix socket mode | big | the endpoint now exists (1.1) but this envelope does not, so the metrics port is plain and unauthenticated |
| OpenGraph passthrough | `cmd/anubis/main.go:79-81`, `lib/http.go:329-336`, `internal/ogtags/fetch.go:23-70` | fetch the protected page from the target, parse `og:` meta, cache 24 h | moderate | Slack/HN/Discord previews of protected pages look blank otherwise |
| Impressum | `lib/config/impressum.go:12-35`, `lib/config.go:205-211` | `footer` string on every page plus `GET /api/imprint` | trivial | German sites are legally required to have one |
| Localization | `lib/localization/localization.go:39-100`, 30 locale files under `lib/localization/locales/` | `go-i18n` bundle keyed on `Accept-Language` | big, not worth it | non-English visitors see English today |
| `preact` challenge | `lib/challenge/preact/preact.go:40-88` | proof-of-JavaScript page, no wasm needed | moderate | the cheap option for clients that cannot run wasm |
| `soteria` | documented at `docs/docs/admin/configuration/challenges/soteria.mdx:1`, no implementation registered | SIMD wasm challenge | n/a | nothing to port from this tree; only 7 methods are registered in total |
| Challenge extensions | `lib/challenge/extension/extension.go:17-65`, `lib/challenge/extension/css-load/cssload.go:32-60` | per-challenge `<head>` additions and a validation hook before minting a JWT | moderate to big | niche anti-automation add-on; not on any drop-in path |
| Honeypot text, IP log, store-backed weight | `internal/honeypot/naive/naive.go:37-92`, `:180`, `lib/config/honeypot.go:10-20` | spintax maze text, `ip_log_file`, network weight shared through the store | trivial (text), moderate (store) | generated prose reads like a real page; store-backed weight survives restarts |
| WebSocket proxying | `cmd/anubis/main.go:177` (Go `httputil.ReverseProxy`, which forwards 101 upgrades) | tunnel the upgraded connection both ways | moderate | Grafana, Jupyter, MinIO consoles break behind a buffering, connection-closing proxy |
| Backend keep-alive | `cmd/anubis/main.go:148-150` | reuse the backend connection | trivial | latency and file descriptor churn under load |
| Signing key persistence | `cmd/anubis/main.go:57`, `:61-62`, `:376-404` | HS512 secret, ed25519 hex, or a file with the hex | trivial | a restart currently re-challenges every user and replicas cannot share cookies (`betterAnusbis.c:3594` generates a random key) |
| `difficulty` claim | `lib/anubis.go:775-777` | put the solved difficulty in the JWT | trivial | diagnostics when users report a hard challenge |
| Cookie dynamic domain | `lib/http.go:148-152` | `Domain=` the eTLD+1 of the request host | moderate | one gate over several subdomains |
| Dynamic cookie suffix | `lib/http.go:118-127` | hash of cookie settings appended to the cookie name | trivial | a cookie minted under other settings will not be read |
| Forced language | `cmd/anubis/main.go:56`, `anubis.go:69`, `main.go:423` | ignore `Accept-Language` | big, not worth it | depends on localization |
| `public-url` / forwardAuth | `cmd/anubis/main.go:85`, `lib/http.go:288-301`, `:398-428` | subrequest mode answers 307 to the public URL instead of rendering a page | moderate | Traefik forwardAuth and nginx `auth_request` deployments |
| Referer query parameters | `lib/anubis.go:812-853` | add `utm_source`/`utm_medium` to the post-challenge URL | trivial | analytics survives the challenge bounce |
| JA4H fingerprint | `internal/ja4h.go:13-17`, `cmd/anubis/main.go:477-479` | adds `X-Http-Fingerprint-Ja4h` for rules to match | big, not worth it | needs the JA4H algorithm; TLS fingerprint rules are a power feature |
| Log sink and rotation | `lib/config/logging.go:17-33`, `:60-90` | stdio or rotated JSON lines file, level override, ASN logging | moderate | production log handling |
| Unix socket listener | `internal/setuplistener.go:41-90`, `cmd/anubis/main.go:46`, `:65` | `--bind-network unix` with socket mode | trivial | sidecars and systemd socket activation |
| Healthcheck mode | `cmd/anubis/main.go:110-122`, `:251-257` | GET `/healthz`, exit 0 or 1 | trivial | container HEALTHCHECK without curl in the image |
| `extract-resources` | `cmd/anubis/main.go:259-268` | dump embedded assets to a directory | n/a | we embed nothing |
| gzip challenge page, no-gzip check | `lib/http.go:391-395`, `:305-309` | gzip the page; refuse 1 in 64 clients that do not send `Accept-Encoding: gzip` | trivial / odd | page weight, plus that check is itself bot filtering |
| `make-challenge` (devel only) | `lib/config.go:239-242` | POST endpoint used by tests | trivial | test harnesses only |
| Verification cookie requirement | `lib/anubis.go:639-648`, `:167-180` | refuse `pass-challenge` without the verification cookie, retry once | moderate | blocks solvers that ignore cookies; also caused real browser false positives, hence the retry |
| Challenge to rule binding | `lib/anubis.go:410-415`, `:682-684` | re-evaluate the rule at pass time and compare `policyRuleHash`, method, difficulty, extensions | moderate | tightening the policy refuses outstanding cookies, as intended |
| Page metadata scripts | `web/index.templ:61-64` | `anubis_version`, `anubis_base_prefix`, `anubis_public_url` JSON | trivial | client tooling that reads them gets undefined today |
| Webmaster email on errors | `lib/http.go:443-455` | appeal contact on the reject page | trivial | users who hit a false positive have a way to ask |
| Offline policy generators | `utils/cmd/iplist2rule/main.go`, `cmd/robots2policy/main.go:22-40` | turn an IP blocklist or a robots.txt into a policy YAML | moderate | not runtime, but this is how operators bootstrap IP or robots rules; a drop-in leaves them emitting YAML we cannot read until the policy reader lands |
| Default bot policy data | `data/botPolicies.yaml:14-52` | about 8 imported rule groups: pathological bots, aggressive AI crawlers, good crawlers, well-known paths | big | this is what makes upstream useful out of the box; ours starts with no rules at all |

---

## 4. Top 10 by value per effort for drop-in replacement

1. **Persist the signing key (`--hs512-secret`, or a hex file).** One flag and a file read. Right now the secret is
   generated at start (`betterAnusbis.c:3594`), so every restart re-challenges every visitor and two replicas cannot
   share cookies. Upstream warns about exactly this when a persistent store has no key (`cmd/anubis/main.go:337-345`).
   Cost trivial, value immediate and visible.

2. **`--dynamic-cookie-suffix` plus `--cookie-dynamic-domain`.** Both are small: an 8-hex-char suffix derived from the
   cookie settings (`lib/http.go:118-127`), and a `Domain=` attribute derived from the request host
   (`lib/http.go:148-152`). Without the suffix, a cookie minted by a differently configured instance on the same host is
   silently accepted; without the domain, every subdomain needs its own solve. The eTLD+1 half needs a public suffix
   list, so it is the one part that could be deferred, but a host-only fallback gets most of the value.

3. **The YAML/JSON `bots[]` reader.** Big, and the only item here that is a project rather than a patch, but it is the
   single hard gate on "drop-in": an existing deployment has a `botPolicies.yaml` (`lib/config/config.go:57-73`,
   `:308-321`), and without a reader the operator must retranslate every rule into our flat line format. Even a subset
   (name/action/conditions/per-rule challenge) covers most real files; `import:` can come later.

4. **POSIX regex for the three condition fields.** `regcomp`/`regexec` is in libc, so this is a moderate patch, not a new
   dependency, and it makes `user_agent_regex`, `path_regex` and `headers_regex` (`lib/config/config.go:58-60`) usable.
   PCRE-only syntax would still fail, but the common `(?i)` and alternation cases are what most policies use, and the
   literal matchers we have today are not a substitute for a config that already ships regexes.

5. **`WEIGH` plus numeric thresholds.** Moderate: a running integer per request, plus a comparison rule and a table of
   weight ranges (`lib/anubis.go:894-930`, `lib/config/threshold.go:19-32`). This is how upstream's default policy says
   "this looks like a scraper, make it harder" without denying, and it is what the honeypot's weight 30 plugs into
   (`lib/config.go:227-231`). Implementing only the arithmetic subset of CEL (`weight > 0`, `weight >= 10`, and friends)
   is enough for the shipped policy.

6. **Per-rule challenge algorithm.** Trivial: our verifier already takes an algorithm argument
   (`betterAnusbis.c:385`), and the challenge page already prints `cfg.algorithm`; a rule-level `algorithm` field and a
   per-request value is a small refactor. Existing configs routinely set `fast` for pages and `argon2id` for APIs, and a
   drop-in that forces one algorithm for the whole site is a visible regression.

7. **Make IPv6 CIDR rules work, or refuse them at load.** Trivial by comparison with the rest: `rule_matches` already
   computes a network key (`betterAnusbis.c:2735-2748`), but every `net` rule is parsed with `inet_pton(AF_INET, ...)`
   (`:2799-2816`), so an IPv6 CIDR line is dropped without a word, and the IPv6 branch of `rule_matches` (`:2742-2745`)
   can never be reached. That is a fail-open: `allow net 2001:db8::/32` silently matches nothing and the operator
   believes it does. Fixing the comparison or rejecting the line with an error are both small; leaving it is a support
   incident waiting to happen.

8. **Backend keep-alive and WebSocket tunnel.** Moderate. `proxy_request` reads the entire reply before writing anything
   (`betterAnusbis.c:1375-1396`) and always sends `Connection: close` (`:1370`), which is fine for HTML and fatal for
   anything that upgrades or streams. Dropping the forced close and reading/writing incrementally is the smaller half;
   detecting a 101 and splicing the two sockets is the other. Self-hosters protect Grafana, Jupyter, MinIO consoles and
   Git over HTTP, and all of those need it.

9. **DNSBL.** Moderate: reverse the client IP, query it under `dnsbl.dronebl.org`, cache the answer for 24 h, deny on a
   non-zero class (`lib/anubis.go:490-521`, `internal/dnsbl/dnsbl.go:88-101`). The DNS client is the work; a first cut
   can use the resolver with an explicit NXDOMAIN path. It is the cheapest real reputation signal available to a gate
   that ships no data files, and it does not need GeoIP.

10. **OpenGraph passthrough, webmaster email, page metadata scripts.** Moderate as a group, trivial individually. The OG
    tags need fetching the target page and parsing `og:` meta (`internal/ogtags/fetch.go:23-70`); the email is one string
    on the reject page (`lib/http.go:448`); the three JSON metadata scripts are constants (`web/index.templ:61-64`).
    Together they are the difference between a challenge page that looks like a wall and one that behaves like upstream
    when a link is shared or a user is wrongly blocked.

Deliberately not recommended: GeoIP and ASN (big cost, an mmdb reader is a subsystem), store backends (big, only pays off
with replicas), localization and soteria (no implementation in this upstream tree), JA4H (big, power-user feature).

---

## 5. Deliberate divergences

| divergence | what we do | upstream | compatibility problem |
|---|---|---|---|
| Literal policy matching, flat file | `contains`/`prefix`/`is` on UA, path, header, IPv4 CIDR, one rule per line (`betterAnusbis.c:2735-2751`, `:2765-2833`) | YAML/JSON with regex and CEL (`lib/config/config.go:57-73`) | yes for config reuse: a `policy.yaml` cannot be loaded at all. No for new users. Does not silently misread an upstream file, which is the important half |
| DENY status | default 200, `--deny-status 403` available (`betterAnusbis.c:3131`) | default 200 (`lib/config/config.go:388-392`), rendered as an HTML error page | none now. The earlier 403 default was the honest answer, but it told a scraper it had been caught; 200 matches upstream and is the safer default for parity |
| Challenge ids | stateful by default, id is `<hex>.<unix time>` (`betterAnusbis.c:3152`); `--stateless` drops the ledger (`ch_issue`, `:444`) | UUIDv7 id, challenge stored for 30 min, `spent` flag (`lib/anubis.go:195-230`, `:676-677`, `:746`) | none for clients: the id is opaque and both formats are accepted by a client that echoes it back. `--stateless` re-opens replay inside the cookie window, which upstream never does, so do not enable it on a hostile site |
| Honeypot punishment | difficulty +8 bits once a network passes 25 hits (`betterAnusbis.c:3139-3145`) | a `WEIGH` rule adding 30 to the weight, then thresholds decide (`lib/config.go:217-236`, `lib/anubis.go:894-905`) | none in the protocol; a behavioural difference. 8 bits is roughly the same wall as weight 30 under the default threshold, but it applies even when the operator's thresholds would not. It is not tunable per rule |
| JWT signing | HS256, random 32-byte secret per process (`betterAnusbis.c:274-306`, `:3594`) | Ed25519 by default, or HS512 with a secret (`cmd/anubis/main.go:57`, `:397-404`, `lib/http.go:535-545`) | yes across a mixed fleet: an Anubis cookie is not accepted here and vice versa. A whole-deployment swap costs every user one extra solve, then nothing |
| JWT restriction claim | claim name `restrict`, value is the computed client address, in cleartext; the flag is an on/off switch, its name is not read (`betterAnusbis.c:283-284`, `:346-353`) | claim name `restriction`, value is `SHA256sum` of the named header, default `X-Real-IP` (`lib/anubis.go:417-420`, `:768-778`) | none across implementations, since the tokens are not interchangeable anyway. Within ours, the flag name promises header-value binding that it does not implement: pointing it at `CF-Connecting-IP` still binds the computed address, which is that header only because `--custom-real-ip-header` maps it. Document or fix the name |
| Metrics default | off unless `--metrics-bind` (`betterAnusbis.c:141`, `:3650`) | on at `:9090` (`cmd/anubis/main.go:63`) | none, and ours is safer: an unauthenticated metrics port on a public address leaks traffic volume. A deployment that had `METRICS_BIND` set keeps working; one that relied on the default loses its scrape until the flag is added |
| `policyRule` claim | hardcoded `"rule-0"` (`betterAnusbis.c:286`) | hash of the matched rule (`lib/anubis.go:410-415`) | none today, because we do not compare it. Consequence: editing the policy does not invalidate existing cookies, which upstream does on purpose |
| Cookie defaults | HttpOnly on, SameSite `Lax`, Secure only when TLS, Partitioned only with Secure (`betterAnusbis.c:121-127`) | HttpOnly off, SameSite `None` (downgraded to `Lax` without Secure), Secure on, Partitioned on (`cmd/anubis/main.go:52-60`, `lib/http.go:136-173`) | yes if the gate sits in a cross-site iframe: `SameSite=None` must be asked for explicitly. Otherwise ours is the stricter, safer set |
| Redirect allow list | default is this host only, `--redirect-domains` to widen (`safe_redirect`, `betterAnusbis.c:1050-1086`) | default allows any domain; a warning is logged (`cmd/anubis/main.go:68`, `:416-418`) | yes if an operator relies on redirecting to a second domain; they must pass the flag. Ours is safer: an open post-challenge redirect is a phishing gadget |
| Client address trust | XFF is believed only from a loopback/private peer; the custom header is believed from anyone (`betterAnusbis.c:954-1000`) | `X-Real-IP` is authoritative; XFF fills it in if absent (`internal/headers.go:98-113`), and a missing value is a 500 (`lib/anubis.go:867-874`) | mostly none, and ours works when directly exposed where upstream returns 500. But a proxy on a public address must be named with `--custom-real-ip-header`, or the peer address is used instead of the client's |
| IPv6 CIDR rules | every `net` rule is parsed as IPv4 only, so an IPv6 CIDR line is skipped by `policy_load` (`betterAnusbis.c:2799-2816`), and `rule_matches` would return 0 for it anyway (`:2742-2745`), although the policy comment promises IPv4/IPv6 (`:2708-2712`) and the struct carries `net_v6`/`mask_v6` (`:2725`) | IPv6 supported through `netip` and `bart` (`lib/policy/checker.go:22-65`) | yes, and it fails open: `allow net 2001:db8::/32` silently matches nothing. Either implement it or reject the line loudly; documenting it is the weakest option |
| Defaults | algorithm `sha256`, listen `:8080`, target required (`betterAnusbis.c:107-112`, `:3272-3348`) | algorithm `fast` (`lib/config/config.go:55`), listen `:8923`, target `http://localhost:3923` (`cmd/anubis/main.go:45`, `:71`) | visible, not protocol: the challenge JSON method differs, and a copied systemd unit will listen on the wrong port. Worth aligning the port or documenting it in the upgrade notes |
| Challenge JSON details | `issuedAt` is a numeric unix second in a string (`betterAnusbis.c:2629`), and the `anubis_version`/`anubis_base_prefix`/`anubis_public_url` scripts are absent | `issuedAt` marshals as RFC3339, all four scripts present (`lib/challenge/challenge.go:6-16`, `web/index.templ:61-65`) | unverified whether any shipped client parses `issuedAt`; our solver does not. A strict consumer would notice. Cheap to fix, so fix it before anyone depends on the old shape |
| No gzip, no verification-cookie gate, `elapsedTime` ignored | plain pages; test cookie set but not required; `elapsedTime` read and dropped (`betterAnusbis.c:2954`) | gzip and a 1-in-64 no-gzip deny (`lib/http.go:305-309`, `:391-395`); test cookie required with one retry (`lib/anubis.go:639-648`); `elapsedTime` required (`proofofwork.go:55-72`) | none for correctness, and being more permissive means fewer false positives. It also means one of upstream's cheap bot filters is absent |
| Honeypot state | 4096-bucket in-memory table plus an optional log file (`betterAnusbis.c:525-580`) | store-backed, shared across replicas, optional `ip_log_file` (`internal/honeypot/naive/naive.go:150-180`) | none functionally; a restart forgets which networks were caught, and two replicas each count separately, so the 25-hit flag is per process |

---

## Appendix: what could not be verified

- The upstream git revision. Only mtimes and file contents were read.
- Whether any real Anubis client parses `issuedAt`, or relies on the three missing page metadata scripts.
- Whether upstream WebSocket upgrades are covered by a test; `httputil.ReverseProxy` handles 101, and no websocket test was
  found by grep, so our "upstream proxies websockets" row rests on the stdlib, not on an upstream test.
- The effective rule set of `data/botPolicies.yaml` after imports are expanded; the import list was read, the expansion was not.
- Runtime behaviour of anything here: nothing was built or executed for this audit. All our-side claims come from source.
- Whether the metric label difference (`asn`, `asn_description`, `anubis_requests_by_asn_total`, `anubis_dronebl_hits`)
  breaks any specific dashboard; the names match but the label sets do not.
- Whether `soteria` exists in another upstream branch; it is documented here but no implementation is registered.

---

## Addendum: what changed right after this audit

The audit is against `betterAnusbis.c` md5 `768d0c966353ebc54afd13405bbda9e8` (3705 lines, 10:09:04). Four items
were fixed or added immediately afterwards, so the rows about them above are stale in our favour. Final blob:
md5 `925898fa36ea34855d0d1d1e7a6b5b7b`, 3755 lines.

| item | was | now |
|---|---|---|
| item 7, IPv6 CIDR | every `net` rule parsed with `inet_pton(AF_INET, ...)`, IPv6 lines dropped silently, the IPv6 branch of `rule_matches` unreachable | `rule` carries a `v6` flag; `policy_load` parses both families and logs a line it cannot parse instead of dropping it; `rule_matches` compares all 16 bytes under the prefix mask, including `::ffff:a.b.c.d` against a v4 client. Three checks in `test_parity.py` |
| `--jwt-restriction-header` | name promised header-value binding, implementation used the computed address | binds to that header's value when it is present (sanitised to `[A-Za-z0-9:.\[\]_-]` before it goes in the JSON), falls back to the computed address when it is absent. Three checks in `test_parity.py` |
| `--metrics-bind`, SIGHUP | recorded in 1.1 | unchanged, now covered: seven checks for the metrics listener, and `print_settings` reads the counters |
| the option parser | hand-written if chain, `--flag value` only | table driven, `--flag=value` too, `--no-flag` / `--flag=false` for every boolean, and the table is the only place a flag is declared |

Still open from the audit: an arbitrary CEL engine and the store backends (bbolt, valkey, S3).

Closed since then:

| audit item | what landed |
|---|---|
| the request preconditions in section 1.2 | a path with a `.` or `..` segment is refused with 400 before the body is read, and repeated slashes are collapsed into `request.ppath` for rule matching only, the path upstream still receives is untouched. Four checks |
| `DEBUG_BENCHMARK`, the fifth action | accepted in an Anubis policy and treated as "always challenge" (`lib/config/config.go:43`), with its metrics going to the CHALLENGE slot. One check |
| the environment-variable surface | every flag in the table is also an environment variable using upstream's `flagenv` mapping, and a flag on the command line wins. Two checks |
| `--healthcheck` | GETs `/healthz` on `--metrics-bind` and exits 0 or 1, which is what a supervisor needs. Two checks |
| GeoIP and ASN | a MaxMind DB reader in C: 24/28/32-bit trees, section-relative pointers, and just the record types Anubis reads (`country.iso_code` with `registered_country` as fallback, `autonomous_system_number` and `..._organization`). Validated against MaxMind's own test databases, checked in under `tools/geoip-testdata`; `--geoip-lookup IP` reports what it sees. Three checks |
| 9, DNSBL | `--dnsbl` (or `dnsbl: true` in a policy) reverses the client address, asks `<reversed>.dnsbl.dronebl.org`, reads the class out of the last octet of the first A record and caches the verdict for a day. A hit denies with the class; a resolver failure answers 503 rather than guessing. One check |
| `verifyFCrDNS` | implemented as an expression leaf: PTR via `getnameinfo`, then a forward lookup whose addresses must include the address asked about, then the pattern is applied to the name. The shipped Yandex rule loads without a warning now, and the whole shipped policy has zero unsupported rules. One check |
| localization | six locales hand-written for this page, chosen by Accept-Language order or `--forced-language`, English as fallback. Four checks |
| impressum | `--impressum-footer` on every page, `--impressum-page-title`/`-body` served at `<API_PREFIX>imprint`, the webmaster address on the deny page. Two checks |
| preact | `--algorithm preact`: a wait of difficulty x 80 ms, `result` = hex SHA-256 of the hex random data, plus the verification cookie. The ledger now records the issue time in milliseconds so the wait is not rounded to a second. Three checks |
| forwardAuth | an empty `--target` is auth-check mode: 200 for ALLOW or a valid cookie, the deny status for DENY, 401 `Authorization required`, or a 307 to `--public-url` with the encoded original URL; `X-Original-Uri` becomes the policy's path. Seven checks |
| OpenGraph passthrough | `--og-passthrough` fetches the protected page once, keeps its `og:` and description tags for `--og-expiry-time`, and injects them into the challenge page's head; `--og-override` replaces them with no fetch at all, which is what upstream's `override` means. Three checks |
| the css-load extension | `--challenge-extension css-load` puts a stylesheet link on the challenge page and refuses pass-challenge until that link has been fetched, keyed on the challenge ledger. `headless` has no implementation in this tree, and asking for it says so. Five checks |
| 8, the keep-alive half | the gate frames each response (Content-Length, chunked with trailers, or no body) and reuses the origin connection from a pool of eight, idle for a minute, with one retry when a pooled connection died quietly (`relay_response` returns -1 only before a byte reaches the client, which is what makes the retry safe). `--target-disable-keepalive` turns it off. Three checks, including a backend that counts its own accept()s |
| 8, the WebSocket half | an `Upgrade` request is forwarded with its `Connection` and `Upgrade` headers intact, the `101` and its headers are relayed, and the two sockets are then spliced with `poll()` until either closes or five minutes pass in silence. An upgrade needs an ALLOW rule or a valid cookie, because a browser cannot solve a challenge over a socket it has not opened yet. Five checks, including a frame echoed through the tunnel |

Closed since the audit:

| audit item | what landed |
|---|---|
| 1, the signing key | `--secret-file PATH` loads it or creates it 0600 on first run; `--secret-hex HEX` takes it inline; a file with the wrong contents is a hard error, never overwritten. Five checks |
| 3, POSIX regex | `matches <ere>` in the policy file, `regcomp(REG_EXTENDED)` at load, `regerror` reported and the rule skipped rather than the gate refusing to start. Four checks |
| 6, per-rule algorithm | `... algorithm argon2id` on a rule, stored in the challenge ledger next to the difficulty, rendered in the page, recorded in the JWT `method` claim and used for verification. Ignored with a warning under `--stateless`, where the id has no room for it. Three checks |
| 2, the `bots[]` reader | `--policy` now detects and reads Anubis's own schema: `bots[]`, `thresholds[]`, `import:` with the `(data)/` macro, `user_agent_regex`, `path_regex`, `headers_regex`, `remote_addresses` as IPv4 and IPv6 CIDR, `expression` in its shipped forms, `challenge{algorithm,difficulty}`, `weight.adjust`, `status_codes`, `honeypot.enabled`. Anubis's default-allow semantics come with it. The shipped policy loads 41 rules and 5 thresholds with 2359 CIDRs, and nine checks in `test_parity.py` assert the decision it produces for nine probe requests |
| 5, WEIGH and thresholds | weight accumulates across `WEIGH` rules in file order, then the thresholds are consulted in order, and a `CHALLENGE` rule still short-circuits them. The arithmetic subset of CEL is understood (`weight <= 0`, `all:`, `any:`), which is all the shipped thresholds use |
