# PARITY DNS/OG/GEOIP SPEC

Scope: upstream Go tree at `/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis` (read only), plus the vendored
MaxMind reader at `/home/miku6/go/pkg/mod/github.com/oschwald/maxminddb-golang/v2@v2.7.0` (cited as
`maxminddb-golang@v2.7.0/...`). Target: what a hand-rolled C implementation in `betterAnusbis.c` must send, parse and
store to match these five upstream features.

Method: source reading only. No build, no execution, no network. Every claim carries `file:line`; anything that could
not be checked against source says **unverified**. Upstream git revision not read (**unverified**).

---

## 1. DNSBL (`internal/dnsbl/`)

### 1.1 Query name

Upstream builds the query name as `Reverse(ip) + ".dnsbl.dronebl.org"` (`internal/dnsbl/dnsbl.go:74`).

- IPv4 `a.b.c.d` becomes `d.c.b.a.dnsbl.dronebl.org` (`dnsbl.go:41-50`; the swap of first/last and middle octets is a
  full octet reversal).
- IPv6 is 32 nibbles, each byte emitted low nibble first then high, bytes walked from last to first, joined with dots,
  and the same zone appended (`dnsbl.go:52-66`, `:74`). For `2001:db8::1` that is
  `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.dnsbl.dronebl.org`, which is standard
  nibble-reverse notation. Whether DroneBL actually publishes results there is **unverified**; the code emits that name
  regardless.
- No EDNS, no TSIG, no DNSSEC validation is configured anywhere; the lookup is `net.LookupIP` (`dnsbl.go:76`), i.e. the
  system resolver.

### 1.2 Record type and answer interpretation

`net.LookupIP` resolves A and AAAA for the name (`dnsbl.go:76`) but only IPv4 answers are consumed: the response class
is the **last octet of the first A record** in the answer set (`dnsbl.go:91-97`). The full mapping is
`DroneBLResponse(v4[3])`, and the class constants are (`dnsbl.go:14-31`, names from
`internal/dnsbl/droneblresponse_string.go:12-28`):

| class | constant | meaning |
|---:|---|---|
| 0 | `AllGood` | not listed |
| 3 | `IRCDrone` | IRC drone |
| 5 | `Bottler` | bottler |
| 6 | `UnknownSpambotOrDrone` | spam bot or drone |
| 7 | `DDOSDrone` | DDoS drone |
| 8 | `SOCKSProxy` | SOCKS proxy |
| 9 | `HTTPProxy` | HTTP proxy |
| 10 | `ProxyChain` | proxy chain |
| 11 | `OpenProxy` | open proxy |
| 12 | `OpenDNSResolver` | open DNS resolver |
| 13 | `BruteForceAttackers` | brute forcer |
| 14 | `OpenWingateProxy` | Wingate proxy |
| 15 | `CompromisedRouter` | compromised router |
| 16 | `AutoRootingWorms` | auto-rooting worm |
| 17 | `AutoDetectedBotIP` | auto-detected bot |
| 255 | `Unknown` | lookup error, see below |

Control flow, exactly (`dnsbl.go:76-88`):
- `net.LookupIP` error whose `*net.DNSError.IsNotFound` is true -> `AllGood`, no error. A no-such-name answer is a clean
  verdict, not an error.
- Any other lookup error (timeout, SERVFAIL, refusal) -> `Unknown` **and** an error is returned.
- Lookup succeeds -> `responseFromIPs`.
- `responseFromIPs` (`dnsbl.go:91-101`): if the answer list is non-empty but contains no IPv4 answer, the verdict is
  `UnknownSpambotOrDrone` (6), i.e. a hit. Only an empty answer list returns 6 as a fallback too; both branches produce
  6, so "name exists, no A record" is a hit upstream, not a clean result.

Note the asymmetry a C port must decide on: upstream treats NXDOMAIN and "no records" as clean only when Go's DNS
resolver reports `IsNotFound`; a NOERROR response with ANCOUNT=0 is reported by Go as a not-found error (**unverified**
from this repo, Go stdlib behaviour).

### 1.3 Caching and TTL

The verdict, not the DNS record, is cached:

- Key: the client address string exactly as it appears in `X-Real-IP` (`lib/anubis.go:495`, `:497`).
- Store: `store.JSON[DroneBLResponse]` with prefix `dronebl:` (`lib/anubis.go:496`).
- TTL: 24 hours, set on every successful lookup (`lib/anubis.go:507`). DNS record TTL is ignored.
- Errors are **not** cached: a failed lookup is retried on the next request (`lib/anubis.go:501-506`), so an
  outage of the resolver translates to one query per request.
- A cache hit skips the lookup and the metric.

### 1.4 What happens on a hit

Order in the request path (`lib/anubis.go:337-359`): the policy check runs first, then the policy-result metric, then
`handleDNSBL`, then `checkRules`. So a DNSBL hit denies even when an `ALLOW` rule matched.

On a non-zero verdict (`lib/anubis.go:512-520`):

- `respondWithStatus` with the HTML error page and status `status_codes.DENY` (`lib/anubis.go:519`), which defaults to
  200 (`lib/config/config.go:388-392`) and is configurable (`lib/config/config.go:285-306`).
- Message: `"<dronebl_entry>: <class name>, <see_dronebl_lookup> https://dronebl.org/lookup?ip=<ip>"`, using locale keys
  `dronebl_entry` and `see_dronebl_lookup` (`lib/localization/locales/en.json:30-31`).
- Log line `"DNSBL hit"` with the class name (`lib/anubis.go:514`).
- Metric `anubis_dronebl_hits{status,asn,asn_description}` incremented on the lookup path only (`lib/anubis.go:82-85`,
  `:509-510`).
- On a lookup error: status 503 with the internal-error page and the request is stopped (`lib/anubis.go:501-505`). That
  is fail-closed, not fail-open.

The feature is enabled by the top-level `dnsbl: true` in the policy file (`lib/config/config.go:315`, plumbed at
`lib/policy/policy.go:295`), there is no per-rule DNSBL.

### 1.5 Minimal C client

One UDP query, one answer expected. Send:

```text
header (12 bytes): ID=any 16-bit, FLAGS=0x0100 (RD=1, QR=0, opcode=0, AA/TC/RD/RA=0 except RD),
                   QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
question:          QNAME = length-prefixed labels of "<reversed-ip>.dnsbl.dronebl.org", terminating 0
                   QTYPE=1 (A), QCLASS=1 (IN)
```

Then parse the reply:

1. Drop it unless the ID matches and QR=1.
2. RCODE=3 (NXDOMAIN) -> class 0. RCODE=0 with ANCOUNT=0 -> class 0 (subject to the `IsNotFound` caveat in 1.2).
   RCODE=2 (SERVFAIL), 5 (REFUSED) or a timeout -> upstream's equivalent is `Unknown` **with** an error, i.e. deny
   (503), not allow. Choose fail-open or fail-closed deliberately.
3. Walk the answer RRs. Skip names (they may be compression pointers, `0xC0` prefix), read TYPE, CLASS, TTL, RDLENGTH.
   For `TYPE=1, CLASS=1, RDLENGTH=4`, take the 4th RDATA byte as the class byte of the **first** such record.
4. If the name resolved but there is no A record, upstream's verdict is 6 (hit), see 1.2.
5. Cache the verdict 24 h keyed by the `X-Real-IP` string; do not cache errors.

Practical notes:
- The name is at most 4+21=25 bytes for IPv4 plus label overhead, so no EDNS and no TCP retry are needed unless the TC
  bit is set (a truncated reply should be treated as an error or retried over TCP; Go's exact behaviour here is
  **unverified**).
- Read the resolver from `/etc/resolv.conf`; upstream uses the system resolver (`dnsbl.go:76`), so no custom resolver
  config exists to match.
- The whole feature is IPv4-only in practice: AAAA answers are ignored by the class extraction.

---

## 2. verifyFCrDNS (as used by `data/crawlers/yandexbot.yaml`)

### 2.1 The policy line

`data/crawlers/yandexbot.yaml:1-6` is an `ALLOW` rule whose expression is an `all:` list, i.e. logical AND:

```yaml
- name: yandexbot
  action: ALLOW
  expression:
    all:
      - userAgent.matches("\\+http\\://yandex\\.com/bots")
      - verifyFCrDNS(remoteAddress, "^.*\\.yandex\\.(ru|com|net)$")
```

So a request is allowed only if the User-Agent matches the Yandex bot marker **and** the address passes FCrDNS with a
Yandex-suffix PTR. The same function is used by `data/clients/vk-preview.yaml:6` and
`data/clients/telegram-preview.yaml:6` with different patterns.

Two CEL overloads are registered (`lib/policy/expressions/environment.go:99-130`): one argument, and two (addr,
pattern). Both call `Dns.VerifyFCrDNS` (`internal/dns/dns.go:108-148`).

### 2.2 What it actually checks

Step by step (`internal/dns/dns.go:90-148`):

1. **Reverse lookup.** `net.LookupAddr(addr)` for PTR records (`dns.go:47`, `:112`), results cached under prefix
   `reverseDNS` with TTL `dns_ttl.reverse` (default 300 s, `lib/config/config.go:393-396`, `internal/dns/cache.go:19-27`,
   `:64-68`). Trailing dots are stripped (`dns.go:57-63`).
2. **No names.** If the reverse lookup returned zero names, the function returns `pattern == nil`
   (`dns.go:118-120`). The one-argument form therefore returns **true** when a host has no PTR at all. The two-argument
   form (the one this policy uses) returns false. This is a deliberate fail-open in the one-argument form and a port
   must not "fix" it silently if bit-for-bit parity is the goal.
3. **Pattern filter.** If a pattern is given, it is compiled as a Go regexp (RE2 syntax), matched against each PTR name,
   and the names that match are kept (`dns.go:122-140`). If none match, return false **without doing any forward
   lookup**. Note the pattern is matched with `MatchString`, i.e. unanchored unless the pattern anchors itself; the
   Yandex pattern anchors both ends.
4. **Forward confirmation.** For each surviving name, `LookupHost(name)` (A and AAAA) is resolved, cached under prefix
   `forwardDNS` with TTL `dns_ttl.forward` (default 300 s, `cache.go:19-27`, `:57-61`), and compared to the original
   address with `slices.Contains` on the **string** form (`dns.go:90-106`, `:140-146`). Any match returns true; all
   names exhausted returns false. Errors on a name are skipped (`dns.go:95-99`).
5. **Cost.** One PTR query and one or more A/AAAA queries per uncached pair, 5 min cached by default. The doc for the
   function warns it can be manipulated by stale records but is the recommended check
   (`docs/docs/admin/configuration/expressions.mdx:343-359`).

### 2.3 Can it be approximated without DNS?

No faithful approximation exists. The check is precisely "the PTR name for this IP matches the owner domain and that
name resolves back to this IP". Without DNS you have two choices:

- **Published CIDR ranges.** Yandex, VK and Telegram publish address lists; `remote_addresses` would allow the same
  traffic with a maintained list. This is a different trust model: it trusts the published ranges, not live DNS, and it
  goes stale between publications. It is the only practical no-DNS substitute.
- **User-Agent only.** Trivially spoofable; it is already the first half of the expression, so dropping the second half
  turns an ownership proof into a string match.

A C implementation needs a PTR query (QTYPE=12) plus name-compression decoding for the answer name, then A and AAAA
queries (QTYPE=1 and 28) for the surviving name(s), plus an IP comparison. A tiny matcher can cover the shipped
patterns (`.yandex.(ru|com|net)`, `ptr\.telegram\.org$`, `^snipster\d+\.go\.mail\.ru$`), or use POSIX
`regcomp`/`regexec`. Budget: two query types and one more parser path on top of the DNSBL client.

---

## 3. OpenGraph passthrough

### 3.1 Configuration

`openGraph` block: `enabled`, `considerHost`, `ttl`, `override` (`lib/config/opengraph.go:13-24`). Validation requires
`ttl` to parse as a Go duration and, when `override` is non-empty, requires `og:title` to be present
(`lib/config/opengraph.go:26-56`). Flags `--og-passthrough`, `--og-expiry-time`, `--og-cache-consider-host` are
fallbacks only used when the policy block is disabled (`cmd/anubis/main.go:431-436`).

Docs confirm the override semantics: "return these opengraph values instead of looking them up with the target
service" (`docs/docs/admin/configuration/open-graph.mdx:30-44`).

### 3.2 Fetch

`GetOGTags` (`internal/ogtags/cache.go:12-50`):

1. If `override` is non-empty, return it immediately: no fetch, no cache (`cache.go:16-18`). So `override` is a complete
   replacement, not a per-tag overlay.
2. Build the target: configured target scheme and host plus the **request path and query** (`internal/ogtags/ogtags.go:141-170`).
3. Cache key: that target string, or `target + "|" + originalHost` when `considerHost` is set (`cache.go:57-66`).
4. Cache lookup in `store.JSON[map[string]string]` prefix `ogtags:` (`ogtags.go:117-120`), TTL `openGraph.ttl`.
5. Fetch (`internal/ogtags/fetch.go:20-130`): `GET`, 5 s client timeout (`ogtags.go:27`), `Host` header from
   `--target-host` or the visitor's host (`fetch.go:35-46`), `X-Forwarded-Proto: https`, `X-Forwarded-Host: <host>`,
   `User-Agent: Anubis-OGTag-Fetcher/1.0` (`fetch.go:50-58`), same-origin redirects only and at most 10
   (`fetch.go:120-130`), body capped at 8 MiB (`ogtags.go:24`, `fetch.go:117`), response must be 200 with
   `Content-Type: text/html` or `application/xhtml+xml` (`fetch.go:88-105`).
6. Parse with `golang.org/x/net/html` (`fetch.go:113`), then extract (`internal/ogtags/parse.go:14-33`).
7. Store the tag map under the cache key; failures cache an empty map for the TTL
   (non-200: `fetch.go:82-87`; timeout: half TTL, `fetch.go:60-68`). A cache entry is therefore a positive "this URL has
   no tags" signal.
8. `syscall.ECONNREFUSED` and `ErrOgHandled` return nil tags without failing the request (`cache.go:35-42`); any other
   error is logged by the caller and the page renders without tags (`lib/http.go:329-336`).

### 3.3 What HTML is parsed

Every `<meta>` element anywhere in the document (`parse.go:14-33`), keyed by its `property` **or** `name` attribute,
value from `content` (`parse.go:40-60`). A key is accepted when it starts with one of `og:`, `twitter:`, `fediverse:` or
equals exactly `description`, `keywords`, `author` (`ogtags.go:66-68`, `:124-127`). The map is built with plain
assignment, so the last duplicate of a key wins (`parse.go:20-23`). No `<title>` fallback, no JSON-LD, no HTML entity
work beyond what the HTML parser does.

### 3.4 How the tags reach the challenge page

`RenderIndex` fetches them only when `openGraph.enabled` (`lib/http.go:329-336`) and passes them into
`web.BaseWithChallengeAndOGTags(...)` (`lib/http.go:380-389`). The base template emits one `<meta property={key}
content={value}>` per entry inside `<head>` (`web/index.templ:12`, `:20-22`), alongside the four JSON scripts at
`:61-64`. Tags appear only on the challenge page, never on proxied responses.

### 3.5 What a C port has to do

A minimal port needs: a bounded HTTP/1.1 GET to the target (the existing `proxy_request` already knows how to talk to
the target, including TLS and `--target-host`/`--target-sni`), a Content-Type check, a tiny HTML meta scanner (a
case-insensitive search for `<meta` followed by attribute parsing is enough for real pages; a real tokenizer is safer),
the whitelist above, a cache with a TTL, and the same override short-circuit. Cost is moderate, and the HTML scanner is
where the edge cases live (attributes in any order, single quotes, unquoted values, duplicate keys).

---

## 4. Localization (`lib/localization/`)

### 4.1 Bundle and selection

`go-i18n v2` with English as the fallback language, every `locales/*.json` embedded and loaded at init
(`lib/localization/localization.go:17-76`). Selection order:

1. `--forced-language` / `FORCED_LANGUAGE`, if set (`cmd/anubis/main.go:56`, `anubis.go:69`, `localization.go:133-140`).
2. Otherwise `Accept-Language`, parsed with quality factors; for each tag the full tag and its base language are tried,
   and `en` is appended as the final fallback (`localization.go:82-116`).
3. `<html lang>` is set by localizing the `loading` key with a tag (`localization.go:125-131`, `web/index.templ:14`), so
   `loading` must exist in every catalog.

`T()` uses `MustLocalize` (`localization.go:120-123`): a key missing from the chosen locale falls back to English; a key
missing from English too is a panic at render time. English is therefore the contract.

### 4.2 How many locales ship

30 JSON catalogs plus `manifest.json`: `bg ca cs de en es et eu fi fil fr hr is it ja lt nb nl nn pl pt-BR pt-PT ru
sv th tr uk vi zh-CN zh-TW` (`ls lib/localization/locales/*.json`, 31 files including the manifest). The manifest lists
28 supported languages (`lib/localization/locales/manifest.json`), omitting `eu` and `th`, which ship as files but are
not advertised (**unverified** whether that is intentional). `en.json` has 62 keys; `de.json`, `nl.json` and `pl.json`
have all 62; `th.json` has 60 and is missing `simplified_explanation` and `missing_required_forwarded_headers`, which
fall back to English.

### 4.3 Minimum keys for a challenge page

A challenge page is `web/index.templ`'s `base` plus one algorithm body, with the title passed in. The required keys and
their `en.json` lines:

| key | en.json | used by |
|---|---|---|
| `making_sure_not_bot` | `en.json:43` | page title (`lib/http.go:381`) |
| `loading` | `en.json:2` | `<html lang>` probe (`localization.go:125`) and status line (`web/index.templ:151`) |
| `protected_by` | `en.json:4` | footer (`web/index.templ:76`) |
| `protected_from` | `en.json:5` | footer (`web/index.templ:76`) |
| `made_with` | `en.json:6` | footer (`web/index.templ:78`) |
| `mascot_design` | `en.json:7` | footer (`web/index.templ:80`) |
| `celphase` | `en.json:44` | footer (`web/index.templ:80`) |
| `version_info` | `en.json:10` | footer (`web/index.templ:87`) |
| `go_home` | `en.json:12` | error body (`web/index.templ:104`, `:110`) |
| `contact_webmaster` | `en.json:13` | error body (`web/index.templ:104`) |
| `javascript_required` | `en.json:15` | PoW/wasm body (`proofofwork_templ.go:91`, `wasm_templ.go`) |
| `script_load_error` | `en.json:63` | PoW/wasm body (`proofofwork_templ.go:82`) |
| `connection_security` | `en.json:14` | metarefresh/preact body (`metarefresh_templ.go`) |

That is 13 keys for the cheapest complete page (base + PoW body). `errorPage` adds `oh_noes`
(`en.json:40`) and the error message itself; `authorization_required`, `cookies_disabled`, `access_denied`,
`internal_server_error` and the redirect errors are needed only for those paths (`lib/http.go:291`, `lib/anubis.go:648`,
`lib/http.go:107`). A C port that hardcodes English needs no i18n library at all: the strings are plain UTF-8 and the
only dynamic part is `<html lang>` and the `Accept-Language` negotiation. Full 30-locale parity is a larger, separate
job (translation data, quality-factor parsing, fallback).

---

## 5. GeoIP (`lib/config/geoip.go`, `lib/geoip/`)

### 5.1 Files and record types

Two MaxMind DB files, both optional:

- ASN: default edition `GeoLite2-ASN` (`lib/config/geoip_databases.go:36`), path `geoip.asn.path`
  (`lib/config/geoip_databases.go:95-99`). Accepted database types: any `DatabaseType` containing `ASN`, or exactly
  `GeoIP2-ISP` (`lib/geoip/geoip.go:277-279`).
- Country: default edition `GeoLite2-Country` (`lib/config/geoip_databases.go:37`), path `geoip.country.path`.
  Accepted: `DatabaseType` containing `Country`, or exactly `GeoLite2-City` (`lib/geoip/geoip.go:278-280`).

Records read (`lib/geoip/geoip.go:65-77`):

```go
type asnRecord struct {
    Number       uint32 `maxminddb:"autonomous_system_number"`
    Organization string `maxminddb:"autonomous_system_organization"`
}
type countryRecord struct {
    Country           struct { ISOCode string `maxminddb:"iso_code"` } `maxminddb:"country"`
    RegisteredCountry struct { ISOCode string `maxminddb:"iso_code"` } `maxminddb:"registered_country"`
}
```

`LookupASN` returns `(number, organization, ok)`, with `ok=false` when the address is not found or the ASN is 0
(`geoip.go:177-201`). `LookupCountry` returns the lowercase ISO code; it prefers `country.iso_code`, falls back to
`registered_country.iso_code`, and swaps the preference when `country_field: registered_country` is configured
(`geoip.go:203-236`, field config at `lib/config/geoip.go:26-36`, `lib/config/geoip_databases.go:145-155`). Both look
ups call `addr.Unmap()` first, so IPv4-in-IPv6 forms work (`geoip.go:190`, `:216`).

### 5.2 Rule matching

Config: `geoip: {countries: [...]}` on a bot rule (`lib/config/config.go:66`), `asns: {match: [15169, ...]}` on a bot
rule (`lib/config/config.go:67`, `lib/config/asn.go:14-16`). A rule's conditions are ANDed; the geoip and ASN checks are
appended to the rule's checker list like any other condition (`lib/policy/policy.go:219-232`).

- ASN check (`lib/geoip/checker.go:13-49`): parse `X-Real-IP`, `LookupASN`, membership in the configured set. Parse
  failure -> false.
- Country check (`lib/geoip/checker.go:59-95`): parse `X-Real-IP`, `LookupCountry`, membership in the lowercased set
  (`lib/config/geoip.go:30-34` lowercases and validates two letters). Parse failure -> false.
- ASN values in the private-use ranges are rejected at config load (`lib/config/asn.go:18-49`).
- If a rule declares `asns` or `geoip` but no database is configured, the condition is **dropped with a warning** and the
  rule keeps its other conditions (`lib/policy/policy.go:219-232`). That is a fail-open: the rule can then match more
  traffic than intended, including a `DENY` rule. Worth deciding deliberately in a port.
- ASN also feeds the `asn`/`asn_description` metric labels (`lib/anubis.go:70-99`) and optional ASN logging
  (`lib/config/logging.go:22`, `lib/policy/policy.go:108-113`).

### 5.3 Database acquisition and refresh

`geoip.auto_update` (`lib/config/geoip_databases.go:158-196`) takes `account_id`, `license_key_env` (the env var is read
at validation time, `:173`), an optional `interval` (default 24 h, minimum 1 h, `:34-35`, `:196-204`) and an optional
`endpoint` (http/https only, `:186-196`). Downloads go through the MaxMind `geoipupdate` client
(`lib/geoip/update.go:18`, `:55-63`), each download is MD5-verified (`update.go:84-90`), capped at 512 MiB
(`update.go:31-32`), written as a timestamped sibling file, validated by opening it, then swapped in atomically
(`update.go:66-98`, `lib/geoip/versions.go:15-30`). Without auto update, files are checked for changes every 5 minutes
(`update.go:34-40`).

### 5.4 Is reading the mmdb the only real work?

For matching, yes. The MaxMind DB format is a search tree plus a data section plus a metadata map:

- Metadata marker `\xAB\xCD\xEFMaxMind.com` at the end of the file (`maxminddb-golang@v2.7.0/reader.go:132`); metadata
  keys used are `database_type`, `binary_format_major_version`, `build_epoch`, `ip_version`, `node_count`,
  `record_size` (24, 28 or 32 bits) (`reader.go:165-197`).
- Layout: search tree of `node_count * record_size / 4` bytes, then a 16-byte separator, then the data section, then the
  metadata (`reader.go:130-132`, `:374-391`). A node's children are at `node * (record_size/4)` and
  `+ record_size/8` bytes (`reader.go:391`); a record value below `node_count` is the next node, exactly `node_count`
  is empty, and above is a data pointer resolved as `pointer - node_count - 16` (`reader.go:474-505`, `:806-818`).
- IPv4 lookup in a v6 database starts at the node reached by walking 96 zero bits (the IPv4 start node), then consumes
  the 32 address bits (`reader.go:452-466`, `:579-612`).
- Data section is a tagged encoding: type numbers 0..15 in the order extended, pointer, string, float64, bytes, uint16,
  uint32, map, int32, uint64, uint128, array, container, end marker, bool, float32
  (`maxminddb-golang@v2.7.0/internal/decoder/data_decoder.go:15-49`). The records above need only map (7), string (2),
  uint32 (6) and pointer (1), plus a skip path for every other type so unknown keys do not abort the record.

So the "only real work" claim is true for lookups, with four caveats: (a) acquisition and refresh is separate work and
can be skipped by pointing at a file the operator downloads; (b) the IP must be normalized (v4-mapped v6, unmap) before
the walk; (c) the country field preference and fallback must match; (d) the record size is not fixed, so 24/28/32-bit
reads all need to be implemented. A C reader is a few hundred lines, no dependencies, and testable against `mmdblookup`
if available (not checked here).

---

## 6. Value per effort

| rank | feature | effort | value | reasoning |
|---:|---|---|---|---|
| 1 | DNSBL | moderate (one UDP query type, ~150 lines with cache) | high | a free reputation signal with no data files, no licence, no maintenance; a single boolean changes behaviour for known-bad proxies and bots |
| 2 | verifyFCrDNS | moderate (PTR plus A/AAAA, name compression, optional regex) | high for crawler-friendly sites | it is what makes the shipped Yandex, VK and Telegram preview allow rules honest; without it, spoofing the UA is enough. Approximating with CIDR lists is possible but is a different trust model and still needs maintenance |
| 3 | OpenGraph passthrough | moderate (bounded GET to the target plus a meta scanner plus cache) | medium-high | visible, user-facing: shared links stop rendering blank previews. Reuses the proxy path already present, and the override short-circuit makes a static version nearly free |
| 4 | GeoIP | big (mmdb reader: metadata, 24/28/32-bit tree, tagged data section, then a download/refresh story) | high if ASN rules are used, otherwise zero | the technology is mechanical but sizeable, and it only pays off when an existing policy has `asns` or `geoip` conditions; for a fresh deployment, DNSBL and CIDR rules cover most of the same ground with far less code |
| 5 | Localization | trivial for English-only, very big for 30 locales done properly | low to medium | the page renders fine with hardcoded English; the cost only appears when the audience is non-English and the operator expects translated pages. The contract is small (13 keys for a complete page), so a single-locale port is cheap and a faithful 30-locale port is a data problem, not a code problem |

Suggested order if only one can be done: DNSBL, because it is the smallest complete feature with the largest behavioural
change, and it validates the DNS code that verifyFCrDNS then reuses.
