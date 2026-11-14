# POLICY-CONFORMANCE

Ground truth for loading the shipped Anubis policy, so a C reimplementation ("the gate") can be checked against it.

- Source anchor: `anubis` checkout at commit `f197f9a6` (2026-11-06).
- All `file:line` references are to that tree unless a path starts with `betterAnusbis/`.
- Policy data is `data/botPolicies.yaml` plus everything it imports.
- "Decision" means the `policy.CheckResult` that `lib/anubis.go` produces, not the HTTP response. Where the HTTP status matters it is stated.
- Anything not directly observable in the referenced code is marked **unverified**.

## 1. Evaluation order

### 1.1 What happens at load time and what happens per request

Load time (once, before the server starts listening):

- Imports are expanded recursively in the order the entries appear in `bots:`. `config.Load` walks `c.Bots`, calls `ImportStatement.load` for import entries, and appends `boi.Bots` to the result (`lib/config/config.go:436-454`). Nested imports are expanded by `ImportStatement.load`, which calls `b.Valid()` on each decoded entry; for an import entry `Valid` itself loads that file (`lib/config/import.go:105-151`, recursion at `130-142`).
- Every matcher is compiled and validated: user agent regex (`lib/config/config.go:128-130`), path regex (`138-140`), headers regex (`153-155`), CIDRs (`160-163`), CEL expressions (`lib/config/config.go:173-177` and `lib/policy/celchecker.go:22-38`), threshold CEL programs (`lib/policy/thresholds.go:14-31`).
- The checkers for each rule are collected in a `checker.List` (`lib/policy/policy.go:150-262`). A rule with several matcher fields gets several checkers; the list is ANDed (`lib/policy/checker/checker.go:31-48`, doc comment at `31-35`).

Per request: `Server.check` (`lib/anubis.go:864-946`).

### 1.2 The exact per-request order

Step 0, preconditions (not a policy decision):

- Reject any path containing a `.` or `..` segment (`lib/anubis.go:865-867`, `lib/policy/checker.go:192-215`). This returns an error, not a rule result.
- Require `X-Real-IP` and require it to parse as an IP (`lib/anubis.go:868-876`). Missing or invalid means an error page.
- Path matching later sees `pathForPolicy`, which collapses repeated `/` (no other rewriting) (`lib/policy/checker.go:117-138`, `lib/policy/checker.go:219-231`).

Step 1: `weight := 0` (`lib/anubis.go:878`).

Step 2: iterate `s.policy.Bots` in exactly the load order produced above (`lib/anubis.go:881`). For each rule, `b.Rules.Check(r)` ANDs all of that rule's checkers and short-circuits on the first false. Any checker error aborts the whole request evaluation and produces an error page (`lib/anubis.go:883-886`, `lib/anubis.go:337-343`).

Step 3: if the rule matched, switch on its action (`lib/anubis.go:888-900`):

- `DENY`, `ALLOW`, `DEBUG_BENCHMARK`, `CHALLENGE`: return immediately with `CheckResult{Name: "bot/"+name, Rule: action, Weight: weight}` (`lib/anubis.go:890-893`). No later rule runs. No threshold runs.
- `WEIGH`: `weight += b.Weight.Adjust` and continue to the next rule (`lib/anubis.go:894-899`).

Step 4: only after the entire bot list is exhausted, evaluate thresholds in their configured order (`lib/anubis.go:903`). Each threshold's CEL program is evaluated with the final weight (`lib/anubis.go:904`); the only variable exposed is `weight` (`lib/policy/thresholds.go:34-47`). A non-bool result is treated as false (`lib/anubis.go:910-914`); an evaluation error is logged and that threshold is skipped (`lib/anubis.go:905-908`). The first true threshold returns `CheckResult{Name: "threshold/"+name, Rule: threshold action, Weight: weight}` (`lib/anubis.go:916-935`).

Step 5: if no threshold matched, return the hard-coded fallback `ALLOW` named `default/allow` (`lib/anubis.go:938-946`).

Direct answers:

- Bot rules are evaluated on every request, before any challenge-cookie check, in load order.
- WEIGH rules accumulate only from rules that match before the first terminal match. A WEIGH rule after a terminal rule never contributes.
- Thresholds are consulted only after no bot rule produced a terminal action.
- If nothing matches and no threshold matches, the action is ALLOW.
- A CHALLENGE bot rule skips thresholds. So do ALLOW, DENY, and DEBUG_BENCHMARK (`lib/anubis.go:890-893`).

### 1.3 Consequences that matter for conformance

- The returned `CheckResult.Weight` is the weight accumulated up to and including the matching terminal rule's position, or the final weight when a threshold matched.
- `CHALLENGE` is not "always challenge". After `checkRules`, a valid cookie whose `policyRule` claim equals the current rule hash passes (`lib/anubis.go:361-427`). A `DENY` ignores cookies and always renders the deny page (`lib/anubis.go:462-474`). `ALLOW` always forwards (`lib/anubis.go:457-461`).
- `DENY` and `CHALLENGE` HTTP status codes come from `status_codes` (`lib/anubis.go:473` for DENY, `lib/http.go:393` for CHALLENGE); the shipped file sets both to 200 (`data/botPolicies.yaml:194-196`).
- With the shipped thresholds the integer weight line is fully covered by `weight <= 0`, `0 < w < 10`, `10 <= w < 20`, `20 <= w < 30`, `w >= 30` (`data/botPolicies.yaml:251-295`). Therefore `default/allow` is unreachable for any request whose threshold expressions evaluate successfully. A weight-0 request is reported as `threshold/minimal-suspicion`, not `default/allow` (`data/botPolicies.yaml:251-253`). This is observable in `X-Anubis-Rule` and in the per-rule metrics (`lib/anubis.go:348`, `lib/anubis.go:929`).
- At startup, if `honeypot.enabled` is true, one extra `WEIGH` +30 bot named `honeypot/network` is appended after every file rule (`lib/config.go:217-232`). It matches only when the stored honeypot weight for the client network is at least 25 (`internal/honeypot/naive/naive.go:167-186`). Fresh probe requests are unaffected, but the rule list for repeat honeypot offenders is 42 entries long, not 41.

## 2. Rules the shipped policy loads

### 2.1 Import expansion

`data/botPolicies.yaml` has eight active imports: `data/botPolicies.yaml:20,21,22,25,42,44,47,50`. Following them recursively:

| Import | Rules it contributes (after recursion) |
| :-- | :-- |
| `(data)/bots/_deny-pathological.yaml:1-9` | 13: cloudflare-kitesurf, cloudflare-workers, lightpanda, headless-chrome, headless-chromium, hyperbrowser, us-artificial-intelligence-scraper, custom-async-http-client, lyrenth-ai-web-index, lyrenth-ai-web-index-ips, no-user-agent, alibaba-cloud, huawei-cloud |
| `(data)/bots/aggressive-brazilian-scrapers.yaml:1-26` | 1: deny-aggressive-brazilian-scrapers |
| `(data)/common/domain-fronting.yaml:5-11` | 1: domain-fronting |
| `(data)/meta/ai-block-aggressive.yaml:3-6` | 4: ai-catchall, ai-clients, ai-crawlers-search, ai-crawlers-training |
| `(data)/crawlers/_allow-good.yaml:1-13` | 14: googlebot, applebot, bingbot, duckduckbot, qwantbot, internet-archive, kagibot, marginalia, mojeekbot, common-crawl, wikimedia-citoid, wikimedia-zotero-translation-server, yandexbot, arquivo-pt |
| `(data)/clients/x-firefox-ai.yaml:2-6` | 1: x-firefox-ai |
| `(data)/crawlers/xai.yaml:1-8` | 2: xai-crawler-and-asn, xai-crawler-user-agent |
| `(data)/common/keep-internet-working.yaml:1-13` | 4: well-known, favicon, robots-txt, sitemap |
| direct entries in `data/botPolicies.yaml:63-70,74-82,104-109` | 3: countries-with-aggressive-scrapers, aggressive-asns-without-functional-abuse-contact, generic-browser |

Totals:

- **43 bot entries after import expansion.** Anubis performs no de-duplication (`lib/config/config.go:436-454` appends every expanded entry); the shipped graph happens to contain no duplicate rule name, so 43 is both the entry count and the unique count.
- **41 of the 43 reach the engine.** `countries-with-aggressive-scrapers` and `aggressive-asns-without-functional-abuse-contact` are dropped during `ParseConfig` because the file configures no GeoIP database: `lib/policy/policy.go:217-224` (ASN) and `lib/policy/policy.go:226-233` (country) `continue` without appending the bot. The `geoip` block is commented out (`data/botPolicies.yaml:115-123`) and no CLI flag injects one (`cmd/anubis/main.go` has no GeoIP flag; the only caller of `geoip.FromContext` is `lib/policy/policy.go:125`); `HasASN`/`HasCountry` are nil-safe (`lib/geoip/geoip.go:165-172`).
- **42 entries at runtime** because of the synthetic `honeypot/network` WEIGH rule (`lib/config.go:217-232`), which is last.
- Actions among the 41 loaded: 18 ALLOW, 17 DENY, 6 WEIGH. There is **no** `CHALLENGE` bot rule and no bot rule with a `challenge:` block. Every CHALLENGE in the shipped policy comes from a threshold. This is the single most important fact for a gate that ignores thresholds.

### 2.2 Largest `remote_addresses` list

Counted from the YAML, and cross-checked by counting list entries:

| Rule | Action | CIDRs | Source |
| :-- | :-- | --: | :-- |
| alibaba-cloud | DENY | **1244** | `data/crawlers/alibaba-cloud.yaml:1-1247` |
| huawei-cloud | DENY | 647 | `data/crawlers/huawei-cloud.yaml:1-650` |
| duckduckbot | ALLOW | 486 | `data/crawlers/duckduckbot.yaml:1-491` |
| googlebot | ALLOW | 317 | `data/crawlers/googlebot.yaml:1-321` |
| applebot | ALLOW | 33 | `data/crawlers/applebot.yaml:3-42` |
| bingbot | ALLOW | 28 | `data/crawlers/bingbot.yaml:1-35` |

The largest list overall is alibaba-cloud with 1244 entries (all unique). Googlebot is not the largest; it is fourth overall and the second largest ALLOW list. If "the big one" meant the largest allow-list, that is duckduckbot with 486.

### 2.3 The rule table

Order is the order the engine walks (`lib/anubis.go:881`). "remote N" means `remote_addresses` with N CIDRs. Matcher fields in one rule are ANDed. Rules 41 and 42 are marked dropped; they never reach the engine.

| # | name | action | matcher fields | WEIGH adjust | source |
| --: | :-- | :-- | :-- | --: | :-- |
| 1 | cloudflare-kitesurf | WEIGH | expression: any of 5 header-membership tests (`Cdn-Loop`, `Cf-Ray`, `Cf-Ew-Via`, `Cf-Visitor`, `Cf-Worker` in `headers`) | +15 | `data/bots/cloudflare-kitesurf.yaml:1-11` |
| 2 | cloudflare-workers | WEIGH | headers_regex `CF-Worker: .*` | +15 | `data/bots/cloudflare-workers.yaml:1-6` |
| 3 | lightpanda | DENY | expression: `userAgent.matches("(?i:lightpanda)")` or `Sec-Ch-Ua` matches | none | `data/bots/headless-browsers.yaml:1-6` |
| 4 | headless-chrome | DENY | user_agent_regex `HeadlessChrome` | none | `data/bots/headless-browsers.yaml:7-9` |
| 5 | headless-chromium | DENY | user_agent_regex `HeadlessChromium` | none | `data/bots/headless-browsers.yaml:10-12` |
| 6 | hyperbrowser | DENY | user_agent_regex `(?i:hyperbrowser)` | none | `data/bots/headless-browsers.yaml:13-15` |
| 7 | us-artificial-intelligence-scraper | DENY | user_agent_regex `\+https\://github\.com/US-Artificial-Intelligence/scraper` | none | `data/bots/us-ai-scraper.yaml:1-3` |
| 8 | custom-async-http-client | WEIGH | user_agent_regex `Custom-AsyncHttpClient` | +10 | `data/bots/custom-async-http-client.yaml:1-5` |
| 9 | lyrenth-ai-web-index | DENY | user_agent_regex `AIWebIndex(-Agent)?/[\d.]+ \(\+https\://lyrenth\.com/bot` | none | `data/bots/lyrenth.yaml:4-6` |
| 10 | lyrenth-ai-web-index-ips | DENY | remote 16 (Hetzner /32s) | none | `data/bots/lyrenth.yaml:11-29` |
| 11 | no-user-agent | DENY | expression: `userAgent == ""` | none | `data/bots/spec-violations.yaml:1-4` |
| 12 | alibaba-cloud | DENY | remote 1244 | none | `data/crawlers/alibaba-cloud.yaml:1-1247` |
| 13 | huawei-cloud | DENY | remote 647 | none | `data/crawlers/huawei-cloud.yaml:1-650` |
| 14 | deny-aggressive-brazilian-scrapers | WEIGH | expression: any of 10 `userAgent.contains(...)` tests | +20 | `data/bots/aggressive-brazilian-scrapers.yaml:1-26` |
| 15 | domain-fronting | DENY | expression: all of 3 tests on `X-Tls-Sni-Name` vs `host` | none | `data/common/domain-fronting.yaml:5-11` |
| 16 | ai-catchall | DENY | user_agent_regex with 52 alternatives | none | `data/bots/ai-catchall.yaml:8-11` |
| 17 | ai-clients | DENY | user_agent_regex `ChatGPT-User`, `Claude-User`, `MistralAI-User`, `Perplexity-User` | none | `data/clients/ai.yaml:5-8` |
| 18 | ai-crawlers-search | DENY | user_agent_regex `OAI-SearchBot`, `Claude-SearchBot`, `PerplexityBot`, `meta-webindexer` | none | `data/crawlers/ai-search.yaml:5-8` |
| 19 | ai-crawlers-training | DENY | user_agent_regex `GPTBot`, `ClaudeBot` | none | `data/crawlers/ai-training.yaml:5-8` |
| 20 | googlebot | ALLOW | user_agent_regex `\+http\://www\.google\.com/bot\.html` AND remote 317 | none | `data/crawlers/googlebot.yaml:1-321` |
| 21 | applebot | ALLOW | user_agent_regex `Applebot` AND remote 33 | none | `data/crawlers/applebot.yaml:3-42` |
| 22 | bingbot | ALLOW | user_agent_regex `\+http\://www\.bing\.com/bingbot\.htm` AND remote 28 | none | `data/crawlers/bingbot.yaml:1-35` |
| 23 | duckduckbot | ALLOW | user_agent_regex `DuckDuckBot/1\.1; \(\+http\://duckduckgo\.com/duckduckbot\.html\)` AND remote 486 | none | `data/crawlers/duckduckbot.yaml:1-491` |
| 24 | qwantbot | ALLOW | user_agent_regex `\+https\://help\.qwant\.com/bot/` AND remote 1 | none | `data/crawlers/qwantbot.yaml:1-5` |
| 25 | internet-archive | ALLOW | remote 3 only (no UA test) | none | `data/crawlers/internet-archive.yaml:1-4` |
| 26 | kagibot | ALLOW | user_agent_regex `\+https\://kagi\.com/bot` AND remote 4 | none | `data/crawlers/kagibot.yaml:1-11` |
| 27 | marginalia | ALLOW | user_agent_regex `search\.marginalia\.nu` AND remote 5 | none | `data/crawlers/marginalia.yaml:1-12` |
| 28 | mojeekbot | ALLOW | user_agent_regex `\+https\://www\.mojeek\.com/bot\.html` AND remote 1 | none | `data/crawlers/mojeekbot.yaml:1-6` |
| 29 | common-crawl | ALLOW | user_agent_regex `CCBot` AND remote 5 | none | `data/crawlers/commoncrawl.yaml:1-12` |
| 30 | wikimedia-citoid | ALLOW | user_agent_regex `Citoid/WMF` AND remote 2 | none | `data/crawlers/wikimedia-citoid.yaml:4-7` |
| 31 | wikimedia-zotero-translation-server | ALLOW | user_agent_regex `ZoteroTranslationServer/WMF` AND remote 2 | none | `data/crawlers/wikimedia-citoid.yaml:9-12` |
| 32 | yandexbot | ALLOW | expression: UA matches yandex bot URL AND `verifyFCrDNS(remoteAddress, ...)` | none | `data/crawlers/yandexbot.yaml:1-6` |
| 33 | arquivo-pt | ALLOW | remote 1 only (no UA test) | none | `data/crawlers/arquivo-pt.yaml:1-7` |
| 34 | x-firefox-ai | WEIGH | expression: `"X-Firefox-Ai" in headers` | +5 | `data/clients/x-firefox-ai.yaml:2-6` |
| 35 | xai-crawler-and-asn | DENY | user_agent_regex `code-review-sourcing.*\+xai-research` AND remote 1 | none | `data/crawlers/xai.yaml:1-5` |
| 36 | xai-crawler-user-agent | DENY | user_agent_regex `code-review-sourcing.*\+xai-research` | none | `data/crawlers/xai.yaml:6-8` |
| 37 | well-known | ALLOW | path_regex `^/\.well-known/.*$` | none | `data/common/keep-internet-working.yaml:2-4` |
| 38 | favicon | ALLOW | path_regex `^/favicon\.(?:ico\|png\|gif\|jpg\|jpeg\|svg)$` | none | `data/common/keep-internet-working.yaml:5-7` |
| 39 | robots-txt | ALLOW | path_regex `^/robots\.txt$` | none | `data/common/keep-internet-working.yaml:8-10` |
| 40 | sitemap | ALLOW | path_regex `^/sitemap\.xml$` | none | `data/common/keep-internet-working.yaml:11-13` |
| 41 | countries-with-aggressive-scrapers | WEIGH **dropped** | geoip.countries BR, CN | +10 (never applied) | `data/botPolicies.yaml:63-70` |
| 42 | aggressive-asns-without-functional-abuse-contact | WEIGH **dropped** | asns.match 13335, 136907, 45102 | +10 (never applied) | `data/botPolicies.yaml:74-82` |
| 43 | generic-browser | WEIGH | user_agent_regex `Mozilla\|Opera` | +10 | `data/botPolicies.yaml:104-109` |

Rule-specific notes:

- `cloudflare-workers` is the only `headers_regex` rule. `.*` is special-cased by the engine to mean "header is present with a non-empty value" (`lib/policy/checker.go:171-174`, implementation `lib/policy/checker.go:144-164`). It is not a literal regex match: an absent header does not match, even though the Go regex `.*` would match the empty string.
- Header matchers test each header value and then the comma-joined values (`lib/policy/checker.go:85-97`).
- Regex matching is unanchored substring search (`regexp.MatchString`), so a UA regex can match anywhere in the value (`lib/policy/checker.go:85-97`).
- `internet-archive` and `arquivo-pt` are IP-only ALLOW rules: any UA from those ranges is allowed at that point. `lyrenth-ai-web-index-ips` is an IP-only DENY with the same property.
- `xai-crawler-and-asn` is UA AND IP; `xai-crawler-user-agent` is UA only and therefore denies any UA containing that substring from anywhere.

## 3. Expected decisions for the probe requests

### 3.0 Assumptions

Unless a probe states otherwise:

- `X-Real-IP: 198.51.100.7`. This address is in none of the shipped `remote_addresses` lists (checked against all 41 loaded rules).
- No `Cookie` header, so no previously solved challenge.
- No `CF-*`, `Cdn-Loop`, `Cf-Ew-Via`, `Cf-Visitor`, `X-Tls-Sni-Name`, `Sec-Ch-Ua`, or `X-Firefox-Ai` headers.
- `--serve-robots-txt` is off, which is the default (`cmd/anubis/main.go:66`).
- UA strings: CURL = `curl/8.10.1`; MOZ = `Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0`; GOOG = `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`; AI = `ChatGPT-User/1.0`.

Every decision below was derived by walking the 41 loaded rules in order with the AND semantics above, then the five thresholds.

### 3.1 curl UA on `/`

- Rules 1-10: no match. `curl/8.10.1` does not contain `Custom-AsyncHttpClient`, and the IP is not in any CIDR list.
- Rule 11 `no-user-agent`: `userAgent == ""` is false, because the UA is non-empty.
- Rules 12-19: no UA match, IP not in any list.
- Rules 20-36: no UA match, IP not in any allow range.
- Rules 37-40: `/` matches none of the four path regexes.
- Rule 43 `generic-browser`: `curl/8.10.1` contains neither `Mozilla` nor `Opera`, so no weight.

Final: weight 0, no bot rule matched. Threshold `minimal-suspicion` (`weight <= 0`) matches. Decision **ALLOW**, name `threshold/minimal-suspicion`, weight 0 (`data/botPolicies.yaml:251-253`, `lib/anubis.go:903-935`). The HTTP response is the origin proxied (`lib/anubis.go:457-461`).

### 3.2 Mozilla UA on `/`

- Rules 1-19 do not match.
- Rules 20-36 do not match (UA is not a crawler and the IP is not allow-listed).
- Rules 37-40 do not match the path `/`.
- Rule 43 `generic-browser` matches `Mozilla`, so `weight = 10` and evaluation continues (WEIGH does not terminate).

Final: weight 10, no threshold matched before `moderate-suspicion` (`10 <= weight < 20`). Decision **CHALLENGE**, name `threshold/moderate-suspicion`, weight 10, challenge `algorithm: fast`, `difficulty: 2` (`data/botPolicies.yaml:268-277`). A fresh client gets the challenge page; a client holding a valid cookie for that rule hash passes (`lib/anubis.go:361-427`).

This is the case where the "default allow" documentation is wrong: no DENY or CHALLENGE bot rule matched, yet the request is challenged.

### 3.3 Googlebot UA from `66.249.64.5`

- No rule before 20 matches: the UA does not match any AI/deny regex, and the IP is in no DENY list.
- Rule 20 `googlebot`:
  - user_agent_regex `\+http\://www\.google\.com/bot\.html` matches the `+http://www.google.com/bot.html` substring of GOOG.
  - `66.249.64.5` is inside `66.249.64.0/27`, one of the 317 CIDRs in `data/crawlers/googlebot.yaml`.
  - Both checkers are true, so the AND matches.
- Rule 20 returns immediately (ALLOW). `generic-browser` at rule 43 is never reached even though GOOG contains `Mozilla`.

Final: Decision **ALLOW**, name `bot/googlebot`, weight 0 (`lib/anubis.go:890-893`). Thresholds are skipped. This weight-0 result is the non-obvious part: a browser-like UA that hits rule 20 reports zero weight because the later WEIGH rule never runs.

### 3.4 Googlebot UA from `1.2.3.4`

- Rules 1-19: no match.
- Rule 20 `googlebot`: the UA regex matches, but `1.2.3.4` is not in the 317 CIDRs (checked against the whole list). AND is false, so the rule does not match.
- Rules 21-36: no UA match; the IP is in no allow range.
- Rule 43 `generic-browser`: the spoofed Googlebot UA is a `Mozilla/...` string, so `weight = 10`.

Final: weight 10, `moderate-suspicion`. Decision **CHALLENGE**, `threshold/moderate-suspicion`, weight 10, `fast` difficulty 2. Not DENY. A spoofed Googlebot is challenged, not blocked.

### 3.5 AI crawler UA from `data/clients/ai.yaml`

`ChatGPT-User/1.0`:

- Rule 16 `ai-catchall` (52 alternatives) does not contain `ChatGPT-User`; no match.
- Rule 17 `ai-clients` matches `ChatGPT-User` (`data/clients/ai.yaml:5-8`). DENY returns immediately.

Final: Decision **DENY**, name `bot/ai-clients`, weight 0, HTTP status 200 (`status_codes.DENY` at `data/botPolicies.yaml:194-196`, used at `lib/anubis.go:473`). Thresholds skipped.

Order nuance: if the AI UA is `Perplexity-User/1.0`, rule 16 also matches (its 52 alternatives include `Perplexity-User`), and rule 16 wins because it is earlier. The action is still DENY but the rule name and hash differ, which is observable in `X-Anubis-Rule` and metrics. Likewise `PerplexityBot` is matched by rule 16 before rule 18.

### 3.6 `/robots.txt`

With CURL or MOZ, `X-Real-IP: 198.51.100.7`:

- No DENY rule matches.
- Rules 20-36: no match.
- Rule 37 `well-known`: no (`/robots.txt` does not start with `/.well-known/`).
- Rule 38 `favicon`: no.
- Rule 39 `robots-txt`: `^/robots\.txt$` matches `/robots.txt`.

Final: Decision **ALLOW**, name `bot/robots-txt`, weight 0.

Two important caveats:

- The path ALLOW rules are at positions 37-40, after 17 DENY rules. If the same request carries a denied UA (for example `GPTBot/1.0`), rule 19 `ai-crawlers-training` matches first and the decision is **DENY**, even for `/robots.txt`. The path ALLOW does not protect robots.txt from a UA deny.
- If the server was started with `--serve-robots-txt`, the request is served from the mux before any policy evaluation (`lib/http.go:466-473`), so the policy decision does not apply at all. Default is off (`cmd/anubis/main.go:66`).

### 3.7 `/favicon.ico`

With CURL or MOZ:

- Rules 37-39 do not match.
- Rule 38 `favicon` is `^/favicon\.(?:ico|png|gif|jpg|jpeg|svg)$` and matches `/favicon.ico`.

Final: Decision **ALLOW**, name `bot/favicon`, weight 0.

Conformance trap: this pattern uses a non-capturing group and glibc POSIX ERE rejects it (section 4). A gate that fails to compile this pattern and silently skips the rule would return ALLOW for CURL but CHALLENGE for MOZ, so the regex failure turns a deterministic ALLOW into a UA-dependent outcome.

Also note: a request with no `User-Agent` is DENIED at rule 11 before reaching this path rule (section 3.11).

### 3.8 `/.well-known/foo`

- Rule 37 `well-known` is `^/\.well-known/.*$` and matches.

Final: Decision **ALLOW**, name `bot/well-known`, weight 0.

`pathForPolicy` collapses repeated slashes (`lib/policy/checker.go:217-231`), so a request path like `//.well-known/foo` is evaluated as `/.well-known/foo` and gets the same ALLOW. A path with a `..` segment is rejected as an error before rules (`lib/policy/checker.go:192-215`).

### 3.9 Request with header `X-Firefox-Ai`

Rule 34 is WEIGH +5 when the header is present (`data/clients/x-firefox-ai.yaml:2-6`). It is before the path ALLOW rules and before `generic-browser`.

With MOZ:

- Rule 34 matches: `weight = 5`.
- Rule 43 matches `Mozilla`: `weight = 15`.
- Threshold `moderate-suspicion` (`10 <= 15 < 20`) matches.

Final: Decision **CHALLENGE**, `threshold/moderate-suspicion`, weight 15, `fast` difficulty 2.

With CURL:

- Rule 34 matches: `weight = 5`.
- Rule 43 does not match.
- Threshold `mild-suspicion` (`0 < 5 < 10`) matches.

Final: Decision **CHALLENGE**, `threshold/mild-suspicion`, weight 5, `metarefresh` difficulty 1 (`data/botPolicies.yaml:256-266`).

Header lookup is canonicalised (`lib/policy/expressions/http_headers.go:43-67`), so `x-firefox-ai: 1` and `X-Firefox-Ai: 1` behave the same.

Consequence of WEIGH before an ALLOW path: `/favicon.ico` with MOZ and `X-Firefox-Ai` accumulates 15, then rule 38 ALLOW returns at once. Final decision ALLOW `bot/favicon` with reported weight 15, and no challenge, because ALLOW skips thresholds. The header changes the reported weight but not the action.

### 3.10 `/api/` with `Accept: application/json`

The documented `allow-api-requests` example (`docs/docs/admin/configuration/expressions.mdx:7-15`) is **not** in the shipped policy. `data/botPolicies.yaml` does not import `data/common/allow-api-like.yaml` or `data/common/json-api.yaml`; the only path rules loaded are the four in `data/common/keep-internet-working.yaml`. No loaded rule reads the `Accept` header; the 7 loaded CEL rules only look at `Cdn-Loop`, `Cf-Ray`, `Cf-Ew-Via`, `Cf-Visitor`, `Cf-Worker`, `User-Agent`, `Sec-Ch-Ua`, `X-Tls-Sni-Name`, `X-Firefox-Ai`, `host`, and `remoteAddress`.

Therefore `Accept` has no effect and the decision is purely the UA decision:

- MOZ: weight 10, **CHALLENGE** `threshold/moderate-suspicion`, `fast` difficulty 2.
- CURL: weight 0, **ALLOW** `threshold/minimal-suspicion`.

A gate that hard-codes the docs example would be wrong for this policy.

### 3.11 Request with no `User-Agent` at all

- Rules 1-10: no match (no UA text and no matching headers/IP).
- Rule 11 `no-user-agent` evaluates `userAgent == ""`. Go's `Request.UserAgent()` returns the `User-Agent` header value, so a missing header yields `""` (`lib/policy/celchecker.go:75-76`), and CEL compares true (`data/bots/spec-violations.yaml:1-4`). DENY returns immediately.

Final: Decision **DENY**, name `bot/no-user-agent`, weight 0, HTTP status 200. Thresholds are skipped.

This fires before `alibaba-cloud`/`huawei-cloud`, before every ALLOW rule, and before every path rule, so a UA-less request is denied even on `/robots.txt`, `/favicon.ico`, and `/.well-known/foo`. If the client instead sends `User-Agent:` with an empty value, `Request.UserAgent()` is also `""`, so the result is the same.

### 3.12 Summary

| Probe (with assumptions above) | Decision | Rule name | Weight | Challenge / status |
| :-- | :-- | :-- | --: | :-- |
| CURL on `/` | ALLOW | `threshold/minimal-suspicion` | 0 | 200, proxied |
| MOZ on `/` | CHALLENGE | `threshold/moderate-suspicion` | 10 | fast, difficulty 2 |
| GOOG from `66.249.64.5` | ALLOW | `bot/googlebot` | 0 | 200, proxied |
| GOOG from `1.2.3.4` | CHALLENGE | `threshold/moderate-suspicion` | 10 | fast, difficulty 2 |
| `ChatGPT-User/1.0` | DENY | `bot/ai-clients` | 0 | HTTP 200 |
| `/robots.txt`, CURL or MOZ | ALLOW | `bot/robots-txt` | 0 | 200, proxied |
| `/robots.txt`, `GPTBot/1.0` | DENY | `bot/ai-crawlers-training` | 0 | HTTP 200 |
| `/favicon.ico`, CURL or MOZ | ALLOW | `bot/favicon` | 0 | 200, proxied |
| `/.well-known/foo`, CURL or MOZ | ALLOW | `bot/well-known` | 0 | 200, proxied |
| `X-Firefox-Ai` + MOZ | CHALLENGE | `threshold/moderate-suspicion` | 15 | fast, difficulty 2 |
| `X-Firefox-Ai` + CURL | CHALLENGE | `threshold/mild-suspicion` | 5 | metarefresh, difficulty 1 |
| `/api/` + Accept json + MOZ | CHALLENGE | `threshold/moderate-suspicion` | 10 | fast, difficulty 2 |
| `/api/` + Accept json + CURL | ALLOW | `threshold/minimal-suspicion` | 0 | 200, proxied |
| no `User-Agent` | DENY | `bot/no-user-agent` | 0 | HTTP 200 |

For CHALLENGE, the HTTP status is 200 (`data/botPolicies.yaml:194-196`); the body is the challenge page, and the client must solve `algorithm`/`difficulty` from the threshold.

## 4. Regexes POSIX ERE cannot compile as written

Method: every active regex was extracted from the loaded rules. glibc's POSIX ERE engine was used as the reference through `sed -E`, which calls `regcomp(REG_EXTENDED)`. Results:

- `(?i:...)` and `(?:...)`: `sed: ... Invalid preceding regular expression`. A hard compile failure.
- `[\d.]`: compiles, but matches `d` (glibc treats `\d` as `d`), not digits. A silent semantic break.

Go uses RE2 (`docs/docs/admin/policies.mdx:565`), which accepts all of these, so the shipped policy is valid for Anubis and only becomes a problem for a POSIX ERE gate.

| # | file:line | field | pattern as written | construct | substitution | does the substitution preserve meaning? |
| --: | :-- | :-- | :-- | :-- | :-- | :-- |
| 1 | `data/common/keep-internet-working.yaml:6` | `path_regex` | `^/favicon\.(?:ico\|png\|gif\|jpg\|jpeg\|svg)$` | non-capturing group | `^/favicon\.(ico\|png\|gif\|jpg\|jpeg\|svg)$` | Yes. Only capture groups change, and nothing reads submatches. The accepted set is identical. |
| 2 | `data/bots/headless-browsers.yaml:14` | `user_agent_regex` | `(?i:hyperbrowser)` | scoped inline flag | `(hyperbrowser)` compiled with `REG_ICASE` | Yes. The flag scope is the whole pattern, so whole-pattern case-insensitivity is equivalent. Without `REG_ICASE` the meaning changes (a UA containing `Hyperbrowser` would stop matching). |
| 3 | `data/bots/headless-browsers.yaml:5` | CEL literal inside `userAgent.matches("...")` | `(?i:lightpanda)` | scoped inline flag | `(lightpanda)` with `REG_ICASE` | Yes for the match language. Only relevant if the gate evaluates CEL at all (section 5); if it does not, the whole rule is ignored. |
| 4 | `data/bots/headless-browsers.yaml:6` | CEL literal inside `headers["Sec-Ch-Ua"].matches("...")` | `(?i:lightpanda)` | scoped inline flag | `(lightpanda)` with `REG_ICASE` | Same as #3. |
| 5 | `data/bots/lyrenth.yaml:6` | `user_agent_regex` | `AIWebIndex(-Agent)?/[\d.]+ \(\+https\://lyrenth\.com/bot` | `\d` | `AIWebIndex(-Agent)?/[0-9.]+ \(\+https\://lyrenth\.com/bot` | This is a real semantic break, not just a compile problem. POSIX has no `\d`; inside a bracket expression POSIX treats backslash as an ordinary character, so `[\d.]` is the set `{ \, d, . }` by the letter of the standard (and `{ d, . }` on glibc). Neither matches a version digit. `[0-9.]` restores the Go meaning. Without it the rule can never match a real `AIWebIndex/1.2 ...` UA. |

Not present in the loaded data (verified by fixed-string scan over `data/`):

- `\w`, `\s`, `\b`: no occurrences anywhere in `data/`.
- Lookarounds `(?=`, `(?!`, `(?<=`, `(?<!`, lazy quantifiers `*?`/`+?`, `\A`, `\z`, `\p{...}`: none.
- Backreferences: none.

Occurrences in data that are not part of the shipped policy:

- `data/clients/vk-preview.yaml:6` contains `\d` in `verifyFCrDNS(remoteAddress, "^snipster\d+\.go\.mail\.ru$")`, but that file is not imported by `data/botPolicies.yaml`.
- `data/botPolicies.yaml:55` and `data/meta/default-config.yaml:38` contain `(?i:bot|crawler)`, but both are commented out.

Additional portability caveat, not a hard failure:

- Many patterns escape `:` and `/`, which are not ERE special characters. Examples: `data/crawlers/googlebot.yaml:2`, `data/crawlers/bingbot.yaml:2`, `data/crawlers/duckduckbot.yaml:2`, `data/crawlers/qwantbot.yaml:2`, `data/crawlers/kagibot.yaml:2`, `data/crawlers/mojeekbot.yaml:2`, `data/bots/us-ai-scraper.yaml:2`, `data/bots/lyrenth.yaml:6`, `data/crawlers/yandexbot.yaml:5`, all of which write `\:` for a literal colon (the `//` after it is already literal). glibc accepts `\:` and `\/` as literals (verified), but POSIX leaves a backslash before a non-special character undefined, so another libc may reject or misread them (the behaviour of libcs other than glibc is unverified). A portable rewrite drops only those two backslashes, for example `\+http://www\.google\.com/bot\.html` instead of `\+http\://www\.google\.com/bot\.html`. Escapes of genuinely special characters (`\+`, `\.`, `\(`, `\)`) are correct POSIX and must be kept.

## 5. Items in the shipped policy that will be ignored

"Will be ignored" means a POSIX-ERE rule gate cannot honour it, so the gate must either implement it separately or accept the divergence listed.

| Item | Defined at | What a regex-only gate does | Divergence this causes |
| :-- | :-- | :-- | :-- |
| `countries-with-aggressive-scrapers` (geoip countries BR, CN, +10) | `data/botPolicies.yaml:63-70` | will be ignored | Anubis itself also drops this rule when no GeoIP DB is configured (`lib/policy/policy.go:226-233`), so for the shipped file the divergence is zero. If a DB is added out of band, a gate cannot reproduce it. |
| `aggressive-asns-without-functional-abuse-contact` (asns 13335, 136907, 45102, +10) | `data/botPolicies.yaml:74-82` | will be ignored | Same as above (`lib/policy/policy.go:217-224`). |
| top-level `geoip` block | commented out, `data/botPolicies.yaml:115-123` | will be ignored | No DB is configured, so no geoip data exists. |
| CEL rule: cloudflare-kitesurf (`Cdn-Loop`/`Cf-Ray`/`Cf-Ew-Via`/`Cf-Visitor`/`Cf-Worker` in headers, +15) | `data/bots/cloudflare-kitesurf.yaml:1-11` | will be ignored | A request carrying `Cf-Ray` with MOZ would be weight 25 (`mild-proof-of-work`, fast 4) in Anubis but weight 10 (`moderate-suspicion`, fast 2) in a gate that ignores it. |
| CEL rule: lightpanda (UA or `Sec-Ch-Ua` matches lightpanda, DENY) | `data/bots/headless-browsers.yaml:1-6` | will be ignored | A lightpanda UA is DENY in Anubis and falls through to the thresholds in the gate. |
| CEL rule: no-user-agent (`userAgent == ""`, DENY) | `data/bots/spec-violations.yaml:1-4` | will be ignored | Major divergence: a UA-less request is DENY in Anubis (section 3.11) but weight 0 ALLOW in a gate that ignores it. |
| CEL rule: deny-aggressive-brazilian-scrapers (10 `userAgent.contains`, +20) | `data/bots/aggressive-brazilian-scrapers.yaml:1-26` | will be ignored | Old-IE and discontinued-OS UAs lose 20 weight and can fall into a lighter threshold. |
| CEL rule: domain-fronting (3 tests on `X-Tls-Sni-Name` vs `host`, DENY) | `data/common/domain-fronting.yaml:5-11` | will be ignored | A domain-fronting request is DENY in Anubis and falls through in the gate. |
| CEL rule: x-firefox-ai (`"X-Firefox-Ai" in headers`, +5) | `data/clients/x-firefox-ai.yaml:2-6` | will be ignored | The +5 is lost; section 3.9 decisions move one threshold band. |
| CEL rule: yandexbot (UA match AND `verifyFCrDNS`, ALLOW) | `data/crawlers/yandexbot.yaml:1-6` | will be ignored | A genuine Yandexbot UA is a `Mozilla/...` string, so a gate that ignores this rule adds +10 through generic-browser and returns `moderate-suspicion` CHALLENGE instead of ALLOW. The reverse-DNS half cannot be reproduced by a regex gate at all. |
| thresholds (5 entries, weight comparisons, `all` lists, actions ALLOW/CHALLENGE, challenge algorithm/difficulty) | `data/botPolicies.yaml:249-295` | will be ignored | This is the largest divergence. There is no CHALLENGE bot rule in the shipped policy, so **every** CHALLENGE in section 3 comes from a threshold. A gate without thresholds turns all of them into its own fallback. |
| `store` (`backend: memory`, `parameters: {}`) | `data/botPolicies.yaml:232-234` | will be ignored | Challenge state only; the gate keeps its own state. |
| `openGraph` (`enabled: false`, `considerHost: false`, `ttl: 24h`) | `data/botPolicies.yaml:168-175` | will be ignored | Disabled, so no decision effect. |
| `status_codes` (`CHALLENGE: 200`, `DENY: 200`) | `data/botPolicies.yaml:194-196` | will be ignored | The values equal Anubis's built-in defaults (`lib/config/config.go:388-392`) and the gate's compiled defaults (`betterAnusbis/betterAnusbis.c:98-99` and `:139-140`), so behaviour matches for this file only. A file with non-200 values would diverge. |
| `honeypot` (`enabled: true`, `implementation: naive`) | `data/botPolicies.yaml:126-136` | config not read | The gate's compiled default is enabled (`betterAnusbis/betterAnusbis.c:118`); whether a CLI flag can turn it off is unverified. What matters behaviourally is the synthetic +30 WEIGH rule (`lib/config.go:217-232`) and the 25 threshold (`internal/honeypot/naive/naive.go:167-186`), which a gate implementation must replicate if it wants parity for repeat offenders. |
| `dnsbl: false` | `data/botPolicies.yaml:111` | will be ignored | Disabled, so no effect. |
| `metrics` block | commented out, `data/botPolicies.yaml:203-230` | will be ignored | No effect. |
| `impressum` block | commented out, `data/botPolicies.yaml:138-165` | will be ignored | No effect. |
| `remote_addresses_url` | not present in the shipped file | not used | No effect for this policy. |

Consequence summary for a gate that implements only regex rules and no thresholds:

- It can reproduce: CURL ALLOW (as its own fallback, not as `threshold/minimal-suspicion`), `bot/googlebot` ALLOW, `bot/ai-clients` and `bot/ai-crawlers-training` DENY, `bot/robots-txt`/`bot/favicon`/`bot/well-known` ALLOW, and `bot/no-user-agent` DENY only if the CEL rule is special-cased.
- It cannot reproduce: MOZ CHALLENGE, spoofed-GOOG CHALLENGE, `X-Firefox-Ai` weight math, `/api/` with a browser UA, or any challenge algorithm/difficulty, because all of those are threshold-driven.

## 6. Where the docs and the Go code disagree

The code is authoritative. Disagreements found:

1. **"Only DENY/CHALLENGE rules block or challenge" is false.**
   `docs/docs/admin/default-allow-behavior.mdx:12` and `:14` claim only requests matching an explicit DENY or CHALLENGE rule are blocked or challenged, and everything else is allowed. The code applies WEIGH rules (`lib/anubis.go:894-899`) and then thresholds (`lib/anubis.go:903-935`), which can CHALLENGE or DENY without any bot rule matching. With the shipped policy a plain MOZ request on `/` is CHALLENGED (section 3.2). The page never mentions WEIGH or thresholds.

2. **"The first match wins" is false for WEIGH.**
   `docs/docs/admin/default-allow-behavior.mdx:88` says rules are evaluated in order and the first match wins. In the code a WEIGH match does not win and does not stop the walk; it only adds weight and evaluation continues (`lib/anubis.go:888-900`). The first *terminal* match wins. The page's advice to put a catch-all DENY last happens to work, but the stated rule is wrong.

3. **"Remove 5 weight -> Meta Refresh in the default configuration" is false for the shipped defaults.**
   `docs/docs/admin/policies.mdx:583` says removing five weight points makes Anubis present the Meta Refresh challenge in the default configuration. The shipped thresholds have `minimal-suspicion` with `expression: weight <= 0` and `action: ALLOW` (`data/botPolicies.yaml:251-253`), so `-5` (and any weight `<= 0`) is ALLOW, not Meta Refresh. The statement only holds for the docs' own sample thresholds, which use `weight < 0` (`docs/docs/admin/configuration/thresholds.mdx:32`). The shipped file and the docs sample disagree with each other; the code follows the file.

4. **Five actions, not four.**
   `docs/docs/admin/policies.mdx:63` says there are four actions; the table at `:65-70` lists ALLOW, DENY, CHALLENGE, WEIGH. `config.Rule` also accepts `DEBUG_BENCHMARK` (`lib/config/config.go:43`, validated at `lib/config/config.go:179-184`) and the engine renders a benchmark page for it (`lib/anubis.go:477-480`). Undocumented but accepted.

5. **`headers_regex: .*` is not a plain regex.**
   `docs/docs/admin/policies.mdx:40-42` uses `headers_regex: {CF-Worker: .*}` as if it were a normal regex. The code special-cases `.*` to mean "header exists with a non-empty value" (`lib/policy/checker.go:171-174`, `lib/policy/checker.go:144-164`). A naive regex reading would also match an absent header, because the Go regex `.*` matches `""`. A reimplementation that treats it as a regex will over-match and deny requests that lack the header.

6. **The docs' API example is not in the shipped policy.**
   `docs/docs/admin/configuration/expressions.mdx:7-15` shows an `allow-api-requests` rule for `/api/` with `Accept: application/json`. It is only an example; the shipped policy contains no such rule, and `Accept` is not read by any loaded rule. Treating it as shipped behaviour is a documentation trap, not a code bug.

Doc claims that were checked and do agree with the code:

- Thresholds do not apply when a CHALLENGE bot rule matches (`docs/docs/admin/configuration/thresholds.mdx:21`); the code also skips them for ALLOW, DENY, and DEBUG_BENCHMARK, and the page's second clause ("don't match any terminal bot rules") covers that.
- A threshold action cannot be WEIGH (`config.Threshold.Valid` rejects it, `lib/config/threshold.go:60-62`), matching `docs/docs/admin/configuration/thresholds.mdx:116`.
- Regexes use Go's standard library syntax (`docs/docs/admin/policies.mdx:565`), matching `regexp.Compile` at `lib/config/config.go:128-130` and `lib/policy/checker.go:78`.
- A missing map key in CEL raises an error and Anubis returns an error page (`docs/docs/admin/configuration/expressions.mdx:116`); the code propagates checker errors out of `Server.check` (`lib/anubis.go:883-886`).
