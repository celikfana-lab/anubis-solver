# PARITY-preactext-spec

Read-only specification of three upstream Anubis features, for reimplementation in `betterAnusbis.c`.

- Source anchor: `anubis` checkout at commit `f197f9a6` (2026-11-06).
- `file:line` references are to that tree unless prefixed with `betterAnusbis/`.
- "Gate" means the C reimplementation.
- "Unverified" marks anything not directly established from this tree.
- No proof of work is involved in any of the three features below except where explicitly stated.

## 0. Executive summary

1. **preact does not verify a browser.** The server checks two things: that at least `difficulty * 80 ms` has elapsed since the challenge was issued, and that the client echoed `sha256(RandomData)` as the `result` form value. The hash input is server-provided and public in the page, so any script can compute it. There is no leading-zero search, no nonce, no work. The "challenge" is a timed hash echo plus a cookies check.
2. **No extension is verifiable from the pass-challenge query alone.** `css-load` is verified from server-side store state that is only set by a separate `GET` to its CSS route; the query supplies only `id`. `headless` is enterprise-only and has no implementation in this tree. Neither extension adds query parameters.
3. **Subrequest mode is switched on by an empty `TARGET`, not by a flag.** It only changes policy path resolution (X-Original-Uri / X-Forwarded-Uri) and leaves `Next` nil. An unauthenticated auth subrequest gets `401 Unauthorized` with body `Authorization required` when `--public-url` is unset, or `307 Temporary Redirect` to `--public-url + "/.within.website/?redir=..."` when it is set. `DENY` still uses `status_codes.DENY`, which is 200 in the shipped policy and must be changed to 403 for forward-auth.

## 1. preact challenge

Source: `lib/challenge/preact/`.

### 1.1 What the client is served

- The page is produced by `preact.templ:8-27`. It is rendered inside the standard base page (`web/index.templ:12-72`), so the response is a full HTML document.
- Response status is `status_codes.CHALLENGE`, which is 200 in the shipped policy (`lib/http.go:391-394`; `data/botPolicies.yaml:194-196`).
- The body contains, in `<main>` (`web/index.templ:70-72`):
  - an `<img>` of the pensive mascot (`preact.templ:11`),
  - `#status` loading text and a connection-security line (`preact.templ:12-13`),
  - a `<script type="application/json" id="preact_info">` with `redir`, `challenge`, `difficulty`, two localized message strings, and `pensive_url` (`preact.templ:15-22`),
  - a `<script type="module">` containing the bundled preact app (`preact.go:23-37`; bundle is `lib/challenge/preact/static/app.js`, 20922 bytes; readable source `lib/challenge/preact/js/app.tsx`),
  - a `<noscript>` fallback (`preact.templ:24-26`).
- The base page also embeds `anubis_version`, `anubis_challenge`, `anubis_base_prefix`, and `anubis_public_url` JSON scripts (`web/index.templ:61-64`). `anubis_challenge` contains the whole `challenge.Challenge` struct, including `ID`, `RandomData`, `Method`, `Difficulty`, and `Extensions` (`lib/challenge/challenge.go:6-16`; `web/index.templ:62`).
- `RenderIndex` sets a test cookie named `anubis.TestCookieName` with the challenge ID as value, path `/`, 30 minute expiry (`lib/http.go:338-344`; name default `techaro.lol-anubis-cookie-verification` at `anubis.go:33`, changable via cookie prefix at `cmd/anubis/main.go:421`).

### 1.2 What the pass-challenge request must contain

The preact page builds the pass-challenge URL in `preact.go:52-60`:

- path: `anubis.BasePrefix + anubis.APIPrefix + "pass-challenge"`, default `/.within.website/x/cmd/anubis/api/pass-challenge` (`anubis.go:55-56`),
- query `redir` = `r.URL.String()` of the challenge-page request (`preact.go:58`),
- query `id` = the challenge UUID (`preact.go:59`).

The client then adds `result` and navigates there (`lib/challenge/preact/js/app.tsx:57-69`; `u()` at `lib/challenge/preact/js/xeact.js:73-80`). The exact request is:

```
GET /.within.website/x/cmd/anubis/api/pass-challenge
    ?redir=<url-encoded challenge-page URL>
    &id=<uuid v7 challenge id>
    &result=<lowercase hex sha256 of the challenge string>
Cookie: techaro.lol-anubis-cookie-verification=<challenge id>
```

Details that a reimplementation must match:

- The route is registered for `GET` only (`lib/config.go:213`).
- Form values may also arrive as a POST body in principle, because `PassChallenge` uses `r.FormValue` after `prepareChallengeForm` (`lib/challenge_form.go:10-33`), but the route registration only accepts GET.
- The body is limited to 64 KiB (`lib/challenge_form.go:11`). An empty multipart body is tolerated (`lib/challenge_form.go:16-25`).
- The test cookie must be present. If it is missing, the server either redirects once to `redir` to retry with a fresh challenge or shows the cookies-disabled error (`lib/anubis.go:639-650`; retry logic `lib/anubis.go:167-180`). The cookie value is not compared to `id`; only presence is required (`lib/http.go:132-134`).
- `redir` is validated by `validateRedirect` (`lib/http.go:65-97`) and must be non-empty and either absolute `http`/`https` or start with `/` (`lib/anubis.go:623-631`). Absolute hosts are checked against `RedirectDomains` when that list is configured (`lib/http.go:93-95`).
- The server re-runs the policy check on the `redir` URL before validating the challenge (`lib/anubis.go:652-660`). The decision must still be `CHALLENGE`, and the stored challenge's policy hash, method, difficulty, and extension list must equal the current rule's (`lib/anubis.go:681-686`). If any differ, the response is 403.

### 1.3 What the server verifies, exactly

`preact.Validate` (`lib/challenge/preact/preact.go:69-88`), in this order:

1. Input sanity check (`in.Valid()`, `lib/challenge/interface.go:76-90`).
2. Time gate: `wantTime = IssuedAt + difficulty * 80ms`; if `time.Now()` is before `wantTime`, fail with `challenge.NewError("validate", "insufficient time", ErrFailed)` (`preact.go:74-78`).
3. Hash gate: `want = internal.SHA256sum(RandomData)`; `got = r.FormValue("result")`; constant-time compare; mismatch fails with `challenge.NewError("validate", "invalid response", ErrFailed)` (`preact.go:80-85`).
4. Success returns nil.

`internal.SHA256sum` is lowercase hex of `sha256([]byte(text))` (`internal/hash.go:13-16`). `RandomData` is 64 random bytes hex-encoded, so 128 hex characters (`lib/anubis.go:201-209`). The client hashes that hex string as UTF-8 text, not the underlying 64 bytes (`app.tsx:40-42`).

Before `impl.Validate` runs, `PassChallenge` also checks (`lib/anubis.go:615-727`):

- `redir` validity (`623-631`),
- test cookie presence (`639-650`),
- policy re-check on `redir` (`652-660`),
- challenge exists, is not spent (`668-679`),
- decision is CHALLENGE, policy hash/method/difficulty/extensions match (`681-686`),
- the method is registered (`690-695`).

`challenge.NewError` sets `StatusCode: 403 Forbidden` (`lib/challenge/error.go:16-23`). A preact validation failure therefore returns 403 with an HTML error page carrying the public reason (`lib/anubis.go:713-718`).

### 1.4 What difficulty means for preact

Difficulty is only a wait multiplier. There is no leading-zero target.

- Server threshold: `difficulty * 80 ms` (`preact.go:74`).
- Client timer: `difficulty * 125 ms` (`app.tsx:52`; the compiled bundle has the same `*125` in `static/app.js:34`).
- Difficulty 0 means no wait; the client also waits 0.
- Config validation requires `0 <= difficulty <= 64` (`lib/config/config.go:235-241`).

The 125 ms client value is larger than the 80 ms server value, which gives the client a 45 ms per difficulty unit of network slack. A solver must wait at least the server threshold measured from the server's `IssuedAt`; the page is served after `IssuedAt`, so waiting 80 ms per unit after reading the page is just barely enough and 125 ms is the safe value.

### 1.5 Exact pass and fail table

| Condition | Result |
| :-- | :-- |
| Success: test cookie present, valid `redir`, policy still CHALLENGE, challenge unspent, time >= `IssuedAt + difficulty*80ms`, `result == sha256hex(RandomData)` | Challenge marked spent (`lib/anubis.go:746-752`), JWT cookie set (`756-788`), 302 Found to `redir` (`805`). |
| Time not reached | 403, HTML error page, public reason `insufficient time` (`preact.go:76-78`, `lib/anubis.go:713-718`). |
| `result` wrong or missing | 403, public reason `invalid response` (`preact.go:83-85`). |
| `id` missing or unknown | 500, `getChallenge failed` (`lib/anubis.go:668-673`; `getChallenge` at `147-154`). |
| Challenge already spent | 500, `double_spend` (`lib/anubis.go:675-679`). |
| Test cookie missing | 500 cookies-disabled page, or one 302 retry to `redir` (`lib/anubis.go:639-650`). |
| `redir` invalid | 400 (`lib/http.go:99-108`). |
| Policy decision on `redir` no longer CHALLENGE, or stored method/difficulty/extensions differ | 403 (`lib/anubis.go:681-686`). |
| Unknown method | 500 (`lib/anubis.go:690-695`). |

### 1.6 Is there any proof of work? What stops a script?

No proof of work. The two server-side checks are an elapsed-time check and a hash echo of a value the server itself published in the page. This is stated plainly by the code: `preact.go:74-85` contains only the time and hash comparisons.

What stops a script:

- The time gate, `difficulty * 80ms`. A solver can wait exactly that long. This is a rate limiter, not a computational barrier.
- The test cookie. A script using a cookie jar satisfies it.
- The `redir` policy re-check and the challenge state checks. These prevent replaying a challenge for a different decision, but not automation of the normal flow.

What does not stop a script:

- Nothing binds the challenge to the client IP or User-Agent. `challenge.Metadata` stores `User-Agent`, `X-Real-IP`, and `Referer` (`lib/anubis.go:214-218`), but preact's `Validate` never reads `Metadata`; the only later use is the `Referer` cookie (`lib/anubis.go:790-798`, `805`). A script can solve from one address and reuse the cookie from another subject to the cookie's domain rules.
- The JWT cookie is the only credential, and it is not IP bound unless `JWTRestrictionHeader` is configured (`lib/anubis.go:766-775`).

A minimal solver is therefore: GET the challenge page, parse `preact_info` for `challenge` and `redir`, compute `sha256hex(challenge)`, keep the test cookie, sleep `80ms * difficulty` (plus clock slack), GET the pass-challenge URL with `id`, `redir`, `result`.

### 1.7 Minimal C gate implementation checklist

- Serve an HTML challenge page for `algorithm: preact` with JSON containing at least `challenge` (the random data string), `difficulty`, and `redir` (the pass-challenge URL with `redir` and `id` already set).
- Issue a UUID challenge ID, store it with `IssuedAt`, `RandomData`, `PolicyRuleHash`, `Method`, `Difficulty`, `Extensions`, `Spent`, 30 minute lifetime (`lib/anubis.go:195-224`).
- Accept `GET .../api/pass-challenge` with query `redir`, `id`, `result`.
- Enforce the test cookie, the `redir` policy re-check, the stored-versus-current rule match, the `80ms * difficulty` wait, and constant-time `sha256hex(RandomData)` comparison.
- Mark spent, mint the auth cookie, 302 to `redir`.
- Do not implement a leading-zero search for preact.
- Accept `preact` as an algorithm name; upstream rejects unknown algorithms at config load (`lib/config.go:94-100`).

### 1.8 Would a self-hoster notice its absence?

- If their policy selects `algorithm: preact`, yes, immediately: the challenge page never appears or behaves differently.
- A stock deployment does not use preact. The shipped thresholds use `metarefresh` and `fast` (`data/botPolicies.yaml:256-295`), and the built-in default algorithm is `fast`, not preact (`lib/config/config.go:55`; `lib/policy/policy.go:243`; `lib/anubis.go:191`, `943`). The docs claim preact is the default (`docs/docs/admin/configuration/challenges/preact.mdx:18`), which is wrong for this source; see section 5.
- Users who follow the docs' recommendation to use preact would notice immediately.

## 2. Challenge extensions

Source: `lib/challenge/extension/`.

### 2.1 Config shape

Extensions are a field of a challenge rule, not a top-level block:

```yaml
- name: some-rule
  action: CHALLENGE
  challenge:
    algorithm: sha256
    difficulty: 8
    extensions:
      - css-load
```

- Struct: `ChallengeRules` has `algorithm`, `difficulty`, `report_as`, `extensions []string` (`lib/config/config.go:212-217`).
- Load-time validation of the names: non-empty and no duplicates (`lib/config/config.go:243-255`), and every name must be registered, otherwise config load fails with `ErrUnknownChallengeExtension` listing the known names (`lib/config.go:116-134`). Unknown names are fatal, not ignored.
- The field is available on bot rules and on thresholds. The shipped policy sets it nowhere, so no extension is active by default.
- At issue, the list is cloned into the stored challenge (`lib/anubis.go:213`). At pass time, the stored list must equal the current rule's list (`lib/anubis.go:683`) and each extension is validated in list order after the method's own validation (`lib/anubis.go:705-744`).
- The extension registry is populated by `extension.Register` in package `init` (`lib/challenge/extension/extension.go:14-45`). In this checkout the only registration is `css-load` (`lib/challenge/extension/css-load/cssload.go:27`). The implementation packages are imported for side effects at `lib/anubis.go:49-50`.

### 2.2 The extension interface (there is no `Check`)

The interface is exactly three methods (`lib/challenge/extension/extension.go:47-65`):

- `Setup(mux, store)` registers routes; routes must include `anubis.BasePrefix` (`48-51`).
- `Head(r, chall) templ.Component` returns markup to inject on the challenge page (`53-57`).
- `Validate(r, lg, in)` runs after the method's validation and can refuse the JWT (`59-64`).

There is no `extension.Check`. The task description's `extension.Check` does not exist in this tree.

Placement discrepancy: the `Head` comment says the output goes into the HTML `<head>` block (`extension.go:53-54`), but `RenderIndex` merges extension heads with the challenge component and passes the result as the base template's `body` parameter (`lib/http.go:267-283`, `lib/http.go:373`, `lib/http.go:380-389`), and the base template renders `@body` inside `<main>` in `<body>` (`web/index.templ:70-72`). The injected `<style>` therefore lands in the body, not the head. Browsers still apply it, but a reimplementation should not assume head placement.

### 2.3 `css-load`, exact behaviour

Registration and state keys:

- register: `cssload.go:26-28`.
- store keys: `ext:css-load:valid:<challengeID>` and `ext:css-load:seen:<challengeID>` (`cssload.go:21-24`).

What the client is made to do:

- On page render, `Head` sets the `valid:` key for the challenge ID for 30 minutes if absent (`cssload.go:51-53`), then emits `<style>@import url("<cssFolder>/<challengeID>");</style>` (`cssload.go:55-58`). `cssFolder` is `BasePrefix + "/.within.website/x/cmd/anubis/ext/css-load"` (`cssload.go:34-36`).
- A CSS-capable browser automatically fetches that URL. The route is `GET {cssFolder}/{challengeID}` (`cssload.go:38-44`).

What the server does on the CSS GET (`cssload.go:74-96`):

1. Parse `{challengeID}` as a UUID; invalid returns 404 (`79-83`).
2. Require the `valid:` key to exist; absent returns 404 (`85-88`).
3. Set the `seen:` key for 30 minutes (`90`).
4. Respond 200 with `Content-Type: text/css; charset=utf-8`, `Cache-Control: no-store, max-age=0`, `Content-Length: 0`, empty body (`92-95`).

What `Validate` does (`cssload.go:61-72`):

1. Read `seen:<challengeID>`.
2. `ErrNotFound` means the CSS route was never fetched, so fail with `challenge.NewError("css-load", "Please ensure your browser has modern web standards enabled", ErrFailed)`; the client sees 403 with that reason (`lib/anubis.go:736-742`).
3. Any other store error is returned as a server error (500 path).

Consequences for a reimplementation:

- The pass-challenge query contributes only `id`. `css-load` adds no query parameters.
- Verification is entirely from store state set by a separate GET. It proves the CSS URL was requested, not that CSS was parsed or rendered.
- A script that can read the page HTML (the challenge ID is in `preact_info` and `anubis_challenge`) can fetch the CSS URL itself and satisfy the check. It raises the cost of a naive solver slightly; it is not a browser attestation.
- The `valid:` key is written with `context.WithoutCancel` (`cssload.go:52`), so it survives a canceled page request.

### 2.4 `headless`, enterprise only, not in this tree

- The docs mark it enterprise-only (`docs/docs/admin/configuration/challenges/extensions/headless.mdx:5-7`) and describe a "small proprietary bit of code" that examines browsers, runs JavaScript and WebAssembly, sends reports to BotStopper before submission, and fails on hard signals or mid-detection User-Agent changes (`headless.mdx:9-12`, `35`, `43-47`).
- There is no `extension.Register("headless", ...)` anywhere in this checkout; the only registration is `css-load` (`cssload.go:27`). No Go source implements it (grep for `headless` finds only docs, a bot rule file, and Playwright test fixtures).
- The CEL variable `headlessNetworkHardReports` documented at `headless.mdx:51-59` is not defined in the open-source CEL environment (`lib/policy/expressions/`, no occurrence).
- Therefore a policy that lists `headless` cannot load in this tree: `lib/config.go:123-126` rejects unregistered extension names. This is a hard startup failure, not a silent ignore.

For the gate, `headless` is unimplementable from open source. Correct behaviour is to reject an unknown extension name at policy load, matching `lib/config.go:116-134`, rather than pretending to support it. Anything beyond that is unverified.

### 2.5 Which extensions are verifiable from the pass-challenge query alone

None. The table is short:

| Extension | Query parameters it adds | What the server actually checks | Verifiable from the query alone? |
| :-- | :-- | :-- | :-- |
| `css-load` | none (only the shared `id`) | `seen:<id>` store key, set by a separate `GET /.../ext/css-load/<id>` | No. Needs the CSS route hit before pass-challenge. |
| `headless` | unknown, not in this tree | proprietary client reports to BotStopper, not in this tree | No. Unverified. |

The challenge method is separate from extensions. For preact, the method verification does use the query: `id` selects the stored challenge and `result` is the hash echo (section 1.3).

### 2.6 Which need a real browser to have executed something

- `css-load`: in practice it requires a client that loads CSS, which a browser does automatically. Technically it requires only an HTTP GET to a URL that appears in the page. No JavaScript execution is required by the extension itself.
- `headless`: requires JavaScript and WebAssembly execution plus a proprietary report, by its own documentation (`headless.mdx:35`). A script could forge some reports, but the checks are proprietary and unverified.
- `preact`: requires JavaScript to run the page script, but not a browser in any meaningful sense. A script can do the same hash and wait.

### 2.7 Would a self-hoster notice its absence?

- `css-load`: only if their policy sets `extensions: [css-load]`, which the shipped policy does not. Otherwise invisible.
- `headless`: an open-source self-hoster cannot use it; they would only notice if they attempted to configure it, at which point upstream fails config load. Enterprise BotStopper users would notice.
- The extension mechanism itself (the `extensions` config field, the merge and validate ordering, and the unknown-name rejection) is what a self-hoster would notice if they use any extension. The mechanism is cheap and worth implementing even if only `css-load` exists.

### 2.8 Minimal C gate implementation checklist

- Parse `challenge.extensions` as a list of strings on bot rules and thresholds.
- Reject unknown names at load with the known list; reject empty and duplicate names.
- Store the extension list on the challenge at issue; require exact equality at pass time.
- Run the method's validation first, then each extension's validation in list order; reject the JWT on any failure with that extension's status code (403 for css-load).
- For `css-load`:
  - set a per-challenge valid marker for 30 minutes when rendering the page,
  - emit `<style>@import url(".../ext/css-load/<id>");</style>` (body placement is acceptable),
  - serve `GET .../ext/css-load/<id>`: 404 for non-UUID or missing valid marker, otherwise mark seen, 200 `text/css`, empty body, no-store,
  - at pass time require the seen marker, else 403 with the documented public reason.
- Do not add extension parameters to the pass-challenge query.
- For `headless`, reject the name rather than half-implement it (or document the deviation explicitly).

## 3. forwardAuth and subrequest mode

Relevant code: `lib/http.go`, `lib/config.go`, `lib/policy/checker.go`, `lib/policy/celchecker.go`, `cmd/anubis/main.go`.

### 3.1 What switches the mode on

There is no `--subrequest-mode` flag. The mode is derived from the target:

- `--target` defaults to `http://localhost:3923` (`cmd/anubis/main.go:71`).
- If `strings.TrimSpace(*target) != ""`, a reverse proxy handler is built (`cmd/anubis/main.go:290-298`).
- The same expression is passed as `subrequestMode` into policy parsing: `LoadPoliciesOrDefault(..., strings.TrimSpace(*target) == "")` (`cmd/anubis/main.go:309`).
- Policy parsing stores it in `ParsedConfig.SubrequestMode` (`lib/policy/policy.go:80-89`), which is used by the path checker and CEL checker (`lib/policy/policy.go:191`, `209`).
- With an empty target, `Options.Next` is nil (`cmd/anubis/main.go:438-441`), so an allowed request is not proxied.

So the exact switch is: set `TARGET` to empty or whitespace (the docs tell systemd/docker users to use a single space, `docs/docs/admin/configuration/subrequest-auth.mdx:31`). This has two effects at once: subrequest path resolution and nil `Next`.

The auth endpoint itself is always registered, in either mode:

- `registerWithPrefix(anubis.APIPrefix+"check", result.maybeReverseProxyHttpStatusOnly, "")` (`lib/config.go:214`).
- That handler calls `maybeReverseProxy(w, r, true)` (`lib/anubis.go:277-279`), so it is always status-only.

The forward-auth URL is therefore `/.within.website/x/cmd/anubis/api/check` (`docs/docs/admin/environments/traefik.mdx:64`; `docs/docs/admin/configuration/subrequest-auth.mdx:100`).

### 3.2 How `--public-url`, X-Original-Uri, and X-Forwarded-Uri are used

`--public-url` (`cmd/anubis/main.go:85`) becomes `Options.PublicUrl` (`cmd/anubis/main.go:461`), is stored globally as `anubis.PublicUrl` (`lib/config.go:154`), and is used in exactly two places relevant here:

1. The status-only challenge response: if it is empty, return 401; if set, build a redirect URL (`lib/http.go:289-300`).
2. `constructRedirectURL`: `PublicUrl + "/.within.website/?redir=" + url.QueryEscape(proto + "://" + host + uri)` (`lib/http.go:425-427`).

Path resolution in subrequest mode:

- `PathChecker.Check` reads `X-Original-Uri` first, falls back to `X-Forwarded-Uri`, parses it, keeps only `.Path` (query dropped), and tests the path regex. If that fails it *also* tests the actual `r.URL.Path` (`lib/policy/checker.go:109-138`).
- CEL `path` returns the header path if present, otherwise `r.URL.Path`; it does not test both (`lib/policy/celchecker.go:77-91`).
- `ValidateRequestPath` checks dot segments in `r.URL.Path` and, in subrequest mode, also in the header path (`lib/policy/checker.go:192-215`).

The redirect builder is stricter and asymmetric:

- `constructRedirectURL` reads only `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri` (`lib/http.go:398-403`). It does not read `X-Original-Uri`.
- All three must be present, or the call fails (`lib/http.go:405-407`).
- `X-Forwarded-Proto` must be exactly `http` or `https` (`lib/http.go:409-416`).
- If `RedirectDomains` is configured, `X-Forwarded-Host` must match it (`lib/http.go:418-423`).

Consequence: an nginx-only deployment that sends `X-Original-URI` but not `X-Forwarded-*` and sets `PUBLIC_URL` will get a 400 from the status-only path, because the redirect cannot be built. The nginx docs avoid this by leaving `PUBLIC_URL` unset and handling the 401 with `error_page` in nginx (`docs/docs/admin/configuration/subrequest-auth.mdx:87-104`). Traefik sends the `X-Forwarded-*` trio and uses the 307 (`docs/docs/admin/environments/traefik.mdx:64`, `79-82`).

### 3.3 Response matrix for the status-only `/api/check`

`maybeReverseProxy` runs `check`, then `checkRules`, then cookie validation, then `RenderIndex(..., httpStatusOnly=true)` when a challenge is required (`lib/anubis.go:328-428`).

| Decision / state | Status | Headers | Body |
| :-- | :-- | :-- | :-- |
| ERROR in `check` (e.g. missing `X-Real-IP`) | 500 | HTML content type from the error page | Error page (`lib/anubis.go:337-343`). |
| ALLOW | 200 | `Cache-Control: no-store`; `X-Anubis-*` are set on the downstream request, not the response (`lib/anubis.go:456-461`; `setDownstreamRiskHeaders` at `lib/anubis.go:317-326`) | Happy page `you_are_not_a_bot` when `Next` is nil (`lib/http.go:504-526`). If `next` is non-nil (target set), the target response instead (`527-532`). |
| DENY | `status_codes.DENY` (200 in the shipped policy; docs recommend 403) | Error page headers | Deny page (`lib/anubis.go:462-474`). |
| CHALLENGE with a valid matching cookie | 200 | Same as ALLOW | Happy page (or proxy). The cookie check and rule-hash check are at `lib/anubis.go:361-427`. |
| CHALLENGE without a valid cookie, `PublicUrl == ""` | 401 Unauthorized | Anubis sets no `Content-Type`, no `WWW-Authenticate`, no `Location`; only the status and body are written (`lib/http.go:289-292`) | Exactly the localized string `Authorization required` (English: `lib/localization/locales/en.json:27`; test asserts it at `lib/http_test.go:179-196`). |
| CHALLENGE without a valid cookie, `PublicUrl != ""` | 307 Temporary Redirect | `Location: <PublicUrl>/.within.website/?redir=<escaped proto://host+uri>` (`lib/http.go:293-300`, `425-427`). Go's `http.Redirect` also emits its standard short HTML body for a GET and sets `text/html; charset=utf-8` if no content type was set (standard library behaviour, not an Anubis decision). | Redirect body from `net/http`. |
| CHALLENGE, `PublicUrl != ""`, but `X-Forwarded-Proto/Host/Uri` missing or invalid | 400 Bad Request | HTML error page | Error page (`lib/http.go:293-296`). |

Notes:

- The 401 and 307 paths do not issue a challenge and do not set the test cookie. They return before `issueChallenge` (`lib/http.go:285-301` versus `311-344`).
- `DENY` in subrequest mode is not a 401. It uses `status_codes.DENY`. The docs explicitly warn that nginx treats the default 200 as successful authentication and tell operators to set `DENY: 403` (`docs/docs/admin/configuration/subrequest-auth.mdx:15-21`). A reimplementation must not silently force a 401 for deny in this mode, or it will not match upstream.
- The 401 body is localized from `Accept-Language` (`localization.GetLocalizer` at `lib/http.go:286`); `Authorization required` is the English string.

### 3.4 Proxy request versus subrequest

For a normal proxy request (target set, browser connects directly to Anubis):

- CHALLENGE without a cookie renders the full challenge page with status `status_codes.CHALLENGE` (`lib/http.go:380-395`; shipped value 200).
- ALLOW proxies to the target (`lib/anubis.go:456-461`, `lib/http.go:527-532`).
- DENY returns the deny page with `status_codes.DENY`.

For a subrequest (`/api/check` with `TARGET` empty):

- CHALLENGE without a cookie returns 401 or 307 and never a challenge page.
- ALLOW returns 200 with the happy page, because `Next` is nil.
- DENY returns `status_codes.DENY`.

The full handoff with `PUBLIC_URL` set (Traefik style):

1. Proxy calls `/api/check` with the original headers. Anubis decides CHALLENGE and returns 307 with `Location = PUBLIC_URL + "/.within.website/?redir=<original URL>"`.
2. Browser follows the 307 to Anubis. Anubis's policy check on `/.within.website/` yields CHALLENGE and `RenderIndex` issues a challenge. The page's `redir` is `r.URL.String()`, which is `/.within.website/?redir=<original URL>` (preact `Issue` at `preact.go:52-60`).
3. Browser solves. `PassChallenge` re-checks policy on the `redir` URL, validates, sets the JWT cookie, and 302s to `/.within.website/?redir=<original URL>` (`lib/anubis.go:805`).
4. Browser requests `/.within.website/?redir=<original URL>`. The policy check yields CHALLENGE, the JWT cookie passes, and `ServeHTTPNext` sees `Next == nil` and a non-empty `redir`, so it 302s to the original URL (`lib/http.go:504-526`).
5. Browser requests the original URL. The proxy calls `/api/check` again, now with the JWT cookie; the cookie matches the rule hash and Anubis returns 200; the proxy serves the resource.

With `PUBLIC_URL` unset, step 1 returns 401 and the proxy is responsible for redirecting to its own `/.within.website/?redir=...` location (`docs/docs/admin/configuration/subrequest-auth.mdx:87-104`, Caddy variant at `205-221`).

### 3.5 Exact conditions for the status-only response

- `returnHTTPStatusOnly` is true only on the `/api/check` handler (`lib/anubis.go:277-279`; route at `lib/config.go:214`).
- 401 requires `PublicUrl == ""` and a CHALLENGE decision with no valid cookie (`lib/http.go:289-292`).
- 307 requires `PublicUrl != ""`, a CHALLENGE decision with no valid cookie, and a successful `constructRedirectURL` (`lib/http.go:292-300`).
- 400 requires `PublicUrl != ""` and a failed `constructRedirectURL`, which happens when any of `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri` is empty, when the proto is not `http`/`https`, when the host fails `RedirectDomains`, or when the URI fails parsing (`lib/http.go:398-428`).
- 200 requires ALLOW, or CHALLENGE with a valid matching cookie (`lib/anubis.go:361-427`, `456-461`).
- No 401 is produced for DENY.

### 3.6 Would a self-hoster notice its absence?

- A deployment behind nginx `auth_request`, Caddy `forward_auth`, or Traefik `forwardAuth` would notice immediately: without subrequest support the gate cannot be used at all in that topology.
- A plain reverse-proxy deployment would not notice.
- The distinction matters because the docs support all three proxies (`subrequest-auth.mdx:27`, `160`; `traefik.mdx:64`).

### 3.7 Minimal C gate implementation checklist

- Treat an empty/whitespace `TARGET` as subrequest mode; do not require a separate flag.
- Always expose `/.within.website/x/cmd/anubis/api/check` as a status-only endpoint.
- In subrequest mode, resolve rule paths from `X-Original-Uri` then `X-Forwarded-Uri` (path only, query dropped), and mirror the fallback to the actual path for `path_regex` but not for CEL `path`, if CEL is implemented.
- Reject dot segments in both the actual path and the header path.
- Store `PUBLIC_URL`.
- On CHALLENGE without a cookie: 401 with body `Authorization required` if `PUBLIC_URL` is empty; otherwise 307 to `PUBLIC_URL + "/.within.website/?redir=" + QueryEscape(proto://host+uri)`, using only `X-Forwarded-Proto/Host/Uri`; 400 if those are missing or invalid.
- On ALLOW or a valid cookie: 200. If no target handler exists, return the happy page; if a target exists, proxy.
- On DENY: use `status_codes.DENY`, default 200, and document that forward-auth deployments must set 403.
- Do not issue a challenge or set cookies from the status-only path.

## 4. Rank by value per effort

1. **preact.** Lowest effort (one page, one hash, one time check, one method name) and it closes a visible parity gap for any policy that selects it. The page is also the smallest of the three to reproduce. A stock shipped policy does not use it, so its value is concentrated in deployments that set `algorithm: preact` or follow the docs' (incorrect) "default" claim.
2. **forwardAuth / subrequest.** Highest absolute capability value: it unlocks whole deployment topologies (nginx auth_request, Caddy forward_auth, Traefik forwardAuth) that otherwise cannot use the gate. Effort is moderate: mode switch from empty target, header-based path resolution, the 401/307/400 matrix, and the challenge handoff. Ranked below preact only on value per line of code, not on importance.
3. **Extensions, specifically `css-load`.** Cheap (one route, two store keys, one style injection) and optional. It catches only naive solvers and is not in the shipped policy, so most self-hosters never see it. `headless` is not implementable from this tree at all; it should be rejected at policy load, not half-implemented.

If the goal is "make the most deployments work", forwardAuth first. If the goal is "match upstream behaviour per unit of C", the order above holds.

## 5. Where the docs and the code disagree

1. **preact difficulty is not in seconds, and the page does not refresh.**
   `docs/docs/admin/configuration/challenges/preact.mdx:14` says `difficulty: 1 # Number of seconds to wait before refreshing the page`. The code waits `difficulty * 80ms` server-side (`lib/challenge/preact/preact.go:74`) and `difficulty * 125ms` client-side (`lib/challenge/preact/js/app.tsx:52`), then navigates to pass-challenge; it does not refresh the page (`app.tsx:57-69`).
2. **preact is not the default challenge method.**
   `docs/docs/admin/configuration/challenges/preact.mdx:18` says "This is the default challenge method for most clients." The code sets `config.DefaultAlgorithm = "fast"` (`lib/config/config.go:55`) and uses it for bot rules and thresholds that omit an algorithm (`lib/policy/policy.go:235-249`, `lib/anubis.go:190-191`, `938-944`). The shipped policy uses `metarefresh` and `fast` (`data/botPolicies.yaml:256-295`), never preact.
3. **Extension `Head` output does not go in `<head>`.**
   The interface comment says it does (`lib/challenge/extension/extension.go:53-54`), but the merged component is passed as the base template's body (`lib/http.go:373`, `380-389`) and rendered inside `<main>` (`web/index.templ:70-72`).
4. **`PUBLIC_URL` absence is a 401, not a broken redirect.**
   `docs/docs/admin/installation.mdx:100` says leaving it unset makes "redirect building fail with redir=null". The status-only path returns 401 and never calls `constructRedirectURL` when `PublicUrl` is empty (`lib/http.go:289-292`). A broken redirect (400) happens when `PublicUrl` is set but the `X-Forwarded-*` headers are missing (`lib/http.go:293-296`, `398-407`).
5. **`headless` is documented in the OSS docs but is not in the OSS tree.**
   `docs/docs/admin/configuration/challenges/extensions/headless.mdx:5-9` marks it enterprise-only, yet the page is in the public docs with configuration examples. In this checkout there is no registration or implementation, and a config that lists it fails to load (`lib/config.go:116-134`). Treat the docs page as describing BotStopper, not this binary.

Doc claims that were checked and agree with the code:

- nginx treats the default DENY 200 as success, so forward-auth needs `DENY: 403` (`docs/docs/admin/configuration/subrequest-auth.mdx:15-21`; `lib/anubis.go:462-474`).
- Subrequest mode is enabled by setting `TARGET` to a space (`docs/docs/admin/configuration/subrequest-auth.mdx:31`; `cmd/anubis/main.go:292`, `309`).
- `css-load` works by importing a test route and checking that the client hit it (`docs/docs/admin/configuration/challenges/extensions/css-load.mdx:3`; `cssload.go:46-72`).

## 6. Unverified and out of scope

- **`headless` internals.** The report format, endpoint, signal checks, and CEL variable are not in this tree. Everything beyond what the docs say is unverified. Do not guess an implementation.
- **Exact `net/http` headers on the 307 response.** Go's `http.Redirect` emits a body and content type for GET; the precise header set is standard library behaviour and was not captured from a live response.
- **Cookie attributes in the reader's deployment.** `CookieDomain`, `CookieSecure`, `DynamicCookieSuffix`, and `--cookie-prefix` change names and scoping (`lib/http.go:118-127`, `136-173`; `cmd/anubis/main.go:421`). The spec uses the defaults.
- **Behaviour under a non-default locale.** The 401 body is localized; only the English string is confirmed (`lib/localization/locales/en.json:27`).
- **Whether any out-of-tree BotStopper build registers additional extensions.** This checkout registers only `css-load`; a commercial build may differ (unverified).
