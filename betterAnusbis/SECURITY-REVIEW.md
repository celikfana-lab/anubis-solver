# Security review: betterAnusbis

Scope: `betterAnusbis.c`, the gate itself. The solver library is out of scope here (it is
covered by `tests/` and the benchmark results).

Method, in the order it happened:

1. Read the gate against upstream's semantics, flag by flag and behaviour by behaviour.
2. Two independent read-only audits of the same file by separate agents, one against
   `cmd/anubis` and `lib/`, one deriving what the shipped `data/botPolicies.yaml` must
   decide (both are checked in: `PARITY.md`, `POLICY-CONFORMANCE.md`).
3. Hand the result to the test suite: 133 checks in `test_parity.py`, which read the wire
   (status line, every Set-Cookie attribute, Location, the headers the backend saw).
4. An AddressSanitizer + UBSan build fired at 17 malformed requests.

Seven findings, all fixed. Five were fail-open conditions, one was a response-splitting
injection, one was a timing side channel. No memory-safety finding. Everything below says
where the vulnerable code was, what an attacker could do with it, and which commit fixed it.

---

## S1: header injection through `redir=` (high)

**Was.** The post-challenge redirect read `redir=` out of the query, percent-decoded it, and
wrote it into `Location:` verbatim. `redir=/%0d%0aSet-Cookie:%20x=1` produced a second header.

**Impact.** Any attacker who could get a browser to the pass-challenge endpoint could set
cookies for the gate's origin, including a forged auth cookie if the gate's signing key was
also compromised by another route, and could otherwise desynchronise a caching proxy in front
of the gate. Response splitting is the classic shape of this bug.

**Fix.** `safe_redirect()` refuses anything with a control character or a space, only allows a
path on this host or a host named by `--redirect-domains`, and rejects scheme-relative URLs
whose host is not on that list. The Location header is also only ever taken from that function.

**Fixed in** `39f2aa0`. **Test:** "a CRLF in redir cannot split the response".

## S2: `--listen 127.0.0.1:PORT` bound every interface (high)

**Was.** `parse_listen()` split off the port and threw the address away, always binding
`in6addr_any`. A gate started with `--listen 127.0.0.1:4949` printed that it was on the
loopback and answered the whole network.

**Impact.** Exposure of the gate and the challenge endpoints to the internet when the operator
had explicitly asked for loopback. For a component that is usually placed behind a proxy this
is the difference between "not routable" and "routable".

**Fix.** The address is parsed; IPv4 literals are mapped to the dual-stack form, brackets are
accepted for IPv6 literals, `:8080` still means every interface, and a hostname is refused
because this is a bind address, not something to resolve.

**Fixed in** `d1ed82c`. **Test:** the parity suite binds, then checks `ss` shows the exact
address; `test_parity.py` also uses this path for every gate it starts.

## S3: IPv6 CIDR rules were silently dropped, a fail-open (high)

**Was.** Every `net` rule was parsed with `inet_pton(AF_INET, ...)`. An IPv6 CIDR line failed
to parse, and the loader moved on without a word. `rule_matches` had an IPv6 branch that could
never be reached.

**Impact.** `allow net 2001:db8::/32` matched nothing, so the operator's allow list was inert.
The same shape applies to a `deny net` rule: a line the operator believes forbids a range
forbade nothing. This is a fail-open in the one part of the policy that is a security control.

**Fix.** The rule carries a family flag, both families parse, a line that parses as neither is
logged and ignored instead of vanishing, and matching compares all 16 bytes under the prefix
mask, including `::ffff:a.b.c.d` against an IPv4 client, which normalises both ways.

**Fixed in** `3e5329d`. **Tests:** "an IPv4 /8 rule denies", "an IPv6 /32 rule denies", "an
IPv6 address outside the rule is challenged".

## S4: `headers_regex: {H: .*}` matched a missing header (medium)

**Was.** The value `.*` was compiled as a regex, which matches the empty string, so the
condition "header H is present" was satisfied by a request that had no such header.

**Impact.** Any policy using upstream's `.*` shorthand for header presence had the condition
silently removed. Against the shipped policy that is a `WEIGH +15` for Cloudflare workers, so
it weakened a weight rather than an outright deny, but the same shorthand on a deny rule would
have matched every request.

**Fix.** `.*` is special-cased as "present and non-empty", which is what
`lib/policy/checker.go:171-174` does.

**Fixed in** `3e5329d`. **Test:** "a headers_regex of .* wants the header present, not absent",
plus the weight-stacking check that proves the condition is real.

## S5: unsupported expression halves were invisible (medium)

**Was.** The expression evaluator short-circuited `||` and `&&`. The load-time validation ran
the same evaluator, so the unsupported half of an `all:` list was never visited and no warning
was emitted. At request time the same short-circuit meant the rule's result depended on which
half came first.

**Impact.** A rule whose second condition this gate cannot evaluate sat there doing something
other than what its author wrote, with no diagnostic. For a `DENY` rule that is fail-open: the
rule never matches and the traffic it was written for is not denied. `data/crawlers/yandexbot.yaml`
was exactly this case (`verifyFCrDNS`), and it went unreported until the evaluator was fixed.

**Fix.** Both sides of `||` and `&&` are always evaluated, and anything unsupported is reported
by rule name at load: "expresses something this gate does not evaluate ... will never match".
`verifyFCrDNS` then got a real implementation, so the shipped policy now has zero unsupported
rules, which is an assertable property and is asserted.

**Fixed in** `3e5329d`, with `verifyFCrDNS` in `4e6452e`. **Test:** "every rule in the shipped
policy is now understood".

## S6: a DENY rule was bypassable by holding any cookie (medium)

**Was.** The auth cookie was checked before the policy, and a valid cookie short-circuited
straight to the backend. The policy was only consulted for requests without one.

**Impact.** An operator who adds a `DENY` for a user agent, a path or a network expects it to
take effect immediately. Here, every client that had already solved a challenge kept getting
through, indefinitely, which is the worst possible failure mode for an incident response: the
control looks applied and is not. Upstream asks the policy first (`lib/anubis.go:881-900`).

**Fix.** The policy is evaluated before the cookie. `ALLOW` forwards, `DENY` denies whatever
cookie is held, and a `CHALLENGE` result is the only one a valid cookie satisfies.

**Fixed in** `3e5329d`. **Test:** "a DENY rule still denies a client that already solved a
challenge", with the companion check that the same cookie still works for everyone else.

## S7: token MAC compared with `strcmp` (low, theoretical)

**Was.** `verify_token` compared the computed HMAC and the restriction claim with `strcmp`,
which stops at the first differing byte.

**Impact.** A timing oracle on token forgery. Each guess leaks the length of the matching
prefix, in theory turning a 2^256 search into a few thousand requests. In practice the network
and the parser noise make this very hard to exploit, which is why it is rated low and why it is
still worth fixing: it is the one comparison in the program where timing is worth more than the
answer. Upstream uses `hmac.Equal` for the same reason.

**Fix.** `ct_equal()` walks the whole string and ORs the differences, for both the signature and
the restriction claim.

**Fixed in** `822d300`. **Test:** the token checks in `test_parity.py` cover both paths
(HS256/HS512/EdDSA accept, cross-scheme reject, restriction accept and reject).

---

## Correctness, not security

`header_value()` returns one shared per-thread buffer, so a caller that keeps two header values
ends up with two pointers to the second one. It produced a nonsense forwardAuth redirect
(`X-Forwarded-Proto` replaced by the host) which was fixed by copying each value, but the API
is still a footgun and the next caller will make the same mistake. A `header_value_into()`
taking a caller buffer would remove the class. Not fixed yet.

## Sanitizer sweep

Built with `-fsanitize=address,undefined -fno-omit-frame-pointer` and fired at:

40 KB single header line, 24 KB `Accept-Language`, 500 headers in one request, `../..` path
segments, `%zz` escapes, a 20-digit nonce, a 5 KB response field, negative `Content-Length`,
12-digit `Content-Length`, `Transfer-Encoding: chunked` with no body, junk bytes in the request
line, a 900-byte `Sec-WebSocket-Key`, a 4 KB honeypot id, `redir` with `%0d%0a`, an unreadable
policy path, and a request with no headers at all.

Result: no ASan or UBSan report, process alive afterwards, and the answers stayed right
(CRLF in `redir` rejected, dot segments 400, both bogus lengths 200 with no body read).

## Known open items

- **`policyRule` is hardcoded to `"rule-0"`.** Upstream puts a hash of the matched rule in the
  token, so tightening a policy invalidates cookies minted under the old one. Here it does not:
  a client that solved a challenge under a permissive rule keeps a valid cookie after the rule
  is removed. Fixing it needs a stable hash per rule, which the flat format does not have yet.
- **The restriction claim is called `restrict` and holds the address; upstream's is
  `restriction` and holds its SHA-256.** The two are not interchangeable, so a token from a real
  Anubis instance is refused, and vice versa.
- **`asns` and `geoip` rules are dropped when no database is configured**, with a loud log line.
  Upstream drops only the condition, which makes a rule match *more* traffic; dropping the rule
  makes it match none. Both are policy loss on a misconfiguration, and both are visible only in
  the log.

## What this review did not cover

- No libFuzzer or AFL campaign. The sanitizer sweep was a hand-written corpus of 17 cases.
- No TLS testing beyond the happy path: no downgrade attempts, no certificate edge cases, no
  session resumption.
- The WebSocket splice was tested with a single echo frame, not with adversarial framing,
  fragmentation, or a peer that half-closes at the wrong moment.
- No timing analysis beyond the MAC comparison. The challenge-id lookup, the cookie parse and
  the policy match are all data-dependent and unaudited for timing.
- No review of the solver library's JIT output.

These are the places to look next, in that order.
