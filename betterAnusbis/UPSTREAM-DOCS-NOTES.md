# Two things in Anubis's docs that its code does not do

Not vulnerabilities, so not for `security@techaro.lol`. Drafted as a public issue because
that is what it is: documentation that describes behaviour the code does not have. It is
written to be posted by a human, under their own name, because the project's `AGENTS.md`
says the project does not accept documentation changes authored by AI agents, and asks an
autonomous agent that files an issue anyway to add a specific sentinel line.

Both findings come from reading the code, not from guessing: the citations are `file:line`
in the tree as of 2026-11-14, and both were reproduced against the shipped policy.

---

## Issue draft

**Title:** `default-allow-behavior` and the threshold examples do not match what the code does

**Body:**

While tracing what the shipped `data/botPolicies.yaml` actually decides, two docs pages turned
out to describe behaviour the code does not have. Both matter because they are the pages a
self-hoster reads before deciding whether the default configuration protects them.

### 1. `docs/docs/admin/default-allow-behavior.mdx` never mentions WEIGH or thresholds

The page says only `DENY` and `CHALLENGE` rules block or challenge traffic, and that a request
matching nothing is allowed. With the shipped policy that is not the whole story: `generic-browser`
(`data/botPolicies.yaml:105-109`) is a `WEIGH` rule that adds 10 for a `Mozilla|Opera` user agent,
and the shipped thresholds (`data/botPolicies.yaml:251-295`) turn `weight >= 10` into
`CHALLENGE` with `fast` at difficulty 2.

So a plain Firefox request matches **no** `DENY` or `CHALLENGE` rule at all, and is still
challenged. The evaluation order is: rules in load order, the first `ALLOW`/`DENY`/`CHALLENGE`
returns immediately, `WEIGH` only accumulates, thresholds are consulted afterwards
(`lib/anubis.go:878-946`). The page would be correct if it said "no rule and no threshold",
and it currently leaves a reader believing WEIGH rules do nothing on their own.

### 2. `docs/docs/admin/policies.mdx:583` says a -5 weight gets Meta Refresh; it gets ALLOW

The example describes removing weight to make a challenge easier, and says the result is Meta
Refresh "in the default configuration". The shipped thresholds start with:

```yaml
- name: minimal-suspicion
  expression: weight <= 0
  action: ALLOW
```

`data/botPolicies.yaml:251-253`

so a client that ends at -5 is allowed outright, not given a Meta Refresh. The sample in
`configuration/thresholds.mdx:32` uses `weight < 0` for its own allow threshold, so the two
pages disagree with each other as well as with the shipped file.

Nothing here is dangerous, but both pages are load-bearing for someone deciding whether the
default policy is sufficient, and both currently overstate how much a `WEIGH` rule is just a
bookkeeping device.

---

## Why this is not a security report

Neither item lets traffic through that the shipped policy would otherwise stop; item 1 makes
a reader underestimate the default protection, item 2 misdescribes which threshold fires. The
place for an actual vulnerability is `SECURITY.md`, which asks for email to
`security@techaro.lol`.

## What not to say

Do not claim the code is wrong in either case. The code is internally consistent and the
thresholds do what their expressions say; the docs describe an older or simplified model. Frame
it as documentation drift, with the file:line evidence, and let them decide.
