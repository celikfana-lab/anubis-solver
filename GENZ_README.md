<p align="center">
  <img src="meme/hourofmisery.jpg" width="420" alt="the hour of unhappiness">
</p>

# GENZ_README.md

> fr fr this is the repo explained like ur brain got deep-fried by 6 hours of
> short-form video. same project, 0 professionalism, all facts still real.
> if u want the grown-up version it's [README.md](README.md) and
> [MIGRATE.md](MIGRATE.md). this one is for the chat.

welcome to the function, chat. nobody read the 3,000-line README so now u get
the version with memes. **no cap, every number in here is real.** the slang is
cosmetic, the benchmarks are not.

---

## TL;DR (the "explain in 10 secs" version)

| what | the actual thing |
|---|---|
| **this repo** | `anubis-solver`, a proof-of-work engine in C + Python + WASM + every GPU backend known to man
| **the gate** | `betterAnusbis`, an Anubis-compatible bot wall, **one C file**, 63 flags, drop-in config
| **the solver** | `libanubis_solver.so`, CUDA → Level Zero → Vulkan → OpenCL → CPU, in that order, always re-verifying
| **current tag** | `v1.50.1 "headslam"` |
| **tests** | 155 parity checks + 11 algorithm checks, all green, or it didn't happen |
| **vibe** | "why is this in C", because it's fast and c doesn't have a `node_modules` folder fr

---

## THE CAST: who is sigms, who is L bozo

this is the part u actually came for. there are exactly two kinds of entity in
this repo's universe.

### 😤 sigms

**sigms = the things that solve the problem.**

- **`betterAnusbis`**, the gate. one C file. no Go toolchain, no container, no
  build system drama. it proxies ur traffic, hands out challenges, checks the
  answer, and gets out of the way. **it does not hesitate.**
- **`libanubis_solver.so`**, the solver. it will mog ur CPU, and if u have a GPU
  it will mog that too. dispatch order CUDA → Level Zero → Vulkan → OpenCL →
  CPU, and every GPU hit gets **re-verified** before it's accepted, because
  trusting a GPU kernel with no check is an L waiting to happen.
- **the hand-written Intel Xe assembly**, yes really, 2,846 instructions for
  SHA-256 and **30,260** for HashX, written and then proved digest-by-digest
  against the C reference. that's not rizz, that's just work.
- **the 155 tests.** sigms does not ship on vibes.

sigms energy: reads the spec, implements it, compares against the reference,
writes the number in a table. no glaze, no cope.

### 💀 L bozo

**L bozo = the things that get walled.**

- **headless bot farms** scraping ur site with 400 tabs of Chromium. they don't
  compute PoW, they don't pass the check, they get the honeypot. **ratio.**
- **"AI crawlers"** that treat `robots.txt` as a suggestion. there's a
  whole `HALL_OF_SHAME.md` for these. skill issue.
- **the wasm-less client** that shows up to an `argon2id` challenge with no
  kernels and asks "why is it slow". bro the kernels are one `--web` flag away.
- **anyone cranking difficulty to 12 "for security"** and then wondering why
  mobile users bounce. that's not sigma grindset that's just making ur users
  cry. difficulty 4 is right there, it's free, it's fast, **bet.**
- **anubis-solver's own bugs**, historically. we found 7 in our own gate
  (header injection, a bind address that ignored the address, IPv6 rules
  silently doing nothing, a DENY that any cookie could walk past). we fixed all
  7 and wrote them down in `SECURITY-REVIEW.md`. **catching ur own L is the most
  sigma thing there is.** the L bozo move is pretending it never happened.

---

## the memes, explained by someone who has read the source

### `ultraallow.jpg`, "BEYOND APPROVED, ∞/10"

this is a negative `WEIGH` rule watching a well-behaved crawler. the gate
matched it on ASN, CIDR and user agent, accumulated negative weight, crossed the
threshold in the good direction, and let it through without a challenge. bro is
**beyond approved**. aura +∞.

### `ultradisallow.jpg`, "ULTRA DENIED, -10/10"

this is the same gate looking at a scraper that faked its user agent but forgot
its ASN doesn't match. `DENY`, no cookie helps u, no challenge, no explanation.
that's not a ratio, that's a **cancellation**. the request never even met the
backend.

### `dumbass.jpg`, "COMPLETE DUMBASS"

a bot that solved the challenge **but** sent the nonce as a string with a
leading zero and got `403`. or a client that solved `sha256` at difficulty 12
on a laptop. same energy. the gate is not mad, it's just disappointed.

### `avoidhim.jpg`, "AVOID HIM"

the **honeypot**. there's a link in the challenge page that no human will ever
click and no legitimate crawler should parse. click it and ur IP gets its own
reputation counter, forever, and the tarpit gets slower on purpose. **avoid
him.** he's not a bug he's a feature.

### `nohesitate.jpg`, "HE DOESN'T HESITATE?"

the hot path. request in → policy evaluated in load order → first
`ALLOW`/`DENY`/`CHALLENGE` wins → response out. no database round trip unless u
asked for one, no allocate-per-header, no "let me think about it". the gate
decides in **microseconds** and moves on. hesitating is for servers with
`node_modules`.

### `hourofmisery.jpg`, "THE HOUR OF UNHAPPINESS"

this is what `hashx` feels like. it is not a hash function. it is a **program**:
512 instructions over eight 64-bit registers, generated fresh from ur challenge
bytes, with 16 conditional branches where at most one ever fires. it is
designed to be cheap on a GPU and miserable on a scraper. the hour of
unhappiness is the scraper's hour, not urs.

### `tearpain.jpg`, "TEARS OF PAIN AND AGONY"

what a bot farm's logs look like after the gate started returning `403` to
everything. every worker thread gets a challenge, none of them can solve it,
and the tarpit keeps them alive for a few extra seconds each. **cope.**

### `whatthefuck.jpg`, "WHAT THE FUCK JUST HAPPEN"

the exact face of a "smart" scraper on its first request to a site running this
gate. it sent `User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)` from a
residential ASN with no reverse DNS and got challenged instead of allowed.
the FCrDNS check said no. nothing happened. that's the point.

### `thefuckisbrosaying.jpg`, "THE FUCK IS HE EVEN SAVING?"

the face of anyone reading our `--store file:PATH` snapshot. it saves the
challenge ledger and the honeypot counters every five seconds and on `SIGTERM`,
so a restart doesn't forget who's been naughty. it is **not** a journal, it
does not coordinate with other processes, and it is not bbolt/valkey/S3. that's
the whole thing. it's a text file. **let him cook.**

---

## the lore (real history, cooked)

- anubis (the upstream, in Go) is the original. this repo is the
  **down-bad reimplementation**: same challenge JSON, same routes, same cookie
  name, so ur browser doesn't even notice it got swapped.
- the gate was written by **DeepSeek V4.1 Flash** running DSH. it was described
  as "one C file" at the start and it has stayed one C file, which is either
  discipline or a cry for help.
- at some point we diffed the gate against upstream line by line and found
  **7 security bugs in our own code**. five of them were **fail-open**: an
  operator wrote a rule and the rule quietly didn't apply. that's the classic
  "it looks secure" L. they're all fixed and all documented. no glaze.
- the GeoIP reader took **four attempts** because pointer offsets in MaxMind DB
  files are relative to the section, not the file, and the pointer width is
  `size >> 3`, not `size`. it now returns GB, GB, CN, SE, JP on MaxMind's own
  test databases. **it's giving "I read the spec eventually".**
- the HashX Intel Xe assembly was verified by executing its own instruction list
  in Python, which caught: three wrong 64-bit multiplier decompositions, two
  aliasing bugs, and a `ror` that should have been `rol`. 30,260 instructions,
  484,160 bytes, **all 8 digests matching**. no hardware run though, we're not
  gonna lie about that. that's the difference between W and cap.

---

## how 2 run it (brainrot edition)

```bash
git clone https://github.com/celikfana-lab/anubis-solver
cd anubis-solver
make                      # the solver. it's one make. that's it. bet
cd betterAnusbis && make  # the gate. also one cc invocation. no cap

# run it in front of ur site
./betterAnusbis --target http://127.0.0.1:3000

# or run it beside ur existing anubis and compare notes
./betterAnusbis --listen 127.0.0.1:8081 --target http://127.0.0.1:3000 \
  --policy /etc/anubis/botPolicies.yaml --data-dir /etc/anubis/data \
  --secret-file /etc/betterAnusbis/secret.key
```

open `http://127.0.0.1:8080/`, the page solves itself, u get in, **W**.

if u run it without `--secret-file` every restart logs everyone out and u will
be in the group chat asking why. that's on u. that's an L.

---

## FAQ

**is it actually a drop-in?**
for the wire protocol and the rules: yes, fr. 41 rules + 5 thresholds + 2,711
CIDRs of the shipped upstream policy load and evaluate. for config: as of 1.50.1
the `store`/`metrics`/`geoip`/`openGraph`/`impressum`/`logging` blocks are read
from the same file. what it doesn't have: bbolt/valkey/S3, 25 of 31 locales,
HTTP/2. it says so out loud instead of silently doing something else.

**why C**
because the alternative was Go and then it would need 400 MB of toolchain to do
what `cc` does in one second. also c doesn't have a build system to argue about.

**is it fast**
it reuses connections to ur backend, decides in microseconds, and the solver
mogs a whole CPU farm with one GPU. the benchmarks in `SPEED.md` are real
numbers with the machine named. we do not do "up to".

**can it stop AI scrapers**
it stops the ones that can't or won't compute PoW, which is most of the cheap
ones. the expensive ones that run real browsers will still get through, and any
README that promises otherwise is **glazing**. it raises the cost. that's the
deal.

**ratio + u fell off**
we know. it's a bot wall. it's not that deep.

---

## real docs, for when the brainrot wears off

- [README.md](README.md), the actual project, actual numbers
- [MIGRATE.md](MIGRATE.md), moving from Anubis, step by step, plus the speed section
- [betterAnusbis/README.md](betterAnusbis/README.md), every flag the gate has
- [betterAnusbis/PARITY.md](betterAnusbis/PARITY.md), the gap list with file:line on both sides
- [SECURITY-REVIEW.md](betterAnusbis/SECURITY-REVIEW.md), the 7 bugs we found in ourselves
- [SPEED.md](SPEED.md), measured throughput, machine named, no vibes
- [HALL_OF_SHAME.md](HALL_OF_SHAME.md), the crawlers, named and shamed

<p align="center">
  <img src="mascot/anti-anti-ai.png" width="260" alt="the betterAnusbis mascot">
</p>

<p align="center">
  anubis mascot made by CELPHASE , anubis-solver mascot made by Chatgpt , everything else written by DeepSeek V4.1 flash running on Deepseek Harness (DSH)
</p>

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)
