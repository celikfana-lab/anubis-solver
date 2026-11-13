# Hall of shame

Claims that did not survive measurement. Other people's first, because that is
funnier, then ours, because that is fairer.

The rule for an entry: it has to be a *checkable* claim, it has to be wrong, and
the receipt has to be a command in this repository rather than an opinion.

---

## 1. "The 'hey Claude vibeslop me a CUDA Anubis solver' route is fundamentally dead"

The claim, from Xe Iaso's
[It took a year to ship WebAssembly in Anubis](https://xeiaso.net/blog/2026/anubis-wasm/)
(September 6, 2026), announcing memory-hard challenges:

> This makes Anubis challenges use a memory-hard proof of work function (argon2id)
> instead of just a CPU hard one. It also means that the "hey Claude vibeslop me a
> CUDA Anubis solver" route is on its way to being fundamentally dead.

**Verdict: falsified, by a file in this repository.**

This repository *is* the vibeslop CUDA Anubis solver — every line of it written by
DeepSeek V4.1 Flash — and it has had a working CUDA Argon2id kernel since before
that post. The relevant file is `results/argon2id-cuda-t4.json`:

| what | throughput | versus |
|---|---:|---|
| Argon2id on 2x Tesla T4, CUDA, shipped kernel | **1,758.6 h/s** (d8) | **20.7x** one Xeon CPU core |
| Argon2id on one T4, SASS A/B (different experiment: 64 concurrent) | 960.2 h/s | 1.34x the 715 h/s shipped kernel in the same A/B |
| Argon2id on an Intel Iris Xe, Level Zero | 195.5-200.5 h/s | 4.7-5.1x a CPU core |
| Argon2id on an Intel Iris Xe, Vulkan | 326.4 h/s | 8.6x a CPU core |
| Argon2id in WebGPU, Intel Iris Xe | **3.6 h/s** | **0.26x**: slower than the WebAssembly module |

Reproduce: `python3 tools/bench_argon2_gpu.py` with `ANUBIS_GPU_ARGON2=1`, and see
`SPEED.md#argon2id-on-cuda-opt-in`. Every run verifies the tag against
`argon2-cffi` before timing, so these are real hashes and not a busy loop that
computes nothing.

### What memory-hardness actually buys

Being fair to the claim, because it is directionally right about the cost and wrong
about the verdict:

- **It raises the floor, enormously.** 19,456 KiB and two passes per attempt means
  a single attempt costs ~13 ms natively and ~70 ms in a browser. That is what
  makes mass scraping expensive, and it is a genuinely good design.
- **It compresses the GPU advantage.** On the same iGPU, SHA-256 runs ~17x a CPU
  core while Argon2id runs ~8x. The ratio shrinks by half, which matters when you
  are choosing what to spend money on.
- **It resists the thing the claim was reaching for:** cheap custom silicon. An
  ASIC for Argon2id has to move 19 MiB per hash, so it gains little over a
  commodity GPU. That is the real win, and it is not nothing.

It does not, however, make a GPU solver "fundamentally dead" — it makes it ~10-20x
instead of ~1000x. A T4 reaches 20.7x a CPU core on the *shipped* kernel with no
tuning at all, and 1.34x more after reading the SASS. The one place memory-hardness
did stop this project was WebGPU on an Intel iGPU, and that was not the algorithm
being memory-hard in a useful way — it was WebGPU capping a storage binding at
128 MiB, which allows six concurrent 19 MiB hashes and therefore six threads' worth
of parallelism. That is an API limit, not a defence.

The honest summary: memory-hardness turns "a bot can do this 1000x faster than a
browser" into "a bot can do this 20x faster than a CPU core, at 19 MiB of bandwidth
per attempt". That is a much better place to be. It is not dead, and this
repository is the counterexample.

And the part that deserves credit: a year of work, a compiler bug found properly,
and a documented rebuild of `wasm-opt` so the build is reproducible. None of that
is in question here — only the prediction.

---

## 2. "A bug in the shared code means the client could send an invalid value that the server would accept as valid, but I don't think this is a practical concern"

Same post, defending the "same binary on client and server" design:

> This also does mean that a bug in the shared code means that the client could send
> an invalid value that the server would accept as valid, but I don't think this is
> a practical concern until something like that happens.

**Verdict: an accepted risk on the security boundary, and one this repository has a
live specimen of.**

The design makes the client and the server agree *by construction*. When the
implementation is right that is elegant. When it is wrong they agree on the wrong
answer, every self-test passes, and no client ever reports a problem — a gate that
is decorative but looks healthy.

Concretely: `webgpu/README.md` documents an Intel WebGPU backend that computes HashX
digests **wrong at 11-47 M hashes/s**. Fast, confident, wrong. If both sides ran
that shader, this is exactly the scenario: no error, no mismatch, no alarm.

That is why every page in `webgpu/` refuses to trust a backend until it has
reproduced known-answer digests from a *different* implementation, and why
`make verify-module` hands our digests to Anubis's own module and requires it to
accept them. A backend that cannot reproduce the reference digest is not used,
however fast it is.

---

## 3. "Our Argon2id module is at parity with Anubis's"

**Ours. Said in this repository's docs, and wrong twice.**

The claim was measured on the *block function* (1.7-1.9 us against their implied
1.8-2.0) and then applied to the whole *module*, which was 2.2x slower. Two
different artefacts, one sentence. Worse: even that module number was mostly a
build flag — `-ffreestanding` disabled the compiler's builtin `memcpy`, turning
every 1 KiB block copy into a call to a byte-at-a-time shim.

Rebuilt without it, and with the fill loop keeping each round in registers:
65-75 ms/hash against Anubis's 68-76, so **1.02-1.05x faster**, not 2.2x slower.
Reproduce: `cd wasm && make verify-module`.

---

## 4. "Our HashX interpreter does 1.7 M hashes/s"

**Ours.** It does 0.43-0.46 M. The 1.7 M figure was the *native C engine* from a
different table two sections away, copied into the wrong row. The compiled path is
honestly 7x the interpreter, not 1.6x — which should have been caught by arithmetic:
an interpreter within 60% of a compiler is not a number, it is a bug report.

---

## 5. "A transcript in the beginner docs"

**Ours.** The first draft of `web/beginner.html` showed the CLI being run with
`--max-chars` and `--difficulty`, neither of which exists. Caught by rendering the
page and reading it, not by any test. The rule that came out of it: **capture
transcripts, never type them.**

---

## 6. "The fallback is verified"

**Ours.** The site's layout check was passing against a server that was down — a
page that never loads also never overflows, so the check was green for the wrong
reason. It now asserts that the page loaded before judging anything else, and
reports a load failure separately from an overflow.

---

## 7. "She's working on a non-JavaScript version of Anubis, but it's not here yet"

The claim, from
[ZDNET, July 10 2025](https://www.zdnet.com/article/fed-up-with-ai-scraping-your-content-this-open-source-bot-blocker-can-help-heres-how/):

> She is well aware that many people are hesitant to run JavaScript due to security
> and privacy concerns. She's working on a non-JavaScript version of Anubis, but it's
> not here yet. It will be a while.

**Verdict: it shipped thirteen days before the article went up.**

Receipts, in a checkout of `TecharoHQ/anubis`:

```
$ git log -1 --format='%ad %s' --date=short 4ac59c3a
2025-06-06 feat(lib/challenge): HTTP meta refresh challenge method (#623)
$ git tag --contains 4ac59c3a | sort -V | head -1
v1.20.0                        # tagged 2025-06-27
```

`lib/challenge/metarefresh/metarefresh.go` registers the method
(`challenge.Register("metarefresh", &Impl{})`), issues an HTTP `Refresh` header, and
accepts the pass when `now >= IssuedAt + difficulty * 800ms`. There is no JavaScript
in it, which is the whole point of the method. It is also not a footnote: the
project's own demo site, `anubis.techaro.lol`, serves `metarefresh` about as often as
it serves `sha256` (see [`dsh-plugin/README.md#the-metarefresh-discovery`](dsh-plugin/README.md)).

The joke is what the JavaScript-free version turned out to be. It is not a puzzle, it
is a **timer**: at difficulty 4 it means "wait 3.2 seconds, then try again". Every
HTTP client follows a refresh header, so the version of Anubis that needs no
JavaScript is also the version that needs no *work* — it is one branch in
`tools/anubis_fetch.js`, and a scraper that is willing to sleep passes it.

---

## 8. "A computational puzzle, which is trivial for PCs but expensive for bots operating at scale"

**Verdict: the first half is exactly right, and it is the second half that the
product rests on.**

Receipts in this repository, at difficulty 4, which is 65,536 expected hashes:

| | hashes/s | one difficulty-4 challenge |
|---|---:|---:|
| one Xeon core, `fast` ([`results/speed-tiers.json`](results/speed-tiers.json)) | 6.69 M | 9.8 ms (the file's own `expected_ms`) |
| 56 threads on one server ([`results/server-2026-11-12.json`](results/server-2026-11-12.json)) | 349.64 M | **0.19 ms**, about 5,300 per second |

And against a live server ([`results/stress-anubis-2026-11-12.json`](results/stress-anubis-2026-11-12.json),
Anubis v1.28.3, `fast`, difficulty 4): 64 concurrent workers solved 116 challenges per
second, and the server used 3.1 of its 56 cores.

None of this is a criticism of Anubis. It is a speed bump, its own documentation never
claims otherwise, and a speed bump is still a speed bump. The claim that does not
survive is the one the article makes on its behalf — that the work is *expensive for
bots at scale* when it is 9.8 ms of one core per page, and cheaper on a GPU (entry 1:
20.7x for Argon2id on a T4, and see [`results/hashx-cuda-t4.json`](results/hashx-cuda-t4.json)).

---

## 9. "Support is currently free"

In full:

> Support is currently free. You can access it via its GitHub issue page or, for live
> chat, join Iaso's Patreon and ask in the Patreon Discord channel.

**Verdict: free support, with the live half behind a monthly payment, in one sentence.**
Two halves of a sentence that contradict each other, and the article does not notice.

It also dismisses the thing that would pay for that support — the commercial edition
"at this point just offers organizations more control over the program's branding" —
which is a strange way to describe the revenue that keeps the free tier free.

---

## 10. The "here's how" that never says how

The headline is "...this open-source bot blocker can help – here's how". The section
titled "How to install and run Anubis" is four sentences, and it contains no command,
no configuration file, no link to the documentation, and not even the name of the
container image. It says that there are "several ways to install" and that Anubis "is
meant to sit between your reverse proxy and your target service", then moves on to
support.

A reader who actually wants to do it gets further with
[`web/beginner.html`](web/beginner.html) in this repository — six commands, and the
output of each — or with Anubis's own README.

To be fair: it gets the licence right (Anubis is MIT — `LICENSE`, Xe Iaso, 2025), which
is more than most articles manage, and the Duke University figures it quotes are the
kind of number that makes the case better than the prose does.

---

## 11. A 1.02x faster Argon2id fill

**Ours, and it nearly shipped.** A rewrite that skipped one of the two 1 KiB
scratch arrays on the first pass measured 1.02x faster and was wrong: with the
"XOR over the old value" flag clear, the value to keep is `ref ^ prev`, not zero.
The digests caught it before release.

Two percent is not worth a wrong proof, and speed without a correctness check is
how you ship one.

---

## Rules this repository took from the above

1. Count attempts, not calls. The search stops when it wins, and the count is
   exponential.
2. Warm up the engine before timing it; WebAssembly and WebGPU both tier up.
3. Interleave A/B candidates in one process. Sequential runs measure the machine's
   mood.
4. Report ratios from one run; absolute numbers move 30% with load and clocks.
5. Verify against something that is not your own previous binary.
6. Say which artefact you measured. "The fill", "the module" and "the search loop"
   are three different claims.

The longer version, with every measurement and every failed idea, is
[`SPEED.md`](SPEED.md); the readable version is
[`web/mistakes.html`](web/mistakes.html).
