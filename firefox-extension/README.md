# Anubis solver — Firefox extension

Solves Anubis proof-of-work challenges faster than the page can, in one of three
engines, and paints the result into Anubis's own progress bar:

1. **native host** — `libanubis_solver.so` picks the best backend the machine
   has (CUDA, Level Zero, Vulkan, OpenCL, then SHA-NI/AVX-512 on the CPU). The
   fast path wherever `install.sh` has been run, Windows and macOS included.
2. **WebGPU** — the extension ships `webgpu/sha256.wgsl` and only uses it after
   a known-answer self-check against WebCrypto. This is the fast path when the
   host is missing but the browser has a real GPU (Firefox with
   `dom.webgpu.enabled`).
3. **wasm 4-wide** — the repository's `wasm/sha256_pow_batch.wasm` in a Worker,
   when neither of the above is available.

While it works, the page carries the repository's anti-anti-AI mascot in place
of Anubis's art and the headline **Hijacked Anubis** (one page in a thousand
gets `mascot/deepseek-chan.webp` and *"what is the point of life? to like and
sub"* instead; `?anubis-easter=1` or `=0` forces either, and
`node test-look.js` checks the odds), re-asserted on every
repaint because the page's own solver fails to start (its wasm is cancelled) and
falls back to a "Calculation error!" panel. The status line also counts seconds,
so a long solve never looks frozen at 99%.

The progress bar no longer invents a denominator. A solve stops at its first
qualifying nonce, and every `solve` call pays a fixed start-up cost, so probing
the rate with short searches measured 1.8-127 MH/s on an engine that actually
runs at ~25-90 MH/s. The first solve of a given (algorithm, payload size) now
reports **no percentage** and the bar pulses; the host then remembers the rate it
really got (`nonces hashed / seconds`) and the next solve has a real estimate.
That rate is cached in `~/.cache/anubis-solver/speeds.json`, keyed by algorithm,
payload size and kernel, so it survives restarts and the next page load shows
speed immediately. The status counts seconds either way, so it never looks
frozen.

The bar names the engine, not just the tier: the native host reports which
backend actually ran (`vulkan`, `levelzero`, `cuda`, `opencl`, `avx512`, `avx2`,
`shani`, `cpu`) and the device it ran on, so the line reads

    Solving natively · sha256 · difficulty 32 — Vulkan · Intel(R) Iris(R) Xe Graphics (ADL GT2) — 137.2 MH/s — 42%

or `AVX-512 · 4 threads` on the CPU, or `WebGPU · Intel · Intel(R) Iris(R) Xe
Graphics` in the browser path. The first frame names the best backend the
machine has before anything runs; the progress frames replace it with the one
that is actually working, so it can change once at the start.

Before any of that, the page's own solver is stopped. Anubis's `main.mjs`
fetches `…/.within.website/x/cmd/anubis/static/wasm/{simd128,baseline}/{alg}.wasm`,
compiles it with `WebAssembly.compileStreaming`, and posts the module into a
worker — so the module is a request the extension can cancel, and cancelling it
means the miner never compiles anything. `block.js` matches exactly that path
(including a base prefix), and `test-block.js` checks the rule against the URLs
a live page builds from its own `anubis_base_prefix`/`anubis_version`.

The page reacts to the missing module by showing its own error state, so the
content script remembers the original headline and mascot and puts them back
while it solves. `fast`/`slow` have no wasm module to cancel (their worker is
plain JS), so those tiers are left to the page — the extension still paints the
bar and navigates first. If nothing of ours works, the tab is unblocked again and
Anubis's solver resumes.

Measured on the same challenge (`difficulty 18–22`, this machine):

Measured on the same challenge (`difficulty 18–22`, this machine):

| engine | SHA-256 rate | where it was measured |
|---|---:|---|
| native host, GPU backend (Level Zero / Vulkan) | ~137 M hashes/s | `tools/bench_gpu.py` |
| WebGPU, `webgpu/sha256.wgsl` | 86.7 M hashes/s | `webgpu/README.md` |
| native host, CPU-only (SHA-NI, 4 threads) | ~20 M hashes/s | this README |
| our wasm, 4 nonces wide (`wasm/sha256_pow_batch.wasm`) | ~3.4 M hashes/s | this README |
| official Anubis wasm (`simd128/sha256.wasm`) | ~1.9 M hashes/s | this README |

The engines are tried in that order for that reason: whatever CUDA/Level Zero/
Vulkan gives the native host is the best this machine can do; WebGPU is next;
the wasm worker is the last resort. The extension does not measure any of them
itself, it only reports what the engine it picked says.

A live `difficulty 12` challenge — 4,000 hashes on average — is solved in
**0.5–0.9 ms** end to end, and the answer is accepted by a real Anubis v1.28.3
(`python3 test-native.py` proves it, no browser needed).

## How it fits together

```
page load
   └─ content.js            reads <script id="anubis_challenge">, starts the bar
   └─ background.js         cancels the page's .wasm, then tries the native host
        └─ anubis_native.py    (Firefox starts it; 4-byte length + JSON on stdio)
             └─ libanubis_solver.so   the C engine, every backend it finds
   └─ if the host is absent: webgpu/gpu-solver.js  (self-check, then scan)
   └─ if the GPU fails:      wasm/pow-worker.js    (4-wide wasm)
   └─ pass-challenge?id=…&response=…&nonce=…
```

Native messaging cannot be used from a content script, so the content script only
extracts the challenge; everything else happens in the background script.

## Install

```bash
./install.sh              # per-user: ~/.mozilla/native-messaging-hosts/anubis_solver.json
sudo ./install.sh --system    # /usr/lib/mozilla/native-messaging-hosts/
```

Then, in Firefox: `about:debugging` → **This Firefox** → **Load Temporary Add-on**
→ pick `manifest.json` in this directory. For a permanent install, zip the
directory and have it signed.

`install.sh` rewrites the manifest's `path` to this checkout's absolute path, so
re-run it if you move the repository.

On Windows the host is the registry key above and `libanubis_solver` must be a
`.dll` next to `anubis_native.py`; the extension does not care which of the two
runs, it only sees whether the host answers.

## The toolbar panel

Clicking the add-on's button opens a panel over the page: solves taken, time
spent, time saved against Anubis's own in-page solver, a bar per engine (average
rate, so `Vulkan` and `AVX-512` and `wasm 4-wide` can be compared at a glance),
the last solves as bars with the page's own expected time behind them, and a
short explanation of what the add-on is. The bars come from
`browser.storage.local`, capped at 500 entries; "Clear history" empties them and
"Solve this page" re-runs detection on the current tab.

"Saved" is an estimate and the panel says so: it compares each solve with
`2^difficulty / page rate`, where the page rates are the measured ones from
`SPEED.md` (1.9 M hashes/s for the shipped sha256 module, 3.2 M for hashx). A
single solve stops at its first hit, so per-solve numbers are noisy - the
session totals are the part worth reading.

## Tests

```bash
node test-block.js                               # the block rule vs Anubis's own solver URLs
node test-block.js --url http://127.0.0.1:8080/  # ...and against a live challenge page
node test-stats.js                               # the panel's arithmetic (21 checks)
node test-look.js                                # the mascot/headline odds (13 checks)
node test-webgpu.js                              # shader nonce placement vs node crypto (25 checks)
python3 test-native.py --start-gate              # betterAnusbis, sha256, difficulty 20
python3 test-native.py --start-anubis            # the real Anubis, built from $ANUBIS_SRC
python3 test-native.py --start-gate --algorithm hashx --difficulty 26
python3 test-native.py --url http://127.0.0.1:8923/   # or against a server you already run
```

`--start-gate` launches `betterAnusbis` in front of a throwaway backend on free
ports, so the full Anubis exchange (page, challenge JSON, cookie,
pass-challenge) is real, with the algorithm and difficulty you name. The
default is `sha256` at difficulty 20 — the tier the WebGPU and 4-wide wasm
kernels implement, and the one a real site issues. `--start-anubis` does the
same with upstream Anubis, built from `$ANUBIS_SRC` (default `../anubis`) unless
`--anubis-binary` names one.

### "Sad Anubis: your browser is configured to disable cookies"

That page is Anubis's own check, not the extension: `PassChallenge` looks for
the verification cookie and answers with that page when it is missing
(`lib/anubis.go`). Anubis sets the cookie as **`Secure; SameSite=None;
Partitioned`**, and a browser will not store that on a plain `http://` origin,
so it is always missing there. Run any local Anubis the way `--start-anubis`
does:

```
-cookie-secure=false -cookie-partitioned=false -cookie-same-site=Lax
-use-remote-address
```

`-use-remote-address` is there because without a proxy in front, Anubis has no
`X-Real-IP` header and answers every request with a 500. Over https none of this
applies.

The flag people forget is `-cookie-partitioned=false`. Anubis defaults to
`Secure; SameSite=None; Partitioned`, and turning off `Secure` for a local http
server leaves a **Partitioned cookie without Secure** - which Firefox rejects
outright, so the challenge cookie silently never exists and every
`pass-challenge` lands on the cookies-disabled page. Check what your server
sends:

```bash
curl -sD- -o /dev/null http://127.0.0.1:8080/ | grep -i set-cookie
```

`SameSite=Lax` with no `Secure` and no `Partitioned` is what a local http gate
should show. The extension now spots that page and says so in the corner of the
window instead of leaving you to guess.

## Try it in a browser

```bash
# one terminal per line: a backend, then a sha256 gate in front of it
(cd /tmp && python3 -m http.server 8000)
./betterAnusbis/betterAnusbis --listen 127.0.0.1:8080 --target http://127.0.0.1:8000 \
    --algorithm sha256 --difficulty 20
```

Load the add-on, open `http://127.0.0.1:8080/`, and the gate's challenge page is
the one the extension takes over. `--algorithm hashx --difficulty 26` gives the
other tier; `--difficulty 24+` makes the progress bar worth watching.

### The bits Firefox requires

- **Extension side**: `"permissions": ["nativeMessaging"]` and an explicit add-on
  ID in `browser_specific_settings.gecko.id` (`anubis-solver@celikfana-lab`). The ID
  must be explicit because the app manifest allow-lists it — an auto-generated ID
  would change and break the pairing.
- **Host side**: `native-host/anubis_solver.json`, with `name` matching the string
  passed to `sendNativeMessage` (`anubis_solver`), `type: "stdio"`, an absolute
  `path`, and `allowed_extensions: ["anubis-solver@celikfana-lab"]`.
- **Manifest location** (Firefox, per-user):
  - Linux `~/.mozilla/native-messaging-hosts/anubis_solver.json`
  - macOS `~/Library/Application Support/Mozilla/NativeMessagingHosts/anubis_solver.json`
  - Windows registry key `HKCU\Software\Mozilla\NativeMessagingHosts\anubis_solver`
    whose default value is the absolute path of the manifest.

## The protocol, as the host implements it

Each message is a 4-byte unsigned length in **native byte order** followed by UTF-8
JSON. Requests (extension → host):

```json
{"cmd": "ping"}
{"cmd": "info"}
{"cmd": "solve",  "algorithm": "sha256", "randomData": "0011…", "difficulty": 12}
{"cmd": "verify", "algorithm": "sha256", "randomData": "0011…", "difficulty": 12, "nonce": 587}
```

Replies (host → extension):

```json
{"ok": true, "pong": true}
{"ok": true, "version": "2.0.2", "threads": 4, "batchWidth": 8, "gpu": null, "algorithms": [...]}
{"ok": true, "algorithm": "sha256", "nonce": 587, "response": "000a…", "elapsedMs": 0.54}
{"ok": true, "valid": true, "response": "000a…"}
{"ok": false, "error": "ValueError: unsupported algorithm 'sha512'"}
```

Nothing but framed replies is ever written to stdout — diagnostics go to stderr,
which Firefox forwards to the browser console.

Algorithms supported: `fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx`
(whatever `libanubis_solver.so` provides, plus GPU backends if the library was
built with them).

## It runs by itself

Anubis's own page already has a status line and a bar — this takes them over
instead of adding a second one. `#status` becomes

```
Solving natively · sha256 · difficulty 26 — 17.83 MH/s — 4 threads — 43%
```

`#progress .bar-inner` is driven with the real percentage, `aria-valuenow`
included, and a `MutationObserver` puts the text back over the page's own solver,
which keeps writing to the same elements until the tab is navigated away. The
panel in the corner only exists for Anubis versions without those elements.

Modes, chosen by what answers:

| mode | when | says |
|---|---|---|
| `native` | the native host is installed | `Solving natively · <kernel>` |
| `wasm` | no host (Windows/macOS without install.sh), algorithm is `sha256` | `Solving with better wasm` |
| `page` | no host and no faster kernel of ours for that algorithm | nothing, Anubis's solver keeps the bar |

The wasm mode packages `wasm/sha256_pow_batch.wasm` (4 nonces wide, 5.1 MH/s here
against Anubis's ~1.9) plus `wasm/pow-worker.js`, which speaks the same ABI as
Anubis's own modules (`data_ptr`/`set_data_length`/`result_hash_ptr`/
`anubis_work`) and posts the nonce and digest back. Proofs from it were checked
against the C library: nonce 5133809 at difficulty 20 verifies with digest
`00000dcaf513…`.

`hashx` deliberately stays in `page` mode: our wasm interpreter does 0.48 MH/s
where Anubis's per-challenge compiled module does ~3.2, so taking it over would
be slower. A `WebGPU` mode is **not** implemented — the repository has WGSL for
`meatrider`, not for the `sha256`/`hashx` challenges a website issues, and a label
that promises WebGPU while running wasm is worse than no label.

## Auto-detection

The add-on now watches for Anubis pages instead of waiting for a click: a content
script runs at `document_start` on every page, returns immediately if there is no
`<script id="anubis_challenge">`, and otherwise parses the challenge and hands it
to the background script. The trade for that is the `*://*/*` permission — an
add-on that only acts on a click can ask for `activeTab` alone; one that starts by
itself has to be allowed to look.

While the native host works, a panel in the bottom-right of the page shows:

```
anubis-solver                    hashx · difficulty 26
[############                        ]
14%        17.83 MH/s · 4 threads        3.2 s
```

The engine name is the kernel that actually answered — `avx512`, `avx2`, `cpu`,
`cuda`, `vulkan`, `opencl`, `levelzero`, `tpu`, `hashx`, `argon2id` or
`meatrider` — reported by the library through `anubis_active_kernel()`, so it
says what ran rather than what is installed. The rate comes from a calibration
probe a few bits below the real difficulty, and the bar is `elapsed / estimate`;
when the proof arrives the panel flips to `solved` and the page navigates.

The protocol is a **port**, not `sendNativeMessage`: `{"cmd": "solve_stream"}`
gets `{"event": "start"}` with the kernel and the estimate, a `{"event":
"progress"}` frame every ~120 ms, and a final `{"event": "done"}` with the nonce
and response. One-shot messaging takes only the first frame, which is why the
streaming path exists.

## The .xpi

```bash
./build-xpi.sh                 # -> ../build/anubis-solver-firefox-2.51.0.xpi
./build-xpi.sh --sign          # the same, then `web-ext sign` (AMO_API_KEY/AMO_API_SECRET)
```

An `.xpi` is a zip with `manifest.json` at its root; the script also checks the two
things that silently break native messaging before it writes one: the add-on ID in
`manifest.json` must appear in `native-host/anubis_solver.json`'s
`allowed_extensions`, and every file the manifest names must exist. It packages
only the runtime files (`manifest.json`, `background.js`, `content.js`, `icons/`)
and leaves the host, the installer and this README out of the archive.

The icons are generated from `../mascot/icon.png` at 48, 96 and 128 pixels.

Install:

1. `./install.sh` once per checkout — it writes the OS-level native manifest
   Firefox reads at startup.
2. **Temporary:** `about:debugging` → This Firefox → Load Temporary Add-on → pick
   the `.xpi`. It lasts until Firefox restarts. Reload it there after rebuilding —
   a temporarily loaded add-on keeps running the old copy until you do.
3. **Permanent:** the file needs a signature. Upload the `.xpi` at
   <https://addons.mozilla.org/developers/> (AMO signs it and hands back a signed
   copy), or run `./build-xpi.sh --sign` with your AMO API key. A plain
   `xpinstall.signatures.required=false` only works on Developer Edition/Nightly.

`web-ext lint` on the packaged file reports 0 errors. The two warnings are
expected: `data_collection_permissions` (required for new AMO submissions since
Firefox 140) is not understood by the 115 minimum this add-on declares, and the
Android variant of the same key is irrelevant because native messaging is
desktop-only.

## Testing without a browser

```bash
python3 test-native.py                       # against http://127.0.0.1:8923/
python3 test-native.py --url https://some.anubis.host/
```

It spawns the host exactly as Firefox does, checks `ping`/`info`/unknown-command
handling, solves a live challenge, verifies the nonce through the C engine, then
does the full pass-challenge exchange with a cookie jar and asserts the protected
page comes back. The page it asserts on is the repo's `PAST THE WALL` fixture, so
put one behind the gate:

```bash
mkdir -p /tmp/ba-site && echo '<html><body><h1>PAST THE WALL</h1></body></html>' \
  > /tmp/ba-site/index.html
(cd /tmp/ba-site && python3 -m http.server 3000 &)
(cd betterAnusbis && ./betterAnusbis --listen 127.0.0.1:8923 \
   --target http://127.0.0.1:3000 --public-url http://127.0.0.1:8923 --difficulty 12 &)
python3 test-native.py --url http://127.0.0.1:8923/
```

Current output:

```
  ok   ping
  ok   info  libanubis_solver 2.50, 4 threads, sha256 batch 8, gpu Intel(R) Iris(R) Xe Graphics (ADL GT2)
  ok   unknown command is an error, not a crash
  ok   live solve (sha256 difficulty 12)  nonce 6839 in 2.95 ms
  ok   the engine agrees the nonce is valid
  ok   the server let the native solve through  49 bytes after the wall
```

`wasm/live-server.md` has the steps to bring up the Anubis instance it tests
against.

## Troubleshooting

| message | cause |
|---|---|
| `No such native application anubis_solver` | manifest not in the right place, or not named `anubis_solver.json`; restart Firefox (manifests are read at startup) |
| `This extension does not have permission to use native application` | `allowed_extensions` does not contain the add-on ID — check `browser_specific_settings.gecko.id` |
| `File at path … does not exist, or is not executable` | `install.sh` has not been run since the repo moved, or the host lost its `+x` bit |
| `TypeError: browser.runtime.connectNative is not a function` | the `nativeMessaging` permission is missing from `manifest.json` |
| host exits immediately | run it by hand: `echo -n '' \| ./native-host/anubis_native.py` — it prints the library version to stderr |

The host also logs the manifest path and add-on ID Firefox passes it, which is the
fastest way to see whether the browser got as far as launching it.

## Chrome, for reference

Same idea, three differences: `allowed_origins: ["chrome-extension://<id>/"]`
instead of `allowed_extensions`, the manifest lives under
`~/.config/google-chrome/NativeMessagingHosts/`, and `browser_specific_settings`
is not supported (use a separate manifest without it). The host itself is
unchanged — the framing protocol is identical.

## Configuration

| variable | effect |
|---|---|
| `ANUBIS_THREADS` | pin the worker count (`ANUBIS_THREADS=1` for a single-threaded number, or on a busy machine) |
| `ANUBIS_LIB_DIR` | where `libanubis_solver.so` lives, if not the repository root |

## Footprint

The host is a Python process, so it costs more RAM than it needs to: **36.3 MB of
RSS**, of which ~30 MB is CPython rather than the solver. CPU is 205 ns per
SHA-256 hash on one thread (the native SHA-NI kernel), against 597 ns for Anubis's
in-page module — see [`../SPEED.md`](../SPEED.md#what-uses-less-ram-and-what-uses-less-cpu).

A native host written in C instead of Python would be a few megabytes; the protocol
is thirty lines and the library is already there. That is the obvious next step for
this directory and the one number here clearly left on the table.

## Security

- The host runs with your privileges. Only the extension ID listed in
  `allowed_extensions` can launch it, and Firefox enforces that, not this code.
- It solves and returns a digest; it does not fetch anything itself, does not read
  files the extension does not ask about, and holds no secrets.
- The extension only reads the page when you click the toolbar button (`activeTab`).

---

Built with [DeepSeek V4.1 Flash](https://huggingface.co/deepseek-ai/DeepSeek-V4.1-Flash-1017)
running [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness),
per the repository's MIT + attribution license.
