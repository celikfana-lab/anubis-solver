# Anubis native solver — Firefox extension

Solves Anubis proof-of-work challenges with **`libanubis_solver.so`** instead of the
page's WebAssembly solver. The page can only use one core of wasm; the native host
uses the SHA-NI/AVX2 kernels and every core.

Measured on the same challenge (`difficulty 18–22`, this machine):

| engine | SHA-256 rate | |
|---|---:|---|
| **native host** (`libanubis_solver.so`, SHA-NI, 4 threads) | **~20 M hashes/s** | |
| our wasm, 4 nonces wide (`wasm/sha256_pow_batch.wasm`) | ~3.4 M hashes/s | **5.9× slower** |
| official Anubis wasm (`simd128/sha256.wasm`) | ~1.9 M hashes/s | **10.5× slower** |

A live `difficulty 12` challenge — 4,000 hashes on average — is solved in
**0.5–0.9 ms** end to end, and the answer is accepted by a real Anubis v1.28.3
(`python3 test-native.py` proves it, no browser needed).

## How it fits together

```
toolbar click
   └─ content.js          reads <script id="anubis_challenge"> from the page
   └─ background.js       browser.runtime.sendNativeMessage("anubis_solver", ...)
        └─ anubis_native.py   (Firefox starts it; 4-byte length + JSON on stdin/stdout)
             └─ libanubis_solver.so   the C engine, via the repo's anubis_solver.py
   └─ tabs.update(pass-challenge?id=…&response=…&nonce=…)
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
{"ok": true, "version": "1.10.0", "threads": 4, "batchWidth": 8, "gpu": null, "algorithms": [...]}
{"ok": true, "algorithm": "sha256", "nonce": 587, "response": "000a…", "elapsedMs": 0.54}
{"ok": true, "valid": true, "response": "000a…"}
{"ok": false, "error": "ValueError: unsupported algorithm 'sha512'"}
```

Nothing but framed replies is ever written to stdout — diagnostics go to stderr,
which Firefox forwards to the browser console.

Algorithms supported: `fast`, `slow`, `sha256`, `wasm-sha256`, `argon2id`, `hashx`
(whatever `libanubis_solver.so` provides, plus GPU backends if the library was
built with them).

## Testing without a browser

```bash
python3 test-native.py                       # against http://127.0.0.1:8923/
python3 test-native.py --url https://some.anubis.host/
```

It spawns the host exactly as Firefox does, checks `ping`/`info`/unknown-command
handling, solves a live challenge, verifies the nonce through the C engine, then
does the full pass-challenge exchange with a cookie jar and asserts the protected
page comes back. Current output:

```
  ok   ping
  ok   info  libanubis_solver 1.10.0, 4 threads, sha256 batch 8, gpu None
  ok   unknown command is an error, not a crash
  ok   live solve (sha256 difficulty 12)  nonce 9195 in 0.86 ms
  ok   the engine agrees the nonce is valid
  ok   the server let the native solve through  69 bytes after the wall
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
