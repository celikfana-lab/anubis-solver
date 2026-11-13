# anubis-fetch — a DSH plugin

A DSH tool, `anubis_fetch`, that fetches pages protected by
[TecharoHQ/anubis](https://github.com/TecharoHQ/anubis). The built-in `web_fetch`
gets the challenge page and stops; this one solves the proof-of-work locally,
submits the response, keeps the auth cookie and returns the page behind it.

```
URL: https://anubis.techaro.lol/
Status: 200  Title: Anubis: Web AI Firewall Utility | Anubis
Anubis challenge solved locally: sha256 difficulty 16 nonce 4845 in 0.897 ms

Anubis: Web AI Firewall Utility | Anubis
Weigh the soul of incoming HTTP requests to protect your website!
...
```

## How it works

```
model ──anubis_fetch(url)──► plugin ──► tools/anubis_fetch.js   (default)
                                   │      crypto + fetch, no Python
                                   └──► tools/anubis_fetch.py   (fallback)
                                          AnubisClient → libanubis_solver.so
```

**Two engines, and the default needs nothing but Node.**

`tools/anubis_fetch.js` is a pure-Node implementation: `node:crypto` for the proof
of work, the built-in `fetch` for HTTP, and a cookie jar of its own. No Python, no
native library, no child process, no npm packages. It handles `fast`, `slow`,
`sha256`, `metarefresh` and `hashx` — the last one by compiling the challenge's
HashX program to wasm with `wasm/hashx_jit.mjs`, which is 7x the interpreter.

`tools/anubis_fetch.py` is the original driver, and `argon2id` is the one algorithm
still worth reaching for it (or for the C engine): ~19 MiB of memory-hard work per
attempt is not something to reimplement in JS. The plugin uses it when the
challenge names `argon2id` and the file is present.

The JS proof of work was checked against the C engine rather than trusted: for the
same challenge both find the same nonce and produce the same digest, and the C
engine accepts the JS nonce — including the little-endian edge case for challenges
whose last byte is >= 0x80.

Returns a JSON value matching the tool's declared schema: `url`, `finalUrl`,
`statusCode`, `title`, `challenge` (algorithm, difficulty, nonce, response,
elapsedMs, rounds), `stillChallenged`, `truncated`, `content`.

## Install

```bash
# from the dsh profile (this is what plugin_manager install_bundle does)
pnpm add @local/anubis-fetch@link:$REPO/dsh-plugin
```

then add `@local/anubis-fetch` to `dsh.profile.bundles` in the profile's
`package.json`, or do the same thing through the sanctioned tool:

```
plugin_manager install_bundle  target=link:/path/to/anubis-solver/dsh-plugin
```

It appears as an entry with id `anubis-fetch`. Uninstall with
`plugin_manager remove_bundle target=@local/anubis-fetch`.

## Configure

`cordis.patch.yml` carries the defaults; override them under `config:`:

| key | default | meaning |
|---|---|---|
| `repo` | this checkout | where `tools/anubis_fetch.js` lives |
| `engine` | `auto` | `auto` = JS, Python only for argon2id/hashx; `js` = never spawn; `python` = always use the driver |
| `python` | `python3` | interpreter for the fallback driver |
| `timeoutMs` | `60000` | tool timeout; the driver gets 5 s less |
| `maxChars` | `100000` | default body cap (the tool also accepts `maxChars`) |
| `threads` | library default | solver worker threads |
| `impersonate` | off | `chrome` / `firefox` / `safari` via curl_cffi, for deployments that weigh JA3/JA4H |

Requirements for the default engine: **Node 20+ and nothing else**. Only the
argon2id/hashx fallback needs `python3` with `requests` and the library built at the
repo root (`make`); `impersonate` additionally needs `curl_cffi`.

## Test

```bash
node --test dsh-plugin/test.mjs
```

Five tests against a stub context, so no DSH packages are needed: the plugin's
declared name and services, the registered tool's schema and prompt section, a
non-http URL rejected before spawning, a **real solve** of
`https://anubis.techaro.lol/` with the result checked against the output schema
and the rendered text, and a missing driver reported rather than swallowed.

## Two things the harness told us, the hard way

- **A prompt section needs a finite `order`.** `ctx.systemPrompt.section({name,
  text})` without one throws `prompt section "..." order must be a finite number`
  at load time, and the plugin silently fails to activate. It now sits at
  `getSectionOrder('TOOL_WEB_FETCH') + 50`, i.e. just after `web_fetch`.
- **The loader only reports a failed activation as a one-line diagnostic.** The
  first attempt failed with `SyntaxError: Unexpected identifier 'challenge'` — a
  quoting slip in the tool description that `node --check` finds instantly.
  `pnpm add` had already succeeded by then, so the package looked installed while
  the tool was missing. `node --check index.js` before installing is the cheap
  habit.

## Plugin-authoring notes

It is deliberately **import-free**: only `node:child_process`, `node:fs` and
`node:path`. The profile has no `@deepseek-ai/*` packages, and Node resolves an
import from this directory by walking up from the checkout, not from the profile,
so importing `@deepseek-ai/dsh-tools` for `defineTool` would fail. A raw tool
object is enough: `register()` requires `name`, `parameters` as JSON Schema,
`output.schema` plus `output.render(args, value)`, and an optional positive
`timeoutMs`. `export const inject = ['tools', 'systemPrompt']` states the services
the plugin needs.

## The metarefresh discovery

`anubis.techaro.lol` serves `metarefresh` (a redirect proof, no maths) as often as
`sha256`. When the page carries a `<meta http-equiv="refresh">` the plugin follows
it. When it does **not** - the deployment's own JS builds the call instead - the
plugin synthesises it from the same parameters `main.mjs` uses, and there is one
that matters:

```
pass-challenge?challenge=<randomData>&id=<id>&redir=<url>&elapsedTime=<ms>
               ^^^^^^^^^^^^^^^^^^^ omitting this is a 403, every time
```

That was found by probing the live endpoint: without `challenge=` every delay from
1.6 s to 2.4 s returned 403, and with it 12/12 attempts passed at every delay. The
delay itself is not what the server checks here.
