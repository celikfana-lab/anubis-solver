# The C MCP server

`anubis_mcp` is a Model Context Protocol server written in C, with no Python
and no Node in the loop. It speaks newline-delimited JSON-RPC 2.0 on stdio and
exposes seven tools: fetch a URL through an Anubis challenge, solve a challenge
from separate fields, solve one from the raw challenge/page, report the version,
and describe the compute backends. Both the solving and the HTTP work come from
this repository: `libanubis_solver.so` and `src/fetch/anubis_fetch.c`.

## Build

```bash
make -j8 libanubis_solver.so
make anubis_mcp
```

The fetch layer is now part of `libanubis_solver.so`, so the server is one
translation unit linked against the library it already needed. (`make services`
builds both the server and the API service.)

## Register it

Any MCP client that can launch a stdio server will do. Claude Desktop:

```json
{
  "mcpServers": {
    "anubis": {
      "command": "/absolute/path/to/anubis_mcp",
      "args": []
    }
  }
}
```

DeepSeek Harness, in `.dsh/config.json` (or the equivalent plugin config):

```json
{
  "mcpServers": {
    "anubis": { "command": "/absolute/path/to/anubis_mcp" }
  }
}
```

Because the binary links `libanubis_solver.so` with `$ORIGIN` in its runpath,
keep the two files in the same directory (the repo root, or an installed pair
under `/usr/local/bin` + `/usr/local/lib`).

## Tools

| tool | arguments | returns |
|---|---|---|
| `anubis_fetch` | `url` (required), `max_chars` (default 100000), `impersonate` optional | `status: <code>`, `url: <final>`, `transport: <openssl\|curl-impersonate/profile>`, then the page as text |
| `anubis_fetch_raw` | same as `anubis_fetch` | the same preamble, then the body exactly as it arrived: raw HTML or bytes, no tag stripping |
| `anubis_dump_headers` | `url` (required), `impersonate` optional | `status:`, `url:`, `transport:`, `headers: <n> bytes`, then the raw header block of every response seen, in order |
| `anubis_solve` | `algorithm`, `challenge` (hex), `difficulty`, `threads` optional | JSON `{"nonce":n,"response":"<hex>","algorithm":"..."}` |
| `anubis_solve_raw` | `input` (required), `threads` optional, `budget_ms` optional | the raw `pass-challenge` query, e.g. `id=<uuid>&response=<hex>&nonce=<n>&elapsedTime=1`; no network I/O |
| `anubis_version` | none | JSON `{"version":"2.40","codename":"shyleaf","algorithms":[...],"impersonate":"chrome116","impersonate_available":true}` |
| `anubis_backends` | none | JSON `{"compiled":["cpu","vulkan","opencl"],"available":["cpu","vulkan","opencl"]}`; `available` probes the drivers and can take a second on a cold stack |

`anubis_solve_raw` is for the case where the challenge is already in hand: paste
the `anubis_challenge` JSON, its `<script>` element, or the whole challenge page
and the tool returns the query parameters to append to `pass-challenge`. It
never fetches anything, so no URL, cookie or TLS fingerprint is involved.
`preact` and `metarefresh` have no leading-zero search; their result carries
`result=`/`challenge=` and their `elapsedTime=` is the wait the server expects.

`anubis_fetch` follows the challenge the same way the browser does: it reads the
`anubis_challenge` JSON, solves it with the algorithm it names (`fast`, `slow`,
`sha256`, `argon2id`, `hashx`, `tensor`, and the time-based `metarefresh` /
`preact`), submits `pass-challenge` with the cookies the server set, and
re-fetches. TLS is verified; `ANUBIS_INSECURE=1` disables verification for
testing against a self-signed gate.

All three fetch tools share that client. `anubis_fetch_raw` is for callers that
want the document rather than prose — an agent reading a page, a scraper that
matches on markup. `anubis_dump_headers` is the debugging view: it returns the
header block of the challenge, of the `pass-challenge` reply, of any redirect
and of the final page, so a gate that answers unexpectedly can be diagnosed
without packet capture.

## Browser TLS fingerprints

When a [curl-impersonate](../3rd_party/curl-impersonate/README.md) library is
installed, `anubis_fetch` sends a real Chrome handshake (cipher list, extension
order, ALPN h2, GREASE) instead of OpenSSL's, which is what sits behind most
fingerprinting walls. The library is loaded with `dlopen()` at runtime, never
linked; without it the built-in OpenSSL client runs and nothing else changes.

| `impersonate` | effect |
|---|---|
| omitted | `chrome`, when the library is installed; otherwise OpenSSL |
| `"chrome"`, `"edge"`, `"safari"` | newest profile of that family |
| `"chrome116"`, `"edge101"`, `"safari15_5"` | exactly that profile |
| `"auto"` | impersonate if available, otherwise OpenSSL |
| `"off"` | built-in OpenSSL client |

`ANUBIS_IMPERSONATE` does the same for the whole process, and `transport:` in
the reply tells you which one was actually used.

## Test

```bash
tests/mcp_test.sh
```

It starts a local gate (`betterAnusbis`) and a static backend, then drives the
server's stdio with real requests: initialize, tools/list, solve for `sha256`
and `tensor`, a version call, an end-to-end fetch through the gate, and an
unknown method. `tests/impersonate_test.sh` (or `make test-impersonate`) covers
the fingerprint path separately, against a local `openssl s_server`. Every assertion prints PASS/FAIL and the script exits non-zero
on failure.
