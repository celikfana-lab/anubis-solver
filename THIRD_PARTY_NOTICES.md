# Third-party notices

This project vendors several third-party components. They remain under their own
licenses; the `LICENSE` covers only the original code, under **MIT + attribution**
(see [ATTRIBUTION.md](ATTRIBUTION.md)). The attribution requirement sits on top of
the terms below and cannot loosen them — where they conflict, the third-party
license wins for that portion.

## The mining clip (`betterAnusbis/web/meatrider-mining.webp`)

A Tenor clip, "Mining Pakistani" (post 16305674345809141538), transcoded from the
3.8 MB GIF to a 150 px, 31-frame animated WebP (194 KB) so a challenged browser
fetches it from the gate instead of from a third party. Tenor's terms apply to
the clip itself; it is included as a joke, is not covered by the project's
licence, and the page links back to the post.

## The other tiers' clip (`betterAnusbis/web/cat-clapping.webp`)

A Tenor GIF, "Cat Clapping" (post 4721454909525108914), transcoded from an 833 KB
GIF to a 142 KB animated WebP (150 px, 12 fps) for the same reason as the miner
clip: a challenged browser fetches it from the gate itself and never asks
tenor.com for a script or an image. Tenor's terms apply to the clip, it is
included as a joke, it is not covered by the project's licence, and the page
links back to the post.

## The meatrider logo (`mascot/meatrider.jpg`)

An internet meme — a man riding a flying steak above the clouds — used as the
logo of the `meatrider` tier. Its origin and licence are unknown; it is included
as a joke, is not covered by the project's licence grant, and is not needed to
build or use anything here. If you hold the rights and want it gone, open an
issue and it will be replaced.

## HashX (`src/hashx.c`, `src/hashx.h`)

A C port of **tevador/hashx** (LGPL-3.0), the proof-of-work function used by
Anubis' `hashx` challenge. It is derived from the `hashx` crate (v0.8.0) via
the Tor Project's re-implementation; the file header records the provenance.

- Upstream: https://github.com/tevador/hashx
- License: GNU Lesser General Public License v3.0
- Full text: [`third_party/hashx-LGPL-3.0.txt`](third_party/hashx-LGPL-3.0.txt)
- Source availability: the complete corresponding source is in this repository.

If you distribute a binary that includes `hashx.c`, LGPL-3.0 requires that
recipients can relink it against a modified version — keep the source and this
notice alongside the binary.

## Argon2 (`third_party/argon2/`)

The reference implementation of Argon2, as used by Anubis' `argon2id`
challenge (`argon2::Argon2::default()` parameters).

- Copyright 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and
  Samuel Neves
- License: CC0 1.0 Universal OR Apache License 2.0 (at your option)
- Upstream text: [`third_party/argon2/LICENSE`](third_party/argon2/LICENSE)
- Apache-2.0 full text: [`third_party/argon2-APACHE-2.0.txt`](third_party/argon2-APACHE-2.0.txt)

## Anubis protocol

This project targets the challenge protocol of
[TecharoHQ/anubis](https://github.com/TecharoHQ/anubis), which is MIT licensed.
No Anubis source is vendored here; the wire format was reimplemented from the
documented behaviour and the project's Rust/Go sources.

### Note on `third_party/argon2/ref.c`

The vendored Argon2 package ships two interchangeable back ends: `opt.c`
(x86 SSE/AVX intrinsics) and `ref.c` (portable C). The build uses `opt.c` on
x86-64 and `ref.c` everywhere else. Both are part of the same Argon2 source
package and carry the same CC0-1.0 / Apache-2.0 terms.

## Anubis HashX WebAssembly modules (`wasm/demo/official/`)

`hashx-baseline.wasm` and `hashx-simd128.wasm` are copied verbatim from
**TecharoHQ/anubis** v1.28.3 (`web/static/wasm/`), MIT licensed, © 2025 Xe Iaso.
They are used only as the comparison baseline in `wasm/bench.mjs`,
`wasm/verify.mjs` and the demo page. The attribution condition in `LICENSE`
section 3 applies to this repository's own work, not to them.

## PCRE2 (`libpcre2-8`, `libpcre2-posix`) — the Windows build

Win32 has no POSIX `regcomp()`/`regexec()`. The Windows build of the gate links
PCRE2's POSIX wrapper (`pcre2posix.h`) so the policy file, the regex rules and
the CLI parsing stay the same C code on every platform. Linux and macOS use the
system regex and do not link PCRE2 at all.

- Upstream: https://github.com/PCRE2Project/pcre2
- License: BSD-3-Clause
- Vendored: **no**. `betterAnusbis/win32/build-windows.sh --deps` fetches the
  upstream release tarball (10.45) and cross-builds it statically for
  `x86_64-w64-mingw32`.
- Scope: the gate only ever asks "does this match" (`REG_NOSUB`-shaped use), so
  leftmost-longest vs leftmost-first POSIX semantics do not change a decision.

## nghttp2 (`libnghttp2`)

HTTP/2 framing and HPACK for the gate's listener and its optional backend hop.
It is a normal system dependency (headers and library), not vendored here;
`make` finds it through pkg-config.

- Upstream: https://github.com/nghttp2/nghttp2
- License: MIT
- Used by: `betterAnusbis/betterAnusbis.c` when built with `-DHAVE_NGHTTP2`

## nghttp3 (`betterAnusbis/third_party/nghttp3/`)

HTTP/3 framing and QPACK, paired with OpenSSL's QUIC stack. A Release,
library-only static build is vendored so the gate can be built and tested
offline; the provenance and rebuild commands are in that directory's README.

- Upstream: https://github.com/ngtcp2/nghttp3
- Version: 1.8.0
- License: MIT
- Full text: [`betterAnusbis/third_party/nghttp3/COPYING`](betterAnusbis/third_party/nghttp3/COPYING)
- Used by: `betterAnusbis/betterAnusbis.c` when built with `-DHAVE_NGHTTP3`

## bbolt file format (`go.etcd.io/bbolt`)

The optional `--store bbolt:PATH` backend reads and writes the on-disk format of
bbolt (BoltDB), the store Anubis uses for its `bbolt` backend: meta page version
2, B+tree pages, inline buckets, and one top-level bucket per record with `data`
and `expiry` (RFC3339Nano).

- Upstream: https://github.com/etcd-io/bbolt
- License: MIT
- Vendored: **no**. The C reader/writer in `betterAnusbis/betterAnusbis.c` is an
  independent implementation of the format; no bbolt source is copied here.
- Tests: when Go and the cached bbolt module are available, `test_parity.py`
  opens the gate's bbolt file with the real `go.etcd.io/bbolt` and runs
  `tx.Check`; otherwise those checks skip.

## Valkey / RESP protocol

The optional `--store valkey:URL` backend speaks RESP2 to Valkey, Redis, or any
compatible server.

- Protocol: https://github.com/valkey-io/valkey (BSD-3-Clause) /
  https://redis.io/docs/latest/develop/reference/protocol-spec/
- Vendored: **no**. The small RESP2 client in `betterAnusbis/betterAnusbis.c`
  is an independent implementation of the public protocol; no Valkey or Redis
  source is copied here.
- Tests: `tests_valkey.py` runs an in-process RESP2 mock server, so no Valkey
  installation is required; it uses a real `valkey-server`/`redis-server` from
  PATH when one is present.

## Amazon S3 API

The optional `--store s3api:BUCKET` backend talks to S3 or S3-compatible object
storage over HTTP with AWS Signature Version 4.

- API: https://docs.aws.amazon.com/AmazonS3/latest/API/
- Signature: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
- Vendored: **no**. The HTTP/1.1 client and SigV4 signer in
  `betterAnusbis/betterAnusbis.c` are independent implementations of the public
  protocol; no AWS SDK source is copied here.
- Tests: `tests_s3.py` runs an in-process S3 mock that independently verifies
  SigV4, so no AWS account or MinIO is required.

## curl-impersonate (optional, runtime only)

The C fetch layer in [`src/fetch/`](src/fetch/) can present a browser TLS
fingerprint by loading a **libcurl-impersonate** with `dlopen()`.

- Upstream: https://github.com/lwthiker/curl-impersonate
- License: MIT (the wrapped curl, BoringSSL, nghttp2 and brotli keep their own
  licenses, and a build embeds them)
- Vendored: **no**, and not linked. `libanubis_solver.so` builds and runs
  without it; the library is only opened at runtime when it is installed (see
  [`3rd_party/curl-impersonate/README.md`](3rd_party/curl-impersonate/README.md)).
  Nothing built here redistributes it, so the terms of your curl-impersonate
  build apply to that file.
- Tests: `tests/impersonate_test.sh` starts a local `openssl s_server` and checks
  the ClientHello for GREASE, so it needs no network.
