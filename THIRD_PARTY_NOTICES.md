# Third-party notices

This project vendors two third-party components. They remain under their own
licenses; the `LICENSE` covers only the original code, under **MIT + attribution**
(see [ATTRIBUTION.md](ATTRIBUTION.md)). The attribution requirement sits on top of
the terms below and cannot loosen them — where they conflict, the third-party
license wins for that portion.

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
