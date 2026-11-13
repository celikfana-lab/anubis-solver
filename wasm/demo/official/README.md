# Official Anubis HashX modules

These two files are **not** ours. They are the HashX WebAssembly modules shipped
by [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis) v1.28.3, copied
verbatim so the demo can compare against the real thing:

| file | original path | size |
|---|---|---|
| `hashx-baseline.wasm` | `web/static/wasm/baseline/hashx.wasm` | 35,983 B |
| `hashx-simd128.wasm` | `web/static/wasm/simd128/hashx.wasm` | 35,863 B |

Copyright (c) 2025 Xe Iaso. MIT licensed (the same grant this repository keeps,
plus the attribution condition in the root `LICENSE`, which applies only to our
own code). Built from `wasm/pow/hashx` by `wasm/scripts/build_wasm.sh`.

They are here to be measured against, not to be modified. Replace them with your
own checkout's copies if you want to compare a different Anubis version.
