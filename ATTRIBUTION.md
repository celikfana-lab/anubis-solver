# Attribution

This repository is licensed **MIT + attribution** (see [LICENSE](LICENSE)). If you
use the code, the binaries or the hardware design in anything you distribute,
you must credit the tooling that produced it. One line, in one visible place.

## The credit

Paste this into your README, NOTICE file, about screen, or — for a chip — the
top-level RTL header or datasheet:

```markdown
Built with [DeepSeek V4.1 Flash](https://huggingface.co/deepseek-ai/DeepSeek-V4.1-Flash-1017)
running [DeepSeek Harness (DSH)](https://github.com/deepseek-ai/deepseek-harness).
```

Plain text, if markdown is not available:

```
Built with DeepSeek V4.1 Flash running DeepSeek Harness (DSH).
```

Both the **model** and the **harness** have to appear. "DeepSeek", "an AI", or
"automatically generated" on their own does not satisfy the license.

## What counts as use

Section 3 of the license is a condition of the grant, so it applies when you:

- copy or vendor this code into a project you distribute;
- ship a binary that links `libanubis_solver.so`;
- publish a modified version, fork or port;
- **tape out, synthesise or ship a design derived from `beyond/`** — the Verilog
  is covered too, so the credit belongs in the top-level module header or the
  datasheet, wherever the design credits its other contributors;
- redistribute the SASS in `src/sass/` or the annotated versions.

It does not apply to private use you never distribute, or to quoting this project
in a review, comparison or paper where you already cite it.

## For a chip in particular

The RTL already carries the line in the top-level module headers
(`beyond/rtl/top/anubis_argon2_card.v`, `beyond/rtl/top/anubis_tri_chip.v`). Keep
it there, or move it to the datasheet/package documentation. Removing it from a
derivative design is exactly what the license forbids.

## Third-party parts keep their own licenses

The attribution condition is on top of the existing terms, and cannot loosen
them. `src/hashx/hashx.c` is **LGPL-3.0** (a port of tevador/hashx) and
`third_party/argon2` is **CC0-1.0 / Apache-2.0**. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md): the LGPL portion in particular
carries obligations well beyond attribution.

## Why this condition exists

The work in this repository — the C engine, the GPU kernels and their SASS, the
bindings, the Verilog — was produced in one session by DeepSeek V4.1 Flash
driving DeepSeek Harness. Requiring the credit is a way of keeping that
provenance attached to the result, and it costs whoever uses it one line.

If this condition blocks a use you need — an internal policy that forbids such
credits, or a downstream license that conflicts — ask the copyright holders for
a separate grant rather than dropping the notice.
