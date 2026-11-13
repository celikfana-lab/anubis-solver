#!/usr/bin/env bash
# Runs every language example, from the repository root.
#
#   ./examples/run_all.sh              # everything that can run here
#   ./examples/run_all.sh node java    # a subset
#
# Each language is skipped with a reason if its toolchain or build output is
# missing, rather than failing the run.
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
if [ $# -gt 0 ]; then WANT=("$@"); else WANT=(python node go csharp r java rust asm); fi

pass=0; fail=0; skip=0
declare -a FAILED=()

want() { local x; for x in "${WANT[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# R may live outside PATH in a sandbox; accept $R_CMD or the extracted copy
r_cmd() {
    if [ -n "${R_CMD:-}" ] && [ -x "$R_CMD" ]; then echo "$R_CMD"; return; fi
    if have Rscript; then echo Rscript; return; fi
    if have R; then echo R; return; fi
    if [ -x /tmp/rprefix/usr/lib/R/bin/exec/R ]; then echo /tmp/rprefix/usr/lib/R/bin/exec/R; fi
}

note()  { printf '  \033[2m%s\033[0m\n' "$*"; }
head_() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()    { printf '  ok\n'; pass=$((pass+1)); }
bad()   { printf '  FAILED (%s)\n' "${1:-exit $?}"; fail=$((fail+1)); FAILED+=("$2"); }
skip_() { printf '  skipped: %s\n' "$*"; skip=$((skip+1)); }

[ -f "$ROOT/libanubis_solver.so" ] || {
    echo "libanubis_solver.so is missing: run 'make' at $ROOT first" >&2; exit 1; }

# ---------------------------------------------------------------- python
if want python; then
    head_ python
    if have python3; then
        python3 examples/solver.py >/dev/null 2>&1 && ok || bad "$?" python
    else
        skip_ "python3 not found"
    fi
fi

# ------------------------------------------------------------------ node
if want node; then
    head_ node
    if ! have node; then skip_ "node not found"
    elif [ ! -d "$ROOT/bindings/node/node_modules/koffi" ]; then
        skip_ "run 'cd bindings/node && npm install' first"
    else
        out=$(node examples/node_demo.js 2>&1) && { printf '%s\n' "$out"; ok; } || bad "$?" node
    fi
fi

# -------------------------------------------------------------------- go
if want go; then
    head_ go
    if have go; then
        out=$(cd examples/go_demo && go run . 2>&1) && { printf '%s\n' "$out"; ok; } || bad "$?" go
    else
        skip_ "go not found"
    fi
fi

# ------------------------------------------------------------------- c#
if want csharp || want cs; then
    head_ csharp
    if have dotnet; then
        out=$(dotnet run examples/csharp_demo.cs 2>/dev/null) && { printf '%s\n' "$out"; ok; } || bad "$?" csharp
    else
        skip_ "dotnet not found"
    fi
fi

# --------------------------------------------------------------------- r
if want r; then
    head_ r
    R=$(r_cmd)
    if [ -z "$R" ]; then skip_ "R not found (set R_CMD)"
    elif [ ! -f "$ROOT/bindings/r/anubisR.so" ]; then skip_ "run 'make' in bindings/r first"
    else
        out=$(R_HOME=${R_HOME:-/tmp/rprefix/usr/lib/R} \
              LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-/tmp/rprefix/usr/lib/R/lib} \
              "$R" --vanilla --slave -f examples/r_demo.R 2>&1 \
              | grep -v "startup\|repositories\|file(file\|Renviron")
        printf '%s\n' "$out"
        if printf '%s\n' "$out" | grep -q "same digest"; then ok; else bad 1 r; fi
    fi
fi

# ------------------------------------------------------------------- java
if want java; then
    head_ java
    if ! have java || ! have javac; then skip_ "JDK not found"
    elif [ ! -d "$ROOT/bindings/java/build/classes" ]; then
        skip_ "run 'make' in bindings/java first"
    else
        outdir=/tmp/anubis-example-java && rm -rf "$outdir" && mkdir -p "$outdir"
        if javac -cp bindings/java/build/classes -d "$outdir" examples/java_demo/AnubisDemo.java \
           && out=$(java -Djava.library.path=bindings/java/build \
                          -cp "bindings/java/build/classes:$outdir" AnubisDemo 2>&1); then
            printf '%s\n' "$out"; ok
        else
            bad "$?" java
        fi
    fi
fi

# ------------------------------------------------------------------- rust
if want rust; then
    head_ rust
    if have cargo; then
        out=$(cd bindings/rust && cargo run --offline --quiet --example solve 2>&1 \
              | grep -v "^warning\|Compiling\|Finished\|Running")
        printf '%s\n' "$out"
        if printf '%s\n' "$out" | grep -q "same digest"; then ok; else bad 1 rust; fi
    else
        skip_ "cargo not found"
    fi
fi

# -------------------------------------------------------------------- asm
if want asm; then
    head_ asm
    if ! have cc; then skip_ "no C compiler to drive the linker"
    else
        # freestanding: no libc, no startup files
        if cc -nostdlib -no-pie -o /tmp/anubis-asm-min examples/asm_min.s \
              -L"$ROOT" -lanubis_solver -Wl,-rpath,"$ROOT" 2>/dev/null \
           && ver=$(/tmp/anubis-asm-min 2>&1) && [ -n "$ver" ]; then
            printf '  asm_min (freestanding) -> %s\n' "$ver"
            if make -C bindings/asm run >/tmp/anubis-asm.log 2>&1; then
                tail -3 /tmp/anubis-asm.log; ok
            else
                bad "$?" asm; fi
        else
            bad 1 asm
        fi
    fi
fi

# ---------------------------------------------------------------- summary
printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$fail" -gt 0 ]; then
    printf 'failed: %s\n' "${FAILED[*]}"
    exit 1
fi
