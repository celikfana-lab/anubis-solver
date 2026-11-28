#!/usr/bin/env bash
# build-dist.sh — a directory (and tarball) that another machine can install.
#
# The add-on on its own works in the browser: WebGPU first, then the 4-wide wasm
# kernel. The native host is the optional fast path, and it is a separate
# install because Firefox launches it as an external process. This bundles
# everything that install needs for the platform it is built on:
#
#   <dist>/anubis-solver-firefox-<ver>.xpi   the add-on
#   <dist>/anubis_native.py                  the native messaging host
#   <dist>/anubis_solver.json                its manifest template
#   <dist>/anubis_solver.py                  the loader the host imports
#   <dist>/libanubis_solver.so               the C engine (.dylib/.dll elsewhere)
#   <dist>/install.sh                        writes the manifest Firefox reads
#   <dist>/README.md                         what to do with all this
#
#   ./build-dist.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VERSION="$(python3 -c 'import json;print(json.load(open("'"$HERE"'/manifest.json"))["version"])')"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
NAME="anubis-solver-${VERSION}-${OS}-${ARCH}"
OUT="$ROOT/build/$NAME"

echo "== building the add-on"
"$HERE/build-xpi.sh" >/dev/null

echo "== building the engine"
make -s -C "$ROOT" -j"$(nproc 2>/dev/null || echo 2)" >/dev/null

case "$(uname -s)" in
  Linux)   LIB="$ROOT/libanubis_solver.so" ;;
  Darwin)  LIB="$ROOT/libanubis_solver.dylib" ;;
  *)       LIB="$ROOT/anubis_solver.dll" ;;
esac
if [ ! -f "$LIB" ]; then
  echo "error: $LIB was not built" >&2
  exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$ROOT/build/anubis-solver-firefox-$VERSION.xpi" "$OUT/"
cp "$HERE/native-host/anubis_native.py" "$OUT/"
cp "$HERE/native-host/anubis_solver.json" "$OUT/"
cp "$ROOT/anubis_solver.py" "$OUT/"
cp "$LIB" "$OUT/"
cp "$HERE/install.sh" "$OUT/"
cp "$HERE/README.md" "$OUT/README.md"

cat > "$OUT/INSTALL.txt" <<TXT
anubis-solver $VERSION ($OS/$ARCH)

1. the add-on, in the browser
     about:debugging -> This Firefox -> Load Temporary Add-on -> $NAME/anubis-solver-firefox-$VERSION.xpi
   (a permanent install needs a signature: build-xpi.sh --sign, or AMO)
   This already solves challenges: WebGPU when the browser has it, otherwise the
   bundled wasm kernel. Nothing below is required for that.

2. the native host, for the fast path
     ./install.sh
   It writes the manifest Firefox reads and points it at this directory. Then
   restart Firefox: manifests are read at startup.
   Needs Python 3.9+ and the engine next to this file ($(basename "$LIB")),
   which is bundled. On Windows, install.sh does not apply: see README.md.
TXT

tar -C "$ROOT/build" -czf "$OUT.tar.gz" "$NAME"

echo
echo "built $OUT"
du -sh "$OUT" "$OUT.tar.gz" | sed 's/^/  /'
ls -1 "$OUT"
