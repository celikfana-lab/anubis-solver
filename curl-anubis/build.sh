#!/bin/sh
# curl-anubis — build a curl that answers Anubis challenges by itself.
#
#   ./build.sh                                  # curl from ../../curl, engine from ..
#   CURL_SRC=/src/curl ./build.sh               # or point it anywhere
#   ./build.sh --curl-src /src/curl --engine /src/anubis-solver
#
# Output: build/curl-anubis  (a static curl, no libcurl.so, one DT_NEEDED on
# libanubis_solver.so whose rpath points at the engine directory you passed).
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

CURL_SRC=${CURL_SRC:-$ROOT/../curl}
ENGINE=${ENGINE:-$ROOT}
WORK=${WORK:-$HERE/build}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case $1 in
    --curl-src) CURL_SRC=$2; shift 2 ;;
    --engine)   ENGINE=$2;   shift 2 ;;
    --work)     WORK=$2;     shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "build.sh: unknown option: $1" >&2; exit 2 ;;
    esac
done

src_abs=$(CDPATH= cd -- "$CURL_SRC" 2>/dev/null && pwd) || {
    echo "build.sh: no curl source at $CURL_SRC" >&2
    echo "  pass --curl-src DIR, or set CURL_SRC" >&2
    exit 1
}
eng_abs=$(CDPATH= cd -- "$ENGINE" 2>/dev/null && pwd) || {
    echo "build.sh: no engine directory at $ENGINE" >&2
    exit 1
}

for f in "$src_abs/lib/http.c" "$src_abs/src/tool_operate.c"; do
    [ -f "$f" ] || { echo "build.sh: $src_abs does not look like a curl tree" >&2; exit 1; }
done
for f in "$eng_abs/include/anubis-solver.h" "$eng_abs/libanubis_solver.so"; do
    [ -f "$f" ] || {
        echo "build.sh: missing $f" >&2
        echo "  build the engine first: cd $eng_abs && make" >&2
        exit 1
    }
done

[ -f "$HERE/patches/curl-anubis.patch" ] || {
    echo "build.sh: $HERE/patches/curl-anubis.patch is missing" >&2
    exit 1
}

echo "==> curl source: $src_abs"
echo "==> engine:      $eng_abs"
echo "==> work:        $WORK"

rm -rf "$WORK"
mkdir -p "$WORK"
SRC=$WORK/curl-anubis-src
# copy, not rsync: keep this dependency-free
(cd "$src_abs" && tar -cf - --exclude=.git .) | (mkdir -p "$SRC" && cd "$SRC" && tar -xf -)

echo "==> applying patches/curl-anubis.patch"
(cd "$SRC" && patch -p1 --forward --silent < "$HERE/patches/curl-anubis.patch") || {
    echo "build.sh: the patch did not apply. It is written against curl 8.23.1-DEV" >&2
    echo "  (commit 23256cf); a different curl version will need rebasing." >&2
    exit 1
}

echo "==> autoconf"
(cd "$SRC" && autoreconf -fi > "$WORK/autoreconf.log" 2>&1) || {
    tail -20 "$WORK/autoreconf.log" >&2
    exit 1
}

echo "==> configure"
(cd "$SRC" && ./configure \
    --disable-shared --enable-static \
    --with-openssl --without-libpsl \
    --disable-ldap --disable-docs --disable-manual \
    CPPFLAGS="-I$eng_abs/include" \
    > "$WORK/configure.log" 2>&1) || {
    tail -30 "$WORK/configure.log" >&2
    exit 1
}

echo "==> make -j$JOBS"
(cd "$SRC" && make -j"$JOBS" \
    ANUBIS_LIBS="-L$eng_abs -lanubis_solver -Wl,-rpath,$eng_abs" \
    > "$WORK/make.log" 2>&1) || {
    grep -E "error:|Error [0-9]" "$WORK/make.log" | head -30 >&2 || tail -30 "$WORK/make.log" >&2
    exit 1
}

cp "$SRC/src/curl" "$WORK/curl-anubis.tmp"
mv "$WORK/curl-anubis.tmp" "$WORK/curl-anubis"
chmod 755 "$WORK/curl-anubis"

echo
"$WORK/curl-anubis" --version | sed -n '1,3p'
echo
echo "built: $WORK/curl-anubis"
if command -v ldd >/dev/null 2>&1; then
    echo "deps:  $(ldd "$WORK/curl-anubis" 2>/dev/null | awk '/anubis|curl/ {printf "%s ", $1}')"
fi
