#!/bin/sh
# check.sh — the site's two checks: links/structure, then layout in a browser.
#
# Links and structure need nothing but Python. The layout check needs Chrome, and
# it starts and stops the static server itself so it can be run from anywhere:
#
#   ./check.sh                 # both
#   CHROME=/path/to/chrome ./check.sh
#   ./check.sh --no-layout     # skip the browser half
set -eu
cd "$(dirname "$0")"

python3 check.py

if [ "${1:-}" = "--no-layout" ]; then
    exit 0
fi

CHROME="${CHROME:-/usr/bin/google-chrome}"
if [ ! -x "$CHROME" ]; then
    echo "layout check skipped: no Chrome at $CHROME (set CHROME=...)"
    exit 0
fi

# serve, check, and always take the server down again
python3 -m http.server 8090 --bind 127.0.0.1 >/dev/null 2>&1 &
srv=$!
trap 'kill "$srv" 2>/dev/null || true' EXIT INT TERM
sleep 1

CHROME="$CHROME" node check-layout.mjs --width 390
CHROME="$CHROME" node check-layout.mjs --width 1280
