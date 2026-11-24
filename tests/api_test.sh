#!/usr/bin/env bash
#
# tests/api_test.sh — black-box tests for the C API service (src/api/anubis_api.c).
#
# Builds the service with the documented command, starts it against the local
# libanubis_solver.so, and talks to it with curl. The last block starts a real
# local Anubis gate (betterAnusbis) in front of a python http.server and proves
# that POST /v1/fetch solves a live challenge and returns the protected page.
#
# Every process this script starts is killed by stored PID in the EXIT trap.
#
# Usage: tests/api_test.sh
# Exit:  0 when every assertion passed, 1 otherwise.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

PASS=0
FAIL=0
TMP="$(mktemp -d "${TMPDIR:-/tmp}/anubis_api_test.XXXXXX")"
BODY="$TMP/body.json"
APID=""
GPID=""
BPID=""

cleanup() {
    trap - EXIT INT TERM
    local p
    for p in "$APID" "$GPID" "$BPID"; do
        if [ -n "$p" ]; then
            kill "$p" 2>/dev/null || true
        fi
    done
    for p in "$APID" "$GPID" "$BPID"; do
        if [ -n "$p" ]; then
            wait "$p" 2>/dev/null || true
        fi
    done
    [ -n "${TMP:-}" ] && rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

ck() { # ck <description> <0|1>
    if [ "$2" = "1" ]; then
        echo "PASS $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL $1"
        FAIL=$((FAIL + 1))
    fi
}

has() { # has <grep -q pattern> -> 1/0 on $BODY
    if grep -q -- "$1" "$BODY" 2>/dev/null; then echo 1; else echo 0; fi
}

code_is() { [ "$1" = "$2" ] && echo 1 || echo 0; }

jget() { # jget <field> -> value from the JSON in $BODY
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
        "$BODY" "$1" 2>/dev/null
}

http() { # http METHOD URL [JSON]
    local method="$1" url="$2" data="${3:-}"
    if [ -n "$data" ]; then
        curl -sS --max-time 20 -o "$BODY" -w '%{http_code}' \
            -X "$method" -H 'Content-Type: application/json' \
            --data-binary "$data" "$url" 2>/dev/null || echo 000
    else
        curl -sS --max-time 20 -o "$BODY" -w '%{http_code}' \
            -X "$method" "$url" 2>/dev/null || echo 000
    fi
}

wait_http_200() { # wait_http_200 URL [tries]
    local url="$1" tries="${2:-100}" i code
    for ((i = 0; i < tries; i++)); do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || echo 000)"
        [ "$code" = "200" ] && return 0
        sleep 0.1
    done
    return 1
}

port_free() {
    # SO_REUSEADDR matches what the gate and http.server set themselves, so a
    # port in TIME_WAIT from an earlier run still counts as available.
    python3 -c 'import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()' "$1"
}

free_port() {
    python3 -c 'import socket
s=socket.socket(); s.bind(("127.0.0.1", 0))
print(s.getsockname()[1]); s.close()'
}

command -v curl >/dev/null 2>&1 || { echo "FAIL curl is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL python3 is required"; exit 1; }

# ---- build prerequisites ------------------------------------------------

if [ ! -f "$ROOT/libanubis_solver.so" ]; then
    echo "building libanubis_solver.so"
    make -C "$ROOT" -j"$(nproc 2>/dev/null || echo 4)" libanubis_solver.so || exit 1
fi

if [ ! -x "$ROOT/betterAnusbis/betterAnusbis" ]; then
    echo "building betterAnusbis (needed for the /v1/fetch end-to-end test)"
    make -C "$ROOT/betterAnusbis" || exit 1
fi

BIN="$TMP/anubis_api"
echo "building $BIN"
# The fetch layer lives in the .so now, so this is one file plus the library.
(cd "$ROOT" && make anubis_api >"$TMP/build_api.log" 2>&1) || {
    cat "$TMP/build_api.log" >&2
    echo "FAIL build"
    exit 1
}
BIN="$ROOT/anubis_api"

# ---- ports --------------------------------------------------------------

if port_free 8098 && port_free 8099; then
    BACKEND_PORT=8098
    GATE_PORT=8099
else
    BACKEND_PORT="$(free_port)"
    GATE_PORT="$(free_port)"
    while [ "$GATE_PORT" = "$BACKEND_PORT" ]; do
        GATE_PORT="$(free_port)"
    done
    echo "NOTE: 8098/8099 are in use; using $BACKEND_PORT/$GATE_PORT instead"
fi
API_PORT="$(free_port)"
API="http://127.0.0.1:$API_PORT"
GATE="http://127.0.0.1:$GATE_PORT"

# ---- start the service --------------------------------------------------

( cd "$ROOT" && exec "$BIN" --listen "127.0.0.1:$API_PORT" --max-body 1048576 ) \
    >"$TMP/api.log" 2>&1 &
APID=$!

if ! wait_http_200 "$API/healthz"; then
    echo "FAIL service did not start"
    cat "$TMP/api.log"
    exit 1
fi
head -1 "$TMP/api.log" | grep -q '^anubis_api 2.40 "shyleaf" listening on ' \
    && ck "startup line names version and codename" 1 \
    || ck "startup line names version and codename" 0

# ---- GET /healthz -------------------------------------------------------

CODE="$(http GET "$API/healthz")"
ck "GET /healthz -> 200" "$(code_is "$CODE" 200)"
ck "/healthz has ok:true" "$(has '"ok":true')"
ck "/healthz has version 2.40" "$(has '"version":"2.40"')"
ck "/healthz has codename shyleaf" "$(has '"codename":"shyleaf"')"

# ---- GET /v1/version ----------------------------------------------------

CODE="$(http GET "$API/v1/version")"
ck "GET /v1/version -> 200" "$(code_is "$CODE" 200)"
ck "/v1/version version+codename" "$(has '"version":"2.40","codename":"shyleaf"')"
ck "/v1/version lists the algorithms" \
   "$(has '"algorithms":\["fast","slow","sha256","wasm-sha256","argon2id","hashx","tensor"\]')"

# ---- POST /v1/solve + /v1/verify (sha256, difficulty 4) -----------------

CHALLENGE="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
CODE="$(http POST "$API/v1/solve" \
    "{\"algorithm\":\"sha256\",\"challenge\":\"$CHALLENGE\",\"difficulty\":4,\"threads\":4,\"budget_ms\":0}")"
ck "POST /v1/solve sha256 -> 200" "$(code_is "$CODE" 200)"
ck "/v1/solve sha256 returns a hex response" "$(has '"response":"[0-9a-f]\{64\}"')"
ck "/v1/solve sha256 returns an integer nonce" "$(has '"nonce":[0-9]')"
NONCE="$(jget nonce)"
RESPONSE="$(jget response)"
case "$NONCE" in
    '' | *[!0-9]*) ck "sha256 nonce parses as an integer" 0 ;;
    *) ck "sha256 nonce parses as an integer" 1 ;;
esac
printf '%s' "$RESPONSE" | grep -Eq '^[0-9a-f]{64}$' \
    && ck "sha256 response is 64 lowercase hex digits" 1 \
    || ck "sha256 response is 64 lowercase hex digits" 0

if [ -n "$NONCE" ]; then
    CODE="$(http POST "$API/v1/verify" \
        "{\"algorithm\":\"sha256\",\"challenge\":\"$CHALLENGE\",\"difficulty\":4,\"nonce\":$NONCE}")"
    ck "POST /v1/verify sha256 -> 200" "$(code_is "$CODE" 200)"
    ck "/v1/verify sha256 ok:true" "$(has '"ok":true')"
    ck "/v1/verify sha256 returns the digest" "$(has '"digest":"[0-9a-f]\{64\}"')"
else
    ck "POST /v1/verify sha256 -> 200" 0
    ck "/v1/verify sha256 ok:true" 0
    ck "/v1/verify sha256 returns the digest" 0
fi

# ---- POST /v1/solve_raw (raw challenge in, raw result out, no network) ---

RAW_ID="00000000-0000-0000-0000-000000000001"
RAW_JSON="{\"rules\":{\"algorithm\":\"fast\",\"difficulty\":1},\"challenge\":\"0123456789abcdef\",\"id\":\"$RAW_ID\"}"
CODE="$(curl -sS --max-time 20 -D "$TMP/solve_raw.head" -o "$BODY" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' --data-binary "$RAW_JSON" \
    "$API/v1/solve_raw" 2>/dev/null || echo 000)"
ck "POST /v1/solve_raw raw JSON -> 200" "$(code_is "$CODE" 200)"
ck "/v1/solve_raw returns the raw pass-challenge query" \
   "$(grep -Eq "^id=$RAW_ID&response=[0-9a-f]{64}&nonce=[0-9]+&elapsedTime=1$" "$BODY" && echo 1 || echo 0)"
ck "/v1/solve_raw reports the algorithm header" \
   "$(grep -qi '^X-Anubis-Algorithm: fast' "$TMP/solve_raw.head" 2>/dev/null && echo 1 || echo 0)"

CODE="$(http POST "$API/v1/solve_raw?format=json" "$RAW_JSON")"
ck "POST /v1/solve_raw?format=json -> 200" "$(code_is "$CODE" 200)"
ck "/v1/solve_raw JSON has the parsed fields" \
   "$(has '"algorithm":"fast","difficulty":1,"id":"'"$RAW_ID"'"')"
ck "/v1/solve_raw JSON raw field is the query" \
   "$(grep -Eq '"raw":"id='"$RAW_ID"'&response=[0-9a-f]{64}&nonce=[0-9]+&elapsedTime=1"' "$BODY" && echo 1 || echo 0)"
RAW_RESPONSE="$(jget response)"
printf '%s' "$RAW_RESPONSE" | grep -Eq '^[0-9a-f]{64}$' \
    && ck "/v1/solve_raw JSON response is 64 lowercase hex digits" 1 \
    || ck "/v1/solve_raw JSON response is 64 lowercase hex digits" 0

# The nested spelling newer Anubis pages use.
RAW_NESTED="{\"rules\":{\"algorithm\":\"fast\",\"difficulty\":1},\"challenge\":{\"id\":\"$RAW_ID\",\"randomData\":\"0123456789abcdef\"}}"
CODE="$(http POST "$API/v1/solve_raw?format=json" "$RAW_NESTED")"
ck "POST /v1/solve_raw nested challenge object -> 200" "$(code_is "$CODE" 200)"
ck "/v1/solve_raw nested challenge keeps the id" \
   "$(has '"id":"'"$RAW_ID"'"')"

# The whole page, not just the payload: the script element is found for us.
RAW_PAGE='<html><body><script type="application/json" id="anubis_challenge">{"rules":{"algorithm":"sha256","difficulty":2},"challenge":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","id":"page-id"}</script></body></html>'
CODE="$(http POST "$API/v1/solve_raw?format=json" "$RAW_PAGE")"
ck "POST /v1/solve_raw whole challenge page -> 200" "$(code_is "$CODE" 200)"
ck "/v1/solve_raw page picks sha256 from the script" "$(has '"algorithm":"sha256"')"

CODE="$(http POST "$API/v1/solve_raw" 'this is not an anubis challenge')"
ck "POST /v1/solve_raw non-challenge -> 400" "$(code_is "$CODE" 400)"
ck "/v1/solve_raw non-challenge error body" "$(has '"error":"input is not an Anubis challenge')"

# ---- POST /v1/solve + /v1/verify (tensor, difficulty 2) -----------------

TCHALLENGE="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
CODE="$(http POST "$API/v1/solve" \
    "{\"algorithm\":\"tensor\",\"challenge\":\"$TCHALLENGE\",\"difficulty\":2,\"threads\":0,\"budget_ms\":0}")"
ck "POST /v1/solve tensor -> 200" "$(code_is "$CODE" 200)"
ck "/v1/solve tensor nonce is 0" "$(has '"nonce":0')"
TNONCE="$(jget nonce)"
case "$TNONCE" in
    '' | *[!0-9]*) TNONCE=0 ;;
esac
CODE="$(http POST "$API/v1/verify" \
    "{\"algorithm\":\"tensor\",\"challenge\":\"$TCHALLENGE\",\"difficulty\":2,\"nonce\":$TNONCE}")"
ck "POST /v1/verify tensor -> 200" "$(code_is "$CODE" 200)"
ck "/v1/verify tensor ok:true" "$(has '"ok":true')"

# ---- error handling -----------------------------------------------------

CODE="$(http POST "$API/v1/solve" \
    '{"algorithm":"nope","challenge":"00","difficulty":1}')"
ck "unknown algorithm -> 400" "$(code_is "$CODE" 400)"
ck "unknown algorithm error body" "$(has '"error":"unknown algorithm"')"

CODE="$(http POST "$API/v1/solve" '{oops')"
ck "malformed JSON -> 400" "$(code_is "$CODE" 400)"
ck "malformed JSON error body" "$(has '"error":"bad json"')"

CODE="$(http GET "$API/does-not-exist")"
ck "unknown path -> 404" "$(code_is "$CODE" 404)"
ck "unknown path error body" "$(has '"error":"not found"')"

# ---- concurrency --------------------------------------------------------

: >"$TMP/conc.txt"
CPIDS=""
for _ in 1 2 3 4 5 6 7 8; do
    curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 "$API/healthz" \
        >>"$TMP/conc.txt" 2>/dev/null &
    CPIDS="$CPIDS $!"
done
for p in $CPIDS; do wait "$p" 2>/dev/null || true; done
CONC_OK="$(grep -c '^200$' "$TMP/conc.txt" 2>/dev/null || true)"
[ "$CONC_OK" = "8" ] \
    && ck "8 concurrent /healthz requests all return 200" 1 \
    || ck "8 concurrent /healthz requests all return 200" 0

# ---- end-to-end: POST /v1/fetch through a real local gate ---------------

WWW="$TMP/www"
mkdir -p "$WWW"
printf '<html><body>PAST THE WALL</body></html>\n' >"$WWW/index.html"

python3 -m http.server "$BACKEND_PORT" --bind 127.0.0.1 --directory "$WWW" \
    >"$TMP/backend.log" 2>&1 &
BPID=$!
if ! wait_http_200 "http://127.0.0.1:$BACKEND_PORT/"; then
    echo "FAIL backend did not start"
    cat "$TMP/backend.log"
    exit 1
fi

( cd "$ROOT/betterAnusbis" && exec ./betterAnusbis \
    --listen "127.0.0.1:$GATE_PORT" \
    --target "http://127.0.0.1:$BACKEND_PORT/" \
    --algorithm sha256 --difficulty 4 ) >"$TMP/gate.log" 2>&1 &
GPID=$!
if ! wait_http_200 "$GATE/"; then
    echo "FAIL gate did not start"
    cat "$TMP/gate.log"
    exit 1
fi

CODE="$(http POST "$API/v1/fetch" "{\"url\":\"$GATE/\"}")"
ck "POST /v1/fetch through live Anubis gate -> 200" "$(code_is "$CODE" 200)"
ck "/v1/fetch answer reports status 200" "$(has '"status":200')"
ck "/v1/fetch content contains PAST THE WALL" "$(has 'PAST THE WALL')"
ck "/v1/fetch returns a final_url" "$(has '"final_url":"http://127.0.0.1:'"$GATE_PORT"'/"')"

# ---- end-to-end: raw body and dumped headers ----------------------------

RAW="$(curl -sS --max-time 20 -D "$TMP/raw.head" -o "$BODY" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' \
    --data-binary "{\"url\":\"$GATE/\"}" "$API/v1/fetch_raw" 2>/dev/null || echo 000)"
ck "POST /v1/fetch_raw through live Anubis gate -> 200" "$(code_is "$RAW" 200)"
ck "/v1/fetch_raw returns the raw HTML, not text" "$(has '<html>')"
ck "/v1/fetch_raw carries the origin Content-Type" \
   "$(grep -qi '^Content-Type: text/html' "$TMP/raw.head" && echo 1 || echo 0)"
ck "/v1/fetch_raw reports X-Anubis-Status" \
   "$(grep -qi '^X-Anubis-Status: 200' "$TMP/raw.head" && echo 1 || echo 0)"
ck "/v1/fetch_raw reports X-Anubis-Final-URL" \
   "$(grep -qi '^X-Anubis-Final-URL: http' "$TMP/raw.head" && echo 1 || echo 0)"

CODE="$(http POST "$API/v1/dump_headers" "{\"url\":\"$GATE/\"}")"
ck "POST /v1/dump_headers through live Anubis gate -> 200" "$(code_is "$CODE" 200)"
ck "/v1/dump_headers reports a headers_len" "$(has '"headers_len":')"
ck "/v1/dump_headers captured the Anubis cookie" "$(has 'et-Cookie')"
ck "/v1/dump_headers has every response, not just the last" \
   "$(count="$(grep -o 'HTTP/1\.[01]' "$BODY" 2>/dev/null | wc -l)"; \
      [ "${count:-0}" -ge 2 ] && echo 1 || echo 0)"

# ---- end-to-end: session cookies ---------------------------------------

CODE="$(http POST "$API/v1/fetch" "{\"url\":\"$GATE/\"}")"
ck "/v1/fetch cold call reports solved" "$(has '"solved":true')"
COOKIES="$(jget cookies)"
ck "/v1/fetch cold call returns a cookie jar" \
   "$([ -n "$COOKIES" ] && echo 1 || echo 0)"

# Whitespace after the comma on purpose: the JSON walker used to stop there.
PAYLOAD="$(python3 -c 'import json,sys; print(json.dumps({"url": sys.argv[1], "cookies": sys.argv[2]}))' \
    "$GATE/" "$COOKIES")"
CODE="$(http POST "$API/v1/fetch" "$PAYLOAD")"
ck "/v1/fetch with returned cookies skips the challenge" "$(has '"solved":false')"
ck "/v1/fetch with returned cookies reports no expiry" "$(has '"expired":false')"
ck "/v1/fetch with returned cookies returns the same jar" \
   "$(JAR="$(jget cookies)"; [ "$JAR" = "$COOKIES" ] && echo 1 || echo 0)"

CODE="$(http POST "$API/v1/fetch" "{\"url\":\"$GATE/\",\"cookies\":\"anubis-auth=stale\"}")"
ck "/v1/fetch with a stale cookie reports expired" "$(has '"expired":true')"
ck "/v1/fetch with a stale cookie still solves" "$(has '"solved":true')"
ck "/v1/fetch with a stale cookie returns a fresh jar" \
   "$(JAR="$(jget cookies)"; [ -n "$JAR" ] && [ "$JAR" != "anubis-auth=stale" ] && echo 1 || echo 0)"

# ---- summary ------------------------------------------------------------

echo
if [ "$FAIL" -ne 0 ]; then
    echo "--- API log ---"
    tail -20 "$TMP/api.log" 2>/dev/null || true
    echo "--- gate log ---"
    tail -20 "$TMP/gate.log" 2>/dev/null || true
fi
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
