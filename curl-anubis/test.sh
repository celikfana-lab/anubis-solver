#!/bin/bash
# test.sh — curl-anubis against a real Anubis-compatible gate.
#
#   ./test.sh                       # build/curl-anubis and ../betterAnusbis/betterAnusbis
#   CURL_ANUBIS=/usr/bin/curl-anubis GATE=/usr/bin/betterAnusbis ./test.sh
#
# Every check is a real request through the gate: the interstitial is served,
# the challenge is solved, the cookie is taken, and the page that comes back is
# compared with what the backend actually holds. The backend counts the requests
# it receives, which is how "solved it in one request, not two" is checked.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CURL_ANUBIS=${CURL_ANUBIS:-$HERE/build/curl-anubis}
GATE=${GATE:-$HERE/../betterAnusbis/betterAnusbis}
DIFFICULTY=${DIFFICULTY:-4}

TMP=$(mktemp -d "${TMPDIR:-/tmp}/curl-anubis-test.XXXXXX")

# the ports this script uses; a leftover server on one of them makes every
# check lie, so say so instead of testing the wrong thing
for port in 8811 8813 8912 8913 8914; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        exec 3>&-
        echo "test.sh: port $port is already in use; stop that server first" >&2
        exit 1
    fi
done
PASS=0
FAIL=0
BACK_PID=
GATE_PID=
FREE_PID=

pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
check() { # check NAME CONDITION
    if [ "$2" = 0 ]; then pass "$1"; else fail "$1"; fi
}

cleanup() {
    [ -n "$FREE_PID" ] && kill "$FREE_PID" 2>/dev/null
    [ -n "$GATE_PID" ] && kill "$GATE_PID" 2>/dev/null
    [ -n "$BACK_PID" ] && kill "$BACK_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

for f in "$CURL_ANUBIS" "$GATE"; do
    [ -x "$f" ] || { echo "test.sh: missing $f" >&2; exit 1; }
done

cat > "$TMP/backend.py" <<'PY'
import http.server, os, sys
class H(http.server.BaseHTTPRequestHandler):
    def handle_one(self):
        with open(os.environ["COUNTER"], "a") as f:
            f.write("%s %s\n" % (self.command, self.path))
        body = os.environ["BODY"].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    do_GET = do_POST = do_HEAD = handle_one
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY

wait_port() { # wait_port PORT
    i=0
    while [ $i -lt 100 ]; do
        curl -s -o /dev/null "http://127.0.0.1:$1/" && return 0
        i=$((i + 1))
        sleep 0.1
    done
    return 1
}

COUNT="$TMP/backend-count.txt"
: > "$COUNT"
BODY="hello from the protected page" COUNTER="$COUNT" \
    python3 "$TMP/backend.py" 8811 > "$TMP/backend.log" 2>&1 &
BACK_PID=$!
wait_port 8811 || { echo "test.sh: backend did not start" >&2; exit 1; }

"$GATE" --target http://127.0.0.1:8811 --listen 127.0.0.1:8912 \
    --difficulty "$DIFFICULTY" > "$TMP/gate.log" 2>&1 &
GATE_PID=$!
wait_port 8912 || { echo "test.sh: gate did not start" >&2; exit 1; }

URL=http://127.0.0.1:8912/
BEHIND='hello from the protected page'

# 1. plain curl gets the gate, not the page
out=$(curl -s "$URL")
case $out in
*anubis_challenge*) pass "plain curl is given the interstitial" ;;
*) fail "plain curl is given the interstitial" ;;
esac

# 2. curl-anubis gets the page
: > "$COUNT"
out=$("$CURL_ANUBIS" -s "$URL")
[ "$out" = "$BEHIND" ]; check "curl-anubis returns the protected page" $?
case $out in
*anubis_challenge*) fail "the page is not the interstitial" ;;
*) pass "the page is not the interstitial" ;;
esac

# 3. exactly one request reached the origin
n=$(wc -l < "$COUNT" | tr -d ' ')
[ "$n" = 1 ]; check "the origin saw exactly one request (got $n)" $?

# 4. -o writes the page, not the interstitial
"$CURL_ANUBIS" -s -o "$TMP/out.html" "$URL"
[ "$(cat "$TMP/out.html")" = "$BEHIND" ]; check "--anubis with -o writes the page" $?

# 5. -i keeps the headers and still gets the page
"$CURL_ANUBIS" -s -i "$URL" > "$TMP/inc.txt"
grep -q "hello from the protected page" "$TMP/inc.txt"; check "-i keeps headers and body" $?
head -1 "$TMP/inc.txt" | grep -q "200"; check "-i shows the real status line" $?

# 6. -v says what it did (-s would silence the note as well as the progress)
"$CURL_ANUBIS" -v "$URL" > /dev/null 2> "$TMP/verbose.txt"
grep -q "anubis: solved the sha256 challenge" "$TMP/verbose.txt"
check "-v reports the solved challenge" $?

# 7. --no-anubis is plain curl
out=$("$CURL_ANUBIS" -s --no-anubis "$URL")
case $out in
*anubis_challenge*) pass "--no-anubis behaves like plain curl" ;;
*) fail "--no-anubis behaves like plain curl" ;;
esac

# 8. a POST is answered and still reaches the origin as a POST
: > "$COUNT"
out=$("$CURL_ANUBIS" -s -d "a=1&b=2" "$URL")
[ "$out" = "$BEHIND" ]; check "POST through the gate returns the page" $?
grep -q "^POST /" "$COUNT"; check "the origin saw the POST, not a GET" $?

# 9. --anubis-max-retries 0 shows the page rather than looping
out=$("$CURL_ANUBIS" -s --anubis-max-retries 0 "$URL")
case $out in
*anubis_challenge*) pass "--anubis-max-retries 0 gives up and shows the page" ;;
*) fail "--anubis-max-retries 0 gives up and shows the page" ;;
esac

# 10. a site without Anubis is untouched: same bytes, same one request
FREE_COUNT="$TMP/free-count.txt"
: > "$FREE_COUNT"
BODY="plain old page" COUNTER="$FREE_COUNT" \
    python3 "$TMP/backend.py" 8813 > "$TMP/free.log" 2>&1 &
FREE_PID=$!
wait_port 8813 || { echo "test.sh: second backend did not start" >&2; exit 1; }
: > "$FREE_COUNT"   # do not count the readiness probe
want=$(curl -s http://127.0.0.1:8813/)
got=$("$CURL_ANUBIS" -s http://127.0.0.1:8813/)
[ "$want" = "$got" ]; check "an unprotected site returns identical bytes" $?
n=$(wc -l < "$FREE_COUNT" | tr -d ' ')
[ "$n" = 2 ]; check "an unprotected site costs no extra request (2 = one each)" $?

# 11. a harder challenge is still solved
kill "$GATE_PID" 2>/dev/null
wait "$GATE_PID" 2>/dev/null
"$GATE" --target http://127.0.0.1:8811 --listen 127.0.0.1:8913 \
    --difficulty 16 > "$TMP/gate16.log" 2>&1 &
GATE_PID=$!
wait_port 8913 || { echo "test.sh: difficulty-16 gate did not start" >&2; exit 1; }
out=$("$CURL_ANUBIS" -s http://127.0.0.1:8913/)
[ "$out" = "$BEHIND" ]; check "difficulty 16 is solved and returns the page" $?

# 12. cookies persist: -c writes the jar, -b reads it back, and a jar that has
#     gone stale is solved again instead of failing.
JAR="$TMP/jar.txt"
rm -f "$JAR"
out=$("$CURL_ANUBIS" -s -c "$JAR" http://127.0.0.1:8913/)
[ "$out" = "$BEHIND" ]; check "-c writes a cookie jar" $?
grep -q "anubis-auth" "$JAR" 2>/dev/null
check "the jar carries the Anubis auth cookie" $?

n=$("$CURL_ANUBIS" -v -b "$JAR" -o /dev/null http://127.0.0.1:8913/ 2>&1 |
        grep -c "anubis: solved")
[ "$n" = 0 ]; check "-b reuses the cookie: no second solve (solved $n times)" $?

# a jar whose token is garbage must be challenged again, not obeyed
awk 'BEGIN{FS=OFS="\t"} /-anubis-auth/ {$7="broken.TOKEN.value"} {print}' \
    "$JAR" > "$TMP/jar-bad.txt"
n=$("$CURL_ANUBIS" -v -b "$TMP/jar-bad.txt" -o "$TMP/stale.html" \
        http://127.0.0.1:8913/ 2>&1 | grep -c "anubis: solved")
[ "$n" = 1 ]; check "a stale cookie is solved again (solved $n times)" $?
[ "$(cat "$TMP/stale.html")" = "$BEHIND" ]; check "the stale-cookie run still gets the page" $?

# one invocation, two URLs on the same gate: the cookie is shared, one solve
n=$("$CURL_ANUBIS" -v -o /dev/null http://127.0.0.1:8913/ \
        -o /dev/null http://127.0.0.1:8913/ 2>&1 | grep -c "anubis: solved")
[ "$n" = 1 ]; check "two URLs in one run are solved once (solved $n times)" $?

# 13. HEAD is the gate's own headers: Anubis sends no challenge body to a HEAD
#     request, so there is nothing to solve and the interstitial headers are what
#     a HEAD gets, exactly as with plain curl.
"$CURL_ANUBIS" -s -I http://127.0.0.1:8913/ > "$TMP/head.txt"
grep -qi "^HTTP/.* 200" "$TMP/head.txt"; check "-I returns the gate's headers" $?

# 14. metarefresh: a timing challenge, no hashing, solved by waiting
kill "$GATE_PID" 2>/dev/null
wait "$GATE_PID" 2>/dev/null
"$GATE" --target http://127.0.0.1:8811 --listen 127.0.0.1:8914 \
    --difficulty 2 --algorithm metarefresh > "$TMP/gate-mr.log" 2>&1 &
GATE_PID=$!
wait_port 8914 >/dev/null
# wait_port makes a request that the gate answers with the timing page
: > "$COUNT"
out=$("$CURL_ANUBIS" -s http://127.0.0.1:8914/)
[ "$out" = "$BEHIND" ]; check "metarefresh is passed by waiting" $?


echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
