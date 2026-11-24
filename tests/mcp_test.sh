#!/usr/bin/env bash
# mcp_test.sh — exercise the Anubis MCP server over stdio.
#
# One JSON-RPC request per line in, one response per line out. Every assertion
# prints one PASS/FAIL line; a leak-proof trap kills the gate and the backend
# HTTP server this script starts. python3 is used only to validate the JSON the
# server produced, never inside the server.
#
#   ./tests/mcp_test.sh            # builds the .so and ./anubis_mcp if needed
#   MCP_BIN=/path/to/bin ./tests/mcp_test.sh
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BIN=${MCP_BIN:-$ROOT/anubis_mcp}

# 8098/8099 are the documented defaults, but another dev server on the machine
# must not turn this into a FAIL. Fall back to ephemeral ports when taken.
port_free() {
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

PORT_BACKEND=${MCP_PORT_BACKEND:-8098}
PORT_GATE=${MCP_PORT_GATE:-8099}
if ! port_free "$PORT_BACKEND"; then
    PORT_BACKEND="$(free_port)"
fi
if [ "$PORT_GATE" = "$PORT_BACKEND" ] || ! port_free "$PORT_GATE"; then
    PORT_GATE="$(free_port)"
    while [ "$PORT_GATE" = "$PORT_BACKEND" ]; do
        PORT_GATE="$(free_port)"
    done
fi

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/anubis_mcp_test.XXXXXX") || {
    echo "FAIL cannot create temp directory" >&2
    exit 1
}
HTTP_PID=""
GATE_PID=""
cleanup() {
    if [ -n "$GATE_PID" ] && kill -0 "$GATE_PID" 2>/dev/null; then
        kill "$GATE_PID" 2>/dev/null
    fi
    if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
        kill "$HTTP_PID" 2>/dev/null
    fi
    sleep 0.2
    if [ -n "$GATE_PID" ] && kill -0 "$GATE_PID" 2>/dev/null; then
        kill -9 "$GATE_PID" 2>/dev/null
    fi
    if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
        kill -9 "$HTTP_PID" 2>/dev/null
    fi
    [ -n "$GATE_PID" ] && wait "$GATE_PID" 2>/dev/null
    [ -n "$HTTP_PID" ] && wait "$HTTP_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

wait_port() { # port seconds
    local i
    for i in $(seq 1 $((10 * $2))); do
        port_open "$1" && return 0
        sleep 0.1
    done
    return 1
}

run_requests() { # outfile request...
    local out=$1
    shift
    printf '%s\n' "$@" | "$BIN" >"$out" 2>"$out.err"
}

# --------------------------------------------------------------- build
if [ ! -f "$ROOT/libanubis_solver.so" ]; then
    make -C "$ROOT" -j8 libanubis_solver.so >"$TMP/build_so.log" 2>&1 ||
        { echo "FAIL make libanubis_solver.so (see $TMP/build_so.log)" >&2; exit 1; }
fi
if [ ! -x "$BIN" ] || [ "$ROOT/src/mcp/anubis_mcp.c" -nt "$BIN" ] ||
    [ "$ROOT/src/fetch/anubis_fetch.c" -nt "$BIN" ] ||
    [ "$ROOT/src/fetch/fetch_impersonate.c" -nt "$BIN" ] ||
    [ "$ROOT/src/fetch/anubis_fetch.h" -nt "$BIN" ] ||
    [ "$ROOT/include/anubis-solver.h" -nt "$BIN" ]; then
    if ! (cd "$ROOT" && make anubis_mcp >"$TMP/build_mcp.log" 2>&1); then
        cat "$TMP/build_mcp.log" >&2
        echo "FAIL build $BIN" >&2
        exit 1
    fi
fi

# --------------------------------------------------------------- validator
cat >"$TMP/check.py" <<'PY'
import json
import re
import sys

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def by_id(lines):
    found = {}
    for resp in lines:
        found[resp.get("id")] = resp
    return found


def tool_text(resp):
    return resp["result"]["content"][0]["text"]


def main():
    mode, path = sys.argv[1], sys.argv[2]
    lines = load(path)
    ids = by_id(lines)

    if mode == "valid":
        assert lines, "no responses"
        assert all(isinstance(r, dict) and r.get("jsonrpc") == "2.0" for r in lines)
    elif mode == "init":
        r = ids[1]["result"]
        assert r["protocolVersion"] == "2024-11-05"
        assert r["serverInfo"]["name"] == "anubis"
        assert r["capabilities"]["tools"] == {}
    elif mode == "tools":
        tools = ids[2]["result"]["tools"]
        names = [t["name"] for t in tools]
        assert sorted(names) == ["anubis_backends", "anubis_dump_headers",
                                 "anubis_fetch", "anubis_fetch_raw",
                                 "anubis_solve", "anubis_solve_raw",
                                 "anubis_version"], names
        for tool in tools:
            assert tool["description"], tool["name"]
            schema = tool["inputSchema"]
            assert schema["type"] == "object"
            assert isinstance(schema["properties"], dict)
            assert isinstance(schema["required"], list)
    elif mode == "solve_sha256":
        inner = json.loads(tool_text(ids[3]))
        assert isinstance(inner["nonce"], int) and inner["nonce"] >= 0
        assert HEX64.match(inner["response"]), inner["response"]
        assert inner["algorithm"] == "sha256"
        assert ids[3]["result"]["isError"] is False
    elif mode == "solve_tensor":
        inner = json.loads(tool_text(ids[4]))
        assert isinstance(inner["nonce"], int)
        assert HEX64.match(inner["response"]), inner["response"]
        assert inner["algorithm"] == "tensor"
    elif mode == "solve_raw":
        text = tool_text(ids[9])
        assert ids[9]["result"]["isError"] is False, text
        match = re.match(
            r"^id=([0-9a-f-]+)&response=([0-9a-f]{64})&nonce=([0-9]+)"
            r"&elapsedTime=1$", text)
        assert match, text
        assert match.group(1) == "00000000-0000-0000-0000-000000000001", match.group(1)
        assert 0 <= int(match.group(3)), text
    elif mode == "version":
        inner = json.loads(tool_text(ids[5]))
        assert inner["version"] == "2.40", inner["version"]
        assert inner["codename"] == "shyleaf", inner["codename"]
        for alg in ("fast", "slow", "sha256", "wasm-sha256", "argon2id", "hashx",
                    "tensor"):
            assert alg in inner["algorithms"], alg
    elif mode == "backends":
        inner = json.loads(tool_text(ids[8]))
        assert "cpu" in inner["compiled"], inner
        assert set(inner["available"]) <= set(inner["compiled"]), inner
        assert "cpu" in inner["available"], inner
    elif mode == "unknown":
        assert ids[6]["error"]["code"] == -32601
        assert "result" not in ids[6]
    elif mode == "ping":
        assert ids[7]["result"] == {}
    elif mode == "one_response_per_request":
        assert len(lines) == 9, [r.get("id") for r in lines]
        assert sorted(ids) == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    elif mode == "malformed":
        assert lines[0]["id"] is None
        assert lines[0]["error"]["code"] == -32700
        assert ids[9]["result"] == {}, "process died after a parse error?"
    elif mode == "fetch":
        r = ids[1]["result"]
        assert r["isError"] is False, tool_text(ids[1])
        text = tool_text(ids[1])
        assert text.startswith("status: 200\nurl: "), text[:80]
        assert "PAST THE WALL" in text, text[:200]
        assert "<h1>" not in text and "<script" not in text, "HTML not stripped"
    elif mode == "fetch_raw":
        r = ids[2]["result"]
        assert r["isError"] is False, tool_text(ids[2])
        text = tool_text(ids[2])
        assert text.startswith("status: 200\nurl: "), text[:80]
        assert "PAST THE WALL" in text, text[:200]
        assert "<html>" in text, "HTML was stripped"
        assert "<script" in text, "script tags were stripped"
    elif mode == "dump_headers":
        r = ids[3]["result"]
        assert r["isError"] is False, tool_text(ids[3])
        text = tool_text(ids[3])
        assert text.startswith("status: 200\nurl: "), text[:80]
        assert "headers: " in text, text[:80]
        assert "Set-Cookie" in text or "set-cookie" in text, text[:400]
        assert text.count("HTTP/1.") >= 2, "only the final response was dumped"
    else:
        raise SystemExit("unknown mode " + mode)
    return 0


try:
    sys.exit(main())
except AssertionError as exc:
    print("assertion: %s" % (exc,), file=sys.stderr)
    sys.exit(1)
except (KeyError, IndexError, TypeError, ValueError) as exc:
    print("bad response shape: %r" % (exc,), file=sys.stderr)
    sys.exit(1)
PY

# --------------------------------------------------------------- protocol batch
OUT1=$TMP/out1.jsonl
run_requests "$OUT1" \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp_test","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"anubis_solve","arguments":{"algorithm":"sha256","challenge":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","difficulty":4}}}' \
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"anubis_solve","arguments":{"algorithm":"tensor","challenge":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","difficulty":2}}}' \
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"anubis_version","arguments":{}}}' \
    '{"jsonrpc":"2.0","id":6,"method":"does/not/exist"}' \
    '{"jsonrpc":"2.0","id":7,"method":"ping"}' \
    '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"anubis_backends","arguments":{}}}' \
    '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"anubis_solve_raw","arguments":{"input":"{\"rules\":{\"algorithm\":\"fast\",\"difficulty\":1},\"challenge\":\"0123456789abcdef\",\"id\":\"00000000-0000-0000-0000-000000000001\"}"}}}' \
    ''

check() { # mode description
    if python3 "$TMP/check.py" "$1" "$OUT1"; then pass "$2"; else fail "$2"; fi
}

check valid "stdout lines are all JSON-RPC 2.0 objects"
check init "initialize returns protocolVersion 2024-11-05 and serverInfo.name anubis"
check tools "tools/list lists exactly anubis_backends, anubis_dump_headers, anubis_fetch, anubis_fetch_raw, anubis_solve, anubis_solve_raw, anubis_version"
check solve_sha256 "anubis_solve sha256 difficulty 4 returns nonce and 64-hex response"
check solve_tensor "anubis_solve tensor difficulty 2 returns nonce and 64-hex response"
check solve_raw "anubis_solve_raw takes the raw challenge and returns the raw pass-challenge query"
check version "anubis_version returns version 2.40 and codename shyleaf"
check backends "anubis_backends agrees with the library inventory"
check unknown "unknown method returns JSON-RPC error -32601"
check ping "ping returns an empty result"
check one_response_per_request "notifications get no response (9 responses for 10 requests)"

# --------------------------------------------------------------- parse error batch
OUT2=$TMP/out2.jsonl
run_requests "$OUT2" \
    'this is not json' \
    '{"jsonrpc":"2.0","id":9,"method":"ping"}'
if python3 "$TMP/check.py" malformed "$OUT2"; then
    pass "malformed JSON returns -32700 and the server keeps running"
else
    fail "malformed JSON returns -32700 and the server keeps running"
fi

# --------------------------------------------------------------- end to end
GATE=$ROOT/betterAnusbis/betterAnusbis
if [ ! -x "$GATE" ] || [ "$ROOT/betterAnusbis/betterAnusbis.c" -nt "$GATE" ]; then
    make -C "$ROOT/betterAnusbis" -j4 >"$TMP/build_gate.log" 2>&1 || true
fi
mkdir -p "$TMP/www"
cat >"$TMP/www/index.html" <<'HTML'
<!doctype html>
<html>
  <head><title>gate test</title><style>body{color:#333}</style></head>
  <body>
    <h1>PAST THE WALL</h1>
    <p>The gate solved the challenge &amp; let us through.</p>
    <script>var hidden = "not text";</script>
  </body>
</html>
HTML

FETCH_OK=0
if [ ! -x "$GATE" ]; then
    fail "anubis_fetch through the local gate (betterAnusbis binary missing)"
elif port_open "$PORT_GATE" || port_open "$PORT_BACKEND"; then
    fail "anubis_fetch through the local gate (port $PORT_GATE or $PORT_BACKEND already in use)"
elif ! python3 -m http.server --help >/dev/null 2>&1; then
    fail "anubis_fetch through the local gate (python3 http.server unavailable)"
else
    (cd "$TMP/www" && exec python3 -m http.server "$PORT_BACKEND" --bind 127.0.0.1) \
        >"$TMP/http.log" 2>&1 &
    HTTP_PID=$!
    (cd "$ROOT/betterAnusbis" && exec ./betterAnusbis --listen "127.0.0.1:$PORT_GATE" \
        --target "http://127.0.0.1:$PORT_BACKEND" --algorithm sha256 --difficulty 4) \
        >"$TMP/gate.log" 2>&1 &
    GATE_PID=$!
    if wait_port "$PORT_BACKEND" 5 && wait_port "$PORT_GATE" 5; then
        OUT3=$TMP/out3.jsonl
        GATE_URL="http://127.0.0.1:$PORT_GATE/"
        run_requests "$OUT3" \
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"anubis_fetch\",\"arguments\":{\"url\":\"$GATE_URL\"}}}" \
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"anubis_fetch_raw\",\"arguments\":{\"url\":\"$GATE_URL\"}}}" \
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"anubis_dump_headers\",\"arguments\":{\"url\":\"$GATE_URL\"}}}"
        if python3 "$TMP/check.py" fetch "$OUT3"; then
            pass "anubis_fetch through the local gate returns isError false and PAST THE WALL"
            FETCH_OK=1
        else
            fail "anubis_fetch through the local gate returns isError false and PAST THE WALL"
        fi
        if python3 "$TMP/check.py" fetch_raw "$OUT3"; then
            pass "anubis_fetch_raw returns raw HTML, script tags intact"
        else
            fail "anubis_fetch_raw returns raw HTML, script tags intact"
        fi
        if python3 "$TMP/check.py" dump_headers "$OUT3"; then
            pass "anubis_dump_headers returns every response header block"
        else
            fail "anubis_dump_headers returns every response header block"
        fi
    else
        fail "anubis_fetch through the local gate (gate did not start)"
    fi
    if [ "$FETCH_OK" -eq 0 ]; then
        echo "--- gate log ---" >&2
        tail -20 "$TMP/gate.log" >&2 2>/dev/null || true
        echo "--- http log ---" >&2
        tail -5 "$TMP/http.log" >&2 2>/dev/null || true
    fi
fi

# --------------------------------------------------------------- summary
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
