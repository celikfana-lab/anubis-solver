#!/usr/bin/env bash
# Every algorithm Anubis supports, gated by betterAnusbis and solved by a client.
#
# fast, slow, sha256 and metarefresh are solved by the Node client; argon2id and
# hashx need the memory-hard kernels, so the Python CLI does those. Each run
# asserts the protected page came back, not just that a challenge was issued.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO="$(cd .. && pwd)"
BACKEND_PORT=8002
PORT=8091
PASS=0; FAIL=0

mkdir -p /tmp/ba-site
echo '<html><body><h1>PAST THE WALL</h1></body></html>' > /tmp/ba-site/index.html
if ! curl -s -m 2 -o /dev/null "http://127.0.0.1:$BACKEND_PORT/"; then
  (cd /tmp/ba-site && setsid nohup python3 -m http.server $BACKEND_PORT --bind 127.0.0.1 >/dev/null 2>&1 &)
  sleep 1
fi

check() { # algorithm difficulty client
  local algo="$1" diff="$2" client="$3"
  pkill -f "betterAnusbis --listen :$PORT" 2>/dev/null; sleep 0.2
  setsid nohup ./betterAnusbis --listen ":$PORT" --target "http://127.0.0.1:$BACKEND_PORT" \
      --algorithm "$algo" --difficulty "$diff" >/tmp/ba-$algo.log 2>&1 &
  sleep 0.6

  local out status
  if [ "$client" = python ]; then
    out=$(cd "$REPO" && timeout 120 python3 anubis_solver.py "http://127.0.0.1:$PORT/" 2>&1)
    status=$?
  else
    out=$(cd "$REPO" && timeout 120 node -e "
      import('./tools/anubis_fetch.js').then(async (m) => {
        const r = await m.anubisFetch('http://127.0.0.1:$PORT/', { headers: { 'user-agent': 'Mozilla/5.0 (algorithm test)' } });
        process.stdout.write(r.content ?? '');
      }).catch(e => { console.error(e.message); process.exit(1); });" 2>&1)
    status=$?
  fi

  if [ $status -eq 0 ] && printf '%s' "$out" | grep -q "PAST THE WALL"; then
    printf '  %-12s difficulty %-3s via %-6s  PASS\n' "$algo" "$diff" "$client"
    PASS=$((PASS+1))
  else
    printf '  %-12s difficulty %-3s via %-6s  FAIL\n' "$algo" "$diff" "$client"
    printf '    %s\n' "$(printf '%s' "$out" | tail -2 | head -2)" | head -2
    FAIL=$((FAIL+1))
  fi
  pkill -f "betterAnusbis --listen :$PORT" 2>/dev/null
}

echo "betterAnusbis: every algorithm, each solve verified by the page coming back"
check fast        4  node
check slow        4  node
check sha256      12 node
check metarefresh 1  node
check argon2id    4  python
check hashx       4  python

# ---- honeypot -----------------------------------------------------------------
echo
echo "honeypot"
pkill -x betterAnusbis 2>/dev/null; sleep 0.2
rm -f /tmp/ba-hp-test.log
setsid nohup ./betterAnusbis --listen ":$PORT" --target "http://127.0.0.1:$BACKEND_PORT" \
    --algorithm sha256 --difficulty 4 --honeypot-log /tmp/ba-hp-test.log >/tmp/ba-hp.log 2>&1 &
sleep 0.6
page=$(curl -s -H "user-agent: crawler-probe" "http://127.0.0.1:$PORT/")
trap=$(printf '%s' "$page" | grep -o 'honeypot/[a-f0-9]*/init' | head -1)
if printf '%s' "$page" | grep -q '<script type="ignore">'; then
  printf '  %-42s PASS\n' "trap link hidden in <script type=\"ignore\">"; PASS=$((PASS+1))
else
  printf '  %-42s FAIL\n' "trap link hidden in <script type=\"ignore\">"; FAIL=$((FAIL+1))
fi

if [ -n "$trap" ]; then
  t1=$(curl -s -o /tmp/ba-maze1.html -w '%{time_total}' "http://127.0.0.1:$PORT/.within.website/x/cmd/anubis/api/$trap")
  for _ in $(seq 1 8); do curl -s -o /dev/null "http://127.0.0.1:$PORT/.within.website/x/cmd/anubis/api/$trap"; done
  t8=$(curl -s -o /tmp/ba-maze9.html -w '%{time_total}' "http://127.0.0.1:$PORT/.within.website/x/cmd/anubis/api/$trap")

  # the tarpit sleeps count^2 ms, so hit 9 must be much slower than hit 1
  if awk -v a="$t1" -v b="$t8" 'BEGIN{exit !(b > a*3)}'; then
    printf '  %-42s PASS  (%ss -> %ss)\n' "tarpit ramps with hit count" "$t1" "$t8"; PASS=$((PASS+1))
  else
    printf '  %-42s FAIL  (%ss -> %ss)\n' "tarpit ramps with hit count" "$t1" "$t8"; FAIL=$((FAIL+1))
  fi

  if grep -q "Document index" /tmp/ba-maze9.html && [ "$(grep -o 'honeypot/[a-f0-9]*/' /tmp/ba-maze9.html | wc -l)" -gt 10 ]; then
    printf '  %-42s PASS\n' "maze page links further in"; PASS=$((PASS+1))
  else
    printf '  %-42s FAIL\n' "maze page links further in"; FAIL=$((FAIL+1))
  fi

  if [ -s /tmp/ba-hp-test.log ]; then
    printf '  %-42s PASS  (%s hits logged)\n' "trap hits are logged" "$(wc -l < /tmp/ba-hp-test.log)"; PASS=$((PASS+1))
  else
    printf '  %-42s FAIL\n' "trap hits are logged"; FAIL=$((FAIL+1))
  fi

  # past the threshold the network gets a harder challenge
  for _ in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:$PORT/.within.website/x/cmd/anubis/api/$trap"; done
  raised=$(curl -s -H "user-agent: crawler-probe" "http://127.0.0.1:$PORT/" | grep -o '"difficulty":[0-9]*' | head -1)
  if [ "$raised" = '"difficulty":12' ]; then
    printf '  %-42s PASS  (4 -> 12)\n' "flagged network gets a harder challenge"; PASS=$((PASS+1))
  else
    printf '  %-42s FAIL  (got %s)\n' "flagged network gets a harder challenge" "$raised"; FAIL=$((FAIL+1))
  fi
fi

pkill -x betterAnusbis 2>/dev/null

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
