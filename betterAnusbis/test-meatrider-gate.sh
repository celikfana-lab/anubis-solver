#!/usr/bin/env bash
# The meatrider gate: suspicion buys a rung, and money buys a receipt.
#
#   ./test-meatrider-gate.sh
#
# Two things a policy file cannot express are tested here:
#
#   1. --meatrider-escalate: a network the honeypot catches gets a meatrider
#      challenge, and each doubling of its hit count moves it one wall up the
#      browser ladder (a second, a minute, an hour, three days, an ASIC's
#      second). No policy edit, no operator in the loop.
#   2. --meatrider-pay: the ASIC rungs publish a bitcoin: amount and accept an
#      operator-issued receipt as the response. The receipt is HMAC over the
#      challenge id, so it is single-use and worthless for any other id.
#
# No browser and no wallet are needed: curl plays both clients. The payout
# address is the repository's test wallet (tests/wallet/test-wallet.json) --
# a real secp256k1 key whose private half is published on purpose, because a
# fixture everyone can check is worth more than a fixture nobody can. Never send
# bitcoin to it. `python3 ../tools/test_wallet.py --check` derives the address
# from the key, so this script is not trusting a copied string.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
PORT_ESC=8096
PORT_PAY=8097
PORT_BACK=8003
PASS=0; FAIL=0
SECRET=$(printf 'ab%.0s' $(seq 32))
WALLET=../tests/wallet/test-wallet.json
TEST_ADDR=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['testnet']['address'])" "$WALLET")

mkdir -p /tmp/ba-pay-site
echo '<html><body><h1>PAST THE WALL</h1></body></html>' > /tmp/ba-pay-site/index.html
if ! curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT_BACK/"; then
  (cd /tmp/ba-pay-site && setsid nohup python3 -m http.server $PORT_BACK --bind 127.0.0.1 >/dev/null 2>&1 &)
  sleep 1
fi

check() { # name condition-detail
  local name="$1" ok="$2" detail="${3:-}"
  if [ "$ok" = 1 ]; then printf '  %-52s PASS\n' "$name"; PASS=$((PASS+1));
  else printf '  %-52s FAIL %s\n' "$name" "$detail"; FAIL=$((FAIL+1)); fi
}

stop() { # pid
  kill "$1" 2>/dev/null
  wait "$1" 2>/dev/null
}

echo "meatrider: suspicion buys a rung"
./betterAnusbis --listen 127.0.0.1:$PORT_ESC --target "http://127.0.0.1:$PORT_BACK" \
    --algorithm sha256 --difficulty 4 --honeypot --flag-threshold 2 \
    --meatrider-escalate >/tmp/ba-mr-esc.log 2>&1 &
ESC_PID=$!
sleep 0.8

BOT="Mozilla/5.0 (compatible; Scrapy/2.11)"
PAGE=$(curl -s -A "$BOT" "http://127.0.0.1:$PORT_ESC/")
TRAP=$(printf '%s' "$PAGE" | grep -o 'honeypot/[a-f0-9]*/init' | head -1)
check "the trap link is rendered" "$([ -n "$TRAP" ] && echo 1 || echo 0)" "$TRAP"

rules() { curl -s -A "$BOT" "http://127.0.0.1:$PORT_ESC/" | grep -o '"rules":{[^}]*}' | head -1; }

hit() { curl -s -A "$BOT" -o /dev/null "http://127.0.0.1:$PORT_ESC/.within.website/x/cmd/anubis/api/$TRAP"; }

hit; hit
check "2 hits: sha256 -> meatrider at a second" \
      "$(rules | grep -q '"algorithm":"meatrider","difficulty":20' && echo 1 || echo 0)" "$(rules)"
hit; hit
check "4 hits: one minute" \
      "$(rules | grep -q '"difficulty":26' && echo 1 || echo 0)" "$(rules)"
hit; hit; hit; hit
check "8 hits: one hour" \
      "$(rules | grep -q '"difficulty":32' && echo 1 || echo 0)" "$(rules)"
stop $ESC_PID

echo
echo "meatrider: \$1 of bitcoin, paid not mined"
./betterAnusbis --listen 127.0.0.1:$PORT_PAY --target "http://127.0.0.1:$PORT_BACK" \
    --meatrider-usd 1 --meatrider-pay "$TEST_ADDR" --secret-hex "$SECRET" \
    >/tmp/ba-mr-pay.log 2>&1 &
PAY_PID=$!
sleep 0.8

PAGE=$(curl -s "http://127.0.0.1:$PORT_PAY/")
check "--meatrider-usd 1 chooses the dollar rung" \
      "$(printf '%s' "$PAGE" | grep -q '"difficulty":61' && echo 1 || echo 0)"
check "the page carries a bitcoin amount in satoshis" \
      "$(printf '%s' "$PAGE" | grep -Eq '"sats":1[0-9]{3}' && echo 1 || echo 0)" \
      "$(printf '%s' "$PAGE" | grep -o '"pay":{[^}]*}')"
check "the amount is under a cent's worth of BTC formatting slips (8dp)" \
      "$(printf '%s' "$PAGE" | grep -q '"btc":"0\.0000[0-9]*"' && echo 1 || echo 0)"
check "the pay field carries the test wallet's address" \
      "$(printf '%s' "$PAGE" | grep -q "\"address\":\"$TEST_ADDR\"" && echo 1 || echo 0)" \
      "$(printf '%s' "$PAGE" | grep -o '\"pay\":{[^}]*}')"
check "which the test wallet's key actually derives" \
      "$(python3 ../tools/test_wallet.py --check >/dev/null 2>&1 && echo 1 || echo 0)"

ID=$(printf '%s' "$PAGE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
RECEIPT=$(./betterAnusbis --meatrider-receipt "$ID" --secret-hex "$SECRET")
check "the receipt command prints one 64-hex line" \
      "$(printf '%s' "$RECEIPT" | grep -Eq '^[0-9a-f]{64}$' && echo 1 || echo 0)" "$RECEIPT"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -D /tmp/ba-mr-pass.hdr \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/pass-challenge?id=$ID&response=$RECEIPT&nonce=0")
check "the receipt is accepted" "$([ "$CODE" = 302 ] && echo 1 || echo 0)" "HTTP $CODE"
check "and it sets the auth cookie" \
      "$(grep -qi 'set-cookie' /tmp/ba-mr-pass.hdr && echo 1 || echo 0)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/pass-challenge?id=$ID&response=$RECEIPT&nonce=0")
check "a spent receipt cannot be replayed" "$([ "$CODE" = 403 ] && echo 1 || echo 0)" "HTTP $CODE"

# every attempt spends the challenge, so each probe below gets a fresh id
fresh_id() { curl -s "http://127.0.0.1:$PORT_PAY/" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4; }

IDW=$(fresh_id)
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/pass-challenge?id=$IDW&response=$(printf '%064d' 0)&nonce=0")
check "a wrong receipt is refused" "$([ "$CODE" = 403 ] && echo 1 || echo 0)" "HTTP $CODE"

# a receipt is bound to its id: the same key must not open a different challenge
IDB=$(fresh_id)
RECEIPT2=$(./betterAnusbis --meatrider-receipt "$IDB" --secret-hex "$SECRET")
check "the receipt is not the same for another id" \
      "$([ "$RECEIPT" != "$RECEIPT2" ] && echo 1 || echo 0)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/pass-challenge?id=$IDB&response=$RECEIPT&nonce=0")
check "id A's receipt does not open id B" "$([ "$CODE" = 403 ] && echo 1 || echo 0)" "HTTP $CODE"

IDC=$(fresh_id)
RECEIPT3=$(./betterAnusbis --meatrider-receipt "$IDC" --secret-hex "$SECRET")
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/pass-challenge?id=$IDC&response=$RECEIPT3&nonce=0")
check "the receipt for id C does" "$([ "$CODE" = 302 ] && echo 1 || echo 0)" "HTTP $CODE"

stop $PAY_PID

# without a published address there is nothing to pay, so the ASIC rung must
# stay unmineable and unpaid: no link, no receipt.
./betterAnusbis --listen 127.0.0.1:$PORT_PAY --target "http://127.0.0.1:$PORT_BACK" \
    --algorithm meatrider --difficulty 61 --secret-hex "$SECRET" \
    >/tmp/ba-mr-nopay.log 2>&1 &
NOPAY_PID=$!
sleep 0.8
check "no --meatrider-pay means no pay field" \
      "$(curl -s "http://127.0.0.1:$PORT_PAY/" | grep -q '"pay":null' && echo 1 || echo 0)"
ID3=$(curl -s "http://127.0.0.1:$PORT_PAY/" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
REC3=$(./betterAnusbis --meatrider-receipt "$ID3" --secret-hex "$SECRET")
CODE=$(curl -s -o /dev/null -w '%{http_code}' \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/pass-challenge?id=$ID3&response=$REC3&nonce=0")
check "and a receipt is refused without an address" "$([ "$CODE" = 403 ] && echo 1 || echo 0)" "HTTP $CODE"

# the mining clip is served by the gate itself, with the right type
CODE=$(curl -s -o /tmp/ba-mr-mining.webp -w '%{http_code}' -D /tmp/ba-mr-mining.hdr \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/static/anubis/meatrider-mining.webp")
check "the mining clip is served as image/webp" \
      "$([ "$CODE" = 200 ] && [ -s /tmp/ba-mr-mining.webp ] \
         && grep -qi 'content-type: image/webp' /tmp/ba-mr-mining.hdr && echo 1 || echo 0)" \
      "HTTP $CODE $(wc -c < /tmp/ba-mr-mining.webp 2>/dev/null)"

# the WebGPU kernel, served by the gate itself: the page asks for it by name and
# falls back to the wasm module when the browser has no adapter.
CODE=$(curl -s -o /tmp/ba-mr.wgsl -w '%{http_code}' -D /tmp/ba-mr-wgsl.hdr \
       "http://127.0.0.1:$PORT_PAY/.within.website/x/cmd/anubis/api/static/anubis/meatrider.wgsl")
check "the WebGPU kernel is served as text" \
      "$([ "$CODE" = 200 ] && grep -q 'entryPoint\|fn main' /tmp/ba-mr.wgsl \
         && grep -qi 'content-type: text/plain' /tmp/ba-mr-wgsl.hdr && echo 1 || echo 0)" \
      "HTTP $CODE $(wc -c < /tmp/ba-mr.wgsl 2>/dev/null)"
check "the page mines on WebGPU before falling back to wasm" \
      "$(curl -s "http://127.0.0.1:$PORT_PAY/" \
         | grep -q 'navigator.gpu.*mrWebGPU\|mrWebGPU(raw,diff' && echo 1 || echo 0)"
check "the meatrider page shows the progress bar" \
      "$(curl -s "http://127.0.0.1:$PORT_PAY/" | grep -q 'workShow(\"2\^\"' && echo 1 || echo 0)"
stop $NOPAY_PID

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
