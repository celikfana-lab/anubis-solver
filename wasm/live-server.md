# Running a real Anubis for `make live`

The live test needs an Anubis serving a `sha256` challenge. Public hosts serve
`metarefresh` at difficulty 1, which measures nothing, so build the real thing:

```bash
# 1. the server (v1.28.3, from https://github.com/TecharoHQ/anubis)
cd /path/to/anubis
go build -o /tmp/anubis ./cmd/anubis

# 2. a page to protect
mkdir -p /tmp/anubistest/site
echo '<html><body><h1>PAST THE WALL</h1></body></html>' > /tmp/anubistest/site/index.html
(cd /tmp/anubistest/site && python3 -m http.server 8001 --bind 127.0.0.1 &)

# 3. one rule: everything gets a sha256 challenge
cat > /tmp/anubistest/policy.yaml <<'YAML'
bots:
  - name: everything-sha256
    user_agent_regex: ".+"
    action: CHALLENGE
    challenge:
      algorithm: sha256
      difficulty: 12
YAML

# 4. run it. -use-remote-address is required: newer Anubis refuses to issue a
#    challenge without an X-Real-IP header and returns 500 otherwise.
/tmp/anubis -bind 127.0.0.1:8923 -target http://127.0.0.1:8001 \
  -policy-fname /tmp/anubistest/policy.yaml -cookie-secure=false -use-remote-address

# 5. the test
cd wasm && make live        # or: node live-test.mjs --runs 8
```

`live-test.mjs` checks the outcome, not just the timing: it follows the
`pass-challenge` URL with the cookie and asserts that a subsequent request returns
the protected page. A solver that computes a wrong digest fails there even if it
was fast.

`-cookie-secure=false` is required over plain HTTP; with the default the cookie is
marked Secure and a browser (or a strict client) will not send it back.
