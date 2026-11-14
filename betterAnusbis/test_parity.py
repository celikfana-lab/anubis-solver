#!/usr/bin/env python3
"""Parity checks for the flags betterAnusbis took from cmd/anubis.

Each test starts the gate with a specific deployment shape, solves the challenge
with the real client library, and then looks at what the wire says: the status
line, the Set-Cookie attributes, the Location header, the headers the backend
received. Nothing here is asserted from the log.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import anubis_solver  # noqa: E402

BACKEND_PORT = 8411
GATE_PORT = 8412
METRICS_PORT = 8413
BASE = f"http://127.0.0.1:{GATE_PORT}"
API = "/.within.website/x/cmd/anubis/api/"

PASS = 0
FAIL = 0
SOLVER = anubis_solver.AnubisSolver(threads=4)


# --------------------------------------------------------------------- backend
class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path.endswith("/echo"):
            body = json.dumps(
                {
                    "host": self.headers.get("Host"),
                    "x_real_ip": self.headers.get("X-Real-IP"),
                    "xff": self.headers.get("X-Forwarded-For"),
                    "path": self.path,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            body = b"<html><body><h1>PAST THE WALL</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_backend():
    srv = ThreadingHTTPServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------------ gate
class Gate:
    def __init__(self, *args, policy: str | None = None):
        self.args = list(args)
        self.policy_path = None
        if policy is not None:
            fd, self.policy_path = tempfile.mkstemp(suffix=".policy")
            with os.fdopen(fd, "w") as f:
                f.write(policy)
            self.args += ["--policy", self.policy_path]
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            [os.path.join(HERE, "betterAnusbis"),
             "--listen", f"127.0.0.1:{GATE_PORT}",
             "--target", f"http://127.0.0.1:{BACKEND_PORT}", *self.args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 8
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out = self.proc.stdout.read().decode() if self.proc.stdout else ""
                raise RuntimeError(f"gate died: {out}")
            try:
                with socket.create_connection(("127.0.0.1", GATE_PORT), 0.2):
                    return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("gate did not start listening")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.policy_path:
            os.unlink(self.policy_path)


# ----------------------------------------------------------------------- http
def request(method, path, headers=None, timeout=15):
    conn = http.client.HTTPConnection("127.0.0.1", GATE_PORT, timeout=timeout)
    conn.request(method, path, headers=headers or {})
    r = conn.getresponse()
    body = r.read()
    status = r.status
    hdrs = r.getheaders()
    conn.close()
    return status, hdrs, body


def header(hdrs, name):
    for k, v in hdrs:
        if k.lower() == name.lower():
            return v
    return None


def set_cookies(hdrs):
    return [v for k, v in hdrs if k.lower() == "set-cookie"]


# ---------------------------------------------------------------------- solve
def solve_once(prefix="", redir=None, headers=None):
    """GET the challenge, solve it, POST the answer back. Returns (status, headers)."""
    status, hdrs, body = request("GET", prefix + "/", headers=headers)
    if status != 200:
        raise RuntimeError(f"challenge page returned {status}: {body[:200]!r}")
    ch = anubis_solver.parse_challenge(body.decode(errors="replace"))
    if ch is None:
        raise RuntimeError(f"no challenge in page: {body[:300]!r}")
    sol = SOLVER.solve(ch)
    q = {"id": ch.id, "response": sol.response_hex, "nonce": str(sol.nonce)}
    if redir is not None:
        q["redir"] = redir
    status, hdrs, body = request("GET", prefix + API + "pass-challenge?" + urlencode(q),
                                 headers=headers)
    return status, hdrs, body, ch


# ---------------------------------------------------------------------- checks
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  {name:<66} PASS")
    else:
        FAIL += 1
        print(f"  {name:<66} FAIL")
        if detail:
            for line in str(detail).splitlines()[:4]:
                print(f"      {line}")


def main():
    global FAIL
    backend = start_backend()
    print("betterAnusbis: the flags it took from cmd/anubis, checked on the wire\n")

    # ---- 1. robots.txt, status codes, benchmark mode
    with Gate("--difficulty", "6", "--serve-robots-txt"):
        st, hdrs, body = request("GET", "/robots.txt")
        check("robots.txt is served and disallows everything",
              st == 200 and b"User-agent: *" in body and b"Disallow: /" in body,
              f"{st} {body!r}")
    with Gate("--difficulty", "6"):
        st, _, body = request("GET", "/robots.txt")
        check("no --serve-robots-txt means /robots.txt is challenged", st == 200 and b"anubis_challenge" in body, st)

    with Gate("--difficulty", "6", "--challenge-status", "429"):
        st, hdrs, body = request("GET", "/")
        check("--challenge-status 429 answers the page with 429", st == 429, st)

    with Gate("--difficulty", "6", "--deny-status", "403",
              policy="deny ua contains ParityBot\n"):
        st, _, body = request("GET", "/", headers={"User-Agent": "ParityBot/1.0"})
        check("--deny-status 403 denies with 403", st == 403, st)
    with Gate("--difficulty", "6", policy="deny ua contains ParityBot\n"):
        st, _, body = request("GET", "/", headers={"User-Agent": "ParityBot/1.0"})
        check("default deny status is 200, as Anubis ships it", st == 200, st)

    # ---- 2. cookies: the full attribute set
    with Gate("--difficulty", "6", "--cookie-domain", "example.org", "--cookie-secure",
              "--cookie-same-site", "none", "--cookie-expiration-time", "120"):
        status, hdrs, body, ch = solve_once()
        jar = set_cookies(hdrs)
        auth = next((c for c in jar if "cookie-verification" not in c), "")
        check("a solved challenge redirects", status == 302, f"{status} {body[:120]!r}")
        check("cookie has Domain=example.org", "Domain=example.org" in auth, auth)
        check("cookie has Secure when asked", "Secure" in auth, auth)
        check("cookie is HttpOnly by default", "HttpOnly" in auth, auth)
        check("cookie is Partitioned when Secure", "Partitioned" in auth, auth)
        check("cookie carries SameSite=None", "SameSite=None" in auth, auth)
        check("--cookie-expiration-time 120 becomes Max-Age=120", "Max-Age=120" in auth, auth)

    with Gate("--difficulty", "6", "--no-cookie-secure", "--cookie-same-site", "none"):
        status, hdrs, body, ch = solve_once()
        auth = next((c for c in set_cookies(hdrs) if "cookie-verification" not in c), "")
        check("SameSite=None downgrades to Lax without Secure", "SameSite=Lax" in auth, auth)
        check("no Secure and no Partitioned over plain HTTP",
              "Secure" not in auth and "Partitioned" not in auth, auth)

    with Gate("--difficulty", "6", "--cookie-expiration-time", "0"):
        status, hdrs, body, ch = solve_once()
        auth = next((c for c in set_cookies(hdrs) if "cookie-verification" not in c), "")
        check("--cookie-expiration-time 0 makes a session cookie", "Max-Age" not in auth, auth)

    # ---- 3. base prefix: routing, the page's links, and the proxy path
    with Gate("--difficulty", "6", "--base-prefix", "/anubis"):
        st, _, body = request("GET", "/anubis/")
        text = body.decode(errors="replace")
        check("--base-prefix serves the challenge under the prefix", st == 200 and "anubis_challenge" in text, st)
        check("the page's API links carry the prefix",
              "/anubis" + API + "pass-challenge" in text, text[:0])
        status, hdrs, body, ch = solve_once(prefix="/anubis")
        check("a challenge solved under the prefix is accepted", status == 302, status)
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/anubis/", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("the token opens the door under the prefix",
              st == 200 and b"PAST THE WALL" in body, st)
        st, _, body = request("GET", "/anubis/echo", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("--base-prefix keeps the prefix on the upstream path (no strip)",
              st == 200 and b"/anubis/echo" in body, body[:200])

    with Gate("--difficulty", "6", "--base-prefix", "/anubis", "--strip-base-prefix"):
        status, hdrs, body, ch = solve_once(prefix="/anubis")
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/anubis/echo", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("--strip-base-prefix removes it before the target",
              st == 200 and b'"path": "/echo"' in body, body[:200])

    # ---- 4. the redirect allow-list
    with Gate("--difficulty", "6", "--redirect-domains", "*.example.org,helpers.test"):
        for target, want, label in [
            ("https://foo.example.org/x", "https://foo.example.org/x", "a glob-allowed host is used"),
            ("https://helpers.test/y", "https://helpers.test/y", "an exact allowed host is used"),
            ("//foo.example.org/z", "//foo.example.org/z", "a scheme-relative allowed host is used"),
            ("https://evil.test/", "/", "an unlisted host is refused"),
            ("https://example.org.evil.test/", "/", "a suffix trick is refused"),
            ("/local/path", "/local/path", "a local path is used"),
        ]:
            status, hdrs, body, ch = solve_once(redir=target)
            got = header(hdrs, "Location")
            check(f"redir {label}", status == 302 and got == want, f"{status} {got}")
    with Gate("--difficulty", "6"):
        status, hdrs, body, ch = solve_once(redir="https://evil.test/")
        check("without --redirect-domains any other host is refused", header(hdrs, "Location") == "/",
              header(hdrs, "Location"))
        status, hdrs, body, ch = solve_once(redir="/a%0d%0aSet-Cookie: injected=1")
        got = header(hdrs, "Location") or ""
        check("a CRLF in redir cannot split the response",
              "\r" not in got and "\n" not in got and "injected" not in got, repr(got))

    # ---- 5. who the client is
    def meta_real_ip(headers=None, args=()):
        with Gate("--difficulty", "6", *args):
            st, _, body = request("GET", "/", headers=headers)
            ch = anubis_solver.parse_challenge(body.decode(errors="replace"))
            return ch.raw["challenge"]["metadata"]["X-Real-IP"]

    ip = meta_real_ip({"X-Forwarded-For": "1.2.3.4, 10.0.0.1"})
    check("X-Forwarded-For flattening picks the public client", ip == "1.2.3.4", ip)
    ip = meta_real_ip({"X-Forwarded-For": "10.1.2.3, 10.0.0.1"})
    check("all-private XFF keeps the leftmost hop", ip == "10.1.2.3", ip)
    ip = meta_real_ip({"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}, args=("--no-xff-strip-private",))
    check("--no-xff-strip-private keeps a private hop", ip == "10.0.0.1", ip)
    ip = meta_real_ip({"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}, args=("--use-remote-address",))
    check("--use-remote-address ignores XFF entirely", ip == "127.0.0.1", ip)
    ip = meta_real_ip({"CF-Connecting-IP": "9.9.9.9", "X-Forwarded-For": "1.2.3.4"},
                      args=("--custom-real-ip-header", "CF-Connecting-IP"))
    check("--custom-real-ip-header wins over XFF", ip == "9.9.9.9", ip)
    ip = meta_real_ip({"X-Forwarded-For": "1.2.3.4:5678"})
    check("a port on an XFF entry is dropped", ip == "1.2.3.4", ip)

    # ---- 6. the backend sees the flattened address and the Host override
    with Gate("--difficulty", "6", "--target-host", "backend.internal"):
        status, hdrs, body, ch = solve_once(headers={"X-Forwarded-For": "5.6.7.8"})
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/echo",
                              headers={"Cookie": f"techaro.lol-anubis-auth={token}",
                                       "X-Forwarded-For": "5.6.7.8"})
        seen = json.loads(body)
        check("--target-host rewrites the upstream Host header",
              seen["host"] == "backend.internal", seen["host"])
        check("the upstream gets the flattened X-Real-IP", seen["x_real_ip"] == "5.6.7.8", seen["x_real_ip"])
        check("the upstream gets a single-address X-Forwarded-For",
              seen["xff"] == "5.6.7.8", seen["xff"])

    # ---- 7. the metrics listener
    def scrape(port, path):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", path)
        r = conn.getresponse()
        body = r.read().decode(errors="replace")
        conn.close()
        return r.status, body

    with Gate("--difficulty", "6", "--metrics-bind", f"127.0.0.1:{METRICS_PORT}"):
        st, body = scrape(METRICS_PORT, "/healthz")
        check("/healthz answers 200 OK", st == 200 and body.strip() == "OK", f"{st} {body!r}")
        st, body = scrape(METRICS_PORT, "/nope")
        check("the metrics listener answers 404 for anything else", st == 404, st)
        status, hdrs, body, ch = solve_once()
        st, metrics = scrape(METRICS_PORT, "/metrics")
        check("/metrics is Prometheus text", st == 200 and "# TYPE" in metrics, st)
        check("/metrics uses Anubis's counter names",
              'anubis_challenges_issued{method="sha256"}' in metrics
              and 'anubis_challenges_validated{method="sha256"}' in metrics
              and "anubis_proxied_requests_total" in metrics, metrics[:200])
        check("a solved challenge is counted as issued and validated",
              'anubis_challenges_issued{method="sha256"} 1' in metrics
              and 'anubis_challenges_validated{method="sha256"} 1' in metrics, metrics)
        check("/metrics carries the build identity",
              'betteranusbis_build_info{version="1.15.0"' in metrics, metrics[:120])
    with Gate("--difficulty", "6", "--metrics-bind", f"127.0.0.1:{METRICS_PORT}",
              policy="deny ua contains ParityBot\n"):
        request("GET", "/", headers={"User-Agent": "ParityBot/1.0"})
        request("GET", "/", headers={"User-Agent": "Mozilla/5.0"})
        st, metrics = scrape(METRICS_PORT, "/metrics")
        check("a deny lands in requests_total{result=\"denied\"}",
              'anubis_requests_total{result="denied"} 1' in metrics,
              [ln for ln in metrics.splitlines() if "requests_total" in ln])
        check("a rule match is labelled with its index in policy_results",
              'anubis_policy_results{rule="rule 0",action="DENY"} 1' in metrics,
              [ln for ln in metrics.splitlines() if "policy_results" in ln])
        check("the challenge a non-matching request got is counted",
              'anubis_requests_total{result="challenged"} 1' in metrics,
              [ln for ln in metrics.splitlines() if "result=" in ln])
    try:
        scrape(METRICS_PORT, "/metrics")
        check("no --metrics-bind means no metrics port", False, "it answered")
    except OSError:
        check("no --metrics-bind means no metrics port", True)

    # ---- 8. the token is bound to the client, like Anubis's --jwt-restriction-header
    def token_for(args=(), headers=None):
        with Gate("--difficulty", "6", *args):
            status, hdrs, body, ch = solve_once(headers=headers)
            return next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                         if "cookie-verification" not in c), "")

    with Gate("--difficulty", "6"):
        status, hdrs, body, ch = solve_once()
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("a token works from the address that solved it", st == 200 and b"PAST THE WALL" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}",
                                                   "X-Forwarded-For": "9.9.9.9"})
        check("the same token is refused from another address",
              b"anubis_challenge" in body and b"PAST THE WALL" not in body, st)
    with Gate("--difficulty", "6", "--jwt-restriction-header", ""):
        status, hdrs, body, ch = solve_once()
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}",
                                                   "X-Forwarded-For": "9.9.9.9"})
        check("--jwt-restriction-header \"\" turns the binding off",
              st == 200 and b"PAST THE WALL" in body, st)

    # ---- 9. policy networks: both families actually match
    with Gate("--difficulty", "6", policy="deny net 10.0.0.0/8\ndeny net 2001:db8::/32\n"):
        st, _, body = request("GET", "/", headers={"X-Forwarded-For": "10.1.2.3"})
        check("an IPv4 /8 rule denies", st == 200 and b"denied by policy" in body, f"{st} {body[:60]!r}")
        st, _, body = request("GET", "/", headers={"X-Forwarded-For": "2001:db8::1"})
        check("an IPv6 /32 rule denies", st == 200 and b"denied by policy" in body, f"{st} {body[:60]!r}")
        st, _, body = request("GET", "/", headers={"X-Forwarded-For": "2001:db9::1"})
        check("an IPv6 address outside the rule is challenged",
              b"anubis_challenge" in body, body[:80])

    # ---- 10. the restriction header is the value the token is bound to
    with Gate("--difficulty", "6", "--jwt-restriction-header", "X-Client-IP"):
        status, hdrs, body, ch = solve_once(headers={"X-Client-IP": "1.1.1.1"})
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}",
                                                   "X-Client-IP": "1.1.1.1"})
        check("the header value that solved it opens the door",
              st == 200 and b"PAST THE WALL" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}",
                                                   "X-Client-IP": "2.2.2.2"})
        check("a different header value is refused",
              b"anubis_challenge" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("losing the header loses the token, as with upstream",
              b"anubis_challenge" in body, st)
    with Gate("--difficulty", "6", "--jwt-restriction-header", "X-Client-IP"):
        status, hdrs, body, ch = solve_once()
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("with no such header at all, the computed address is the binding",
              st == 200 and b"PAST THE WALL" in body, st)

    # ---- 11. the signing key outlives the process
    secret = os.path.join(tempfile.mkdtemp(), "signing.key")
    with Gate("--difficulty", "6", "--secret-file", secret):
        status, hdrs, body, ch = solve_once()
        token = next((c.split("=", 1)[1].split(";")[0] for c in set_cookies(hdrs)
                      if "cookie-verification" not in c), "")
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("a token works while the gate that minted it is up",
              st == 200 and b"PAST THE WALL" in body, st)
    check("--secret-file created the key", os.path.exists(secret), secret)
    mode = os.stat(secret).st_mode & 0o777 if os.path.exists(secret) else 0
    check("the key file is 0600", mode == 0o600, oct(mode))
    with Gate("--difficulty", "6", "--secret-file", secret):
        st, _, body = request("GET", "/", headers={"Cookie": f"techaro.lol-anubis-auth={token}"})
        check("the same token still works after a restart",
              st == 200 and b"PAST THE WALL" in body, st)
    junk = os.path.join(tempfile.mkdtemp(), "junk.key")
    with open(junk, "w") as f:
        f.write("this is not a key\n")
    dead = subprocess.run(
        [os.path.join(HERE, "betterAnusbis"), "--listen", f"127.0.0.1:{GATE_PORT}",
         "--target", f"http://127.0.0.1:{BACKEND_PORT}", "--secret-file", junk],
        capture_output=True, timeout=10)
    check("a key file with the wrong contents is refused, not overwritten",
          dead.returncode != 0 and b"Refusing" in dead.stderr,
          f"{dead.returncode} {dead.stderr[:120]!r}")
    with open(junk) as f:
        check("...and the bad file was left alone", "not a key" in f.read())

    # ---- 12. regex rules, and the per-rule algorithm
    policy = ("deny ua matches (ParityBot|Scraper)[0-9]+\n"
              "challenge path matches ^/private/ difficulty 8\n")
    with Gate("--difficulty", "6", policy=policy):
        st, _, body = request("GET", "/", headers={"User-Agent": "ParityBot42"})
        check("ua matches a regex and denies", st == 200 and b"denied by policy" in body,
              f"{st} {body[:60]!r}")
        st, _, body = request("GET", "/", headers={"User-Agent": "ParityBot"})
        check("the regex does not match what it should not",
              b"anubis_challenge" in body, body[:60])
        st, _, body = request("GET", "/private/x")
        ch = anubis_solver.parse_challenge(body.decode(errors="replace"))
        check("path matches a regex and sets the difficulty",
              ch is not None and ch.difficulty == 8, ch and ch.difficulty)
    with Gate("--difficulty", "6", policy="deny ua matches [unclosed\n"):
        st, _, body = request("GET", "/")
        check("a regex that does not compile does not take the gate down",
              st == 200 and b"anubis_challenge" in body, st)

    pol = "challenge ua contains RuleBot algorithm fast difficulty 3\n"
    with Gate("--difficulty", "6", policy=pol):
        status, hdrs, body, ch = solve_once(headers={"User-Agent": "RuleBot/1.0"})
        check("a rule can name its own algorithm", ch.algorithm == "fast", ch.algorithm)
        check("and the challenge it issued is solved as that algorithm", status == 302, status)
        status, hdrs, body, ch = solve_once(headers={"User-Agent": "Mozilla/5.0"})
        check("everyone else keeps the global algorithm", ch.algorithm == "sha256", ch.algorithm)

    # ---- 13. a real Anubis botPolicies.yaml, imported and evaluated
    upstream = os.environ.get("ANUBIS_DATA_DIR",
                              "/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis/data")
    policy = os.path.join(upstream, "botPolicies.yaml")
    if not os.path.exists(policy):
        print("  (skipped the Anubis policy checks: no botPolicies.yaml under "
              f"{upstream}; set ANUBIS_DATA_DIR)")
    else:
        with Gate("--policy", policy, "--data-dir", upstream):
            def decide(ua, path="/", headers=None):
                hdrs = {"User-Agent": ua}
                hdrs.update(headers or {})
                st, _, body = request("GET", path, headers=hdrs)
                text = body.decode(errors="replace")
                if "PAST THE WALL" in text:
                    return "allow"
                if "denied by policy" in text:
                    return "deny"
                ch = anubis_solver.parse_challenge(text)
                if ch is not None:
                    return f"challenge {ch.algorithm} {ch.difficulty}"
                return "other"

            check("a curl UA carries weight 0 and is allowed", decide("curl/8.5.0") == "allow",
                  decide("curl/8.5.0"))
            check("a browser UA is weighed +10 and gets fast at 2",
                  decide("Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0") == "challenge fast 2",
                  decide("Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"))
            check("an AI client UA is denied", decide("ChatGPT-User/1.0") == "deny",
                  decide("ChatGPT-User/1.0"))
            googlebot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            check("Googlebot from a Google range is allowed",
                  decide(googlebot, headers={"X-Forwarded-For": "66.249.64.5"}) == "allow",
                  decide(googlebot, headers={"X-Forwarded-For": "66.249.64.5"}))
            check("Googlebot from anywhere else is only a browser",
                  decide(googlebot, headers={"X-Forwarded-For": "1.2.3.4"}) == "challenge fast 2",
                  decide(googlebot, headers={"X-Forwarded-For": "1.2.3.4"}))
            check("the keep-internet-working rules allow /robots.txt",
                  decide("curl/8.5.0", path="/robots.txt") not in ("deny",) and
                  "challenge" not in decide("curl/8.5.0", path="/robots.txt"),
                  decide("curl/8.5.0", path="/robots.txt"))
            check("a header expression adds weight 5 and gets metarefresh at 1",
                  decide("curl/8.5.0", headers={"X-Firefox-Ai": "1"}) == "challenge metarefresh 1",
                  decide("curl/8.5.0", headers={"X-Firefox-Ai": "1"}))
            check("an empty User-Agent is denied by the rfc-violations rule",
                  decide("") == "deny", decide(""))
            status, hdrs, body, ch = solve_once(headers={"User-Agent": "Mozilla/5.0 Firefox/128.0"})
            check("a challenge the YAML policy chose is solvable end to end",
                  status == 302 and ch.algorithm == "fast" and ch.difficulty == 2,
                  f"{status} {ch.algorithm} {ch.difficulty}")

    # ---- 14. the old flags still behave
    with Gate("--difficulty", "6", "--stateless"):
        status, hdrs, body, ch = solve_once()
        check("--stateless still solves", status == 302, status)
    with Gate("--difficulty", "6", "--no-honeypot"):
        st, _, body = request("GET", "/")
        check("--no-honeypot leaves the trap link out", b'href="/.within.website/x/cmd/anubis/api/honeypot/' not in body, "")
    with Gate("--difficulty", "6"):
        st, _, body = request("GET", "/")
        check("the trap link is there by default", b'honeypot/' in body, "")

    print(f"\n{PASS} passed, {FAIL} failed")
    backend.shutdown()
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
