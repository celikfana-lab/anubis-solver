#!/usr/bin/env python3
"""Parity checks for the flags betterAnusbis took from cmd/anubis.

Each test starts the gate with a specific deployment shape, solves the challenge
with the real client library, and then looks at what the wire says: the status
line, the Set-Cookie attributes, the Location header, the headers the backend
received. Nothing here is asserted from the log.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import base64
import stat as statmod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import anubis_solver  # noqa: E402

BACKEND_PORT = 8411
GATE_PORT = 8412
METRICS_PORT = 8413
WS_PORT = 8414
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
BASE = f"http://127.0.0.1:{GATE_PORT}"
API = "/.within.website/x/cmd/anubis/api/"

PASS = 0
FAIL = 0
SOLVER = anubis_solver.AnubisSolver(threads=4)


# --------------------------------------------------------------------- backend
class CountingServer(ThreadingHTTPServer):
    conns = 0
    hits = 0

    def get_request(self):
        conn, addr = super().get_request()
        CountingServer.conns += 1
        return conn, addr


class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path.endswith("/hits"):
            body = json.dumps({"hits": CountingServer.hits}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.endswith("/ogpage"):
            CountingServer.hits += 1
            page = (b'<html><head><title>the real page</title>'
                    b'<meta property="og:title" content="Cached Title">'
                    b'<meta property="og:description" content="about the thing">'
                    b'</head><body>hello</body></html>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
        elif self.path.endswith("/count"):
            body = json.dumps({"conns": CountingServer.conns}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.endswith("/chunked"):
            payload = b"hello chunked world"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(b"%x\r\n" % 5 + payload[:5] + b"\r\n")
            self.wfile.write(b"%x\r\n" % (len(payload) - 5) + payload[5:] + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif self.path.endswith("/echo"):
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


def _ws_serve(conn):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        key = ""
        for line in data.split(b"\r\n\r\n")[0].decode(errors="replace").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept +
                      "\r\n\r\n").encode())
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            conn.sendall(chunk)          # echo the frame bytes verbatim
    except OSError:
        pass
    finally:
        conn.close()


def start_ws_backend():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", WS_PORT))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=_ws_serve, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def start_backend():
    srv = CountingServer(("127.0.0.1", BACKEND_PORT), Backend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def backend_hits():
    c = http.client.HTTPConnection("127.0.0.1", BACKEND_PORT, timeout=5)
    c.request("GET", "/hits")
    r = c.getresponse()
    body = r.read()
    c.close()
    return json.loads(body)["hits"]


def backend_conns():
    """How many connections the backend has accepted so far."""
    c = http.client.HTTPConnection("127.0.0.1", BACKEND_PORT, timeout=5)
    c.request("GET", "/count")
    r = c.getresponse()
    body = r.read()
    c.close()
    return json.loads(body)["conns"]


# ------------------------------------------------------------------------ gate
class Gate:
    def __init__(self, *args, policy: str | None = None, env: dict | None = None,
                 target: int = BACKEND_PORT):
        self.args = list(args)
        self.env = env
        self.target = target
        self.policy_path = None
        if policy is not None:
            fd, self.policy_path = tempfile.mkstemp(suffix=".policy")
            with os.fdopen(fd, "w") as f:
                f.write(policy)
            self.args += ["--policy", self.policy_path]
        self.proc = None

    def __enter__(self):
        env = dict(os.environ)
        env.update(self.env or {})
        self.proc = subprocess.Popen(
            [os.path.join(HERE, "betterAnusbis"),
             "--listen", f"127.0.0.1:{GATE_PORT}",
             "--target", f"http://127.0.0.1:{self.target}", *self.args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
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


def ws_roundtrip(cookie: str | None = None, timeout=10):
    """Upgrade through the gate and push one frame through the tunnel."""
    sock = socket.create_connection(("127.0.0.1", GATE_PORT), timeout)
    req = ("GET /ws HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           "Sec-WebSocket-Version: 13\r\n")
    if cookie:
        req += f"Cookie: {AUTH_NAME}={cookie}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    status = head.split(b"\r\n")[0].decode(errors="replace")
    if "101" not in status:
        sock.settimeout(1.0)
        try:
            while len(head) < 65536:
                more = sock.recv(4096)
                if not more:
                    break
                head += more
        except (socket.timeout, OSError):
            pass
    payload = b"\x81\x85\x00\x00\x00\x00hello"
    echoed = b""
    if "101" in status:
        sock.sendall(payload)
        echoed = sock.recv(4096)
    sock.close()
    return status, head, echoed, payload


def unix_http(sockpath, path, timeout=10):
    """One request over a AF_UNIX socket, answered until the peer closes."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(sockpath)
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: unix.test\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    sock.close()
    return data


def set_cookies(hdrs):
    return [v for k, v in hdrs if k.lower() == "set-cookie"]

AUTH_NAME = "techaro.lol-anubis-auth"


def token_of(hdrs):
    """The auth cookie value, and remember the name it actually arrived under."""
    global AUTH_NAME
    for c in set_cookies(hdrs):
        if "cookie-verification" in c:
            continue
        name, _, rest = c.partition("=")
        AUTH_NAME = name.strip()
        return rest.split(";")[0]
    return ""


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
        token = token_of(hdrs)
        st, _, body = request("GET", "/anubis/", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("the token opens the door under the prefix",
              st == 200 and b"PAST THE WALL" in body, st)
        st, _, body = request("GET", "/anubis/echo", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("--base-prefix keeps the prefix on the upstream path (no strip)",
              st == 200 and b"/anubis/echo" in body, body[:200])

    with Gate("--difficulty", "6", "--base-prefix", "/anubis", "--strip-base-prefix"):
        status, hdrs, body, ch = solve_once(prefix="/anubis")
        token = token_of(hdrs)
        st, _, body = request("GET", "/anubis/echo", headers={"Cookie": f"{AUTH_NAME}={token}"})
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
        token = token_of(hdrs)
        st, _, body = request("GET", "/echo",
                              headers={"Cookie": f"{AUTH_NAME}={token}",
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
              'betteranusbis_build_info{version="1.50.1"' in metrics, metrics[:120])
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
            return token_of(hdrs)

    with Gate("--difficulty", "6"):
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("a token works from the address that solved it", st == 200 and b"PAST THE WALL" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}",
                                                   "X-Forwarded-For": "9.9.9.9"})
        check("the same token is refused from another address",
              b"anubis_challenge" in body and b"PAST THE WALL" not in body, st)
    with Gate("--difficulty", "6", "--jwt-restriction-header", ""):
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}",
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
        token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}",
                                                   "X-Client-IP": "1.1.1.1"})
        check("the header value that solved it opens the door",
              st == 200 and b"PAST THE WALL" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}",
                                                   "X-Client-IP": "2.2.2.2"})
        check("a different header value is refused",
              b"anubis_challenge" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("losing the header loses the token, as with upstream",
              b"anubis_challenge" in body, st)
    with Gate("--difficulty", "6", "--jwt-restriction-header", "X-Client-IP"):
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("with no such header at all, the computed address is the binding",
              st == 200 and b"PAST THE WALL" in body, st)

    # ---- 11. the signing key outlives the process
    secret = os.path.join(tempfile.mkdtemp(), "signing.key")
    with Gate("--difficulty", "6", "--secret-file", secret):
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("a token works while the gate that minted it is up",
              st == 200 and b"PAST THE WALL" in body, st)
    check("--secret-file created the key", os.path.exists(secret), secret)
    mode = os.stat(secret).st_mode & 0o777 if os.path.exists(secret) else 0
    check("the key file is 0600", mode == 0o600, oct(mode))
    with Gate("--difficulty", "6", "--secret-file", secret):
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}"})
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
            check("a headers_regex of .* wants the header present, not absent",
                  decide("curl/8.5.0") == "allow" and
                  decide("curl/8.5.0", headers={"CF-Worker": "yes"}).startswith("challenge"),
                  decide("curl/8.5.0"))
            check("the CF-Worker weight stacks with the other Cloudflare rules",
                  decide("curl/8.5.0", headers={"CF-Worker": "yes"}) == "challenge fast 6",
                  decide("curl/8.5.0", headers={"CF-Worker": "yes"}))
            check("a UA deny outranks the path allows, even on /robots.txt",
                  decide("GPTBot/1.0", path="/robots.txt") == "deny",
                  decide("GPTBot/1.0", path="/robots.txt"))
            status, hdrs, body, ch = solve_once(headers={"User-Agent": "Mozilla/5.0 Firefox/128.0"})
            check("a challenge the YAML policy chose is solvable end to end",
                  status == 302 and ch.algorithm == "fast" and ch.difficulty == 2,
                  f"{status} {ch.algorithm} {ch.difficulty}")

    # ---- 13b. a DENY rule is not bypassed by holding a cookie
    with Gate("--difficulty", "6", "--deny-status", "403",
              policy="deny ua matches ParityBot\n"):
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}",
                                                   "User-Agent": "ParityBot/1.0"})
        check("a DENY rule still denies a client that already solved a challenge",
              st == 403 and b"denied by policy" in body, st)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={token}"})
        check("and that same cookie is fine for everyone else",
              st == 200 and b"PAST THE WALL" in body, st)

    # ---- 14. the request-shape rules Anubis applies before any policy
    with Gate("--difficulty", "6", policy="allow path prefix /health\n"):
        st, _, body = request("GET", "/a/../b")
        check("a path with a .. segment is refused before anything else", st == 400, st)
        st, _, body = request("GET", "/a/./b")
        check("a path with a . segment is refused too", st == 400, st)
        st, _, body = request("GET", "/health//deep")
        check("repeated slashes are collapsed for rule matching",
              st == 200 and b"PAST THE WALL" in body, st)

    # ---- 15. every flag is an environment variable
    env = {"LISTEN": f"127.0.0.1:{GATE_PORT}", "TARGET": f"http://127.0.0.1:{BACKEND_PORT}",
           "DIFFICULTY": "6", "ALGORITHM": "sha256",
           "COOKIE_SAME_SITE": "strict"}
    proc = subprocess.Popen([os.path.join(HERE, "betterAnusbis")],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env={**os.environ, **env})
    try:
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", GATE_PORT), 0.2):
                    break
            except OSError:
                time.sleep(0.05)
        st, hdrs, body = request("GET", "/")
        check("LISTEN, TARGET, DIFFICULTY and ALGORITHM work from the environment",
              st == 200 and b"anubis_challenge" in body, st)
        status, hdrs, body, ch = solve_once()
        auth = next((c for c in set_cookies(hdrs) if "cookie-verification" not in c), "")
        check("COOKIE_SAME_SITE is read from the environment too",
              "SameSite=Strict" in auth, auth)
    finally:
        proc.terminate()
        proc.wait(3)

    # ---- 16. DEBUG_BENCHMARK as a rule action, and the healthcheck
    with Gate("--difficulty", "6", "--metrics-bind", f"127.0.0.1:{METRICS_PORT}",
              policy="- name: bench\n  action: DEBUG_BENCHMARK\n  path_regex: .*\n"):
        st, _, body = request("GET", "/anything")
        check("a DEBUG_BENCHMARK rule always challenges",
              st == 200 and b"anubis_challenge" in body, st)
        hc = subprocess.run([os.path.join(HERE, "betterAnusbis"),
                             "--healthcheck", "--metrics-bind", f"127.0.0.1:{METRICS_PORT}"],
                            capture_output=True, timeout=10)
        check("--healthcheck exits 0 against a live metrics listener", hc.returncode == 0,
              hc.stderr.decode()[-120:])
    hc = subprocess.run([os.path.join(HERE, "betterAnusbis"),
                         "--healthcheck", "--metrics-bind", "127.0.0.1:8499"],
                        capture_output=True, timeout=10)
    check("--healthcheck exits 1 when nothing answers", hc.returncode == 1, hc.returncode)

    # ---- 17. WebSocket upgrades
    start_ws_backend()
    allow = os.path.join(tempfile.mkdtemp(), "ws-allow.policy")
    with open(allow, "w") as f:
        f.write("allow path prefix /ws\n")
    with Gate("--difficulty", "6", "--policy", allow, target=WS_PORT):
        status, head, echoed, payload = ws_roundtrip()
        check("an allowed path is upgraded to 101", "101 Switching Protocols" in status, status)
        check("the 101 relays the backend's Sec-WebSocket-Accept",
              b"Sec-WebSocket-Accept:" in head, head[:80])
        check("frames cross the gate byte for byte", echoed == payload, (echoed, payload))
    with Gate("--difficulty", "6", target=WS_PORT):
        status, head, echoed, payload = ws_roundtrip()
        check("an unauthenticated upgrade gets the challenge, not a tunnel",
              "200" in status and b"anubis_challenge" in head + b"", status)
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        status, head, echoed, payload = ws_roundtrip(cookie=token)
        check("a client that solved a challenge is upgraded", "101" in status, status)
        check("and its frames cross too", echoed == payload, (echoed, payload))
    deny = os.path.join(tempfile.mkdtemp(), "ws-deny.policy")
    with open(deny, "w") as f:
        f.write("deny path prefix /ws\n")
    with Gate("--difficulty", "6", "--policy", deny, target=WS_PORT):
        status, head, echoed, payload = ws_roundtrip()
        check("a denied path is denied before any upgrade", "101" not in status
              and b"denied by policy" in head, status)

    # ---- 18. the small parity flags
    with Gate("--difficulty", "6"):
        status, hdrs, body, ch = solve_once()
        names = [c.split("=", 1)[0].strip() for c in set_cookies(hdrs)
                 if "cookie-verification" not in c]
        check("the cookie name carries the settings suffix by default",
              names and names[0].startswith("techaro.lol-anubis-auth-")
              and len(names[0].split("-")[-1]) == 8, names)
    with Gate("--difficulty", "6", "--no-dynamic-cookie-suffix"):
        status, hdrs, body, ch = solve_once()
        names = [c.split("=", 1)[0].strip() for c in set_cookies(hdrs)
                 if "cookie-verification" not in c]
        check("--no-dynamic-cookie-suffix leaves the name alone",
              names == ["techaro.lol-anubis-auth"], names)
    with Gate("--difficulty", "6", "--difficulty-in-jwt"):
        status, hdrs, body, ch = solve_once()
        token = token_of(hdrs)
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        check("--difficulty-in-jwt puts the difficulty in the token",
              claims.get("difficulty") == 6, claims)
    with Gate("--difficulty", "6", "--webmaster-email", "ops@example.org",
              "--deny-status", "403", policy="deny ua matches ParityBot\n"):
        st, _, body = request("GET", "/", headers={"User-Agent": "ParityBot/1"})
        check("--webmaster-email is printed on the deny page",
              st == 403 and b"ops@example.org" in body, body[:80])
    with Gate("--difficulty", "6", "--preserve-referer-query-param"):
        status, hdrs, body, ch = solve_once(redir="/landing")
        check("an internal challenge redirect gets no attribution",
              header(hdrs, "Location") == "/landing", header(hdrs, "Location"))
    with Gate("--difficulty", "6", "--preserve-referer-query-param"):
        st, hdrs, body = request("GET", "/", headers={"Referer": "https://news.example/x"})
        ch = anubis_solver.parse_challenge(body.decode(errors="replace"))
        sol = SOLVER.solve(ch)
        q = urlencode({"id": ch.id, "response": sol.response_hex, "nonce": str(sol.nonce),
                       "redir": "/landing"})
        status, hdrs, body = request("GET", API + "pass-challenge?" + q,
                                     headers={"Referer": "https://news.example/x"})
        loc = header(hdrs, "Location") or ""
        check("an external Referer becomes utm_source/utm_medium",
              "utm_source=news.example" in loc and "utm_medium=referral" in loc, loc)

    # ---- 19. unix sockets for either listener
    sockdir = tempfile.mkdtemp()
    gate_sock = os.path.join(sockdir, "gate.sock")
    metrics_sock = os.path.join(sockdir, "metrics.sock")
    proc = subprocess.Popen(
        [os.path.join(HERE, "betterAnusbis"), "--listen", gate_sock, "--bind-network", "unix",
         "--target", f"http://127.0.0.1:{BACKEND_PORT}", "--difficulty", "6",
         "--metrics-bind", metrics_sock, "--metrics-bind-network", "unix"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 8
        while time.time() < deadline and not os.path.exists(gate_sock):
            time.sleep(0.05)
        reply = unix_http(gate_sock, "/")
        check("a unix listener serves the challenge", b"anubis_challenge" in reply, reply[:60])
        mode = statmod.S_IMODE(os.stat(gate_sock).st_mode) if os.path.exists(gate_sock) else 0
        check("the unix socket is 0770 by default", mode == 0o770, oct(mode))
        metrics = unix_http(metrics_sock, "/metrics")
        check("a unix metrics listener serves /metrics",
              b"anubis_challenges_issued" in metrics, metrics[:80])
    finally:
        proc.terminate()
        proc.wait(3)

    # ---- 20. token signing schemes
    def jwt_alg(hdrs):
        token = token_of(hdrs)
        h = token.split(".")[0]
        h += "=" * (-len(h) % 4)
        return json.loads(base64.urlsafe_b64decode(h)).get("alg")

    with Gate("--difficulty", "6", "--hs512-secret", "hunter2"):
        status, hdrs, body, ch = solve_once()
        check("--hs512-secret signs with HS512", jwt_alg(hdrs) == "HS512", jwt_alg(hdrs))
        hs512_token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={hs512_token}"})
        check("an HS512 token opens the door", st == 200 and b"PAST THE WALL" in body, st)
    with Gate("--difficulty", "6"):
        status, hdrs, body, ch = solve_once()
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={hs512_token}"})
        check("a token from a different scheme is refused",
              b"anubis_challenge" in body, st)
    with Gate("--difficulty", "6", "--ed25519-private-key-hex", os.urandom(32).hex()):
        status, hdrs, body, ch = solve_once()
        check("--ed25519-private-key-hex signs with EdDSA", jwt_alg(hdrs) == "EdDSA",
              jwt_alg(hdrs))
        ed_token = token_of(hdrs)
        st, _, body = request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={ed_token}"})
        check("an EdDSA token opens the door", st == 200 and b"PAST THE WALL" in body, st)

    # ---- 21. localization and the impressum
    with Gate("--difficulty", "6"):
        st, _, body = request("GET", "/", headers={"Accept-Language": "de-DE,de;q=0.9,en;q=0.5"})
        check("Accept-Language picks the German page", b"Nachweis" in body,
              body[:120])
        st, _, body = request("GET", "/", headers={"Accept-Language": "xx-YY"})
        check("an unknown language falls back to English",
              b"Proving you are not a robot" in body, body[:120])
    with Gate("--difficulty", "6", "--forced-language", "fr"):
        st, _, body = request("GET", "/", headers={"Accept-Language": "de-DE,de;q=0.9"})
        check("--forced-language wins over the header", b"Prouver" in body, body[:120])
    with Gate("--difficulty", "6", "--impressum-footer", "<p>hosted by the cat</p>",
              "--impressum-page-title", "Imprint", "--impressum-page-body", "<p>no cookies</p>"):
        st, _, body = request("GET", "/")
        check("--impressum-footer is on the challenge page", b"hosted by the cat" in body,
              body[-200:])
        st, _, body = request("GET", API + "imprint")
        check("the imprint page is served", st == 200 and b"no cookies" in body and
              b"hosted by the cat" in body, body[:200])

    # ---- 22. preact: patience plus a digest, no proof of work
    with Gate("--difficulty", "2", "--algorithm", "preact"):
        st, hdrs, body = request("GET", "/")
        text = body.decode(errors="replace")
        rd = re.search(r'"randomData":"([0-9a-f]+)"', text).group(1)
        vid = re.search(r'"id":"([^"]+)"', text).group(1)
        vc = next((v.split(";")[0] for k, v in hdrs if k.lower() == "set-cookie"), "")
        result = hashlib.sha256(rd.encode()).hexdigest()
        path = API + f"pass-challenge?id={vid}&result={result}&redir=/"
        st, _, body = request("GET", path, headers={"Cookie": vc})
        check("preact refuses before difficulty x 80 ms", st == 403, st)
        time.sleep(0.25)
        st, hdrs, body = request("GET", path, headers={"Cookie": vc})
        check("preact passes after the wait", st == 302, st)
        st, _, body = request("GET", path)
        check("preact wants the verification cookie", st == 403, st)

    # ---- 23. forwardAuth: an empty target means auth checks only
    fwddir = tempfile.mkdtemp()
    fwdpol = os.path.join(fwddir, "fwd.policy")
    with open(fwdpol, "w") as f:
        f.write("allow path prefix /public\ndeny path prefix /private\n")

    def fwd_gate(*extra):
        proc = subprocess.Popen([os.path.join(HERE, "betterAnusbis"),
                                 "--listen", f"127.0.0.1:{GATE_PORT}", "--target", "",
                                 "--difficulty", "6", "--policy", fwdpol, *extra],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", GATE_PORT), 0.2):
                    return proc
            except OSError:
                time.sleep(0.05)
        return proc

    proc = fwd_gate()
    try:
        st, hdrs, body = request("GET", "/")
        check("forwardAuth answers 401 Authorization required",
              st == 401 and b"Authorization required" in body, f"{st} {body[:40]}")
        st, _, body = request("GET", "/public/x")
        check("an ALLOW rule answers 200 in forwardAuth mode", st == 200 and b"ok" in body, st)
        st, hdrs, body = request("GET", "/private/y")
        check("a DENY rule is still a deny", b"denied" in body, f"{st} {body[:40]}")
        pass
    finally:
        proc.terminate()
        proc.wait(3)

    # a token minted by a normal gate is honoured here when the key is shared
    secretfile = os.path.join(fwddir, "shared.key")
    # the policy digest travels in the token, so both gates must run the same
    # policy for the cookie to be honoured (that is the point of O1)
    with Gate("--difficulty", "6", "--secret-file", secretfile,
              policy="allow path prefix /public\ndeny path prefix /private\n"):
        status, hdrs, body, ch = solve_once()
        shared_token = token_of(hdrs)
        shared_name = AUTH_NAME
    proc = fwd_gate("--secret-file", secretfile)
    try:
        st, _, body = request("GET", "/", headers={"Cookie": f"{shared_name}={shared_token}"})
        check("a cookie from another gate with the same key answers 200",
              st == 200 and b"ok" in body, st)
    finally:
        proc.terminate()
        proc.wait(3)
    proc = fwd_gate("--public-url", "https://gate.example")
    try:
        st, hdrs, body = request("GET", "/deep", headers={"X-Forwarded-Proto": "https",
                                                          "X-Forwarded-Host": "site.example"})
        loc = header(hdrs, "Location") or ""
        check("--public-url sends the browser to the challenge page with 307",
              st == 307 and loc.startswith("https://gate.example/.within.website/?redir=") and
              "site.example" in loc, f"{st} {loc}")
        st, _, body = request("GET", "/deep")
        check("the redirect needs the X-Forwarded headers", st == 400, st)
    finally:
        proc.terminate()
        proc.wait(3)

    # ---- 23b. O1: the token records the policy it was minted under
    o1key = os.path.join(tempfile.mkdtemp(), "o1.key")
    base_policy = "allow path prefix /health\n"
    with Gate("--difficulty", "6", "--secret-file", o1key, policy=base_policy):
        status, hdrs, body, ch = solve_once()
        o1_token, o1_name = token_of(hdrs), AUTH_NAME
    with Gate("--difficulty", "6", "--secret-file", o1key, policy=base_policy):
        st, _, body = request("GET", "/", headers={"Cookie": f"{o1_name}={o1_token}"})
        check("a cookie survives a restart under the same policy",
              st == 200 and b"PAST THE WALL" in body, st)
    with Gate("--difficulty", "6", "--secret-file", o1key,
              policy=base_policy + "deny ua contains Bot\n"):
        st, _, body = request("GET", "/", headers={"Cookie": f"{o1_name}={o1_token}"})
        check("editing the policy invalidates the cookies minted before it",
              b"anubis_challenge" in body, st)

    # ---- 23c. GeoIP country and ASN rules, against MaxMind's own test databases
    cdb = os.path.join(HERE, "tools", "geoip-testdata", "GeoIP2-Country-Test.mmdb")
    adb = os.path.join(HERE, "tools", "geoip-testdata", "GeoLite2-ASN-Test.mmdb")
    if os.path.exists(cdb) and os.path.exists(adb):
        geo_policy = (
            "bots:\n"
            "  - name: deny-gb\n"
            "    geoip:\n"
            "      countries:\n"
            "        - GB\n"
            "    action: DENY\n"
            "  - name: asn-29518\n"
            "    asns:\n"
            "      match:\n"
            "        - 29518\n"
            "    action: CHALLENGE\n"
            "    challenge:\n"
            "      algorithm: fast\n"
            "      difficulty: 3\n")
        with Gate("--difficulty", "6", "--deny-status", "403", policy=geo_policy,
                  *("--geoip-country", cdb, "--geoip-asn", adb)):
            st, _, body = request("GET", "/", headers={"X-Forwarded-For": "2.125.160.216"})
            check("a country rule denies a GB address", st == 403 and b"denied" in body, st)
            st, _, body = request("GET", "/", headers={"X-Forwarded-For": "175.16.199.1"})
            check("a CN address is not caught by the GB rule and is allowed",
                  b"PAST THE WALL" in body, body[:60])
            st, _, body = request("GET", "/", headers={"X-Forwarded-For": "89.160.20.112"})
            ch = anubis_solver.parse_challenge(body.decode(errors="replace"))
            check("an ASN rule challenges the address in that ASN",
                  ch is not None and ch.algorithm == "fast" and ch.difficulty == 3,
                  ch and (ch.algorithm, ch.difficulty))
    else:
        print("  (skipped the GeoIP checks: tools/geoip-testdata is missing)")

    # ---- 23d. upstream keep-alive
    with Gate("--difficulty", "6"):
        cookie = token_of(solve_once()[1])
        before = backend_conns()
        for _ in range(3):
            request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={cookie}"})
        # the count call itself opens one connection, hence the +1
        used = backend_conns() - before - 1
        check("three proxied requests reuse one upstream connection", used == 1, used)
        st, _, body = request("GET", "/chunked", headers={"Cookie": f"{AUTH_NAME}={cookie}"})
        check("a chunked response is relayed intact",
              st == 200 and body == b"hello chunked world", body[:40])
    with Gate("--difficulty", "6", "--target-disable-keepalive"):
        cookie = token_of(solve_once()[1])
        before = backend_conns()
        for _ in range(3):
            request("GET", "/", headers={"Cookie": f"{AUTH_NAME}={cookie}"})
        used = backend_conns() - before - 1
        check("--target-disable-keepalive opens one per request", used == 3, used)

    # ---- 23e. OpenGraph passthrough and its cache
    with Gate("--difficulty", "6", "--og-passthrough"):
        st, _, body = request("GET", "/ogpage")
        check("og tags from the protected page reach the challenge page",
              b"og:title" in body and b"Cached Title" in body, body[:160])
        first = backend_hits()
        st, _, body = request("GET", "/ogpage")
        check("the second challenge uses the cached tags", backend_hits() == first,
              backend_hits() - first)
    with Gate("--difficulty", "6", "--og-override",
              "og:title=Fixed Title;og:description=Fixed description"):
        st, _, body = request("GET", "/ogpage")
        check("--og-override replaces the tags without a fetch",
              b"Fixed Title" in body and b"og:title" in body, body[:160])

    # ---- 23f. the css-load extension
    with Gate("--difficulty", "6", "--challenge-extension", "css-load"):
        st, hdrs, body = request("GET", "/")
        text = body.decode(errors="replace")
        m = re.search(r'<link rel="stylesheet" href="([^"]+)"', text)
        check("the challenge page carries the css-load link", m is not None, text[:120])
        ch = anubis_solver.parse_challenge(text)
        sol = SOLVER.solve(ch)
        q = urlencode({"id": ch.id, "response": sol.response_hex,
                       "nonce": str(sol.nonce), "redir": "/"})
        st, _, body = request("GET", API + "pass-challenge?" + q)
        check("a correct answer is refused until the stylesheet is fetched", st == 403, st)
        st2, _, _ = request("GET", m.group(1)) if m else (0, [], b"")
        check("the stylesheet route answers", st2 == 200, st2)
        st3, hdrs, body = request("GET", API + "pass-challenge?" + q)
        check("and the same answer is accepted afterwards", st3 == 302, st3)

    # ---- 23g. the file store survives a restart
    storepath = os.path.join(tempfile.mkdtemp(), "state.txt")
    with Gate("--difficulty", "6", "--store", f"file:{storepath}"):
        st, hdrs, body = request("GET", "/")
        ch = anubis_solver.parse_challenge(body.decode(errors="replace"))
        sol = SOLVER.solve(ch)
    check("the store file is written on shutdown",
          os.path.exists(storepath) and os.path.getsize(storepath) > 0,
          os.path.getsize(storepath) if os.path.exists(storepath) else "absent")
    with Gate("--difficulty", "6", "--store", f"file:{storepath}"):
        q = urlencode({"id": ch.id, "response": sol.response_hex,
                       "nonce": str(sol.nonce), "redir": "/"})
        st, hdrs, body = request("GET", API + "pass-challenge?" + q)
        check("a challenge issued before the restart still verifies", st == 302, st)

    # ---- 23h. the policy file configures the gate, not just the rules
    cdb = os.path.join(HERE, "tools", "geoip-testdata", "GeoIP2-Country-Test.mmdb")
    storepath = os.path.join(tempfile.mkdtemp(), "dropin.txt")
    if os.path.exists(cdb):
        dropin = (
            "bots:\n"
            "  - name: deny-gb\n"
            "    geoip:\n"
            "      countries: [GB]\n"
            "    action: DENY\n"
            "thresholds:\n"
            "  - name: minimal-suspicion\n"
            "    expression: weight <= 0\n"
            "    action: ALLOW\n"
            "store:\n"
            "  backend: file\n"
            "  parameters:\n"
            "    path: " + storepath + "\n"
            "metrics:\n"
            "  enabled: true\n"
            "  bind: \"127.0.0.1:9099\"\n"
            "geoip:\n"
            "  country:\n"
            "    path: " + cdb + "\n"
            "openGraph:\n"
            "  enabled: true\n"
            "  expiryTime: 90m\n"
            "impressum:\n"
            "  enabled: true\n"
            "  footer: a drop-in footer\n"
            "dns_ttl: 600\n")
        with Gate("--difficulty", "6", "--deny-status", "403", policy=dropin):
            st, _, body = request("GET", "/", headers={"X-Forwarded-For": "2.125.160.216"})
            check("a country rule configured in the file denies (flow list)", st == 403, st)
            st, _, body = request("GET", "/ogpage")
            check("openGraph.enabled in the file puts tags on the page",
                  b"og:title" in body and b"Cached Title" in body, body[:120])
            st, _, body = request("GET", API + "imprint")
            check("impressum.enabled in the file answers the imprint route",
                  st == 200 and b"Impressum" in body, st)
            m = http.client.HTTPConnection("127.0.0.1", 9099, timeout=5)
            m.request("GET", "/metrics")
            mr = m.getresponse()
            mbody = mr.read()
            m.close()
            check("metrics.bind in the file starts the listener", mr.status == 200 and
                  b"anubis_requests_total" in mbody, mr.status)
        check("store.backend file in the file writes its snapshot",
              os.path.exists(storepath), "absent")

    # ---- 24. DNS: the shipped policy is fully understood, and DNSBL answers
    if os.path.exists(policy):
        try:
            subprocess.run([os.path.join(HERE, "betterAnusbis"),
                            "--listen", "127.0.0.1:8496", "--target", "http://127.0.0.1:9",
                            "--policy", policy, "--data-dir", upstream], timeout=2,
                           capture_output=True)
            out = b""
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"") + (exc.stderr or b"")
        check("every rule in the shipped policy is now understood",
              b"never match" not in out and b"does not evaluate" not in out, out[-160:])
    with Gate("--difficulty", "6", "--dnsbl"):
        st, _, body = request("GET", "/")
        check("--dnsbl clears a client or says it could not check (never guesses)",
              st in (200, 503), st)

    # ---- 25. the old flags still behave
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
