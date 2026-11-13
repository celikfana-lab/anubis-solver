#!/usr/bin/env python3
"""bench-server-resources.py — RAM and CPU for Anubis vs betterAnusbis.

Reads /proc/<pid>/{status,stat}, so the numbers are the kernel's, not an estimate.
Two phases per server: 300 challenge pages, then 40 full pass-challenge exchanges
(the second includes the server's proof-of-work verification).

    python3 tools/bench-server-resources.py     # both servers must be running:
    #   /tmp/anubis -bind 127.0.0.1:8923 -target http://127.0.0.1:8002 ...
    #   ./betterAnusbis --listen :8096 --target http://127.0.0.1:8002 ...
"""
import json, os, subprocess, sys, time, urllib.parse, urllib.request, urllib.error

def find(comm_name):
    """The process whose executable is named comm_name.

    Matching the command line was wrong: a shell that had cd'd into the directory
    matched too, and the script happily measured the shell (3.6 MB, 1 thread, no
    CPU). /proc/<pid>/comm is the kernel's own name for the executable.
    """
    for pid in os.listdir('/proc'):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            comm = open(f'/proc/{pid}/comm').read().strip()
        except OSError:
            continue
        if comm == comm_name:
            return int(pid)
    return None

def rss_kb(pid):
    for line in open(f'/proc/{pid}/status'):
        if line.startswith('VmRSS:'): return int(line.split()[1])
    return 0

def hwm_kb(pid):
    for line in open(f'/proc/{pid}/status'):
        if line.startswith('VmHWM:'): return int(line.split()[1])
    return 0

def cpu_ms(pid):
    f = open(f'/proc/{pid}/stat').read().rsplit(')',1)[1].split()
    return (int(f[11]) + int(f[12])) * 1000.0 / os.sysconf('SC_CLK_TCK')

def threads(pid):
    try: return len(os.listdir(f'/proc/{pid}/task'))
    except OSError: return 0

def get(url, ua='resource probe'):
    req = urllib.request.Request(url, headers={'user-agent': ua})
    try:
        with urllib.request.urlopen(req, timeout=10) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def challenge(base):
    _, body = get(base)
    import re
    m = re.search(rb'id="anubis_challenge"[^>]*>\s*(\{.*?\})\s*</script>', body, re.S)
    return json.loads(m.group(1)) if m else None


class Native:
    """The Firefox extension's native messaging host, driven over stdio."""
    def __init__(self):
        self.p = subprocess.Popen(
            [sys.executable, '-u',
             '/media/miku6/kubuntu_2404/home/miku/DOWN/pyani/anubis-solver/firefox-extension/native-host/anubis_native.py'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.call({'cmd': 'info'})

    def call(self, payload):
        body = json.dumps(payload, separators=(',', ':')).encode()
        self.p.stdin.write(__import__('struct').pack('=I', len(body)))
        self.p.stdin.write(body); self.p.stdin.flush()
        n = __import__('struct').unpack('=I', self.p.stdout.read(4))[0]
        return json.loads(self.p.stdout.read(n))

    def solve(self, random_data, difficulty):
        r = self.call({'cmd': 'solve', 'algorithm': 'sha256',
                       'randomData': random_data, 'difficulty': difficulty})
        return r if r.get('ok') else None

    def close(self):
        try: self.p.stdin.close()
        except Exception: pass

SERVERS = [('Anubis v1.28.3 (Go)', 8923, 'anubis'),
           ('betterAnusbis (C)', 8096, 'betterAnusbis')]
N_PAGES, N_PASS = 300, 40

rows = []
for name, port, comm_name in SERVERS:
    pid = find(comm_name)
    if not pid:
        print(f'{name}: not running'); continue
    base = f'http://127.0.0.1:{port}/'
    idle_rss, idle_cpu, idle_thr = rss_kb(pid), cpu_ms(pid), threads(pid)

    t0 = time.time()
    for _ in range(N_PAGES): get(base)
    page_wall = time.time() - t0
    page_cpu = cpu_ms(pid) - idle_cpu
    rss_after_pages = rss_kb(pid)

    # a full pass: solve with the native host, hand it over, fetch the page
    solve = Native()
    cpu_before = cpu_ms(pid)
    passes = 0
    for _ in range(N_PASS):
        ch = challenge(base)
        if not ch: break
        r = solve.solve(ch['challenge']['randomData'], ch['rules']['difficulty'])
        if not r: break
        q = urllib.parse.urlencode({'id': ch['challenge']['id'], 'response': r['response'],
                                    'nonce': r['nonce'], 'redir': '/', 'elapsedTime': 1})
        get(base + '.within.website/x/cmd/anubis/api/pass-challenge?' + q)
        passes += 1
    pass_cpu = cpu_ms(pid) - cpu_before

    rows.append(dict(name=name, pid=pid, idle_rss=idle_rss, rss_after=max(rss_after_pages, rss_kb(pid)),
                     hwm=hwm_kb(pid), threads=idle_thr,
                     page_wall_ms=page_wall*1000/N_PAGES, page_cpu_ms=page_cpu/N_PAGES,
                     pass_cpu_ms=pass_cpu/max(passes,1), passes=passes))
    solve.close()

print(f'\n{"":26}{"idle RSS":>10}{"peak RSS":>10}{"threads":>9}'
      f'{"cpu/page":>11}{"cpu/pass":>11}')
for r in rows:
    print(f'{r["name"]:26}{r["idle_rss"]/1024:9.1f}M{r["hwm"]/1024:9.1f}M{r["threads"]:9d}'
          f'{r["page_cpu_ms"]*1000:10.0f}us{r["pass_cpu_ms"]:10.2f}ms')
