#!/usr/bin/env python3
"""
picker.py - Auto mode failover for proxy-unifi.

Health: every node is probed through xray's loopback SOCKS "probe" inbound,
whose user name routes to that node's outbound, so a probe takes exactly the
path real traffic does (same core, same transport, same server). A probe is an
HTTPS GET of a 204 URL; it passes on any HTTP status line.

Choice (priority = country order, then pinned, then RTT):
  * the active node is kept while it answers; after FAIL_LIMIT failed probes in
    a row it is dropped at once;
  * the best live node of the highest-priority country wins; a node of a
    higher country takes over only after it answered UP_LIMIT full rounds in a
    row (no flapping back to a country that just recovered);
  * inside the active country a faster node replaces the active one only when
    it is clearly faster (SWITCH_RATIO) -- RTT noise does not move traffic;
  * nothing alive -> the balancer is overridden to "block" (kill switch: VPN
    traffic stops instead of leaking out directly).

The choice is applied with `xray api bo` (no restart, open connections stay)
and re-applied every round, so a core restart is healed within one round.

State: <state>/status.json (atomic) and <state>/switches.log (last 500 lines).
Stdlib only (Python 3.9+).
"""

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

FAIL_LIMIT = 2
UP_LIMIT = 2
SWITCH_RATIO = 0.6
FAST_INTERVAL = 5          # active node
FULL_INTERVAL = 30         # every node
PROBE_TIMEOUT = 5.0
MAX_WORKERS = 16
LOG_KEEP = 500


def log(msg):
    sys.stdout.write("%s\n" % msg)
    sys.stdout.flush()


# ---------------------------------------------------------------- probing

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("socks: connection closed")
        buf += chunk
    return buf


def probe(tag, password, socks_port, url):
    """RTT in ms through node `tag`, or None."""
    u = urlsplit(url)
    host, port = u.hostname, u.port or 443
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    start = time.monotonic()
    try:
        sock = socket.create_connection(("127.0.0.1", socks_port), timeout=PROBE_TIMEOUT)
    except OSError:
        return None
    try:
        sock.settimeout(PROBE_TIMEOUT)
        sock.sendall(b"\x05\x01\x02")
        if _recv_exact(sock, 2) != b"\x05\x02":
            return None
        ub, pb = tag.encode(), password.encode()
        sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        if _recv_exact(sock, 2)[1] != 0:
            return None
        hb = host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            return None
        atyp = head[3]
        skip = {1: 4, 4: 16}.get(atyp)
        if skip is None:
            skip = _recv_exact(sock, 1)[0]
        _recv_exact(sock, skip + 2)
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        sock = tls
        tls.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: proxy-unifi-picker\r\n"
                     "Connection: close\r\n\r\n" % (path, host)).encode())
        line = b""
        while b"\r\n" not in line and len(line) < 256:
            chunk = tls.recv(64)
            if not chunk:
                break
            line += chunk
        if not line.startswith(b"HTTP/"):
            return None
        return int((time.monotonic() - start) * 1000)
    except (OSError, ssl.SSLError, ValueError, IndexError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- state

class Picker:
    def __init__(self, args):
        self.args = args
        self.password = open(args.probe_pass_file, encoding="utf-8").read().strip()
        self.nodes = []            # usable nodes, in priority order
        self.nodes_mtime = None
        self.order = []
        self.health = {}           # tag -> dict(ok, rtt, fails, ups, last_ok, last_probe)
        self.active = None         # tag or "block"
        self.applied_at = 0.0
        self.last_full = 0.0
        os.makedirs(args.state_dir, exist_ok=True)
        self.switch_log = os.path.join(args.state_dir, "switches.log")

    def reload_nodes(self):
        try:
            mtime = os.stat(self.args.nodes_file).st_mtime
        except OSError:
            return
        if mtime == self.nodes_mtime:
            return
        try:
            with open(self.args.nodes_file, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        self.nodes_mtime = mtime
        self.order = data.get("order", [])
        self.nodes = [n for n in data.get("nodes", []) if n.get("usable")]
        tags = {n["tag"] for n in self.nodes}
        self.health = {t: h for t, h in self.health.items() if t in tags}
        if self.active not in tags and self.active != "block":
            self.active = None
        self.last_full = 0.0       # new node set: probe everything now

    def _h(self, tag):
        return self.health.setdefault(tag, {"ok": False, "rtt": None, "fails": 0, "ups": 0,
                                            "last_ok": 0, "last_probe": 0})

    def record(self, tag, rtt, full_round):
        h = self._h(tag)
        h["last_probe"] = int(time.time())
        if rtt is None:
            h["fails"] += 1
            h["ups"] = 0
            if h["fails"] >= FAIL_LIMIT or h["rtt"] is None:
                h["ok"] = False
        else:
            h["fails"] = 0
            h["ok"] = True
            h["last_ok"] = h["last_probe"]
            h["rtt"] = rtt if h["rtt"] is None else int(h["rtt"] * 0.6 + rtt * 0.4)
            if full_round:
                h["ups"] += 1

    def probe_many(self, tags, full_round):
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(probe, t, self.password, self.args.probe_port, self.args.url): t
                    for t in tags}
            for f in concurrent.futures.as_completed(futs):
                self.record(futs[f], f.result(), full_round)

    # ------------------------------------------------------------ choice

    def _rank(self, node):
        c = node.get("country", "")
        return self.order.index(c) if c in self.order else len(self.order) + (0 if c else 1)

    def choose(self):
        live = [n for n in self.nodes if self._h(n["tag"])["ok"]]
        if not live:
            return "block"
        by_tag = {n["tag"]: n for n in self.nodes}
        cur = by_tag.get(self.active)
        cur_ok = cur is not None and self._h(cur["tag"])["ok"]
        best_rank = min(self._rank(n) for n in live)
        if cur_ok:
            cur_rank = self._rank(cur)
            # a higher-priority country must be stably up before it takes over
            stable_better = [n for n in live if self._rank(n) < cur_rank
                             and self._h(n["tag"])["ups"] >= UP_LIMIT]
            if not stable_better:
                return self._within_country(cur, [n for n in live if self._rank(n) == cur_rank])
            best_rank = min(self._rank(n) for n in stable_better)
            live = stable_better
        group = [n for n in live if self._rank(n) == best_rank]
        return self._best_of(group)["tag"]

    def _best_of(self, group):
        pinned = [n for n in group if n.get("pinned")]
        pool = pinned or group
        return min(pool, key=lambda n: (self._h(n["tag"])["rtt"] or 10 ** 9, n["priority"]))

    def _within_country(self, cur, group):
        best = self._best_of(group)
        if best["tag"] == cur["tag"]:
            return cur["tag"]
        if best.get("pinned") and not cur.get("pinned"):
            return best["tag"]
        if cur.get("pinned") and not best.get("pinned"):
            return cur["tag"]
        crt, brt = self._h(cur["tag"])["rtt"] or 10 ** 9, self._h(best["tag"])["rtt"] or 10 ** 9
        return best["tag"] if brt < crt * SWITCH_RATIO else cur["tag"]

    # ------------------------------------------------------------ apply

    def apply(self, tag, force=False):
        changed = tag != self.active
        if not changed and not force:
            return
        cmd = [self.args.xray, "api", "bo", "--server=127.0.0.1:%d" % self.args.api_port,
               "-b", "vpn", tag]
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return
        if r.returncode != 0:
            return                 # core not up yet; retried next round
        self.applied_at = time.time()
        if changed:
            prev = self.active
            self.active = tag
            self.note_switch(prev, tag)

    def label(self, tag):
        if tag == "block":
            return "kill switch (no live server)"
        for n in self.nodes:
            if n["tag"] == tag:
                return "%s [%s]" % (n.get("label", tag), n.get("country") or "??")
        return tag or "-"

    def note_switch(self, prev, new):
        line = "%s\t%s\t%s\t%s" % (time.strftime("%Y-%m-%d %H:%M:%S"), prev or "-", new,
                                   "%s -> %s" % (self.label(prev) if prev else "start",
                                                 self.label(new)))
        log(line)
        try:
            lines = []
            if os.path.exists(self.switch_log):
                with open(self.switch_log, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()[-(LOG_KEEP - 1):]
            lines.append(line)
            self._atomic(self.switch_log, "\n".join(lines) + "\n")
        except OSError:
            pass

    def _atomic(self, path, text):
        fd, tmp = tempfile.mkstemp(prefix=".w.", dir=os.path.dirname(path))
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)

    def write_status(self):
        status = {
            "updated": int(time.time()),
            "active": self.active,
            "active_label": self.label(self.active) if self.active else "",
            "killswitch": self.active == "block",
            "order": self.order,
            "nodes": [dict(tag=n["tag"], id=n["id"], label=n.get("label", ""),
                           country=n.get("country", ""), pinned=bool(n.get("pinned")),
                           **self._h(n["tag"])) for n in self.nodes],
        }
        try:
            self._atomic(os.path.join(self.args.state_dir, "status.json"),
                         json.dumps(status, ensure_ascii=False))
        except OSError:
            pass

    # ------------------------------------------------------------ loop

    def step(self):
        self.reload_nodes()
        if not self.nodes:
            self.write_status()
            return
        now = time.monotonic()
        full = now - self.last_full >= FULL_INTERVAL
        if full:
            self.probe_many([n["tag"] for n in self.nodes], True)
            self.last_full = now
        elif self.active and self.active != "block":
            self.probe_many([self.active], False)
        self.apply(self.choose(), force=full)
        self.write_status()

    def run(self):
        while True:
            started = time.monotonic()
            self.step()
            time.sleep(max(0.5, FAST_INTERVAL - (time.monotonic() - started)))


def main():
    ap = argparse.ArgumentParser(description="proxy-unifi Auto mode failover picker")
    ap.add_argument("--nodes-file", required=True)
    ap.add_argument("--probe-pass-file", required=True)
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--xray", required=True)
    ap.add_argument("--api-port", type=int, default=51822)
    ap.add_argument("--probe-port", type=int, default=51823)
    ap.add_argument("--url", default="https://www.gstatic.com/generate_204")
    ap.add_argument("--once", action="store_true", help="one full round, then exit (tests)")
    args = ap.parse_args()
    if not args.url.startswith("https://"):
        sys.stderr.write("picker: --url must be https\n")
        sys.exit(2)
    p = Picker(args)
    if args.once:
        p.reload_nodes()
        for _ in range(UP_LIMIT):
            p.probe_many([n["tag"] for n in p.nodes], True)
        p.apply(p.choose(), force=True)
        p.write_status()
        return
    p.run()


if __name__ == "__main__":
    main()
