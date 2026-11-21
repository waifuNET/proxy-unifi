#!/usr/bin/env python3
"""
panel.py - LAN web panel for proxy-unifi Auto mode.

It is a thin front end: every change runs `proxy-unifi auto ...` (the same
locked, transactional code the SSH menu uses), secrets go over stdin, and the
page only ever sees `auto status-json` (no keys, URLs or links).

Security:
  * listens on the gateway's LAN address only and answers private/loopback
    clients only;
  * password (PBKDF2-SHA256) -> random session cookie (HttpOnly, SameSite=Strict);
  * login attempts are throttled per client and globally;
  * state-changing requests need the session, a JSON body, the X-Panel header
    and a same-origin Origin/Referer (CSRF).

Stdlib only (Python 3.9+).
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSION_TTL = 12 * 3600
MAX_BODY = 16384
PBKDF2_ITER = 200000
# Short (PIN-like) passwords are allowed on the LAN-only panel; the login
# throttle below (5 per client per minute, 20 in total per 15 minutes) keeps
# a 4-digit PIN at days of guessing.
MIN_PASSWORD = 4
CLI_TIMEOUT = 600

_sessions = {}
_fails = {}
_lock = threading.Lock()
_cli_lock = threading.Lock()


def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return "pbkdf2$%d$%s$%s" % (PBKDF2_ITER, salt.hex(), dk.hex())


def check_password(pw, stored):
    try:
        kind, it, salt, want = stored.strip().split("$")
        if kind != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk.hex(), want)
    except (ValueError, TypeError):
        return False


def _str(d, key, maximum=2048, allow_empty=False):
    v = d.get(key, "")
    if not isinstance(v, str) or len(v) > maximum or (not v and not allow_empty) \
            or any(ord(c) < 32 for c in v):
        raise ValueError("bad field: %s" % key)
    return v


def action_command(a):
    """(argv tail, stdin text) for one panel action; raises ValueError."""
    op = a.get("op")
    if op == "enable":
        return ["enable"], ""
    if op == "refresh":
        return ["refresh"], ""
    if op == "geo_update":
        return ["geo-update"], ""
    if op == "add_sub":
        ua = _str(a, "ua", 120, True)
        return ["add-sub", _str(a, "name", 60)], _str(a, "url") + "\n" + ua + "\n"
    if op == "add_link":
        return ["add-link", _str(a, "name", 60)], _str(a, "link", 8000) + "\n"
    if op == "source":
        state = _str(a, "state", 3)
        if state not in ("on", "off"):
            raise ValueError("bad state")
        return ["source", _str(a, "id", 16), state], ""
    if op == "del":
        return ["del", _str(a, "id", 16)], ""
    if op == "rule":
        if a.get("action") not in ("add", "del") or a.get("list") not in ("vpn", "direct"):
            raise ValueError("bad rule")
        return ["rule", a["action"], a["list"], _str(a, "value", 253)], ""
    if op == "set":
        if a.get("key") not in ("mode", "order", "ru_blocked", "ru_direct"):
            raise ValueError("bad setting")
        return ["set", a["key"], _str(a, "value", 400)], ""
    if op == "node":
        if a.get("action") not in ("disable", "enable", "pin", "unpin", "country"):
            raise ValueError("bad node action")
        tail = ["node", a["action"], _str(a, "id", 64)]
        if a["action"] == "country":
            tail.append(_str(a, "cc", 2, True) or "-")
        return tail, ""
    if op == "hwid":
        return ["hwid", _str(a, "value", 36)], ""
    raise ValueError("unknown action")


class Panel(BaseHTTPRequestHandler):
    server_version = "proxy-unifi-panel"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    # ------------------------------------------------------------ helpers

    def _client_ok(self):
        try:
            ip = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local

    def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj, headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), headers=headers)

    def _session(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "pu_session":
                with _lock:
                    exp = _sessions.get(v)
                    if exp and exp > time.time():
                        return v
                    _sessions.pop(v, None)
        return None

    def _same_origin(self):
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        return bool(host) and (origin == "http://" + host or origin.startswith("http://" + host + "/"))

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if n <= 0 or n > MAX_BODY:
            return None
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return None
        try:
            v = json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return v if isinstance(v, dict) else None

    def _cli(self, tail, stdin=""):
        with _cli_lock:
            try:
                r = subprocess.run([self.server.cli, "auto"] + tail, input=stdin.encode(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=CLI_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                return False, "timed out"
        out = r.stdout.decode("utf-8", "replace")
        errtxt = r.stderr.decode("utf-8", "replace")
        if r.returncode != 0:
            msg = [l for l in errtxt.splitlines() if l.strip()]
            text = (msg[-1] if msg else "failed").replace("\x1b[31m", "").replace("\x1b[0m", "")
            return False, text.replace("error: ", "")
        return True, out

    # ------------------------------------------------------------ routes

    def do_GET(self):
        if not self._client_ok():
            return self._send(403, "forbidden", "text/plain")
        if self.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if self.path == "/api/status":
            if not self._session():
                return self._json(401, {"error": "login"})
            ok, out = self._cli(["status-json"])
            if not ok:
                return self._json(500, {"error": out})
            return self._send(200, out)
        return self._send(404, "not found", "text/plain")

    def do_POST(self):
        if not self._client_ok():
            return self._send(403, "forbidden", "text/plain")
        if self.headers.get("X-Panel") != "1" or not self._same_origin():
            return self._json(403, {"error": "cross-site request refused"})
        body = self._body()
        if body is None:
            return self._json(400, {"error": "bad request"})
        if self.path == "/api/login":
            return self._login(body)
        sid = self._session()
        if not sid:
            return self._json(401, {"error": "login"})
        if self.path == "/api/logout":
            with _lock:
                _sessions.pop(sid, None)
            return self._json(200, {"ok": True},
                              {"Set-Cookie": "pu_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"})
        if self.path == "/api/action":
            try:
                tail, stdin = action_command(body)
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            ok, out = self._cli(tail, stdin)
            return self._json(200 if ok else 422, {"ok": ok, "message": out.strip()[-400:]})
        return self._json(404, {"error": "not found"})

    def _login(self, body):
        ip = self.client_address[0]
        now = time.time()
        with _lock:
            f = _fails.get(ip, [0, 0.0])
            glob = _fails.get("*", [0, 0.0])
            if f[1] > now or glob[1] > now:
                return self._json(429, {"error": "too many attempts, wait a minute"})
        pw = body.get("password")
        try:
            with open(self.server.password_file, encoding="utf-8") as fh:
                stored = fh.read()
        except OSError:
            return self._json(503, {"error": "panel password is not set"})
        if not isinstance(pw, str) or not check_password(pw, stored):
            with _lock:
                f = _fails.setdefault(ip, [0, 0.0])
                f[0] += 1
                if f[0] >= 5:
                    f[0], f[1] = 0, now + 60
                g = _fails.setdefault("*", [0, 0.0])
                g[0] += 1
                if g[0] >= 20:
                    g[0], g[1] = 0, now + 900
            time.sleep(1)
            return self._json(403, {"error": "wrong password"})
        sid = secrets.token_urlsafe(32)
        with _lock:
            _fails.pop(ip, None)
            for k in [k for k, v in _sessions.items() if v < now]:
                _sessions.pop(k, None)
            _sessions[sid] = now + SESSION_TTL
        return self._json(200, {"ok": True}, {
            "Set-Cookie": "pu_session=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Strict"
                          % (sid, SESSION_TTL)})


PAGE = r"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proxy Auto</title>
<style>
:root{--bg:#f4f5f6;--side:#fff;--card:#fff;--card2:#f8f9fa;--line:#e4e6e9;--fg:#212327;--mut:#7e868f;--acc:#006fff;--accs:rgba(0,111,255,.1);--ok:#20b25a;--oks:rgba(32,178,90,.12);--warn:#e8930c;--bad:#e5484d;--bads:rgba(229,72,77,.12);--sh:0 1px 2px rgba(16,24,40,.05);--sh2:0 12px 32px rgba(16,24,40,.16);color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121315;--side:#17181b;--card:#1c1e21;--card2:#222428;--line:#2c2f34;--fg:#e9ebee;--mut:#8b929b;--acc:#4797ff;--accs:rgba(71,151,255,.14);--ok:#3ccf74;--oks:rgba(60,207,116,.13);--warn:#f5a524;--bad:#f06468;--bads:rgba(240,100,104,.14);--sh:none;--sh2:0 12px 32px rgba(0,0,0,.5);color-scheme:dark}}
:root[data-theme="dark"]{--bg:#121315;--side:#17181b;--card:#1c1e21;--card2:#222428;--line:#2c2f34;--fg:#e9ebee;--mut:#8b929b;--acc:#4797ff;--accs:rgba(71,151,255,.14);--ok:#3ccf74;--oks:rgba(60,207,116,.13);--warn:#f5a524;--bad:#f06468;--bads:rgba(240,100,104,.14);--sh:none;--sh2:0 12px 32px rgba(0,0,0,.5);color-scheme:dark}
*{box-sizing:border-box}[hidden]{display:none!important}
html,body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}button,input,select{font:inherit;color:inherit}
svg.i{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
.flag{display:inline-block;vertical-align:-3px;border-radius:2px;box-shadow:0 0 0 1px rgba(0,0,0,.12);flex:none;overflow:hidden}
.mut{color:var(--mut)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.sm{font-size:12px}.nowrap{white-space:nowrap}
/* top progress */
#prog{position:fixed;left:0;top:0;height:2px;width:100%;z-index:60;overflow:hidden;opacity:0;transition:opacity .2s}
#prog.on{opacity:1}#prog::after{content:"";position:absolute;top:0;height:100%;width:35%;background:var(--acc);animation:prog 1.1s ease-in-out infinite}
@keyframes prog{0%{left:-35%}100%{left:100%}}
/* layout */
header{position:sticky;top:0;z-index:30;height:52px;display:flex;align-items:center;gap:12px;padding:0 16px;background:var(--side);border-bottom:1px solid var(--line)}
.logo{display:flex;align-items:center;gap:10px;font-weight:600;font-size:15px;letter-spacing:.1px}
.mark{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#0a84ff,#0058e6);display:grid;place-items:center;color:#fff;box-shadow:0 2px 6px rgba(0,111,255,.35)}
.mark svg{width:17px;height:17px}.sub{font-weight:400;color:var(--mut);font-size:12px}
.sp{flex:1}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:500;background:var(--oks);color:var(--ok);white-space:nowrap}
.pill.bad{background:var(--bads);color:var(--bad)}.pill.off{background:var(--card2);color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor;position:relative;flex:none}
.dot.live::after{content:"";position:absolute;inset:0;border-radius:50%;background:currentColor;animation:ping 2s cubic-bezier(0,0,.2,1) infinite}
@keyframes ping{0%{transform:scale(1);opacity:.7}80%,100%{transform:scale(2.6);opacity:0}}
.ib{width:34px;height:34px;display:grid;place-items:center;border-radius:8px;border:0;background:none;color:var(--mut);cursor:pointer;transition:background .15s,color .15s}
.ib:hover{background:var(--card2);color:var(--fg)}
.wrap{display:flex;min-height:calc(100vh - 52px)}
nav{width:212px;flex:none;background:var(--side);border-right:1px solid var(--line);padding:12px 10px;position:sticky;top:52px;height:calc(100vh - 52px)}
nav a{display:flex;align-items:center;gap:11px;padding:8px 11px;border-radius:8px;color:var(--mut);font-weight:500;margin-bottom:2px;position:relative;transition:background .15s,color .15s}
nav a:hover{background:var(--card2);color:var(--fg)}
nav a.on{background:var(--accs);color:var(--acc)}
nav a .cnt{margin-left:auto;font-size:11px;background:var(--card2);color:var(--mut);padding:1px 7px;border-radius:999px}
nav a.on .cnt{background:var(--acc);color:#fff}
main{flex:1;min-width:0;padding:22px 24px 60px;max-width:1180px}
@media (max-width:860px){.wrap{display:block}nav{position:sticky;top:52px;z-index:20;width:auto;height:auto;display:flex;gap:4px;overflow-x:auto;padding:8px 12px;border-right:0;border-bottom:1px solid var(--line);scrollbar-width:none}
 nav a{flex:none;margin:0;padding:7px 11px}nav a .cnt{display:none}main{padding:16px 16px 60px}.hide-m{display:none!important}}
.sec{display:none}.sec.show{display:block}
.sec.show>*{animation:up .45s cubic-bezier(.2,.8,.2,1) both}
.sec.show>*:nth-child(2){animation-delay:.04s}.sec.show>*:nth-child(3){animation-delay:.08s}.sec.show>*:nth-child(4){animation-delay:.12s}.sec.show>*:nth-child(5){animation-delay:.16s}.sec.show>*:nth-child(n+6){animation-delay:.2s}
@keyframes up{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
h1{font-size:20px;font-weight:600;margin:0 0 4px}.lead{color:var(--mut);margin:0 0 18px}
h2{font-size:14px;font-weight:600;margin:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:var(--sh);margin-bottom:16px}
.ch{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.cb{padding:16px}
.grid{display:grid;gap:16px}.g4{grid-template-columns:repeat(4,1fr)}.g2{grid-template-columns:1fr 1fr}
@media (max-width:1000px){.g4{grid-template-columns:1fr 1fr}}@media (max-width:700px){.g2{grid-template-columns:1fr}}
@media (max-width:420px){.g4{grid-template-columns:1fr}}
.grid>.card{margin:0}
/* buttons / inputs */
.btn{display:inline-flex;align-items:center;gap:7px;height:32px;padding:0 13px;border-radius:8px;border:1px solid var(--line);background:var(--card);cursor:pointer;font-weight:500;font-size:13px;white-space:nowrap;transition:background .15s,border-color .15s,transform .1s,box-shadow .15s}
.btn:hover{background:var(--card2)}.btn:active{transform:scale(.97)}
.btn.p{background:var(--acc);border-color:var(--acc);color:#fff}.btn.p:hover{filter:brightness(1.08)}
.btn.d{color:var(--bad)}.btn.d:hover{background:var(--bads);border-color:transparent}
.btn.sm{height:28px;padding:0 10px;font-size:12px}.btn svg.i{width:15px;height:15px}
.in{height:34px;padding:0 11px;border-radius:8px;border:1px solid var(--line);background:var(--card);min-width:0;outline:none;transition:border-color .15s,box-shadow .15s}
.in:focus{border-color:var(--acc);box-shadow:0 0 0 3px var(--accs)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.fld{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--mut)}
/* switch */
.sw{display:flex;align-items:flex-start;gap:12px;padding:12px 0;cursor:pointer}.sw+.sw{border-top:1px solid var(--line)}
.sw input{display:none}.sw .t{flex:1}.sw .t b{display:block;font-weight:500}.sw .t span{color:var(--mut);font-size:12.5px}
.tg{width:36px;height:20px;border-radius:999px;background:var(--line);position:relative;flex:none;margin-top:2px;transition:background .2s}
.tg::after{content:"";position:absolute;left:2px;top:2px;width:16px;height:16px;border-radius:50%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.25);transition:transform .25s cubic-bezier(.3,1.4,.5,1)}
input:checked+.tg{background:var(--acc)}input:checked+.tg::after{transform:translateX(16px)}
/* segmented */
.seg{display:inline-flex;background:var(--card2);border:1px solid var(--line);border-radius:9px;padding:3px;position:relative;width:100%}
.seg button{flex:1;position:relative;z-index:1;border:0;background:none;padding:7px 10px;border-radius:6px;cursor:pointer;font-weight:500;color:var(--mut);transition:color .2s}
.seg button.on{color:var(--fg)}
.seg i{position:absolute;top:3px;bottom:3px;border-radius:6px;background:var(--card);box-shadow:0 1px 3px rgba(0,0,0,.15);transition:left .3s cubic-bezier(.3,1.2,.5,1),width .3s}
/* hero */
.hero{display:flex;gap:18px;align-items:center;padding:18px}
.hero .bigflag{border-radius:6px;box-shadow:0 0 0 1px rgba(0,0,0,.1),0 6px 18px rgba(0,0,0,.15);animation:float 5s ease-in-out infinite}
@keyframes float{50%{transform:translateY(-3px)}}
.hero .nm{font-size:20px;font-weight:600;line-height:1.2}
.chip{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:6px;background:var(--card2);border:1px solid var(--line);font-size:11.5px;color:var(--mut);font-weight:500;white-space:nowrap}
.chip.acc{background:var(--accs);border-color:transparent;color:var(--acc)}
.chip.ok{background:var(--oks);border-color:transparent;color:var(--ok)}
.chip.bad{background:var(--bads);border-color:transparent;color:var(--bad)}
.rtt{margin-left:auto;text-align:right}.rtt b{font-size:30px;font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:-.5px}
/* topology */
.topo{display:flex;align-items:center;padding:6px 18px 20px;gap:0}
.tn{display:flex;flex-direction:column;align-items:center;gap:6px;width:96px;flex:none;text-align:center;font-size:12px}
.tn .ic{width:46px;height:46px;border-radius:12px;background:var(--card2);border:1px solid var(--line);display:grid;place-items:center;color:var(--fg);position:relative}
.tn .ic svg.i{width:22px;height:22px}.tn .ic.acc{background:var(--accs);border-color:transparent;color:var(--acc)}
.tn small{color:var(--mut);font-size:11px;line-height:1.2;max-width:96px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl{flex:1;height:22px;min-width:16px;margin-bottom:22px}
.tl line{stroke:var(--acc);stroke-width:2;stroke-dasharray:4 6;animation:flow .9s linear infinite}
.tl.dim line{stroke:var(--line);animation:none;stroke-dasharray:none}.tl.bad line{stroke:var(--bad);animation:none}
@keyframes flow{to{stroke-dashoffset:-10}}
@media (max-width:560px){.tn{width:64px}.tn small{max-width:64px}.hero{flex-wrap:wrap}.rtt{margin-left:0;text-align:left}}
/* stat tiles */
.stat{padding:14px 16px}.stat .k{color:var(--mut);font-size:12px;display:flex;align-items:center;gap:6px}.stat .v{font-size:22px;font-weight:600;margin-top:4px;font-variant-numeric:tabular-nums}
.stat .v small{font-size:13px;color:var(--mut);font-weight:500}
.bar{height:6px;border-radius:999px;background:var(--card2);overflow:hidden;margin-top:8px}.bar i{display:block;height:100%;border-radius:999px;background:var(--ok);transition:width .6s cubic-bezier(.2,.8,.2,1)}
/* spark */
.spark{width:100%;height:120px;display:block}
.spark path.l{fill:none;stroke:var(--acc);stroke-width:2;stroke-linejoin:round}.spark path.a{fill:url(#sg);stroke:none}
.spark text{fill:var(--mut);font-size:10px}
.spark .gl{stroke:var(--line);stroke-dasharray:2 4}
/* country summary */
.cty{display:flex;align-items:center;gap:10px;padding:9px 0}.cty+.cty{border-top:1px solid var(--line)}
.cty .n{flex:1;min-width:0}.cty .n b{font-weight:500}.cty .bar{margin-top:5px;height:4px}
.cty .r{font-variant-numeric:tabular-nums;font-weight:500;min-width:62px;text-align:right}
/* table */
.tbl{width:100%;border-collapse:collapse}
.tbl th{font-size:11.5px;font-weight:500;color:var(--mut);text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap;text-transform:uppercase;letter-spacing:.3px}
.tbl td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
.tbl tr:last-child td{border-bottom:0}.tbl tbody tr{transition:background .15s}.tbl tbody tr:hover{background:var(--card2)}
.tbl tr.act{background:var(--accs)}.tbl tr.off td{opacity:.5}.tbl tr.off td:last-child{opacity:1}
.scroll{overflow-x:auto}
.srv{display:flex;align-items:center;gap:10px;min-width:0}.srv .nm{font-weight:500}.srv .h{font-size:11.5px;color:var(--mut)}
.meter{display:flex;align-items:center;gap:8px;min-width:120px}.meter .bar{flex:1;margin:0;height:5px;min-width:50px}
.meter span{font-variant-numeric:tabular-nums;font-size:12.5px;min-width:52px}
.fb{border:0;background:none;padding:2px;border-radius:5px;cursor:pointer;line-height:0}.fb:hover{background:var(--card2)}
.acts{display:flex;gap:4px;justify-content:flex-end}
.ib.sm{width:30px;height:30px}.ib.on{color:var(--acc)}
.tbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line)}
.fchip{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 10px;border-radius:999px;border:1px solid var(--line);background:var(--card);cursor:pointer;font-size:12.5px;transition:all .15s}
.fchip:hover{background:var(--card2)}.fchip.on{background:var(--accs);border-color:var(--acc);color:var(--acc)}
/* order chips */
.ord{display:flex;gap:8px;flex-wrap:wrap;align-items:center;min-height:40px}
.oc{display:inline-flex;align-items:center;gap:8px;height:36px;padding:0 6px 0 10px;border-radius:9px;border:1px solid var(--line);background:var(--card2);cursor:grab;user-select:none;transition:transform .2s,box-shadow .2s,opacity .2s;animation:pop .3s cubic-bezier(.3,1.4,.5,1) both}
.oc:hover{box-shadow:var(--sh2);transform:translateY(-1px)}.oc.drag{opacity:.35}.oc.over{box-shadow:0 0 0 2px var(--acc)}
.oc .n{font-size:11px;width:18px;height:18px;border-radius:50%;background:var(--acc);color:#fff;display:grid;place-items:center;font-weight:600}
.oc .x{border:0;background:none;color:var(--mut);cursor:pointer;padding:3px;border-radius:5px;line-height:0}.oc .x:hover{color:var(--bad);background:var(--bads)}
.oc .x svg.i{width:14px;height:14px}
@keyframes pop{from{transform:scale(.8);opacity:0}to{transform:none;opacity:1}}
.arr{color:var(--mut);display:flex}.arr svg.i{width:14px;height:14px}
.save{transition:opacity .25s,transform .25s}.save.hid{opacity:0;transform:translateX(-6px);pointer-events:none}
/* rules */
.rl{max-height:320px;overflow:auto}
.ri{display:flex;align-items:center;gap:10px;padding:7px 16px;border-bottom:1px solid var(--line);animation:up .3s both}
.ri:last-child{border-bottom:0}.ri span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.ri.out{animation:out .25s forwards}@keyframes out{to{opacity:0;transform:translateX(16px)}}
.empty{padding:22px 16px;text-align:center;color:var(--mut);font-size:13px}
.cnt2{font-size:11px;background:var(--card2);border:1px solid var(--line);padding:0 7px;border-radius:999px;color:var(--mut);font-weight:500}
/* pipeline */
.pipe{position:relative;padding:4px 0}
.st{display:flex;align-items:center;gap:12px;padding:8px 0;position:relative;transition:opacity .3s}
.st .num{width:24px;height:24px;border-radius:50%;background:var(--card2);border:1px solid var(--line);display:grid;place-items:center;font-size:11px;font-weight:600;color:var(--mut);flex:none;z-index:1}
.st:not(:last-child)::before{content:"";position:absolute;left:11.5px;top:30px;bottom:-10px;width:1px;background:var(--line)}
.st .w{flex:1;min-width:0}.st .w b{font-weight:500}.st .w div{font-size:12px;color:var(--mut)}
.st.off{opacity:.38}.st.off .chip{filter:grayscale(1)}
/* sources */
.srcc{padding:16px;display:flex;gap:14px;align-items:flex-start;flex-wrap:wrap}.srcc+.srcc{border-top:1px solid var(--line)}
.srcc .ic{width:40px;height:40px;border-radius:10px;background:var(--accs);color:var(--acc);display:grid;place-items:center;flex:none}
.srcc .w{flex:1;min-width:200px}
.kv{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;font-size:12.5px}.kv div span{color:var(--mut);display:block;font-size:11.5px}
/* log */
.ev{display:flex;gap:12px;padding:10px 16px;border-bottom:1px solid var(--line);align-items:center}.ev:last-child{border-bottom:0}
.ev .ic{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;background:var(--card2);color:var(--mut);flex:none}
.ev .ic svg.i{width:15px;height:15px}.ev .ic.ok{background:var(--oks);color:var(--ok)}.ev .ic.bad{background:var(--bads);color:var(--bad)}.ev .ic.acc{background:var(--accs);color:var(--acc)}
.ev .w{flex:1;min-width:0}.ev .t{color:var(--mut);font-size:12px;white-space:nowrap}
/* popover / modal / toast */
.pop{position:fixed;z-index:70;background:var(--card);border:1px solid var(--line);border-radius:12px;box-shadow:var(--sh2);padding:8px;width:300px;max-height:340px;overflow:auto;animation:pin .18s cubic-bezier(.2,.8,.2,1)}
@keyframes pin{from{opacity:0;transform:translateY(-6px) scale(.98)}}
.pop input{width:100%;margin-bottom:6px}
.pop .opts{display:grid;grid-template-columns:1fr 1fr;gap:2px}
.pop button{display:flex;align-items:center;gap:8px;border:0;background:none;padding:7px 8px;border-radius:7px;cursor:pointer;text-align:left;font-size:13px;min-width:0}
.pop button:hover{background:var(--card2)}.pop button span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pop .full{grid-column:1/-1;color:var(--acc)}
.veil{position:fixed;inset:0;z-index:80;background:rgba(10,12,16,.45);display:grid;place-items:center;padding:16px;animation:fade .2s}
@keyframes fade{from{opacity:0}}
.modal{background:var(--card);border-radius:14px;box-shadow:var(--sh2);width:100%;max-width:400px;padding:20px;animation:zoom .25s cubic-bezier(.3,1.3,.5,1)}
@keyframes zoom{from{transform:scale(.92);opacity:0}}
.modal h3{margin:0 0 6px;font-size:16px}.modal p{margin:0 0 18px;color:var(--mut)}.modal .row{justify-content:flex-end}
#toasts{position:fixed;right:16px;bottom:16px;z-index:90;display:flex;flex-direction:column;gap:8px;align-items:flex-end;max-width:calc(100vw - 32px)}
.toast{display:flex;align-items:center;gap:10px;background:var(--card);border:1px solid var(--line);border-left:3px solid var(--ok);border-radius:10px;padding:11px 14px;box-shadow:var(--sh2);min-width:220px;max-width:420px;animation:tin .35s cubic-bezier(.2,1.2,.4,1)}
.toast.bad{border-left-color:var(--bad)}.toast svg.i{color:var(--ok)}.toast.bad svg.i{color:var(--bad)}
.toast.out{animation:tout .3s forwards}@keyframes tin{from{transform:translateX(30px);opacity:0}}@keyframes tout{to{transform:translateX(30px);opacity:0}}
/* login */
#login{min-height:100vh;display:grid;place-items:center;padding:16px;background:radial-gradient(1200px 500px at 50% -10%,var(--accs),transparent)}
.lcard{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px;box-shadow:var(--sh2);animation:zoom .4s cubic-bezier(.3,1.3,.5,1)}
.lcard .mark{width:48px;height:48px;border-radius:14px;margin-bottom:14px}.lcard .mark svg{width:26px;height:26px}
.lcard h1{margin-bottom:2px}.lcard form{display:flex;flex-direction:column;gap:10px;margin-top:20px}
.lcard .in{height:40px;font-size:15px}.lcard .in:not(:placeholder-shown){letter-spacing:3px}.lcard .btn{height:40px;justify-content:center;font-size:14px}
.shake{animation:shake .45s}@keyframes shake{20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}
.skel{background:linear-gradient(90deg,var(--card2) 25%,var(--line) 50%,var(--card2) 75%);background-size:200% 100%;animation:sh 1.2s infinite;border-radius:6px;color:transparent!important}
@keyframes sh{to{background-position:-200% 0}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
</style></head><body>
<div id="prog"></div>
<div id="login" hidden><div class="lcard" id="lcard">
<div class="mark"><svg viewBox="0 0 24 24" class="i" style="stroke-width:2"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></div>
<h1>Proxy Auto</h1><div class="mut">UniFi Dream Machine · VPN-шлюз</div>
<form id="lf"><input class="in" id="pw" type="password" inputmode="numeric" placeholder="Пароль" autocomplete="current-password" autofocus><button class="btn p">Войти</button></form></div></div>

<div id="app" hidden>
<header><div class="logo"><div class="mark"><svg viewBox="0 0 24 24" class="i" style="stroke-width:2.2"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/></svg></div><div>Proxy Auto <span class="sub hide-m">· Dream Machine</span></div></div>
<div class="sp"></div><span class="pill" id="hpill"><span class="dot live"></span><span>…</span></span>
<button class="ib" id="theme" title="Тема"></button><button class="ib" id="logout" title="Выйти"></button></header>
<div class="wrap"><nav id="nav"></nav><main>

<section class="sec" id="s-overview">
<h1>Обзор</h1><p class="lead">Куда сейчас идёт трафик VPN и как себя чувствуют серверы.</p>
<div class="card"><div class="hero" id="hero"></div><div class="topo" id="topo"></div>
<div class="row" style="padding:0 18px 16px" id="enablebox" hidden><span class="warn">Авто-режим выключен.</span><button class="btn p sm" data-op="enable">Включить</button></div></div>
<div class="grid g4" id="tiles"></div>
<div class="grid g2" style="margin-top:16px">
<div class="card"><div class="ch"><h2>Задержка активного сервера</h2><span class="sp"></span><span class="mut sm" id="sparkinfo">за этот сеанс</span></div><div class="cb" style="padding:10px 12px 6px"><svg class="spark" id="spark" viewBox="0 0 600 120" preserveAspectRatio="none"></svg></div></div>
<div class="card"><div class="ch"><h2>Страны</h2><span class="sp"></span><a href="#servers" class="sm">Порядок →</a></div><div class="cb" style="padding:6px 16px" id="ctys"></div></div>
</div></section>

<section class="sec" id="s-servers">
<h1>Серверы</h1><p class="lead">Трафик получает первая живая страна по порядку, а внутри страны — самый быстрый сервер (или закреплённый).</p>
<div class="card"><div class="ch"><h2>Порядок стран</h2><span class="sp"></span><button class="btn p sm save hid" id="saveorder"><svg viewBox="0 0 24 24" class="i"><path d="M5 12l5 5 9-10"/></svg>Сохранить порядок</button><button class="btn sm" id="addcty"><svg viewBox="0 0 24 24" class="i"><path d="M12 5v14M5 12h14"/></svg>Страна</button></div>
<div class="cb"><div class="ord" id="order"></div><div class="mut sm" style="margin-top:10px">Перетащите страны мышью. Изменения вступят в силу после «Сохранить».</div></div></div>
<div class="card"><div class="tbar"><input class="in" id="q" placeholder="Поиск сервера" style="width:220px"><div class="row" id="cfilter"></div></div>
<div class="scroll"><table class="tbl"><thead><tr><th>#</th><th>Сервер</th><th class="hide-m">Протокол</th><th>Задержка</th><th class="hide-m">Источник</th><th></th></tr></thead><tbody id="nodes"></tbody></table></div></div>
</section>

<section class="sec" id="s-routing">
<h1>Маршрутизация</h1><p class="lead">Что идёт через VPN, а что напрямую.</p>
<div class="grid g2">
<div class="card"><div class="ch"><h2>Режим</h2></div><div class="cb">
<div class="seg" id="mode"><i></i><button data-m="list">Через VPN только списки</button><button data-m="all">Всё через VPN</button></div>
<div style="margin-top:8px">
<label class="sw"><input type="checkbox" id="rub"><span class="tg"></span><span class="t"><b>Заблокированное в РФ — через VPN</b><span>Готовые списки доменов и IP (runetfreedom), обновляются сами.</span></span></label>
<label class="sw"><input type="checkbox" id="rud"><span class="tg"></span><span class="t"><b>Российские сервисы — всегда напрямую</b><span>Онлайн-кинотеатры, ТВ-каналы, IPTV, банки, Госуслуги, ВК, Яндекс.</span></span></label>
</div><div class="row" style="margin-top:8px"><button class="btn sm" data-op="geo_update"><svg viewBox="0 0 24 24" class="i"><path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/></svg>Обновить списки сейчас</button></div></div></div>
<div class="card"><div class="ch"><h2>Порядок проверки</h2><span class="sp"></span><span class="mut sm">первое совпадение решает</span></div><div class="cb" style="padding:10px 16px"><div class="pipe" id="pipe"></div></div></div>
</div>
<div class="grid g2" style="margin-top:16px">
<div class="card"><div class="ch"><span class="chip acc">VPN</span><h2>Свои: через VPN</h2><span class="cnt2" id="nvpn">0</span></div>
<div class="tbar"><input class="in" id="rv" placeholder="example.com или 1.2.3.0/24" style="flex:1"><button class="btn p sm" data-add="vpn">Добавить</button></div><div class="rl" id="lvpn"></div></div>
<div class="card"><div class="ch"><span class="chip">Напрямую</span><h2>Свои: напрямую</h2><span class="cnt2" id="ndirect">0</span></div>
<div class="tbar"><input class="in" id="rd" placeholder="example.ru или 5.6.7.8" style="flex:1"><button class="btn p sm" data-add="direct">Добавить</button></div><div class="rl" id="ldirect"></div></div>
</div></section>

<section class="sec" id="s-sources">
<h1>Источники</h1><p class="lead">Подписки и отдельные ссылки, из которых берутся серверы.</p>
<div class="card"><div class="ch"><h2>Подключённые</h2><span class="sp"></span><button class="btn sm" data-op="refresh"><svg viewBox="0 0 24 24" class="i"><path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/></svg>Обновить подписки</button></div><div id="sources"></div></div>
<div class="grid g2">
<div class="card"><div class="ch"><h2>Добавить подписку</h2></div><div class="cb" style="display:flex;flex-direction:column;gap:10px">
<label class="fld">Название<input class="in" id="sn" placeholder="Моя подписка"></label><label class="fld">Ссылка<input class="in" id="su" placeholder="https://…"></label>
<label class="fld">User-Agent (необязательно)<input class="in" id="sua"></label><div><button class="btn p" id="addsub">Добавить подписку</button></div></div></div>
<div class="card"><div class="ch"><h2>Добавить ссылку</h2></div><div class="cb" style="display:flex;flex-direction:column;gap:10px">
<label class="fld">Название<input class="in" id="ln" placeholder="Мой сервер"></label><label class="fld">Ссылка<input class="in" id="ll" placeholder="vless://… hysteria2://… trojan://…"></label>
<div><button class="btn p" id="addlink">Добавить ссылку</button></div>
<label class="fld" style="margin-top:8px">HWID устройства (передаётся подпискам)<span class="row"><input class="in" id="hw" placeholder="UUID" style="flex:1"><button class="btn" id="sethw">Сохранить</button></span></label></div></div>
</div></section>

<section class="sec" id="s-log">
<h1>Журнал</h1><p class="lead">Когда и почему менялся сервер.</p>
<div class="card" id="log"></div></section>
</main></div></div>
<div id="toasts"></div>
<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
let S=null,order=[],orderDirty=false,busy=false,hist=[],qtxt='',cflt='';
const IC={
 overview:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
 servers:'<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
 routing:'<path d="M4 12h6l4-6h6M14 18h6M10 12l4 6"/><path d="M17 3l3 3-3 3M17 15l3 3-3 3"/>',
 sources:'<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
 log:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 logout:'<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 17l5-5-5-5M15 12H3"/>',
 sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
 moon:'<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
 auto:'<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor"/>',
 pin:'<path d="M9 4h6l-1 6 4 4H6l4-4zM12 14v7"/>',
 power:'<path d="M12 3v9M6.3 7a8 8 0 1 0 11.4 0"/>',
 trash:'<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
 x:'<path d="M6 6l12 12M18 6L6 18"/>',ok:'<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',err:'<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>',
 devices:'<rect x="2" y="5" width="14" height="10" rx="1.5"/><path d="M6 19h6M9 15v4"/><rect x="17" y="9" width="5" height="10" rx="1.2"/>',
 router:'<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 9a6 6 0 0 1 8 0M5.5 6.5a10 10 0 0 1 13 0"/>',
 globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>',
 shield:'<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/>',
 sw:'<path d="M7 4L3 8l4 4M3 8h14M17 20l4-4-4-4M21 16H7"/>',bolt:'<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
 gauge:'<path d="M12 14l4-4M3.5 17a9 9 0 1 1 17 0"/>',db:'<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
 split:'<path d="M12 21v-7M12 14L5 5M12 14l7-9M5 5v4M5 5h4M19 5v4M19 5h-4"/>'};
const ic=(n,st)=>`<svg viewBox="0 0 24 24" class="i"${st?` style="${st}"`:''}>${IC[n]}</svg>`;
function esc(t){return String(t??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function put(el,h){if(el&&el._h!==h){el.innerHTML=h;el._h=h}}
/* ---------- flags (inline SVG, 3:2) ---------- */
const CN={DE:'Германия',PL:'Польша',FI:'Финляндия',NL:'Нидерланды',SE:'Швеция',NO:'Норвегия',DK:'Дания',IS:'Исландия',EE:'Эстония',LV:'Латвия',LT:'Литва',FR:'Франция',IT:'Италия',ES:'Испания',PT:'Португалия',GB:'Великобритания',IE:'Ирландия',BE:'Бельгия',LU:'Люксембург',CH:'Швейцария',AT:'Австрия',CZ:'Чехия',HU:'Венгрия',RO:'Румыния',BG:'Болгария',GR:'Греция',RS:'Сербия',UA:'Украина',BY:'Беларусь',MD:'Молдова',GE:'Грузия',AM:'Армения',AZ:'Азербайджан',KZ:'Казахстан',UZ:'Узбекистан',TR:'Турция',IL:'Израиль',AE:'ОАЭ',IN:'Индия',JP:'Япония',KR:'Южная Корея',CN:'Китай',HK:'Гонконг',SG:'Сингапур',AU:'Австралия',US:'США',CA:'Канада',MX:'Мексика',BR:'Бразилия',AR:'Аргентина',RU:'Россия',ID:'Индонезия'};
const FL={DE:['h','#000','#dd0000','#ffce00'],NL:['h','#ae1c28','#fff','#21468b'],RU:['h','#fff','#0039a6','#d52b1e'],PL:['h','#fff','#dc143c'],UA:['h','#0057b7','#ffd700'],AT:['h','#c8102e','#fff','#c8102e'],HU:['h','#ce2939','#fff','#477050'],BG:['h','#fff','#00966e','#d62612'],LT:['h','#fdb913','#006a44','#c1272d'],EE:['h','#0072ce','#000','#fff'],LU:['h','#ed2939','#fff','#00a1de'],AM:['h','#d90012','#0033a0','#f2a800'],ID:['h','#ce1126','#fff'],RS:['h','#c6363c','#0c4076','#fff'],UZ:['h','#0099b5','#fff','#1eb53a'],AZ:['h','#00b5e2','#ef3340','#509e2f'],LV:['h','#9e3039','#9e3039','#fff','#9e3039','#9e3039'],AR:['h','#74acdf','#fff','#74acdf'],
 FR:['v','#002654','#fff','#ce1126'],IT:['v','#009246','#fff','#ce2b37'],IE:['v','#169b62','#fff','#ff883e'],BE:['v','#000','#fdda24','#ef3340'],RO:['v','#002b7f','#fcd116','#ce1126'],MX:['v','#006847','#fff','#ce1126'],MD:['v','#0046ae','#ffd200','#cc092f'],
 FI:['n','#fff','#002f6c'],SE:['n','#006aa7','#fecc00'],DK:['n','#c8102e','#fff'],NO:['n','#ba0c2f','#fff','#00205b'],IS:['n','#02529c','#fff','#dc1e35']};
function star(cx,cy,r,f){let p=[];for(let i=0;i<10;i++){const a=Math.PI/5*i-Math.PI/2,rr=i%2?r*.4:r;p.push((cx+rr*Math.cos(a)).toFixed(2)+','+(cy+rr*Math.sin(a)).toFixed(2))}return `<polygon points="${p.join(' ')}" fill="${f}"/>`}
const R=(x,y,w,h,f)=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${f}"/>`,C=(x,y,r,f)=>`<circle cx="${x}" cy="${y}" r="${r}" fill="${f}"/>`;
const SP={
 US:()=>{let s='';for(let i=0;i<13;i++)s+=R(0,i*20/13,30,20/13+.05,i%2?'#fff':'#b22234');s+=R(0,0,12,10.77,'#3c3b6e');for(let y=0;y<4;y++)for(let x=0;x<5;x++)s+=C(1.4+x*2.3,1.5+y*2.6,.45,'#fff');return s},
 GB:()=>R(0,0,30,20,'#012169')+'<path d="M0 0L30 20M30 0L0 20" stroke="#fff" stroke-width="4"/><path d="M0 0L30 20M30 0L0 20" stroke="#c8102e" stroke-width="1.3"/>'+R(12,0,6,20,'#fff')+R(0,7,30,6,'#fff')+R(13.2,0,3.6,20,'#c8102e')+R(0,8.2,30,3.6,'#c8102e'),
 CH:()=>R(0,0,30,20,'#d52b1e')+R(13,4,4,12,'#fff')+R(9,8,12,4,'#fff'),JP:()=>R(0,0,30,20,'#fff')+C(15,10,6,'#bc002d'),
 KZ:()=>R(0,0,30,20,'#00afca')+C(15,9.5,4,'#fec50c'),TR:()=>R(0,0,30,20,'#e30a17')+C(11,10,5,'#fff')+C(12.3,10,4,'#e30a17')+star(18,10,2.6,'#fff'),
 CN:()=>R(0,0,30,20,'#de2910')+star(5,5,3,'#ffde00')+star(10,2,1,'#ffde00')+star(12,4,1,'#ffde00')+star(12,7,1,'#ffde00')+star(10,9,1,'#ffde00'),
 KR:()=>R(0,0,30,20,'#fff')+'<path d="M10 10a5 5 0 0 1 10 0z" fill="#cd2e3a"/><path d="M10 10a5 5 0 0 0 10 0z" fill="#0047a0"/>',
 IN:()=>R(0,0,30,6.7,'#ff9933')+R(0,6.66,30,6.7,'#fff')+R(0,13.33,30,6.7,'#138808')+'<circle cx="15" cy="10" r="2.4" fill="none" stroke="#000080" stroke-width=".7"/>',
 BR:()=>R(0,0,30,20,'#009c3b')+'<polygon points="3,10 15,2.2 27,10 15,17.8" fill="#ffdf00"/>'+C(15,10,4.6,'#002776'),
 GE:()=>R(0,0,30,20,'#fff')+R(13,0,4,20,'#ff0000')+R(0,8,30,4,'#ff0000'),
 AE:()=>R(0,0,30,6.7,'#00732f')+R(0,6.66,30,6.7,'#fff')+R(0,13.33,30,6.7,'#000')+R(0,0,7.5,20,'#ff0000'),
 IL:()=>R(0,0,30,20,'#fff')+R(0,2,30,3,'#0038b8')+R(0,15,30,3,'#0038b8')+'<path d="M15 6.3l3.2 5.6h-6.4zM15 13.7l3.2-5.6h-6.4z" fill="none" stroke="#0038b8" stroke-width=".9"/>',
 HK:()=>R(0,0,30,20,'#de2910')+star(15,10,4.5,'#fff'),SG:()=>R(0,0,30,10,'#ef3340')+R(0,10,30,10,'#fff')+C(6,5,3,'#fff')+C(7.2,5,2.7,'#ef3340'),
 AU:()=>R(0,0,30,20,'#00008b')+star(7.5,15,2.2,'#fff')+star(22,4,1.2,'#fff')+star(25.5,9,1.2,'#fff')+star(22,16,1.2,'#fff')+star(19,9.5,1.2,'#fff'),
 CA:()=>R(0,0,30,20,'#fff')+R(0,0,7.5,20,'#d52b1e')+R(22.5,0,7.5,20,'#d52b1e')+star(15,10,4.2,'#d52b1e'),
 CZ:()=>R(0,0,30,10,'#fff')+R(0,10,30,10,'#d7141a')+'<polygon points="0,0 15,10 0,20" fill="#11457e"/>',
 ES:()=>R(0,0,30,5,'#aa151b')+R(0,5,30,10,'#f1bf00')+R(0,15,30,5,'#aa151b'),PT:()=>R(0,0,12,20,'#046a38')+R(12,0,18,20,'#da291c')+C(12,10,3.5,'#ffe900'),
 GR:()=>{let s='';for(let i=0;i<9;i++)s+=R(0,i*20/9,30,20/9+.05,i%2?'#fff':'#0d5eaf');return s+R(0,0,11.1,11.1,'#0d5eaf')+R(4.44,0,2.22,11.1,'#fff')+R(0,4.44,11.1,2.22,'#fff')},
 BY:()=>R(0,0,30,13.3,'#c8313e')+R(0,13.3,30,6.7,'#4aa657')+R(0,0,3.3,20,'#fff')};
function flag(cc,w){w=w||22;const h=Math.round(w*2/3);cc=(cc||'').toUpperCase();const f=FL[cc];let s;
 if(f){const k=f[0],c=f.slice(1),n=c.length;s='';
  if(k=='h')c.forEach((x,i)=>s+=R(0,i*20/n,30,20/n+.05,x));
  else if(k=='v')c.forEach((x,i)=>s+=R(i*30/n,0,30/n+.05,20,x));
  else{s=R(0,0,30,20,c[0])+R(8,0,5,20,c[1])+R(0,7.5,30,5,c[1]);if(c[2])s+=R(9.5,0,2,20,c[2])+R(0,9,30,2,c[2])}}
 else if(SP[cc])s=SP[cc]();
 else return `<svg class="flag" width="${w}" height="${h}" viewBox="0 0 30 20"><rect width="30" height="20" fill="var(--card2)"/><text x="15" y="14" text-anchor="middle" font-size="10" font-weight="600" fill="var(--mut)">${esc(cc||'?')}</text></svg>`;
 return `<svg class="flag" width="${w}" height="${h}" viewBox="0 0 30 20" preserveAspectRatio="none"><title>${esc(CN[cc]||cc)}</title>${s}</svg>`}
/* emoji flags in names -> SVG (Windows shows them as letters) */
function nice(t,w,drop){t=String(t||'');if(drop){const m=t.match(/^([\u{1F1E6}-\u{1F1FF}]{2})\s*/u);if(m&&!/→/.test(t)){const c=[...m[1]].map(x=>String.fromCharCode(x.codePointAt(0)-0x1F1A5)).join('');if(c==drop)t=t.slice(m[0].length)}}return esc(t).replace(/([\u{1F1E6}-\u{1F1FF}])([\u{1F1E6}-\u{1F1FF}])/gu,(m,a,b)=>flag(String.fromCharCode(a.codePointAt(0)-0x1F1A5,b.codePointAt(0)-0x1F1A5),w||16)).replace(/\s*\[[A-Z]{2}\]/g,'')}
function bare(t){return String(t||'').replace(/[\u{1F1E6}-\u{1F1FF}]/gu,'').replace(/\s*\[[A-Z]{2}\]$/,'').replace(/^\s*→\s*/,'').trim()}
const PROTO={hysteria2:'Hysteria2',vless:'VLESS',vmess:'VMess',trojan:'Trojan',ss:'Shadowsocks',shadowsocks:'Shadowsocks',wireguard:'WireGuard',tuic:'TUIC'};
const rttColor=r=>r<250?'var(--ok)':r<450?'var(--warn)':'var(--bad)';
/* ---------- infra ---------- */
function prog(on){$('#prog').classList.toggle('on',on)}
function toast(t,bad){const el=document.createElement('div');el.className='toast'+(bad?' bad':'');el.innerHTML=ic(bad?'err':'ok')+'<span>'+esc(t)+'</span>';$('#toasts').appendChild(el);
 setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),300)},bad?6000:2600)}
function ask(title,text,okL,danger){return new Promise(res=>{const v=document.createElement('div');v.className='veil';
 v.innerHTML=`<div class="modal"><h3>${esc(title)}</h3><p>${esc(text)}</p><div class="row"><button class="btn" data-a="0">Отмена</button><button class="btn ${danger?'d':'p'}" data-a="1">${esc(okL)}</button></div></div>`;
 v.onclick=e=>{const a=e.target.closest('[data-a]');if(e.target===v||a){v.remove();res(a&&a.dataset.a==='1')}};document.body.appendChild(v);v.querySelector('[data-a="1"]').focus()})}
async function api(path,body){const r=await fetch(path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-Panel':'1'}:{},body:body?JSON.stringify(body):undefined,credentials:'same-origin'});
 if(r.status==401){show(false);throw new Error('login')}const j=await r.json().catch(()=>({}));if(!r.ok&&!('ok' in j))throw new Error(j.error||r.status);return j}
async function act(a,okText){if(busy)return false;busy=true;prog(true);try{const j=await api('/api/action',a);if(j.ok){toast(okText||'Готово');await load();return true}toast(j.message||'Ошибка',true)}catch(e){if(e.message!='login')toast(e.message,true)}finally{busy=false;prog(false)}return false}
function show(app){$('#app').hidden=!app;$('#login').hidden=app;if(!app)setTimeout(()=>$('#pw').focus(),50)}
/* ---------- theme ---------- */
const store={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};
function applyTheme(t){if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;else delete document.documentElement.dataset.theme;$('#theme').innerHTML=ic(t==='light'?'sun':t==='dark'?'moon':'auto');$('#theme').title='Тема: '+(t==='light'?'светлая':t==='dark'?'тёмная':'как в системе')}
let theme=store.get('pu-theme')||'auto';applyTheme(theme);
$('#theme').onclick=()=>{theme={auto:'dark',dark:'light',light:'auto'}[theme]||'auto';store.set('pu-theme',theme);applyTheme(theme)};
$('#logout').innerHTML=ic('logout');
/* ---------- nav ---------- */
const PAGES=[['overview','Обзор'],['servers','Серверы'],['routing','Маршрутизация'],['sources','Источники'],['log','Журнал']];
function nav(){const p=(location.hash||'#overview').slice(1),cur=PAGES.some(x=>x[0]==p)?p:'overview';
 put($('#nav'),PAGES.map(([k,t])=>`<a href="#${k}" class="${k==cur?'on':''}">${ic(k)}<span>${t}</span>${k=='servers'&&S?`<span class="cnt">${S.nodes.length}</span>`:''}</a>`).join(''));
 $$('.sec').forEach(s=>{const on=s.id=='s-'+cur;if(on&&!s.classList.contains('show')){s.classList.add('show')}else if(!on)s.classList.remove('show')});return cur}
window.addEventListener('hashchange',()=>{nav();scrollTo({top:0});if(S)render()});
/* ---------- render ---------- */
function countUp(el,to){const from=+el.dataset.v||0;el.dataset.v=to;if(!from||from===to){el.textContent=to;return}const t0=performance.now();
 const step=t=>{const k=Math.min(1,(t-t0)/500),e=1-Math.pow(1-k,3);el.textContent=Math.round(from+(to-from)*e);if(k<1)requestAnimationFrame(step)};requestAnimationFrame(step)}
function hb(){const m={};((S.health||{}).nodes||[]).forEach(n=>m[n.tag]=n);return m}
function nodeState(n,x,st){if(st.disabled&&st.disabled.includes(n.id))return['off','выключен'];if(!n.usable)return['off',n.reason||'не подходит'];if(x.ok)return['ok',x.rtt+' мс'];if(x.last_probe)return['bad','нет ответа'];return['wait','проверка…']}
function phase(ms){return `animation-delay:-${Date.now()%ms}ms`}
function render(){const h=S.health||{},st=S.settings||{},H=hb();
 const act_=S.nodes.find(n=>n.tag==h.active),ax=act_?H[act_.tag]||{}:{};
 const up=S.nodes.filter(n=>(H[n.tag]||{}).ok).length;
 // header pill
 const pill=$('#hpill');let pc='',pt='';
 if(!S.auto_active){pc='off';pt='Авто-режим выключен'}else if(h.killswitch){pc='bad';pt='Нет живых серверов'}else{pt='VPN активен'}
 pill.className='pill '+pc;put(pill,`<span class="dot ${pc?'':'live'}" style="${phase(2000)}"></span><span>${pt}</span>`);
 // hero
 const cc=act_?act_.country:'';
 put($('#hero'),h.killswitch?`<div class="ic" style="width:60px;height:40px;display:grid;place-items:center;color:var(--bad)">${ic('shield','width:34px;height:34px')}</div><div><div class="nm bad">VPN-трафик остановлен</div><div class="mut">Ни один сервер не отвечает — заблокированное не уйдёт напрямую (kill switch).</div></div>`:
  act_?`<span class="bigflag" style="line-height:0">${flag(cc,60)}</span><div style="min-width:0"><div class="mut sm">Трафик VPN идёт через</div><div class="nm">${nice(act_.label,20,cc)}</div>
  <div class="row" style="margin-top:6px"><span class="chip">${esc(CN[cc]||cc)}</span><span class="chip acc">${esc(PROTO[act_.scheme]||act_.scheme||'')}</span>${act_.pinned?'<span class="chip">закреплён</span>':''}<span class="chip">${esc(act_.source_name||'')}</span></div></div>
  <div class="rtt"><b id="rttv" style="color:${rttColor(ax.rtt||0)}">0</b> <span class="mut">мс</span><div class="mut sm" id="ago"></div></div>`:'<div class="mut">Ждём первой проверки серверов…</div>');
 const rv=$('#rttv');if(rv&&ax.rtt)countUp(rv,ax.rtt);
 // topology
 const tl=h.killswitch?'bad':(act_?'':'dim'),dash=`<svg class="tl ${tl}" viewBox="0 0 100 22" preserveAspectRatio="none"><line x1="0" y1="11" x2="100" y2="11" style="${phase(900)}"/></svg>`;
 put($('#topo'),`<div class="tn"><div class="ic">${ic('devices')}</div>Устройства<small>сеть VPN</small></div>${dash}<div class="tn"><div class="ic">${ic('router')}</div>Dream Machine<small>xray · правила</small></div>${dash}
  <div class="tn"><div class="ic ${act_?'acc':''}">${act_?flag(cc,26):ic('shield')}</div>${esc(CN[cc]||'VPN')}<small>${act_?esc(bare(act_.label)):'—'}</small></div>${dash}<div class="tn"><div class="ic">${ic('globe')}</div>Интернет<small>заблокированное</small></div>`);
 $('#enablebox').hidden=S.auto_active;
 // tiles
 const sub=(S.sources||[])[0],ui=parseUI(sub&&sub.userinfo);
 put($('#tiles'),[
  ['servers','Серверов в сети',`${up}<small> / ${S.nodes.length}</small>`,`<div class="bar"><i style="width:${S.nodes.length?up/S.nodes.length*100:0}%"></i></div>`],
  ['split','Режим',st.mode=='all'?'Всё через VPN':'Списки',`<div class="mut sm" style="margin-top:6px">${st.ru_blocked?'заблокированное → VPN':''}${st.ru_blocked&&st.ru_direct?' · ':''}${st.ru_direct?'РФ-сервисы напрямую':''}</div>`],
  ['db','Трафик подписки',ui.down!=null?fmtB(ui.down+(ui.up||0)):'—',`<div class="mut sm" style="margin-top:6px">${ui.total?'из '+fmtB(ui.total):'без лимита'}</div>`],
  ['log','Подписка до',ui.expire?new Date(ui.expire*1000).toLocaleDateString('ru-RU'):'—',ui.expire?`<div class="mut sm" style="margin-top:6px">осталось ${Math.max(0,Math.round((ui.expire*1000-Date.now())/864e5))} дн.</div>`:'']
 ].map(([i,k,v,x])=>`<div class="card stat"><div class="k">${ic(i,'width:15px;height:15px')}${k}</div><div class="v">${v}</div>${x}</div>`).join(''));
 // countries
 const ord=[...(st.order||[])];S.nodes.forEach(n=>{if(n.country&&!ord.includes(n.country))ord.push(n.country)});
 put($('#ctys'),ord.map((c,i)=>{const ns=S.nodes.filter(n=>n.country==c),ok=ns.filter(n=>(H[n.tag]||{}).ok),best=Math.min(...ok.map(n=>H[n.tag].rtt));
  return `<div class="cty">${flag(c,26)}<div class="n"><b>${esc(CN[c]||c)}</b> ${c==cc?'<span class="chip acc">сейчас</span>':''} ${(st.order||[]).includes(c)?`<span class="mut sm">#${i+1}</span>`:'<span class="mut sm">не в порядке</span>'}
  <div class="bar"><i style="width:${ns.length?ok.length/ns.length*100:0}%;background:${ok.length?'var(--ok)':'var(--bad)'}"></i></div></div><div class="r ${ok.length?'':'bad'}">${ok.length?best+' мс':'нет связи'}<div class="mut sm" style="font-weight:400">${ok.length}/${ns.length} в сети</div></div></div>`}).join('')||'<div class="empty">Нет серверов</div>');
 spark();
 // order chips
 if(!orderDirty)order=[...(st.order||[])];drawOrder();
 // country filter
 const cs=[...new Set(S.nodes.map(n=>n.country).filter(Boolean))];
 put($('#cfilter'),`<button class="fchip ${cflt?'':'on'}" data-cf="">Все</button>`+cs.map(c=>`<button class="fchip ${cflt==c?'on':''}" data-cf="${c}">${flag(c,16)}${esc(CN[c]||c)}</button>`).join(''));
 // nodes
 const q=qtxt.toLowerCase();
 const rows=S.nodes.filter(n=>(!cflt||n.country==cflt)&&(!q||(bare(n.label)+' '+(n.server||'')+' '+(CN[n.country]||'')).toLowerCase().includes(q))).map(n=>{const x=H[n.tag]||{},[k,t]=nodeState(n,x,st),isA=h.active==n.tag,dis=st.disabled&&st.disabled.includes(n.id);
  const meter=k=='ok'?`<div class="meter"><div class="bar"><i style="width:${Math.max(6,100-Math.min(94,x.rtt/7))}%;background:${rttColor(x.rtt)}"></i></div><span style="color:${rttColor(x.rtt)}">${t}</span></div>`:
   `<span class="${k=='bad'?'bad':'mut'} sm">${k=='bad'?'● ':''}${esc(t)}</span>`;
  return `<tr class="${isA?'act':''} ${dis?'off':''}"><td class="mut">${n.priority+1}</td><td><div class="srv"><button class="fb" data-cc="${n.id}" title="Сменить страну">${flag(n.country,24)}</button><div style="min-width:0"><div class="nm">${nice(n.label,16,n.country)} ${isA?`<span class="pill" style="padding:1px 8px;font-size:11px"><span class="dot live" style="width:6px;height:6px;${phase(2000)}"></span>сейчас</span>`:''}${n.pinned?' <span class="chip acc">закреплён</span>':''}</div><div class="h">${esc(n.server||'')}</div></div></div></td>
  <td class="hide-m"><span class="chip">${esc(PROTO[n.scheme]||n.scheme||'—')}</span></td><td>${meter}</td><td class="hide-m mut sm">${esc(n.source_name)}</td>
  <td><div class="acts"><button class="ib sm ${n.pinned?'on':''}" data-node="${n.pinned?'unpin':'pin'}" data-id="${n.id}" title="${n.pinned?'Открепить':'Закрепить в стране'}">${ic('pin')}</button><button class="ib sm ${dis?'':'on'}" data-node="${dis?'enable':'disable'}" data-id="${n.id}" title="${dis?'Включить':'Выключить'}">${ic('power')}</button></div></td></tr>`}).join('');
 put($('#nodes'),rows||'<tr><td colspan="6" class="empty">Ничего не найдено</td></tr>');
 // routing
 const seg=$('#mode');seg.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.m==st.mode));moveSeg();
 $('#rub').checked=!!st.ru_blocked;$('#rud').checked=!!st.ru_direct;
 const nv=(S.rules.vpn||[]).length,nd=(S.rules.direct||[]).length,L=st.mode=='list';
 const steps=[['Локальные сети','192.168.x, 10.x и т.п.',0,1],['Свои «напрямую»',nd+' записей',0,nd>0],['Свои «через VPN»',nv+' записей',1,nv>0],
  ['Заблокированные в РФ домены','runetfreedom ru-blocked',1,(L&&st.ru_blocked)||st.ru_direct],['Российские сервисы','кинотеатры, ТВ, банки, госуслуги, ВК, Яндекс',0,st.ru_direct],
  ['Заблокированные в РФ IP','подсети из ru-blocked',1,L&&st.ru_blocked],['Всё остальное',L?'не попало ни в один список':'режим «всё через VPN»',L?0:1,1]];
 put($('#pipe'),steps.map((s,i)=>`<div class="st ${s[3]?'':'off'}"><span class="num">${i+1}</span><div class="w"><b>${s[0]}</b><div>${esc(s[1])}</div></div><span class="chip ${s[2]?'acc':''}">${s[2]?'VPN':'Напрямую'}</span></div>`).join(''));
 for(const l of ['vpn','direct']){$('#n'+l).textContent=(S.rules[l]||[]).length;put($('#l'+l),(S.rules[l]||[]).map(v=>`<div class="ri"><span title="${esc(v)}">${esc(v)}</span><button class="ib sm" data-del="${l}" data-v="${esc(v)}" title="Удалить">${ic('x','width:15px;height:15px')}</button></div>`).join('')||'<div class="empty">Пусто</div>')}
 // sources
 put($('#sources'),S.sources.map(s=>{const u=parseUI(s.userinfo);return `<div class="srcc"><div class="ic">${ic(s.type=='sub'?'sources':'bolt')}</div><div class="w"><div class="row"><b>${esc(s.name)}</b><span class="chip ${s.enabled?'ok':''}">${s.enabled?'включён':'выключен'}</span><span class="chip">${s.type=='sub'?'подписка':'ссылка'}</span></div>
  <div class="kv">${s.fetched?`<div><span>Обновлена</span>${new Date(s.fetched*1000).toLocaleString('ru-RU')}</div>`:''}${u.down!=null?`<div><span>Трафик</span>${fmtB(u.down+(u.up||0))}${u.total?' из '+fmtB(u.total):''}</div>`:''}${u.expire?`<div><span>Действует до</span>${new Date(u.expire*1000).toLocaleDateString('ru-RU')}</div>`:''}<div><span>Серверов</span>${S.nodes.filter(n=>n.source==s.id).length}</div><div><span>ID</span>${esc(s.id)}</div></div>
  ${u.total?`<div class="bar" style="max-width:360px"><i style="width:${Math.min(100,(u.down+(u.up||0))/u.total*100)}%;background:var(--acc)"></i></div>`:''}</div>
  <div class="row"><button class="btn sm" data-src="${s.enabled?'off':'on'}" data-id="${s.id}">${ic('power')}${s.enabled?'Выключить':'Включить'}</button><button class="btn sm d" data-srcdel="${s.id}">${ic('trash')}Удалить</button></div></div>`}).join('')||'<div class="empty">Источников нет — добавьте подписку ниже.</div>');
 // log
 put($('#log'),(S.switches||[]).slice().reverse().slice(0,100).map(l=>{const t=String(l[3]||''),kind=/start/.test(t)?'acc':/fail|down|dead|kill|no /i.test(t)?'bad':'ok';
  const txt=t.replace(/^start\s*->\s*/,'Запуск → ').replace(/^back\s*->\s*/,'Возврат → ').replace(/kill switch \(no live server\)/g,'kill switch (нет живых серверов)').replace(/^(\S+) down\s*->/,'$1 недоступна →').replace(/->/g,'→');
  return `<div class="ev"><div class="ic ${kind}">${ic(kind=='acc'?'power':kind=='bad'?'err':'sw')}</div><div class="w">${nice(txt)}</div><div class="t">${esc(l[0])}</div></div>`}).join('')||'<div class="empty">Переключений пока не было</div>');
 nav();ago()}
function parseUI(s){const o={};String(s||'').split(';').forEach(p=>{const [k,v]=p.split('=').map(x=>x&&x.trim());if(k&&v&&!isNaN(+v))o[k]=+v});return{up:o.upload,down:o.download,total:o.total,expire:o.expire}}
function fmtB(b){if(b==null)return'—';const u=['Б','КБ','МБ','ГБ','ТБ','ПБ'];let i=0;while(b>=1024&&i<u.length-1){b/=1024;i++}return(b<10&&i?b.toFixed(2):b<100&&i?b.toFixed(1):Math.round(b))+' '+u[i]}
function ago(){const el=$('#ago');if(!el||!S||!S.health||!S.health.updated)return;const s=Math.max(0,Math.round(Date.now()/1000-S.health.updated));el.textContent='проверено '+(s<5?'только что':s<60?s+' с назад':Math.round(s/60)+' мин назад')}
setInterval(ago,1000);
function moveSeg(){const seg=$('#mode'),b=seg.querySelector('button.on'),i=seg.querySelector('i');if(!b||!b.offsetWidth)return;i.style.left=b.offsetLeft+'px';i.style.width=b.offsetWidth+'px'}
window.addEventListener('resize',moveSeg);
function spark(){const el=$('#spark');const W=600,Hh=120,pad=18;
 if(hist.length<2){put(el,`<text x="300" y="64" text-anchor="middle" style="font-size:12px">график появится через несколько секунд</text>`);return}
 const v=hist.map(p=>p.r),mx=Math.max(...v)*1.15,mn=Math.max(0,Math.min(...v)*.8),n=hist.length;
 const X=i=>pad+i*(W-pad*2)/(Math.max(n,30)-1),Y=r=>Hh-14-(r-mn)/(mx-mn||1)*(Hh-30);
 const pts=hist.map((p,i)=>X(i).toFixed(1)+','+Y(p.r).toFixed(1));
 const last=hist[n-1];
 put(el,`<defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--acc)" stop-opacity=".28"/><stop offset="1" stop-color="var(--acc)" stop-opacity="0"/></linearGradient></defs>
  <line class="gl" x1="0" x2="${W}" y1="${Y(mx/1.15)}" y2="${Y(mx/1.15)}"/><text x="4" y="${Y(mx/1.15)-3}">${Math.round(mx/1.15)} мс</text>
  <path class="a" d="M${pts[0]} L${pts.join(' L')} L${X(n-1)},${Hh} L${X(0)},${Hh}Z"/><path class="l" d="M${pts.join(' L')}"/>
  <circle cx="${X(n-1)}" cy="${Y(last.r)}" r="4" fill="var(--acc)"/><circle cx="${X(n-1)}" cy="${Y(last.r)}" r="4" fill="var(--acc)" opacity=".4"><animate attributeName="r" values="4;10" dur="1.6s" repeatCount="indefinite"/><animate attributeName="opacity" values=".4;0" dur="1.6s" repeatCount="indefinite"/></circle>`);
 $('#sparkinfo').textContent='среднее '+Math.round(v.reduce((a,b)=>a+b,0)/n)+' мс · '+n+' замеров'}
function drawOrder(){const el=$('#order');
 put(el,order.map((c,i)=>`${i?`<span class="arr">${'<svg viewBox="0 0 24 24" class="i"><path d="M9 6l6 6-6 6"/></svg>'}</span>`:''}<span class="oc" draggable="true" data-i="${i}"><span class="n">${i+1}</span>${flag(c,22)}<span>${esc(CN[c]||c)}</span><button class="x" data-rm="${i}" title="Убрать">${ic('x')}</button></span>`).join('')||'<span class="mut">Порядок пуст — добавьте страну</span>');
 $('#saveorder').classList.toggle('hid',!orderDirty);
 el.querySelectorAll('.oc').forEach(ch=>{ch.ondragstart=e=>{ch.classList.add('drag');e.dataTransfer.setData('text',ch.dataset.i)};ch.ondragend=()=>ch.classList.remove('drag');
  ch.ondragover=e=>{e.preventDefault();ch.classList.add('over')};ch.ondragleave=()=>ch.classList.remove('over');
  ch.ondrop=e=>{e.preventDefault();ch.classList.remove('over');const f=+e.dataTransfer.getData('text'),t=+ch.dataset.i;if(f===t)return;const [m]=order.splice(f,1);order.splice(t,0,m);orderDirty=true;el._h=null;drawOrder()}})}
/* country picker */
function picker(anchor,opts,onPick){document.querySelectorAll('.pop').forEach(p=>p.remove());const p=document.createElement('div');p.className='pop';
 const list=Object.keys(CN).filter(c=>!(opts.exclude||[]).includes(c)).sort((a,b)=>CN[a].localeCompare(CN[b],'ru'));
 p.innerHTML=`<input class="in" placeholder="Найти страну"><div class="opts">${opts.auto?`<button class="full" data-c="">${ic('auto','width:16px;height:16px')}<span>Автоматически (по флагу в имени)</span></button>`:''}${list.map(c=>`<button data-c="${c}" data-n="${esc(CN[c].toLowerCase()+' '+c.toLowerCase())}">${flag(c,20)}<span>${esc(CN[c])}</span></button>`).join('')}</div>`;
 document.body.appendChild(p);const r=anchor.getBoundingClientRect();p.style.top=Math.min(r.bottom+6,innerHeight-350)+'px';p.style.left=Math.max(8,Math.min(r.left,innerWidth-310))+'px';
 const inp=p.querySelector('input');inp.focus();inp.oninput=()=>{const q=inp.value.toLowerCase();p.querySelectorAll('button[data-n]').forEach(b=>b.hidden=!b.dataset.n.includes(q))};
 p.onclick=e=>{const b=e.target.closest('button');if(b){p.remove();onPick(b.dataset.c)}};
 setTimeout(()=>document.addEventListener('click',function h(e){if(!p.contains(e.target)){p.remove();document.removeEventListener('click',h)}}),0)}
$('#addcty').onclick=e=>{e.stopPropagation();picker($('#addcty'),{exclude:order},c=>{if(c&&!order.includes(c)){order.push(c);orderDirty=true;drawOrder()}})};
$('#saveorder').onclick=async()=>{if(await act({op:'set',key:'order',value:order.join(',')},'Порядок сохранён')){orderDirty=false;drawOrder()}};
async function load(){try{S=await api('/api/status');const h=S.health||{},H=hb(),a=H[h.active];
 if(a&&a.ok&&(!hist.length||hist[hist.length-1].u!==h.updated)){hist.push({u:h.updated,r:a.rtt});if(hist.length>120)hist.shift()}
 show(true);render()}catch(e){if(e.message!='login')toast('Статус: '+e.message,true)}}
document.addEventListener('click',async e=>{const t=e.target.closest('[data-op],[data-node],[data-del],[data-add],[data-src],[data-srcdel],[data-rm],[data-cc],[data-cf],[data-m]');if(!t)return;e.preventDefault();const d=t.dataset;
 if(d.op)act({op:d.op},{enable:'Авто-режим включён',refresh:'Подписки обновлены',geo_update:'Списки обновлены'}[d.op]);
 else if(d.node)act({op:'node',action:d.node,id:d.id},{pin:'Сервер закреплён',unpin:'Сервер откреплён',disable:'Сервер выключен',enable:'Сервер включён'}[d.node]);
 else if(d.del){const row=t.closest('.ri');if(row)row.classList.add('out');if(!await act({op:'rule',action:'del',list:d.del,value:d.v},'Удалено')&&row)row.classList.remove('out')}
 else if(d.add){const i=d.add=='vpn'?$('#rv'):$('#rd');if(i.value.trim()&&await act({op:'rule',action:'add',list:d.add,value:i.value.trim()},'Добавлено'))i.value=''}
 else if(d.src)act({op:'source',id:d.id,state:d.src});
 else if(d.srcdel){if(await ask('Удалить источник?','Серверы из него пропадут из списка.','Удалить',true))act({op:'del',id:d.srcdel},'Источник удалён')}
 else if(d.rm!==undefined){order.splice(+d.rm,1);orderDirty=true;drawOrder()}
 else if(d.cc!==undefined&&d.cc){e.stopPropagation();const n=S.nodes.find(x=>x.id==d.cc);picker(t,{auto:true},c=>act({op:'node',action:'country',id:d.cc,cc:c},c?'Страна: '+(CN[c]||c):'Страна по имени сервера'))}
 else if(d.cf!==undefined){cflt=d.cf;render()}
 else if(d.m){if(d.m!==S.settings.mode)act({op:'set',key:'mode',value:d.m},d.m=='all'?'Всё через VPN':'Через VPN только списки')}});
['rv','rd'].forEach(id=>$('#'+id).onkeydown=e=>{if(e.key=='Enter')document.querySelector(`[data-add="${id=='rv'?'vpn':'direct'}"]`).click()});
$('#q').oninput=e=>{qtxt=e.target.value;render()};
$('#rub').onchange=e=>act({op:'set',key:'ru_blocked',value:e.target.checked?'on':'off'},e.target.checked?'Списки блокировок включены':'Списки блокировок выключены').then(ok=>{if(!ok)e.target.checked=!e.target.checked});
$('#rud').onchange=e=>act({op:'set',key:'ru_direct',value:e.target.checked?'on':'off'},e.target.checked?'Российские сервисы — напрямую':'Российские сервисы — по общим правилам').then(ok=>{if(!ok)e.target.checked=!e.target.checked});
$('#addsub').onclick=async()=>{if(await act({op:'add_sub',name:$('#sn').value.trim(),url:$('#su').value.trim(),ua:$('#sua').value.trim()},'Подписка добавлена'))$('#su').value=''};
$('#addlink').onclick=async()=>{if(await act({op:'add_link',name:$('#ln').value.trim(),link:$('#ll').value.trim()},'Ссылка добавлена'))$('#ll').value=''};
$('#sethw').onclick=()=>act({op:'hwid',value:$('#hw').value.trim()},'HWID сохранён');
$('#logout').onclick=async()=>{await api('/api/logout',{x:1}).catch(()=>{});show(false)};
$('#lf').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;prog(true);
 try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Panel':'1'},body:JSON.stringify({password:$('#pw').value})});const j=await r.json();
  if(r.ok){$('#pw').value='';await load()}else{toast(j.error=='wrong password'?'Неверный пароль':j.error&&j.error.startsWith('too many')?'Слишком много попыток, подождите':j.error||'Ошибка',true);const c=$('#lcard');c.classList.remove('shake');void c.offsetWidth;c.classList.add('shake');$('#pw').select()}}
 catch(e){toast(e.message,true)}finally{b.disabled=false;prog(false)}};
nav();load();setInterval(()=>{if(!$('#app').hidden&&!busy&&!document.hidden)load()},5000);
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="proxy-unifi Auto mode LAN panel")
    ap.add_argument("--hash-password", action="store_true",
                    help="read a password on stdin, print its hash, exit")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5200)
    ap.add_argument("--password-file", default="")
    ap.add_argument("--cli", default="/data/proxy-unifi/bin/proxy-unifi")
    args = ap.parse_args()
    if args.hash_password:
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < MIN_PASSWORD:
            sys.stderr.write("panel: password must have at least %d characters\n" % MIN_PASSWORD)
            sys.exit(1)
        sys.stdout.write(hash_password(pw))
        return
    ip = ipaddress.ip_address(args.listen)
    if not (ip.is_private or ip.is_loopback):
        sys.stderr.write("panel: refusing to listen on a public address\n")
        sys.exit(2)
    if not os.path.isfile(args.password_file):
        sys.stderr.write("panel: password file is missing\n")
        sys.exit(2)
    srv = ThreadingHTTPServer((args.listen, args.port), Panel)
    srv.daemon_threads = True
    srv.cli = args.cli
    srv.password_file = args.password_file
    srv.serve_forever()


if __name__ == "__main__":
    main()
