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
                if g[0] >= 30:
                    g[0], g[1] = 0, now + 300
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
<title>proxy-unifi Auto</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2329;--mut:#69737d;--line:#e2e6ea;--acc:#2563eb;--ok:#15803d;--bad:#b91c1c;--warn:#b45309}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1f25;--fg:#e6e9ec;--mut:#98a2ad;--line:#2b323a;--acc:#60a5fa;--ok:#4ade80;--bad:#f87171;--warn:#fbbf24}}
[hidden]{display:none!important}a{color:var(--acc)}.chip a{text-decoration:none;padding:0 3px}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:16px}h1{font-size:20px;margin:4px 0 16px}h2{font-size:16px;margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin-bottom:14px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.mut{color:var(--mut)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
button,input,select{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:7px;padding:6px 10px}
button{cursor:pointer}button.p{background:var(--acc);border-color:var(--acc);color:#fff}button.s{padding:3px 8px;font-size:13px}
input{min-width:0}table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:6px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}
th{color:var(--mut);font-weight:500}.big{font-size:18px;font-weight:600}.scroll{overflow-x:auto}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{border:1px solid var(--line);border-radius:999px;padding:4px 10px;cursor:grab;user-select:none;background:var(--bg)}
.chip.drag{opacity:.4}.rules{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media (max-width:700px){.rules{grid-template-columns:1fr}}
.list{max-height:240px;overflow:auto;border:1px solid var(--line);border-radius:7px;margin-top:8px}.list div{display:flex;justify-content:space-between;padding:4px 8px;border-bottom:1px solid var(--line)}
#msg{position:fixed;left:16px;right:16px;bottom:16px;max-width:600px;margin:auto;padding:10px 14px;border-radius:8px;background:var(--fg);color:var(--bg);display:none}
#login{max-width:340px;margin:12vh auto}
</style></head><body>
<div id="login" class="card" hidden><h2>proxy-unifi</h2><form id="lf" class="row"><input id="pw" type="password" placeholder="Пароль" autocomplete="current-password" style="flex:1"><button class="p">Войти</button></form></div>
<main id="app" hidden>
<div class="row" style="justify-content:space-between"><h1>Авто-режим VPN</h1><button class="s" id="logout">Выйти</button></div>
<div class="card"><div class="mut">Сейчас трафик VPN идёт через</div><div class="big" id="active">…</div><div class="mut" id="sub"></div>
<div class="row" style="margin-top:8px" id="enablebox" hidden><span class="warn">Авто-режим выключен.</span><button class="p" data-op="enable">Включить</button></div></div>

<div class="card"><h2>Режим</h2>
<div class="row"><label><input type="radio" name="mode" value="list"> Через VPN только списки (остальное напрямую)</label></div>
<div class="row"><label><input type="radio" name="mode" value="all"> Всё через VPN, кроме списка «напрямую»</label></div>
<div class="row" style="margin-top:8px"><label><input type="checkbox" id="rub"> Готовый список «заблокировано в РФ» (только для первого режима)</label><button class="s" data-op="geo_update">Обновить список</button></div><div class="row" style="margin-top:8px"><label><input type="checkbox" id="rud"> Российские сервисы всегда напрямую (онлайн-кинотеатры, ТВ, банки, Госуслуги, ВК, Яндекс)</label></div></div>

<div class="card"><h2>Порядок стран</h2><div class="mut" style="margin-bottom:8px">Перетащите или двигайте стрелками. Первая живая страна получает трафик; внутри страны — самый быстрый сервер (или закреплённый).</div>
<div class="chips" id="order"></div>
<div class="row" style="margin-top:8px"><input id="addcc" placeholder="Код, напр. SE" maxlength="2" style="width:120px"><button class="s" id="addccb">Добавить</button><button class="p s" id="saveorder">Сохранить порядок</button></div></div>

<div class="card"><h2>Серверы</h2><div class="scroll"><table><thead><tr><th>#</th><th>Страна</th><th>Сервер</th><th>Источник</th><th>Состояние</th><th></th></tr></thead><tbody id="nodes"></tbody></table></div></div>

<div class="card"><h2>Свои домены и IP</h2><div class="rules">
<div><b>Через VPN</b><div class="row" style="margin-top:6px"><input id="rv" placeholder="example.com или 1.2.3.0/24" style="flex:1"><button class="s" data-add="vpn">Добавить</button></div><div class="list" id="lvpn"></div></div>
<div><b>Напрямую</b><div class="row" style="margin-top:6px"><input id="rd" placeholder="example.ru или 5.6.7.8" style="flex:1"><button class="s" data-add="direct">Добавить</button></div><div class="list" id="ldirect"></div></div>
</div></div>

<div class="card"><h2>Источники</h2><div class="scroll"><table><tbody id="sources"></tbody></table></div>
<div class="row" style="margin-top:10px"><button class="s" data-op="refresh">Обновить подписки</button></div>
<h2 style="margin-top:14px">Добавить подписку</h2><div class="row"><input id="sn" placeholder="Название" style="width:160px"><input id="su" placeholder="https://…" style="flex:1"><input id="sua" placeholder="User-Agent (необязательно)" style="width:200px"><button class="p s" id="addsub">Добавить</button></div>
<h2 style="margin-top:14px">Добавить ссылку</h2><div class="row"><input id="ln" placeholder="Название" style="width:160px"><input id="ll" placeholder="vless://… hysteria2://… trojan://…" style="flex:1"><button class="p s" id="addlink">Добавить</button></div>
<h2 style="margin-top:14px">HWID</h2><div class="row"><input id="hw" placeholder="UUID устройства" style="flex:1;max-width:380px"><button class="s" id="sethw">Сохранить</button></div></div>

<div class="card"><h2>Переключения</h2><div class="scroll"><table><tbody id="log"></tbody></table></div></div>
</main><div id="msg"></div>
<script>
const $=s=>document.querySelector(s);let S=null,order=[],busy=false;
function esc(t){return String(t??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function toast(t,bad){const m=$('#msg');m.textContent=t;m.style.display='block';m.style.background=bad?'var(--bad)':'';clearTimeout(m._t);m._t=setTimeout(()=>m.style.display='none',bad?7000:2500)}
async function api(path,body){const r=await fetch(path,{method:body?'POST':'GET',headers:body?{'Content-Type':'application/json','X-Panel':'1'}:{},body:body?JSON.stringify(body):undefined,credentials:'same-origin'});
 if(r.status==401){show(false);throw new Error('login')}const j=await r.json().catch(()=>({}));if(!r.ok&&!('ok' in j))throw new Error(j.error||r.status);return j}
async function act(a,okText){if(busy)return;busy=true;document.body.style.cursor='progress';try{const j=await api('/api/action',a);if(j.ok){toast(okText||'Готово');await load()}else toast(j.message||'Ошибка',true)}catch(e){if(e.message!='login')toast(e.message,true)}finally{busy=false;document.body.style.cursor=''}}
function show(app){$('#app').hidden=!app;$('#login').hidden=app}
const flag=cc=>cc&&cc.length==2?String.fromCodePoint(...[...cc].map(c=>0x1F1A5+c.charCodeAt(0))):'🏳';
function render(){const h=S.health||{},st=S.settings||{};
 $('#active').textContent=h.killswitch?'Нет живых серверов — VPN-трафик остановлен':(h.active_label||'—');$('#active').className='big '+(h.killswitch?'bad':'');
 $('#sub').textContent=h.updated?('проверено '+new Date(h.updated*1000).toLocaleTimeString()):'';$('#enablebox').hidden=S.auto_active;
 document.querySelectorAll('input[name=mode]').forEach(r=>r.checked=r.value==st.mode);$('#rub').checked=!!st.ru_blocked;$('#rud').checked=!!st.ru_direct;
 if(!$('#order')._dirty){order=[...(st.order||[])];drawOrder()}
 const hb={};(h.nodes||[]).forEach(n=>hb[n.tag]=n);
 $('#nodes').innerHTML=S.nodes.map(n=>{const x=hb[n.tag]||{};let s;if(!n.usable)s='<span class="mut">'+esc(n.reason)+'</span>';else if(x.ok)s='<span class="ok">● '+x.rtt+' мс</span>';else if(x.last_probe)s='<span class="bad">● нет ответа</span>';else s='<span class="mut">проверка…</span>';
  const act_=h.active==n.tag?' <b>◀ сейчас</b>':'';const dis=st.disabled&&st.disabled.includes(n.id);
  return `<tr><td>${n.priority+1}</td><td>${flag(n.country)} <a href="#" data-cc="${n.id}" title="Изменить страну">${esc(n.country||'??')}</a></td><td>${esc(n.label)}${act_}</td><td class="mut">${esc(n.source_name)}</td><td>${s}</td><td class="row">
  <button class="s" data-node="${n.pinned?'unpin':'pin'}" data-id="${n.id}">${n.pinned?'Открепить':'Закрепить'}</button>
  <button class="s" data-node="${dis?'enable':'disable'}" data-id="${n.id}">${dis?'Включить':'Выключить'}</button></td></tr>`}).join('');
 for(const l of ['vpn','direct'])$('#l'+l).innerHTML=(S.rules[l]||[]).map(v=>`<div><span>${esc(v)}</span><button class="s" data-del="${l}" data-v="${esc(v)}">✕</button></div>`).join('')||'<div class="mut">пусто</div>';
 $('#sources').innerHTML=S.sources.map(s=>`<tr><td><b>${esc(s.name)}</b> <span class="mut">${s.type=='sub'?'подписка':'ссылка'} · ${esc(s.id)}</span>${s.userinfo?'<div class="mut">'+esc(s.userinfo)+'</div>':''}</td><td class="mut">${s.fetched?new Date(s.fetched*1000).toLocaleString():''}</td><td class="row">
  <button class="s" data-src="${s.enabled?'off':'on'}" data-id="${s.id}">${s.enabled?'Выключить':'Включить'}</button><button class="s" data-srcdel="${s.id}">Удалить</button></td></tr>`).join('')||'<tr><td class="mut">Источников нет</td></tr>';
 $('#log').innerHTML=(S.switches||[]).slice().reverse().map(l=>`<tr><td class="mut">${esc(l[0])}</td><td>${esc(l[3]||'')}</td></tr>`).join('')||'<tr><td class="mut">Пока не было</td></tr>'}
function drawOrder(){const el=$('#order');el.innerHTML=order.map((c,i)=>`<span class="chip" draggable="true" data-i="${i}">${i?`<a href="#" data-mv="${i}" data-d="-1" title="Раньше">◀</a>`:''}${i+1}. ${flag(c)} ${esc(c)}${i<order.length-1?`<a href="#" data-mv="${i}" data-d="1" title="Позже">▶</a>`:''} <a href="#" data-rm="${i}" title="Убрать">✕</a></span>`).join('');
 el.querySelectorAll('.chip').forEach(ch=>{ch.ondragstart=e=>{ch.classList.add('drag');e.dataTransfer.setData('text',ch.dataset.i)};ch.ondragend=()=>ch.classList.remove('drag');
 ch.ondragover=e=>e.preventDefault();ch.ondrop=e=>{e.preventDefault();const f=+e.dataTransfer.getData('text'),t=+ch.dataset.i;const [m]=order.splice(f,1);order.splice(t,0,m);el._dirty=true;drawOrder()}})}
async function load(){try{S=await api('/api/status');show(true);render()}catch(e){if(e.message!='login')toast('Статус: '+e.message,true)}}
document.addEventListener('click',e=>{const t=e.target.closest('[data-op],[data-node],[data-del],[data-add],[data-src],[data-srcdel],[data-rm],[data-mv],[data-cc]');if(!t)return;e.preventDefault();const d=t.dataset;
 if(d.op)act({op:d.op},d.op=='enable'?'Авто-режим включён':'Готово');
 else if(d.node)act({op:'node',action:d.node,id:d.id});
 else if(d.del)act({op:'rule',action:'del',list:d.del,value:d.v});
 else if(d.add){const i=d.add=='vpn'?$('#rv'):$('#rd');if(i.value.trim())act({op:'rule',action:'add',list:d.add,value:i.value.trim()}).then(()=>i.value='')}
 else if(d.src)act({op:'source',id:d.id,state:d.src});
 else if(d.srcdel){if(confirm('Удалить источник?'))act({op:'del',id:d.srcdel})}
 else if(d.mv!==undefined){const i=+d.mv,j=i+(+d.d);[order[i],order[j]]=[order[j],order[i]];$('#order')._dirty=true;drawOrder()}
 else if(d.rm!==undefined){order.splice(+d.rm,1);$('#order')._dirty=true;drawOrder()}
 else if(d.cc){const v=prompt('Код страны (DE, PL, …), пусто — по флагу в имени');if(v!==null)act({op:'node',action:'country',id:d.cc,cc:v.trim().toUpperCase()})}});
document.querySelectorAll('input[name=mode]').forEach(r=>r.onchange=()=>act({op:'set',key:'mode',value:r.value}));
$('#rub').onchange=e=>act({op:'set',key:'ru_blocked',value:e.target.checked?'on':'off'});
$('#rud').onchange=e=>act({op:'set',key:'ru_direct',value:e.target.checked?'on':'off'});
$('#addccb').onclick=()=>{const v=$('#addcc').value.trim().toUpperCase();if(/^[A-Z]{2}$/.test(v)&&!order.includes(v)){order.push(v);$('#order')._dirty=true;drawOrder();$('#addcc').value=''}};
$('#saveorder').onclick=()=>act({op:'set',key:'order',value:order.join(',')},'Порядок сохранён').then(()=>$('#order')._dirty=false);
$('#addsub').onclick=()=>act({op:'add_sub',name:$('#sn').value.trim(),url:$('#su').value.trim(),ua:$('#sua').value.trim()},'Подписка добавлена').then(()=>{$('#su').value=''});
$('#addlink').onclick=()=>act({op:'add_link',name:$('#ln').value.trim(),link:$('#ll').value.trim()},'Ссылка добавлена').then(()=>{$('#ll').value=''});
$('#sethw').onclick=()=>act({op:'hwid',value:$('#hw').value.trim()},'HWID сохранён');
$('#logout').onclick=async()=>{await api('/api/logout',{x:1}).catch(()=>{});show(false)};
$('#lf').onsubmit=async e=>{e.preventDefault();try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-Panel':'1'},body:JSON.stringify({password:$('#pw').value})});const j=await r.json();if(r.ok){$('#pw').value='';load()}else toast(j.error||'Ошибка',true)}catch(e){toast(e.message,true)}};
load();setInterval(()=>{if(!$('#app').hidden&&!busy)load()},5000);
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
        if len(pw) < 8:
            sys.stderr.write("panel: password must have at least 8 characters\n")
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
