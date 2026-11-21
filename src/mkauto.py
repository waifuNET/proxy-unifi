#!/usr/bin/env python3
"""
mkauto.py - the "Auto" connection mode: every node of every source in one
xray-core, a country-priority failover picker, and traffic split by rules.

Topology (xray -confdir, like the JSON pool mode):

  01-auto.json   outbounds n-<id> for each usable node + direct + block,
                 balancer "vpn" (members n-*), routing rules (mode + lists),
                 a loopback API (RoutingService, for `xray api bo`) and a
                 loopback SOCKS "probe" inbound whose user name selects the node
                 to test, so health checks take exactly the path real traffic does.
  99-overlay.json the proxy-unifi WireGuard inbound (mkjson.build_overlay).
  self-hosts.txt "host port" per line: loopback dokodemo-door inbounds self-N
                 that carry the router's own HTTPS to geo-blocked hosts
                 (Ubiquiti updates) through the balancer; `proxy _self-route`
                 points the hosts there with /etc/hosts + an OUTPUT redirect.
  nodes.json     tag -> node facts and priority, read by picker.py and the panel.

The picker (picker.py) chooses the active node with `xray api bo`; until it
does, the balancer picks randomly among the members.

Inputs are files under the proxy-unifi data root:
  sources/<id>.json         {"id","type":"sub"|"link","name","enabled"}
  sources/<id>.catalog.json mksub catalog (type sub), or
  sources/<id>.link         one share link (type link)
  auto.json                 settings (see DEFAULTS)
  rules/vpn.txt, rules/direct.txt   user entries, one per line

Subcommands:
  build   --root R --out-dir O --geo-dir G --listen --port --address --mtu
          --keepalive --loglevel --secret-key-file --peer-pubkey-file
          --api-port N --probe-port N --probe-pass-file F [--self-port N]
  rule    --value V                -> normalized entry or error (exit 1)
  settings --root R [--set k=v ...] -> print effective settings JSON
  nodes   --root R                 -> every node with usability + reason (JSON)

Stdlib only (Python 3.9+).
"""

import argparse
import contextlib
import io
import ipaddress
import json
import os
import re
import sys

from proxylib import die, safe_port, valid_host
import mkjson
import mksingbox
import mksub
import mkxray

DEFAULTS = {
    "mode": "list",            # list: only listed traffic uses VPN; all: everything but "direct"
    "order": ["DE", "PL", "FI", "NL"],
    "ru_blocked": True,        # runetfreedom ru-blocked lists (domains + IPs) count as "VPN"
    "ru_direct": True,         # big Russian services (TV, banks, gov, VK, Yandex...) stay direct
    "disabled": [],            # node ids never used
    "pinned": [],              # node ids preferred first inside their country
    "country": {},             # node id -> country code override
    # The router's own HTTPS to these hosts goes through the VPN (geo-blocked
    # Ubiquiti firmware/app downloads); see self-hosts.txt and `_self-route`.
    "self_hosts": ["fw-download.ubnt.com", "apt.artifacts.ui.com"],
}
MAX_SELF_HOSTS = 32
MODES = ("list", "all")
MAX_RULES = 5000
MAX_NODES = 256
SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
CC_RE = re.compile(r"^[A-Z]{2}$")
NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
# Never tunnelled: private, loopback, link-local, CGNAT and multicast ranges.
# Listed instead of geoip:private so Auto does not depend on geoip.dat.
PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
                "fc00::/7", "fe80::/10", "::1/128", "ff00::/8"]
RU_GEOSITE = "ru-geosite.dat"
RU_GEOIP = "ru-geoip.dat"
# ru_direct: Russian services that refuse foreign IPs or are slow through the
# VPN. Matched after the ru-blocked domain list (a blocked domain still uses
# the VPN) but before the ru-blocked IP list, whose wide CDN ranges otherwise
# catch Russian video CDNs. category-ru is deliberately absent: it lists whole
# TLDs and ~20k blocked sites.
RU_DIRECT_CATEGORIES = [
    "ru-available-only-inside", "category-gov-ru", "category-bank-ru",
    "category-entertainment-ru", "category-media-ru", "category-ecommerce-ru",
    "category-retail-ru", "vk", "yandex", "mailru-group", "mts-ru", "tbank-ru", "rutube",
]
# Online cinemas, TV channels and IPTV apps the categories miss (smart TVs).
RU_DIRECT_DOMAINS = [
    "kinopoisk.ru", "ivi.ru", "ivi.tv", "okko.tv", "okko.sport", "playfamily.ru",
    "wink.ru", "rt.ru", "ngenix.net", "start.ru", "premier.one", "kion.ru",
    "more.tv", "amediateka.ru", "1tv.ru", "1tv.com", "smotrim.ru", "vgtrk.com",
    "vgtrk.ru", "ntv.ru", "ctc.ru", "ctc-media.ru", "videomore.ru", "tnt-online.ru",
    "gpm.ru", "gpmd.ru", "matchtv.ru", "friday.ru", "tv3.ru", "ren.tv", "5-tv.ru",
    "smotreshka.tv", "lfstrm.tv", "24h.tv", "24htv.platform24.tv", "peers.tv",
    "limehd.tv", "megafon.tv", "beeline.tv", "tricolor.tv", "ntvplus.ru",
    "movix.ru", "dom.ru", "zvuk.com", "sber.ru", "sberbank.ru", "sberdevices.ru",
    "salute.ru", "kinoteatr.ru", "tvzavr.ru", "liveinternet.ru",
]


# ---------------------------------------------------------------- rules

def normalize_rule(value):
    """One user rule line -> ("domain", "example.com") or ("ip", "1.2.3.0/24").

    Accepted: a domain (matches it and every subdomain), "*.domain" (same),
    an IPv4/IPv6 address or CIDR. Cyrillic domains are IDNA-encoded."""
    v = (value or "").strip().lower()
    if not v or len(v) > 253:
        die("empty or too long entry")
    if v.startswith("*."):
        v = v[2:]
    v = v.rstrip(".")
    try:
        net = ipaddress.ip_network(v, strict=False)
        return "ip", str(net)
    except ValueError:
        pass
    try:
        ascii_name = v.encode("idna").decode("ascii")
    except UnicodeError:
        die("not a domain or IP: %s" % mksub.clean(value, 60))
    labels = ascii_name.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels) \
            or labels[-1].isdigit():
        die("not a domain or IP: %s" % mksub.clean(value, 60))
    return "domain", ascii_name


def read_rules(path):
    """[(kind, value)] from a rules file; bad lines are an error (the CLI and
    panel validate before writing, so a bad line means tampering)."""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        out.append(normalize_rule(line))
        if len(out) > MAX_RULES:
            die("too many rules in %s" % os.path.basename(path))
    return out


def _rule_fields(rules):
    domains = ["domain:" + v for k, v in rules if k == "domain"]
    ips = [v for k, v in rules if k == "ip"]
    return domains, ips


# ---------------------------------------------------------------- settings

def load_settings(root):
    s = json.loads(json.dumps(DEFAULTS))
    path = os.path.join(root, "auto.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        raw = {}
    except ValueError:
        die("auto.json is not valid JSON")
    if not isinstance(raw, dict):
        die("auto.json must be an object")
    s.update({k: raw[k] for k in DEFAULTS if k in raw})
    return validate_settings(s)


def _valid_hostname(h):
    if not isinstance(h, str) or not 1 <= len(h) <= 253 or "." not in h:
        return False
    return all(_LABEL_RE.match(x) for x in h.split("."))


def validate_settings(s):
    if not isinstance(s["self_hosts"], list) or len(s["self_hosts"]) > MAX_SELF_HOSTS \
            or not all(_valid_hostname(h) for h in s["self_hosts"]) \
            or len(set(s["self_hosts"])) != len(s["self_hosts"]):
        die("self_hosts must be a list of distinct host names (at most %d)" % MAX_SELF_HOSTS)
    if s["mode"] not in MODES:
        die("mode must be one of: %s" % ", ".join(MODES))
    if not isinstance(s["order"], list) or len(s["order"]) > 64 \
            or not all(isinstance(c, str) and CC_RE.match(c) for c in s["order"]) \
            or len(set(s["order"])) != len(s["order"]):
        die("order must be a list of distinct two-letter country codes")
    for key in ("ru_blocked", "ru_direct"):
        if not isinstance(s[key], bool):
            die("%s must be true/false" % key)
    for key in ("disabled", "pinned"):
        if not isinstance(s[key], list) or len(s[key]) > 4096 \
                or not all(isinstance(x, str) and NODE_ID_RE.match(x) for x in s[key]):
            die("%s must be a list of node ids" % key)
    if not isinstance(s["country"], dict) or len(s["country"]) > 4096 \
            or not all(NODE_ID_RE.match(k) and isinstance(v, str) and CC_RE.match(v)
                       for k, v in s["country"].items()):
        die("country overrides must map node ids to two-letter codes")
    return s


def apply_setting(s, key, value):
    """CLI/panel setter: key=value with a JSON or plain value."""
    if key not in DEFAULTS:
        die("unknown setting '%s'" % key)
    if key == "mode":
        s[key] = value
    elif key == "order":
        s[key] = [c.strip().upper() for c in value.split(",") if c.strip()]
    elif key == "self_hosts":
        if value.lstrip().startswith("["):
            try:
                s[key] = json.loads(value)
            except ValueError:
                die("self_hosts takes a comma list or JSON")
        else:
            s[key] = [h.strip().lower() for h in value.split(",") if h.strip()]
    elif key in ("ru_blocked", "ru_direct"):
        if value not in ("on", "off", "true", "false", "1", "0"):
            die("%s takes on/off" % key)
        s[key] = value in ("on", "true", "1")
    else:
        try:
            s[key] = json.loads(value)
        except ValueError:
            die("%s takes JSON" % key)
    return validate_settings(s)


# ---------------------------------------------------------------- sources/nodes

def _quiet(fn, *a):
    """Run a generator parser; return (result, '') or (None, its error)."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            return fn(*a), ""
    except SystemExit:
        return None, err.getvalue().strip().split("error: ", 1)[-1] or "not supported"


def hysteria2_outbound(link):
    """hysteria2:// -> xray-core hysteria (v2) outbound. The link is validated
    by the sing-box parser (the same checks as the single-link path); options
    xray cannot reproduce faithfully are refused instead of dropped."""
    sb, host, port = mksingbox.parse_hysteria2(link)
    if sb.get("server_ports") or sb.get("hop_interval"):
        die("port hopping is not supported in Auto mode")
    if sb.get("obfs"):
        die("hysteria2 obfs is not supported in Auto mode")
    if sb.get("up_mbps") or sb.get("down_mbps"):
        die("hysteria2 bandwidth hints are not supported in Auto mode")
    tls = {"serverName": sb["tls"]["server_name"],
           "alpn": sb["tls"].get("alpn") or ["h3"]}
    ob = {"tag": "proxy", "protocol": "hysteria",
          "settings": {"version": 2, "address": host, "port": port},
          "streamSettings": {"network": "hysteria", "security": "tls",
                             "tlsSettings": tls,
                             "hysteriaSettings": {"version": 2, "auth": sb["password"]}}}
    return ob, host, port


def outbound_for_link(link):
    """(outbound, '') for a link xray can carry in the pool, else (None, reason)."""
    scheme = link.split("://", 1)[0].lower()
    if scheme in ("hysteria2", "hy2"):
        res, why = _quiet(hysteria2_outbound, link)
    elif scheme in ("vless", "vmess", "trojan"):
        res, why = _quiet(mkxray.parse_link, link)
    elif scheme == "ss":
        node = mksub.node_from_link(link)
        if not node or node.get("engine") != "xray":
            return None, "this Shadowsocks variant needs sing-box (not in Auto mode)"
        res, why = _quiet(mkxray.parse_link, link)
    else:
        return None, "%s is not supported in Auto mode" % scheme
    return (res[0] if res else None), why


def read_sources(root):
    sdir = os.path.join(root, "sources")
    try:
        names = sorted(os.listdir(sdir))
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        if not name.endswith(".json") or name.endswith(".catalog.json"):
            continue
        sid = name[:-5]
        if not SOURCE_ID_RE.match(sid):
            continue
        try:
            with open(os.path.join(sdir, name), "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            die("source %s is unreadable" % sid)
        if not isinstance(meta, dict) or meta.get("type") not in ("sub", "link"):
            die("source %s has an unknown type" % sid)
        meta["id"] = sid
        meta["enabled"] = meta.get("enabled", True) is not False
        meta["name"] = mksub.clean(str(meta.get("name") or sid), 60)
        out.append(meta)
    return out


def _source_links(root, src):
    """[(label, link)] of one source."""
    sdir = os.path.join(root, "sources")
    if src["type"] == "link":
        try:
            with open(os.path.join(sdir, src["id"] + ".link"), "r", encoding="utf-8") as fh:
                link = fh.read().strip()
        except OSError:
            return []
        return [("", link)] if link else []
    try:
        with open(os.path.join(sdir, src["id"] + ".catalog.json"), "r", encoding="utf-8") as fh:
            cat = json.load(fh)
    except (OSError, ValueError):
        return []
    rows = cat.get("nodes", []) if isinstance(cat, dict) else []
    return [(r.get("label", ""), r.get("link", "")) for r in rows
            if isinstance(r, dict) and r.get("link")]


def collect_nodes(root, settings):
    """Every node of every source, with usability, country and priority."""
    nodes = []
    seen = set()
    for src in read_sources(root):
        for label, link in _source_links(root, src):
            meta = mksub.node_from_link(link)
            if meta is None:
                continue
            nid = meta["id"]
            if nid in seen:            # the same server listed by two sources
                continue
            seen.add(nid)
            label = meta.get("label") or label or meta.get("server", "")
            if src["type"] == "link" and src.get("name"):
                label = label or src["name"]
            cc = settings["country"].get(nid) or meta.get("country") \
                or mksub.country_from_label(src.get("name", ""))
            node = {"id": nid, "tag": "n-" + nid[:12], "label": mksub.clean(label, 80),
                    "server": meta.get("server", ""), "scheme": meta.get("scheme", ""),
                    "source": src["id"], "source_name": src["name"],
                    "country": cc, "usable": False, "reason": "", "_link": link}
            if not src["enabled"]:
                node["reason"] = "source is turned off"
            elif nid in settings["disabled"]:
                node["reason"] = "turned off"
            elif not meta.get("recognized", True):
                node["reason"] = meta.get("reason") or "not supported"
            else:
                ob, why = outbound_for_link(link)
                if ob is None:
                    node["reason"] = why
                else:
                    ob["tag"] = node["tag"]
                    node["_outbound"] = ob
                    node["usable"] = True
            nodes.append(node)
    order = settings["order"]
    pinned = settings["pinned"]

    def rank(n):
        c = n["country"]
        crank = order.index(c) if c in order else len(order) + (0 if c else 1)
        return (crank, c, 0 if n["id"] in pinned else 1)
    for i, n in enumerate(sorted(nodes, key=rank)):
        n["priority"] = i
        n["pinned"] = n["id"] in pinned
    nodes.sort(key=lambda n: n["priority"])
    usable = [n for n in nodes if n["usable"]]
    if len(usable) > MAX_NODES:
        for n in usable[MAX_NODES:]:
            n["usable"] = False
            n["reason"] = "more than %d nodes" % MAX_NODES
    return nodes


def public_nodes(nodes):
    return [{k: v for k, v in n.items() if not k.startswith("_")} for n in nodes]


# ---------------------------------------------------------------- config

def build_config(args, settings, nodes, probe_pass):
    usable = [n for n in nodes if n["usable"]]
    if not usable:
        die("no usable node in any source")
    tags = [n["tag"] for n in usable]
    vpn_rules = read_rules(os.path.join(args.root, "rules", "vpn.txt"))
    direct_rules = read_rules(os.path.join(args.root, "rules", "direct.txt"))
    rules = [
        {"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"},
    ]
    # health probes: SOCKS user name = node tag
    for t in tags:
        rules.append({"type": "field", "inboundTag": ["probe-in"], "user": [t], "outboundTag": t})
    rules.append({"type": "field", "inboundTag": ["probe-in"], "outboundTag": "block"})
    self_tags = ["self-%d" % i for i in range(len(settings["self_hosts"]))]
    if self_tags:
        rules.append({"type": "field", "inboundTag": self_tags, "balancerTag": "vpn"})
    rules.append({"type": "field", "inboundTag": ["wg-in"], "ip": PRIVATE_NETS,
                  "outboundTag": "direct"})
    d_dom, d_ip = _rule_fields(direct_rules)
    v_dom, v_ip = _rule_fields(vpn_rules)
    if d_dom:
        rules.append({"type": "field", "inboundTag": ["wg-in"], "domain": d_dom, "outboundTag": "direct"})
    if d_ip:
        rules.append({"type": "field", "inboundTag": ["wg-in"], "ip": d_ip, "outboundTag": "direct"})
    if v_dom:
        rules.append({"type": "field", "inboundTag": ["wg-in"], "domain": v_dom, "balancerTag": "vpn"})
    if v_ip:
        rules.append({"type": "field", "inboundTag": ["wg-in"], "ip": v_ip, "balancerTag": "vpn"})
    use_ru_blocked = settings["mode"] == "list" and settings["ru_blocked"]
    need = ([RU_GEOSITE, RU_GEOIP] if use_ru_blocked else []) \
        + ([RU_GEOSITE] if settings["ru_direct"] else [])
    for f in sorted(set(need)):
        if not os.path.isfile(os.path.join(args.geo_dir, f)):
            die("the ru-blocked list is not downloaded yet (%s)" % f)
    if use_ru_blocked or settings["ru_direct"]:
        # A blocked domain uses the VPN even when a Russian category lists it.
        rules.append({"type": "field", "inboundTag": ["wg-in"],
                      "domain": ["ext:%s:ru-blocked" % RU_GEOSITE], "balancerTag": "vpn"})
    if settings["ru_direct"]:
        rules.append({"type": "field", "inboundTag": ["wg-in"], "outboundTag": "direct",
                      "domain": ["ext:%s:%s" % (RU_GEOSITE, c) for c in RU_DIRECT_CATEGORIES]
                      + ["domain:" + d for d in RU_DIRECT_DOMAINS]})
    if settings["mode"] == "list":
        if use_ru_blocked:
            rules.append({"type": "field", "inboundTag": ["wg-in"],
                          "ip": ["ext:%s:ru-blocked" % RU_GEOIP], "balancerTag": "vpn"})
        rules.append({"type": "field", "inboundTag": ["wg-in"], "outboundTag": "direct"})
    else:
        rules.append({"type": "field", "inboundTag": ["wg-in"], "balancerTag": "vpn"})

    outbounds = [n["_outbound"] for n in usable]
    outbounds += [
        {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]
    return {
        "api": {"tag": "api", "services": ["RoutingService"]},
        "inbounds": [
            {"tag": "api-in", "listen": "127.0.0.1", "port": args.api_port,
             "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
            {"tag": "probe-in", "listen": "127.0.0.1", "port": args.probe_port,
             "protocol": "socks",
             "settings": {"auth": "password", "udp": False,
                          "accounts": [{"user": t, "pass": probe_pass} for t in tags]}},
        ] + [
            # TLS passes through untouched: the router's client still sees the
            # real certificate of the real host.
            {"tag": "self-%d" % i, "listen": "127.0.0.1", "port": args.self_port + i,
             "protocol": "dokodemo-door",
             "settings": {"address": h, "port": 443, "network": "tcp"}}
            for i, h in enumerate(settings["self_hosts"])
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [{"tag": "vpn", "selector": tags, "strategy": {"type": "random"}}],
            "rules": rules,
        },
    }


def cmd_build(args):
    valid_host(args.listen)
    safe_port(args.port)
    for p in (args.api_port, args.probe_port, args.self_port,
              args.self_port + MAX_SELF_HOSTS - 1):
        safe_port(p)
    self_range = set(range(args.self_port, args.self_port + MAX_SELF_HOSTS))
    if len({args.port, args.api_port, args.probe_port}) != 3 \
            or self_range & {args.port, args.api_port, args.probe_port}:
        die("WireGuard, API, probe and self-route ports must differ")
    if not 576 <= args.mtu <= 9000:
        die("WireGuard MTU is out of range")
    if args.loglevel not in ("debug", "info", "warning", "error", "none"):
        die("invalid loglevel")
    try:
        with open(args.probe_pass_file, "r", encoding="utf-8") as fh:
            probe_pass = fh.read().strip()
    except OSError:
        die("probe password file is missing")
    if not re.match(r"^[A-Za-z0-9]{16,64}$", probe_pass):
        die("probe password is malformed")
    settings = load_settings(args.root)
    nodes = collect_nodes(args.root, settings)
    cfg = build_config(args, settings, nodes, probe_pass)
    overlay = mkjson.build_overlay(args, "wg-in", None)
    os.makedirs(args.out_dir, exist_ok=True)
    try:
        with open(os.path.join(args.out_dir, "01-auto.json"), "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, ensure_ascii=False)
        with open(os.path.join(args.out_dir, "99-overlay.json"), "w", encoding="utf-8") as fh:
            json.dump(overlay, fh, ensure_ascii=False)
        with open(os.path.join(args.out_dir, "self-hosts.txt"), "w", encoding="utf-8") as fh:
            for i, h in enumerate(settings["self_hosts"]):
                fh.write("%s %d\n" % (h, args.self_port + i))
        with open(os.path.join(args.out_dir, "nodes.json"), "w", encoding="utf-8") as fh:
            json.dump({"order": settings["order"], "mode": settings["mode"],
                       "nodes": public_nodes(nodes)}, fh, ensure_ascii=False)
    except OSError as e:
        die("could not write output: %s" % e)
    usable = sum(1 for n in nodes if n["usable"])
    sys.stdout.write("ok\tnodes=%d\tusable=%d\tmode=%s\n" % (len(nodes), usable, settings["mode"]))


def cmd_rule(args):
    kind, value = normalize_rule(args.value)
    sys.stdout.write("%s\t%s\n" % (kind, value))


def cmd_settings(args):
    s = load_settings(args.root)
    for kv in args.set or []:
        if "=" not in kv:
            die("--set takes key=value")
        k, v = kv.split("=", 1)
        s = apply_setting(s, k, v)
    json.dump(s, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


def cmd_nodes(args):
    s = load_settings(args.root)
    json.dump({"order": s["order"], "mode": s["mode"],
               "nodes": public_nodes(collect_nodes(args.root, s))},
              sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")


def main():
    ap = argparse.ArgumentParser(description="proxy-unifi Auto mode builder")
    sub = ap.add_subparsers()
    b = sub.add_parser("build")
    b.add_argument("--root", required=True)
    b.add_argument("--out-dir", required=True)
    b.add_argument("--geo-dir", required=True)
    b.add_argument("--listen", default="127.0.0.1")
    b.add_argument("--port", type=int, required=True)
    b.add_argument("--address", default="10.66.66.1/32")
    b.add_argument("--mtu", type=int, default=1340)
    b.add_argument("--keepalive", type=int, default=25)
    b.add_argument("--loglevel", default="warning")
    b.add_argument("--secret-key-file", required=True)
    b.add_argument("--peer-pubkey-file", required=True)
    b.add_argument("--api-port", type=int, default=51822)
    b.add_argument("--probe-port", type=int, default=51823)
    b.add_argument("--self-port", type=int, default=51830)
    b.add_argument("--probe-pass-file", required=True)
    b.set_defaults(fn=cmd_build)
    r = sub.add_parser("rule")
    r.add_argument("--value", required=True)
    r.set_defaults(fn=cmd_rule)
    s = sub.add_parser("settings")
    s.add_argument("--root", required=True)
    s.add_argument("--set", action="append")
    s.set_defaults(fn=cmd_settings)
    n = sub.add_parser("nodes")
    n.add_argument("--root", required=True)
    n.set_defaults(fn=cmd_nodes)
    args = ap.parse_args()
    if not getattr(args, "fn", None):
        ap.print_help()
        sys.exit(2)
    args.fn(args)


if __name__ == "__main__":
    main()
