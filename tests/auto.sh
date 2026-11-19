#!/bin/sh
# Sandboxed Auto mode test: sources, rules, settings, node actions, panel
# password, engine switching and uninstall, with the real xray validator and
# mocked systemd. Never touches /data, /etc/systemd or /usr/bin.
# usage: tests/auto.sh /path/to/xray /dir/with/ru-geosite.dat+ru-geoip.dat
set -eu

[ $# -eq 2 ] && [ -x "$1" ] || { echo "usage: auto.sh /path/to/xray /geo/dir" >&2; exit 2; }
XRAY_SRC="$1"; GEO="$2"
REPO="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
T="$(mktemp -d)"
STATE="$T/mock-state"
mkdir -p "$T/root/bin" "$T/mock-bin" "$STATE"
cleanup() {
    if [ -s "$STATE/pid" ]; then kill "$(cat "$STATE/pid")" 2>/dev/null || true; fi
    rm -rf "$T"
}
trap cleanup EXIT INT TERM HUP

for f in mkxray.py mksingbox.py mksub.py mkawg.py mkjson.py mkauto.py picker.py panel.py proxylib.py safeexec.py; do
    cp "$REPO/src/$f" "$T/root/bin/$f"
done
cp "$XRAY_SRC" "$T/root/bin/xray"
for f in ru-geosite.dat ru-geoip.dat; do
    if [ -f "$GEO/$f" ]; then cp "$GEO/$f" "$T/root/bin/$f"; fi
done
chmod 0755 "$T/root/bin"/*

sed \
    -e "s|sleep 0\.25 2>/dev/null|sleep 0.01 2>/dev/null|" \
    -e "s|^ROOT=\"/data/proxy-unifi\"|ROOT=\"$T/root\"|" \
    -e "s|^SERVICE_FILE=.*|SERVICE_FILE=\"$T/proxy-unifi.service\"|" \
    -e "s|^REFRESH_SERVICE_FILE=.*|REFRESH_SERVICE_FILE=\"$T/proxy-unifi-refresh.service\"|" \
    -e "s|^REFRESH_TIMER_FILE=.*|REFRESH_TIMER_FILE=\"$T/proxy-unifi-refresh.timer\"|" \
    -e "s|^GUARD_SERVICE_FILE=.*|GUARD_SERVICE_FILE=\"$T/proxy-unifi-guard.service\"|" \
    -e "s|^GUARD_TIMER_FILE=.*|GUARD_TIMER_FILE=\"$T/proxy-unifi-guard.timer\"|" \
    -e "s|^AU_SERVICE_FILE=.*|AU_SERVICE_FILE=\"$T/proxy-unifi-autoupdate.service\"|" \
    -e "s|^AU_TIMER_FILE=.*|AU_TIMER_FILE=\"$T/proxy-unifi-autoupdate.timer\"|" \
    -e "s|^PICKER_SERVICE_FILE=.*|PICKER_SERVICE_FILE=\"$T/proxy-unifi-picker.service\"|" \
    -e "s|^PANEL_SERVICE_FILE=.*|PANEL_SERVICE_FILE=\"$T/proxy-unifi-panel.service\"|" \
    -e "s|^ONBOOT_DST=.*|ONBOOT_DST=\"$T/on_boot.sh\"|" \
    -e "s|^PROXY_LINK=\"/usr/bin/proxy\"|PROXY_LINK=\"$T/proxy\"|" \
    "$REPO/src/proxy-unifi" > "$T/root/bin/proxy-base"
awk -v user="$(id -un)" -v group="$(id -gn)" '
    /^# Dispatch$/ && !done {
        print "ensure_service_user() { SERVICE_USER=\"" user "\"; SERVICE_GROUP=\"" group "\"; }"
        print "need_root() { :; }"
        print "validate_as_service() { \"$@\"; }"
        done=1
    }
    { print }
' "$T/root/bin/proxy-base" > "$T/root/bin/proxy-unifi"
chmod 0755 "$T/root/bin/proxy-unifi"

cat > "$T/mock-bin/systemctl" <<'SH'
#!/bin/sh
set -eu
D="${MOCK_STATE:?}"
cmd="$1"; shift || true
for arg in "$@"; do case "$arg" in --*) : ;; *) echo "$cmd $arg" >> "$D/calls" ;; esac; done
unit=""; for arg in "$@"; do case "$arg" in --*) : ;; *) unit="$arg" ;; esac; done
key="$(printf '%s' "$unit" | tr '/.' '__')"
case "$cmd" in
    daemon-reload) : ;;
    enable) for u in "$@"; do case "$u" in --*) : ;; *) : > "$D/enabled_$(printf '%s' "$u" | tr '/.' '__')" ;; esac; done ;;
    disable) for u in "$@"; do case "$u" in --*) : ;; *) rm -f "$D/enabled_$(printf '%s' "$u" | tr '/.' '__')" ;; esac; done ;;
    start|restart)
        if [ "$unit" = proxy-unifi ]; then
            if [ -s "$D/pid" ]; then kill "$(cat "$D/pid")" 2>/dev/null || true; fi
            sleep 300 </dev/null >/dev/null 2>&1 & echo $! > "$D/pid"
        fi
        : > "$D/active_$key" ;;
    stop) rm -f "$D/active_$key" ;;
    is-active) [ -f "$D/active_$key" ] && { [ "${1:-}" = --quiet ] || echo active; exit 0; }; [ "${1:-}" = --quiet ] || echo inactive; exit 3 ;;
    is-enabled) [ -f "$D/enabled_$key" ] && { [ "${1:-}" = --quiet ] || echo enabled; exit 0; }; [ "${1:-}" = --quiet ] || echo disabled; exit 1 ;;
    show) printf 'MainPID=%s\n' "$(cat "$D/pid" 2>/dev/null || echo 0)"; [ -f "$D/active_proxy-unifi" ] && echo ActiveState=active || echo ActiveState=inactive ;;
    *) : ;;
esac
SH
cat > "$T/mock-bin/ss" <<'SH'
#!/bin/sh
D="${MOCK_STATE:?}"
echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
[ -s "$D/pid" ] && echo "UNCONN 0 0 127.0.0.1:51821 0.0.0.0:* users:((\"xray\",pid=$(cat "$D/pid"),fd=3))"
exit 0
SH
printf '#!/bin/sh\nexit 0\n' > "$T/mock-bin/chown"
chmod 0755 "$T/mock-bin"/*

P() { MOCK_STATE="$STATE" PATH="$T/mock-bin:$PATH" "$T/root/bin/proxy-unifi" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
J() { P auto status-json | python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

VLESS='vless://11111111-2222-4333-8444-555555555555@de.example.com:443?security=tls&type=tcp&sni=de.example.com#%F0%9F%87%A9%F0%9F%87%AA%20Germany'
HY2='hysteria2://secret@pl.example.com:443?sni=pl.example.com&fm=%7B%22quicParams%22%3A%7B%22debug%22%3Afalse%2C%22congestion%22%3A%22bbr%22%7D%7D#%F0%9F%87%B5%F0%9F%87%B1%20Poland'
TROJAN='trojan://pw@fi.example.com:443?security=tls&sni=fi.example.com#%F0%9F%87%AB%F0%9F%87%AE%20Finland'

P install-service >/dev/null || fail "install-service"

# enabling with no sources is refused
if P auto enable >/dev/null 2>&1; then fail "enable without sources"; fi

S1="$(printf '%s\n' "$VLESS" | P auto add-link "Germany box")"
S2="$(printf '%s\n' "$HY2" | P auto add-link "Poland box")"
printf '%s\n' "$TROJAN" | P auto add-link "Finland box" >/dev/null
# a link xray cannot carry in the pool is refused with its reason
if printf '%s\n' 'tuic://u:p@x.example.com:443#t' | P auto add-link "bad" >/dev/null 2>&1; then fail "tuic accepted"; fi
[ "$(J 'len(d["sources"])')" = 3 ] || fail "three sources expected"

# without the lists (offline CI) Auto runs with ru-blocked off
[ -f "$T/root/bin/ru-geosite.dat" ] || P auto set ru_blocked off
P auto enable >/dev/null
[ "$(cat "$T/root/etc/engine")" = xrayauto ] || fail "engine is not xrayauto"
[ -f "$T/root/etc/pool/01-auto.json" ] || fail "no Auto config"
grep -q "run -confdir $T/root/etc/pool" "$T/proxy-unifi.service" || fail "service does not run the pool dir"
grep -q "picker.py" "$T/proxy-unifi-picker.service" || fail "picker unit missing"
[ -f "$STATE/enabled_proxy-unifi-picker" ] || fail "picker not enabled"
[ "$(J '[n["country"] for n in d["nodes"]]')" = "['DE', 'PL', 'FI']" ] || fail "priority order DE,PL,FI"
[ "$(J 'all(n["usable"] for n in d["nodes"])')" = True ] || fail "all nodes usable (hy2 with fm)"

# country order
P auto set order FI,DE,PL
[ "$(J '[n["country"] for n in d["nodes"]]')" = "['FI', 'DE', 'PL']" ] || fail "reordered countries"
if P auto set order "DE,de1" 2>/dev/null; then fail "bad order accepted"; fi

# modes and lists
P auto set mode all
python3 - "$T/root/etc/pool/01-auto.json" <<'PY' || fail "mode all must send the rest to the balancer"
import json,sys; r=json.load(open(sys.argv[1]))["routing"]["rules"]; assert r[-1].get("balancerTag")=="vpn"
PY
P auto set mode list
P auto set ru_blocked off
python3 - "$T/root/etc/pool/01-auto.json" <<'PY' || fail "mode list must end in direct and drop ru-blocked"
import json,sys; r=json.load(open(sys.argv[1]))["routing"]["rules"]; assert r[-1].get("outboundTag")=="direct"
assert not any("ext:" in str(x) for x in r)
PY
if P auto set mode sometimes 2>/dev/null; then fail "bad mode accepted"; fi

P auto rule add vpn '*.YouTube.com'
P auto rule add direct 10.20.0.0/16
P auto rule add vpn 'пример.рф'
if P auto rule add direct youtube.com 2>/dev/null; then fail "same entry in both lists"; fi
if P auto rule add vpn 'not a domain' 2>/dev/null; then fail "bad rule accepted"; fi
[ "$(J 'd["rules"]["vpn"]')" = "['youtube.com', 'xn--e1afmkfd.xn--p1ai']" ] || fail "normalized vpn rules"
grep -q 'domain:youtube.com' "$T/root/etc/pool/01-auto.json" || fail "rule not in config"
P auto rule del vpn youtube.com
grep -q 'domain:youtube.com' "$T/root/etc/pool/01-auto.json" && fail "deleted rule still in config"

# node actions
NID="$(J '[n["id"] for n in d["nodes"] if n["country"]=="PL"][0]')"
P auto node pin "$NID"
[ "$(J '[n["pinned"] for n in d["nodes"] if n["id"]=="'"$NID"'"][0]')" = True ] || fail "pin"
P auto node disable "$NID"
[ "$(J '[n["usable"] for n in d["nodes"] if n["id"]=="'"$NID"'"][0]')" = False ] || fail "disable"
grep -q "n-${NID%"${NID#????????????}"}" "$T/root/etc/pool/01-auto.json" && fail "disabled node still in config"
P auto node enable "$NID"
P auto node country "$NID" NL
[ "$(J '[n["country"] for n in d["nodes"] if n["id"]=="'"$NID"'"][0]')" = NL ] || fail "country override"

# sources on/off/delete
P auto source "$S1" off
[ "$(J '[n["usable"] for n in d["nodes"] if n["source"]=="'"$S1"'"][0]')" = False ] || fail "source off"
P auto source "$S1" on
P auto del "$S2"
[ "$(J 'len(d["sources"])')" = 2 ] || fail "source delete"

# HWID
if P auto hwid not-a-uuid 2>/dev/null; then fail "bad hwid accepted"; fi
P auto hwid 0a1b2c3d-1111-4222-8333-444455556666 >/dev/null
[ "$(cat "$T/root/etc/subscription/hwid")" = 0a1b2c3d-1111-4222-8333-444455556666 ] || fail "hwid not stored"

# panel password
if printf 'short\n' | P auto panel-password >/dev/null 2>&1; then fail "short panel password"; fi
printf 'correct horse battery\n' | P auto panel-password >/dev/null
grep -q '^pbkdf2\$' "$T/root/etc/panel.pass" || fail "panel password not hashed"
grep -q "panel.py" "$T/proxy-unifi-panel.service" || fail "panel unit missing"

# a failed change keeps the running config (transaction rollback)
cp "$T/root/etc/pool/01-auto.json" "$T/before.json"
mv "$T/root/bin/xray" "$T/xray.off"; printf '#!/bin/sh\nexit 1\n' > "$T/root/bin/xray"; chmod 755 "$T/root/bin/xray"
if P auto set mode all 2>/dev/null; then fail "change with a broken core succeeded"; fi
mv "$T/xray.off" "$T/root/bin/xray"
cmp -s "$T/before.json" "$T/root/etc/pool/01-auto.json" || fail "config changed after a failed apply"
[ "$(J 'd["settings"]["mode"]')" = list ] || fail "settings changed after a failed apply"

P auto status >/dev/null || fail "status text"
echo "auto lifecycle ok"
