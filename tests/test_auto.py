#!/usr/bin/env python3
"""Auto mode: Happ's hysteria2 'fm' option, node countries, user rules, the
hysteria2 -> xray conversion and the failover picker's choices."""

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import mkauto
import mksingbox
import mksub
import picker

FM = "%7B%22quicParams%22%3A%7B%22debug%22%3Afalse%2C%22congestion%22%3A%22bbr%22%7D%7D"


def refused(fn, *a):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        try:
            fn(*a)
        except SystemExit:
            return err.getvalue()
    return None


class FinalMask(unittest.TestCase):
    def test_harmless_fm_is_accepted(self):
        out, host, port = mksingbox.parse_hysteria2(
            "hysteria2://pw@pl.example.com:443?sni=pl.example.com&fm=%s#PL" % FM)
        self.assertEqual((host, port), ("pl.example.com", 443))

    def test_other_fm_is_refused(self):
        for fm in ('{"udp":{"mask":"x"}}', '{"quicParams":{"congestion":"evil"}}',
                   '{"quicParams":{"window":1}}', "not json"):
            from urllib.parse import quote
            link = "hysteria2://pw@pl.example.com:443?fm=%s#PL" % quote(fm)
            self.assertIsNotNone(refused(mksingbox.parse_hysteria2, link), fm)


class Labels(unittest.TestCase):
    def test_country_is_the_last_flag(self):
        self.assertEqual(mksub.country_from_label("🇷🇺 → 🇩🇪 Германия"), "DE")
        self.assertEqual(mksub.country_from_label("🇳🇱 NL 2 | HY2"), "NL")
        self.assertEqual(mksub.country_from_label("no flag"), "")

    def test_happ_description_is_stripped(self):
        self.assertEqual(mksub.strip_description("🇫🇮 Финляндия?serverDescription=0KHQtdGA0LI="),
                         "🇫🇮 Финляндия")
        node = mksub.node_from_link(
            "vless://11111111-2222-4333-8444-555555555555@fi.example.com:443?security=tls&type=tcp"
            "#%F0%9F%87%AB%F0%9F%87%AE%20Fin%3FserverDescription%3DAAAA")
        self.assertEqual(node["label"], "🇫🇮 Fin")
        self.assertEqual(node["country"], "FI")


class Rules(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(mkauto.normalize_rule("*.YouTube.com."), ("domain", "youtube.com"))
        self.assertEqual(mkauto.normalize_rule("пример.рф"), ("domain", "xn--e1afmkfd.xn--p1ai"))
        self.assertEqual(mkauto.normalize_rule("1.2.3.4"), ("ip", "1.2.3.4/32"))
        self.assertEqual(mkauto.normalize_rule("10.1.2.3/8"), ("ip", "10.0.0.0/8"))
        self.assertEqual(mkauto.normalize_rule("2001:db8::1"), ("ip", "2001:db8::1/128"))

    def test_refused(self):
        for bad in ("", "localhost", "a b.com", "-x.com", "x..com", "1.2.3", "http://x.com",
                    "x.com/path", "a" * 300):
            self.assertIsNotNone(refused(mkauto.normalize_rule, bad), bad)

    def test_settings_validation(self):
        s = mkauto.validate_settings(dict(mkauto.DEFAULTS))
        self.assertEqual(mkauto.apply_setting(s, "order", "de, pl")["order"], ["DE", "PL"])
        self.assertIsNotNone(refused(mkauto.apply_setting, dict(s), "order", "DE,DE"))
        self.assertIsNotNone(refused(mkauto.apply_setting, dict(s), "mode", "x"))
        self.assertIsNotNone(refused(mkauto.apply_setting, dict(s), "disabled", '["zz"]'))


class SelfRoute(unittest.TestCase):
    def test_setting(self):
        s = mkauto.validate_settings(dict(mkauto.DEFAULTS))
        self.assertIn("fw-download.ubnt.com", s["self_hosts"])
        self.assertEqual(mkauto.apply_setting(dict(s), "self_hosts", "A.ui.com, b.ui.com")["self_hosts"],
                         ["a.ui.com", "b.ui.com"])
        self.assertIsNotNone(refused(mkauto.apply_setting, dict(s), "self_hosts", "bad host"))
        self.assertIsNotNone(refused(mkauto.apply_setting, dict(s), "self_hosts", "a.com,a.com"))

    def test_inbounds_go_through_the_balancer(self):
        import argparse
        args = argparse.Namespace(root="/nonexistent", geo_dir="/nonexistent",
                                  api_port=51822, probe_port=51823, self_port=51830)
        settings = dict(mkauto.DEFAULTS, mode="list", ru_blocked=False, ru_direct=False)
        node = {"usable": True, "tag": "n-1",
                "_outbound": {"tag": "n-1", "protocol": "freedom", "settings": {}}}
        cfg = mkauto.build_config(args, settings, [node], "x" * 16)
        selfs = [i for i in cfg["inbounds"] if i["tag"].startswith("self-")]
        self.assertEqual([(i["port"], i["settings"]["address"]) for i in selfs],
                         [(51830, "fw-download.ubnt.com"), (51831, "apt.artifacts.ui.com")])
        self.assertTrue(all(i["listen"] == "127.0.0.1" for i in selfs))
        rule = [r for r in cfg["routing"]["rules"] if "self-0" in r.get("inboundTag", [])]
        self.assertEqual(rule[0].get("balancerTag"), "vpn")

    def test_ru_direct_sits_between_blocked_domains_and_blocked_ips(self):
        import argparse, tempfile
        geo = tempfile.mkdtemp()
        for f in (mkauto.RU_GEOSITE, mkauto.RU_GEOIP):
            open(os.path.join(geo, f), "w").close()
        args = argparse.Namespace(root="/nonexistent", geo_dir=geo,
                                  api_port=51822, probe_port=51823, self_port=51830)
        node = {"usable": True, "tag": "n-1",
                "_outbound": {"tag": "n-1", "protocol": "freedom", "settings": {}}}

        def wg_rules(**kw):
            cfg = mkauto.build_config(args, dict(mkauto.DEFAULTS, **kw), [node], "x" * 16)
            return [(r.get("outboundTag") or r.get("balancerTag"),
                     (r.get("domain") or r.get("ip") or ["*"])[0])
                    for r in cfg["routing"]["rules"]
                    if r.get("inboundTag") == ["wg-in"] and r.get("ip") != mkauto.PRIVATE_NETS]
        geosite = "ext:ru-geosite.dat:"
        self.assertEqual(wg_rules(mode="list"), [
            ("vpn", geosite + "ru-blocked"),
            ("direct", geosite + mkauto.RU_DIRECT_CATEGORIES[0]),
            ("vpn", "ext:ru-geoip.dat:ru-blocked"),
            ("direct", "*")])
        self.assertEqual(wg_rules(mode="all"), [
            ("vpn", geosite + "ru-blocked"),
            ("direct", geosite + mkauto.RU_DIRECT_CATEGORIES[0]),
            ("vpn", "*")])
        self.assertEqual(wg_rules(mode="list", ru_direct=False), [
            ("vpn", geosite + "ru-blocked"), ("vpn", "ext:ru-geoip.dat:ru-blocked"),
            ("direct", "*")])
        s = mkauto.apply_setting(dict(mkauto.DEFAULTS), "ru_direct", "off")
        self.assertFalse(s["ru_direct"])
        self.assertIsNotNone(refused(mkauto.apply_setting, dict(s), "ru_direct", "maybe"))


class Hysteria2Xray(unittest.TestCase):
    def test_outbound(self):
        ob, why = mkauto.outbound_for_link(
            "hysteria2://pa%3Ass@pl.example.com:8443?sni=x.example.com&fm=" + FM + "#PL")
        self.assertEqual(why, "")
        self.assertEqual(ob["protocol"], "hysteria")
        self.assertEqual(ob["settings"], {"version": 2, "address": "pl.example.com", "port": 8443})
        st = ob["streamSettings"]
        self.assertEqual(st["hysteriaSettings"], {"version": 2, "auth": "pa:ss"})
        self.assertEqual(st["tlsSettings"]["serverName"], "x.example.com")

    def test_unsupported_options_are_refused(self):
        for q in ("mport=20000-30000", "obfs=salamander&obfs-password=x", "upmbps=10"):
            ob, why = mkauto.outbound_for_link("hysteria2://pw@pl.example.com:443?%s#PL" % q)
            self.assertIsNone(ob, q)
            self.assertTrue(why, q)

    def test_tuic_is_not_in_auto(self):
        ob, why = mkauto.outbound_for_link("tuic://u:p@x.example.com:443#t")
        self.assertIsNone(ob)
        self.assertIn("not supported", why)


class Choice(unittest.TestCase):
    def make(self, nodes, order=("DE", "PL", "FI", "NL")):
        p = picker.Picker.__new__(picker.Picker)
        p.nodes = [dict(tag=t, id=t, country=c, pinned=pin, priority=i, label=t)
                   for i, (t, c, pin) in enumerate(nodes)]
        p.order = list(order)
        p.health = {}
        p.active = None
        return p

    def up(self, p, tag, rtt, rounds=2):
        for _ in range(rounds):
            p.record(tag, rtt, True)

    def down(self, p, tag):
        for _ in range(picker.FAIL_LIMIT):
            p.record(tag, None, True)

    def test_country_priority_then_rtt(self):
        p = self.make([("de1", "DE", False), ("de2", "DE", False), ("pl1", "PL", False)])
        self.up(p, "de1", 300); self.up(p, "de2", 100); self.up(p, "pl1", 10)
        self.assertEqual(p.choose(), "de2")

    def test_failover_and_kill_switch(self):
        p = self.make([("de1", "DE", False), ("pl1", "PL", False), ("fi1", "FI", False)])
        self.up(p, "de1", 100); self.up(p, "pl1", 100); self.up(p, "fi1", 100)
        p.active = p.choose()
        self.assertEqual(p.active, "de1")
        self.down(p, "de1")
        p.active = p.choose()
        self.assertEqual(p.active, "pl1")
        self.down(p, "pl1"); self.down(p, "fi1")
        self.assertEqual(p.choose(), "block")

    def test_no_kill_switch_before_nodes_are_known(self):
        p = self.make([("de1", "DE", False), ("pl1", "PL", False)])
        self.assertIsNone(p.choose())           # nothing probed yet
        p.record("de1", None, True); p.record("pl1", None, True)
        self.assertIsNone(p.choose())           # one failure each: still unknown
        p.record("de1", None, True); p.record("pl1", None, True)
        self.assertEqual(p.choose(), "block")   # FAIL_LIMIT failures: really down

    def test_one_failed_probe_does_not_switch(self):
        p = self.make([("de1", "DE", False), ("pl1", "PL", False)])
        self.up(p, "de1", 100); self.up(p, "pl1", 50)
        p.active = "de1"
        p.record("de1", None, False)
        self.assertEqual(p.choose(), "de1")

    def test_recovered_country_must_be_stable(self):
        p = self.make([("de1", "DE", False), ("pl1", "PL", False)])
        self.up(p, "pl1", 100)
        p.active = "pl1"
        p.record("de1", 80, True)               # one good round only
        self.assertEqual(p.choose(), "pl1")
        p.record("de1", 80, True)               # second round -> stable
        self.assertEqual(p.choose(), "de1")

    def test_same_country_needs_a_clear_win(self):
        p = self.make([("de1", "DE", False), ("de2", "DE", False)])
        self.up(p, "de1", 100); self.up(p, "de2", 80)
        p.active = "de1"
        self.assertEqual(p.choose(), "de1")     # 80 is not < 100 * 0.6
        p.health["de2"]["rtt"] = 40
        self.assertEqual(p.choose(), "de2")

    def test_pinned_wins_inside_its_country(self):
        p = self.make([("de1", "DE", False), ("de2", "DE", True), ("pl1", "PL", True)])
        self.up(p, "de1", 50); self.up(p, "de2", 400); self.up(p, "pl1", 10)
        self.assertEqual(p.choose(), "de2")

    def test_unlisted_and_unknown_countries_come_last(self):
        p = self.make([("xx", "", False), ("se", "SE", False), ("nl", "NL", False)])
        for t in ("xx", "se", "nl"):
            self.up(p, t, 100)
        self.assertEqual(p.choose(), "nl")
        self.down(p, "nl")
        self.assertEqual(p.choose(), "se")


if __name__ == "__main__":
    unittest.main(verbosity=1)
