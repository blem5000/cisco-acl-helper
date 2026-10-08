"""Tests for HA partner tracking helpers (headless-safe)."""

import os
import queue
import sys
import threading
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import track
from app import App
from i18n import STRINGS


class PortChannelTest(unittest.TestCase):
    def test_portchannel_forms(self):
        for p in ("Po1", "po10", "PO2", "Port-channel1", "portchannel 5",
                  "PORT-CHANNEL12"):
            self.assertTrue(track.is_portchannel(p), p)

    def test_regular_ports(self):
        for p in ("Gi1/0/5", "Te1/1", "Fa0/1", "Vl10", "", "Ethernet1"):
            self.assertFalse(track.is_portchannel(p), p)


class PortNameTest(unittest.TestCase):
    def test_twentyfive_gig_forms_match(self):
        # MAC table "Twe1/0/13" vs CDP detail "TwentyFiveGigE1/0/13"
        # vs summary "Twe 1/0/13" must all normalize identically
        forms = [track.normalize_port(p) for p in
                 ("Twe1/0/13", "TwentyFiveGigE1/0/13", "Twe 1/0/13",
                  "twentyfivegigabitethernet1/0/13")]
        self.assertTrue(all(f == forms[0] for f in forms), forms)

    def test_twe_not_confused_with_twogig(self):
        self.assertNotEqual(track.normalize_port("Twe1/0/13"),
                            track.normalize_port("Tw1/0/1"))
        self.assertEqual(track.normalize_port("Tw1/0/1"),
                         "twogigabitethernet1/0/1")

    def test_cdp_found_on_twe_port(self):
        detail = ("--------------------------\n"
                  "Device ID: MA1_2F_3_5_96105_O.lgema.local\n"
                  "Entry address(es):\n"
                  "  IP address: 10.207.96.5\n"
                  "Platform: cisco WS-C2960X, Capabilities: Switch IGMP\n"
                  "Interface: TwentyFiveGigE1/0/13, "
                  "Port ID (outgoing port): GigabitEthernet1/0/49\n"
                  "Holdtime : 142 sec\n")
        nb = track.find_cdp_on_port(track.parse_cdp_detail(detail),
                                    "Twe1/0/13")
        self.assertIsNotNone(nb)
        self.assertEqual(nb["device"],
                         "MA1_2F_3_5_96105_O.lgema.local")


class FindPartnerTest(unittest.TestCase):
    def test_by_host(self):
        devs = [{"host": "10.0.0.1", "partner": "10.0.0.2"},
                {"host": "10.0.0.2", "partner": "10.0.0.1"}]
        self.assertEqual(track.find_partner(devs, devs[0])["host"], "10.0.0.2")

    def test_missing(self):
        devs = [{"host": "10.0.0.1", "partner": "10.0.9.9"}]
        self.assertIsNone(track.find_partner(devs, devs[0]))
        self.assertIsNone(track.find_partner(devs, {"host": "10.0.0.1"}))
        self.assertIsNone(track.find_partner([], {"host": "a", "partner": "b"}))

    def test_self_link_ignored(self):
        devs = [{"host": "10.0.0.1", "partner": "10.0.0.1"}]
        self.assertIsNone(track.find_partner(devs, devs[0]))

    def test_case_insensitive(self):
        devs = [{"host": "10.0.0.1", "partner": "10.0.0.2"},
                {"host": "10.0.0.2"}]
        self.assertEqual(track.find_partner(devs, devs[0])["host"], "10.0.0.2")


def _dev_stub(devices):
    stub = types.SimpleNamespace(
        devices=[dict(d) for d in devices],
        persisted=[], refreshed=[],
    )
    stub.persist_store = lambda: stub.persisted.append(True)
    stub.refresh_tree = lambda: stub.refreshed.append(True)
    return stub


class LinkPartnerTest(unittest.TestCase):
    def test_primary_sets_secondary_backlink(self):
        stub = _dev_stub([{"host": "10.0.0.1", "partner": "10.0.0.2",
                           "ha_role": "primary"},
                          {"host": "10.0.0.2"}])
        App._link_partner(stub, 0, {})
        b = stub.devices[1]
        self.assertEqual(b["partner"], "10.0.0.1")
        self.assertEqual(b["ha_role"], "secondary")

    def test_secondary_sets_primary_backlink(self):
        stub = _dev_stub([{"host": "10.0.0.1", "partner": "10.0.0.2",
                           "ha_role": "secondary"},
                          {"host": "10.0.0.2"}])
        App._link_partner(stub, 0, {})
        self.assertEqual(stub.devices[1]["ha_role"], "primary")

    def test_repoint_clears_stale_backlink(self):
        stub = _dev_stub([
            {"host": "10.0.0.1", "partner": "10.0.0.3", "ha_role": "primary"},
            {"host": "10.0.0.2", "partner": "10.0.0.1", "ha_role": "secondary"},
            {"host": "10.0.0.3"}])
        App._link_partner(stub, 0, {"host": "10.0.0.1", "partner": "10.0.0.2"})
        self.assertEqual(stub.devices[1]["partner"], "")
        self.assertEqual(stub.devices[1]["ha_role"], "")
        self.assertEqual(stub.devices[2]["partner"], "10.0.0.1")
        self.assertEqual(stub.devices[2]["ha_role"], "secondary")

    def test_clearing_partner_clears_backlink(self):
        stub = _dev_stub([{"host": "10.0.0.1"},
                          {"host": "10.0.0.2", "partner": "10.0.0.1",
                           "ha_role": "secondary"}])
        App._link_partner(stub, 0, {"host": "10.0.0.1", "partner": "10.0.0.2"})
        self.assertEqual(stub.devices[1]["partner"], "")
        self.assertEqual(stub.devices[1]["ha_role"], "")


class TrackVisibleTest(unittest.TestCase):
    def _stub(self, devices, show_all):
        return types.SimpleNamespace(
            devices=[dict(d) for d in devices],
            track_all_var=types.SimpleNamespace(get=lambda: show_all))

    def _hosts(self, stub):
        return [d["host"] for d in App._track_visible_devices(stub)]

    def test_default_hides_l2_and_secondary(self):
        devs = [{"host": "10.0.0.1", "l3": True, "ha_role": "primary"},
                {"host": "10.0.0.2", "l3": True, "ha_role": "secondary"},
                {"host": "10.0.0.3", "l3": False},
                {"host": "10.0.0.4", "l3": True},
                {"host": "10.0.0.5"}]
        self.assertEqual(self._hosts(self._stub(devs, False)),
                         ["10.0.0.1", "10.0.0.4"])

    def test_show_all_bypasses_filters(self):
        devs = [{"host": "10.0.0.1", "l3": True, "ha_role": "primary"},
                {"host": "10.0.0.2", "l3": True, "ha_role": "secondary"},
                {"host": "10.0.0.3", "l3": False},
                {"host": ""}]
        self.assertEqual(self._hosts(self._stub(devs, True)),
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])


def _worker_stub(run_fn, stop_set=None):
    stub = types.SimpleNamespace(
        msg_queue=queue.Queue(),
        T=lambda k: STRINGS["en"].get(k, k),
        _track_stop=stop_set or threading.Event(),
    )
    stub._track_run = types.MethodType(run_fn, stub)
    stub._track_hop_run = types.MethodType(App._track_hop_run, stub)
    return stub


def _drain(stub, start=None):
    """Run the worker synchronously, collect (kind, payload) list."""
    out = []
    devices = [{"host": "10.0.0.1", "partner": "10.0.0.2"},
               {"host": "10.0.0.2", "partner": "10.0.0.1",
                "ha_role": "secondary"}]
    App._track_worker(stub, "10.9.9.9",
                      dict(start) if start else dict(devices[0]),
                      devices, False, None)
    while not stub.msg_queue.empty():
        out.append(stub.msg_queue.get_nowait())
    return out


def _kinds(msgs):
    return [k for k, _p in msgs]


class WorkerDoneTest(unittest.TestCase):
    """Every terminal path must emit exactly one track_done (UI unfreeze)."""

    def test_arp_miss_emits_done(self):
        def run(_self, _dev, cmd, _dbg):
            return ""
        msgs = _drain(_worker_stub(run))
        self.assertIn("track_done", _kinds(msgs))
        self.assertEqual(_kinds(msgs).count("track_done"), 1)
        chunks = [p[1] for k, p in msgs if k == "track_chunk"]
        self.assertTrue(any("10.0.0.2" in c for c in chunks))  # partner tried
        self.assertTrue(any("nor on HA partner" in c for c in chunks))

    def test_exception_emits_done(self):
        def run(_self, _dev, cmd, _dbg):
            raise RuntimeError("ssh gone")
        msgs = _drain(_worker_stub(run))
        self.assertEqual(_kinds(msgs).count("track_done"), 1)
        self.assertTrue(any("ERROR" in p[1]
                            for k, p in msgs if k == "track_chunk"))

    def test_stop_emits_done(self):
        stop = threading.Event()
        stop.set()
        msgs = _drain(_worker_stub(lambda *_a: "", stop))
        self.assertEqual(_kinds(msgs).count("track_done"), 1)

    def test_cdp_continue_keeps_payload(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = ("  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5")
        cdp = ("--------------------------\nDevice ID: sw2\n"
               "IP address: 10.0.0.2\n"
               "Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Gi1/0/1\n"
               "Platform: cisco WS-C2960X\n"
               "--------------------------\n")
        script = {"arp": mac_line, "mac": mactab, "cdp": cdp}

        def run(_self, _dev, cmd, _dbg):
            if "ip arp" in cmd:
                return script["arp"]
            if "mac address-table" in cmd:
                return script["mac"]
            return script["cdp"]
        msgs = _drain(_worker_stub(run))
        dones = [p for k, p in msgs if k == "track_done"]
        self.assertEqual(len(dones), 1)
        self.assertEqual(dones[0]["host"], "10.0.0.2")  # Continue button target

    def test_partner_hop_over_portchannel(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = "  10    aaaa.bbbb.cccc    DYNAMIC     Po1"
        script = {"10.0.0.1": {"arp": mac_line, "mac": mactab, "cdp": ""},
                  "10.0.0.2": {"arp": "", "mac": "", "cdp": ""}}

        def run(_self, dev, cmd, _dbg):
            host = dev.get("host", "")
            if "ip arp" in cmd:
                return script[host]["arp"]
            if "mac address-table" in cmd:
                return script[host]["mac"]
            return script[host]["cdp"]
        msgs = _drain(_worker_stub(run))
        chunks = [p[1] for k, p in msgs if k == "track_chunk"]
        self.assertTrue(any("HA partner 10.0.0.2" in c for c in chunks))
        self.assertTrue(any("nor on HA partner 10.0.0.1" in c
                            for c in chunks))
        self.assertEqual(_kinds(msgs).count("track_done"), 1)


class TrackFoundTest(unittest.TestCase):
    """The worker emits exactly one structured compact summary."""

    def _founds(self, msgs):
        founds = [p for k, p in msgs if k == "track_found"]
        self.assertEqual(len(founds), 1)
        self.assertEqual(len(founds[0]), 4)  # (ip, found, reason, fail_host)
        return founds[0]

    def test_arp_miss_found_none(self):
        msgs = _drain(_worker_stub(lambda *_a: ""))
        ip, found, reason, fail_host = self._founds(msgs)
        self.assertEqual(ip, "10.9.9.9")
        self.assertIsNone(found)
        self.assertEqual(reason, "no_arp")

    def test_manual_continue_reports_step(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = ("  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5")
        cdp = ("--------------------------\nDevice ID: sw2\n"
               "IP address: 10.0.0.2\n"
               "Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Gi1/0/1\n"
               "Platform: cisco WS-C2960X\n"
               "--------------------------\n")

        def run(_self, _dev, cmd, _dbg):
            if "ip arp" in cmd:
                return mac_line
            if "mac address-table" in cmd:
                return mactab
            return cdp
        msgs = _drain(_worker_stub(run))
        ip, found, reason, fail_host = self._founds(msgs)
        self.assertEqual(reason, "step")  # UI skips intermediate summaries
        self.assertEqual(found, {"host": "10.0.0.1", "port": "Gi1/0/5",
                                 "mac": "aaaa.bbbb.cccc"})

    def test_clean_edge_reports_ok(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = ("  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5")

        def run(_self, _dev, cmd, _dbg):
            if "ip arp" in cmd:
                return mac_line
            if "mac address-table" in cmd:
                return mactab
            return ""  # no CDP -> edge device
        stub = _worker_stub(run)
        devices = [{"host": "10.0.0.1"}]
        App._track_worker(stub, "10.9.9.9", dict(devices[0]), devices,
                          True, None)
        msgs = []
        while not stub.msg_queue.empty():
            msgs.append(stub.msg_queue.get_nowait())
        ip, found, reason, fail_host = self._founds(msgs)
        self.assertEqual(reason, "ok")
        self.assertEqual(found, {"host": "10.0.0.1", "port": "Gi1/0/5",
                                 "mac": "aaaa.bbbb.cccc"})

    def test_error_reports_error(self):
        def run(_self, _dev, cmd, _dbg):
            raise RuntimeError("ssh gone")
        msgs = _drain(_worker_stub(run))
        _ip, found, reason, fail_host = self._founds(msgs)
        self.assertIsNone(found)
        self.assertEqual(reason, "error")

    def test_auth_failure_on_next_hop_reports_auth(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = ("  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5")
        cdp = ("--------------------------\nDevice ID: sw2\n"
               "IP address: 10.0.0.2\n"
               "Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Gi1/0/1\n"
               "Platform: cisco WS-C2960X\n"
               "--------------------------\n")

        def run(_self, dev, cmd, _dbg):
            if dev.get("host") == "10.0.0.2":
                raise RuntimeError(
                    "Authentication failed for 10.0.0.2: bad password")
            if "ip arp" in cmd:
                return mac_line
            if "mac address-table" in cmd:
                return mactab
            return cdp
        stub = _worker_stub(run)
        devices = [{"host": "10.0.0.1"}, {"host": "10.0.0.2"}]
        App._track_worker(stub, "10.9.9.9", dict(devices[0]), devices,
                          True, None)
        msgs = []
        while not stub.msg_queue.empty():
            msgs.append(stub.msg_queue.get_nowait())
        _ip, found, reason, fail_host = self._founds(msgs)
        self.assertEqual(reason, "auth")
        self.assertEqual(fail_host, "10.0.0.2")
        # stale first-hop hit is kept as context, not as the verdict
        self.assertEqual(found["host"], "10.0.0.1")
        self.assertEqual(found["port"], "Gi1/0/5")

    def test_parent_creds_fallback_reaches_next_hop(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab1 = ("  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5")
        mactab2 = ("  10    aaaa.bbbb.cccc    DYNAMIC     Fa0/45")
        cdp = ("--------------------------\nDevice ID: sw2\n"
               "IP address: 10.0.0.2\n"
               "Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Gi1/0/1\n"
               "Platform: cisco WS-C2960X\n"
               "--------------------------\n")
        seen_users = []

        def run(_self, dev, cmd, _dbg):
            seen_users.append((dev.get("host"), dev.get("username")))
            if dev.get("host") == "10.0.0.2" and \
                    dev.get("username") == "parent":
                # unknown user dropped by the switch (no clean auth error)
                raise RuntimeError("Socket EOF during SSH auth")
            if "ip arp" in cmd:
                return mac_line if dev.get("host") == "10.0.0.1" else ""
            if "mac address-table" in cmd:
                return mactab1 if dev.get("host") == "10.0.0.1" else mactab2
            return cdp if dev.get("host") == "10.0.0.1" else ""
        stub = _worker_stub(run)
        devices = [{"host": "10.0.0.1", "username": "parent",
                    "password": "p1"},
                   {"host": "10.0.0.2", "username": "other",
                    "password": "p2"}]
        App._track_worker(stub, "10.9.9.9", dict(devices[0]), devices,
                          True, None)
        msgs = []
        while not stub.msg_queue.empty():
            msgs.append(stub.msg_queue.get_nowait())
        _ip, found, reason, fail_host = self._founds(msgs)
        self.assertEqual(reason, "ok")
        self.assertEqual(found, {"host": "10.0.0.2", "port": "Fa0/45",
                                 "mac": "aaaa.bbbb.cccc"})
        users_on_2 = [u for h, u in seen_users if h == "10.0.0.2"]
        self.assertEqual(users_on_2[0], "parent")  # auto-continue first
        self.assertIn("other", users_on_2)  # then stored credentials
        chunks = [p[1] for k, p in msgs if k == "track_chunk"]
        self.assertTrue(any("stored credentials" in c for c in chunks))

    def test_no_fallback_on_unrelated_error(self):
        def run(_self, _dev, cmd, _dbg):
            raise RuntimeError("timed out after 15s")
        stub = _worker_stub(run)
        devices = [{"host": "10.0.0.1", "username": "parent"},
                   {"host": "10.0.0.2", "username": "other"}]
        with self.assertRaises(RuntimeError):
            App._track_hop_run(stub, dict(devices[0]), devices, [],
                               "show ip arp 10.9.9.9", None)

    def test_unfollowed_neighbor_reports_next(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = ("  10    aaaa.bbbb.cccc    DYNAMIC     Te1/0/2")
        cdp = ("--------------------------\nDevice ID: edge-sw\n"
               "IP address: 10.0.0.9\n"
               "Interface: TenGigabitEthernet1/0/2,  Port ID (outgoing port): Gi0/2\n"
               "Platform: cisco WS-C2960\n"
               "--------------------------\n")

        def run(_self, _dev, cmd, _dbg):
            if "ip arp" in cmd:
                return mac_line
            if "mac address-table" in cmd:
                return mactab
            return cdp
        stub = _worker_stub(run)
        devices = [{"host": "10.0.0.1"}]  # neighbor NOT listed, manual mode
        App._track_worker(stub, "10.9.9.9", dict(devices[0]), devices,
                          False, None)
        msgs = []
        while not stub.msg_queue.empty():
            msgs.append(stub.msg_queue.get_nowait())
        _ip, found, reason, fail_host = self._founds(msgs)
        self.assertEqual(reason, "next")
        self.assertEqual(found["host"], "10.0.0.1")
        self.assertEqual(found["port"], "Te1/0/2")
        self.assertIn("edge-sw", found["via"])


class LoginErrorTest(unittest.TestCase):
    def test_login_like(self):
        for msg in ("Authentication failed for 10.0.0.2: bad password",
                    "Socket EOF during SSH auth",
                    "Transport shut down during auth",
                    "Permission denied (password)"):
            self.assertTrue(track.looks_login_error(RuntimeError(msg)), msg)

    def test_not_login_like(self):
        for msg in ("timed out after 15s",
                    "Cannot reach 10.0.0.2 (TCP/SSH port closed)",
                    "Host key mismatch",
                    ""):
            self.assertFalse(track.looks_login_error(RuntimeError(msg)), msg)


class FormatSummaryTest(unittest.TestCase):
    def _stub(self):
        stub = types.SimpleNamespace(
            T=lambda k: STRINGS["en"].get(k, k))
        stub._format_track_summary = types.MethodType(
            App._format_track_summary, stub)
        return stub

    def test_found_line(self):
        text = self._stub()._format_track_summary(
            "10.9.9.9", {"host": "10.0.0.1", "port": "Gi1/0/5",
                         "mac": "aaaa.bbbb.cccc"}, "ok")
        self.assertIn("10.9.9.9", text)
        self.assertIn("aaaa.bbbb.cccc", text)
        self.assertIn("10.0.0.1", text)
        self.assertIn("Gi1/0/5", text)

    def test_missing_line_uses_reason(self):
        text = self._stub()._format_track_summary("10.9.9.9", None, "no_arp")
        self.assertIn("10.9.9.9", text)
        self.assertIn("no ARP entry", text)

    def test_next_line_names_direction(self):
        text = self._stub()._format_track_summary(
            "10.9.9.9", {"host": "10.0.0.1", "port": "Te1/0/2",
                         "mac": "aaaa.bbbb.cccc", "via": "edge-sw (10.0.0.9)"},
            "next")
        self.assertIn("Te1/0/2", text)
        self.assertIn("edge-sw", text)
        self.assertNotIn("found on", text)

    def test_auth_line_names_failed_host_and_last_seen(self):
        text = self._stub()._format_track_summary(
            "10.9.9.9", {"host": "10.0.0.1", "port": "Gi1/0/5",
                         "mac": "aaaa.bbbb.cccc"},
            "auth", "10.0.0.2")
        self.assertIn("10.0.0.2", text)
        self.assertIn("10.0.0.1", text)
        self.assertIn("Gi1/0/5", text)
        self.assertNotIn("found on", text)

    def test_auth_without_prior_hit(self):
        text = self._stub()._format_track_summary(
            "10.9.9.9", None, "auth", "10.0.0.1")
        self.assertIn("10.0.0.1", text)

    def test_error_with_stale_hit_surfaces_error(self):
        text = self._stub()._format_track_summary(
            "10.9.9.9", {"host": "10.0.0.1", "port": "Gi1/0/5",
                         "mac": "aaaa.bbbb.cccc"},
            "error", "10.0.0.2")
        self.assertIn("10.0.0.2", text)
        self.assertIn("10.0.0.1", text)
        self.assertNotIn("found on", text)

    def test_error_without_hit_names_host(self):
        text = self._stub()._format_track_summary(
            "10.9.9.9", None, "error", "10.0.0.1")
        self.assertIn("10.0.0.1", text)

    def test_unknown_reason_falls_back_to_error(self):
        text = self._stub()._format_track_summary("10.9.9.9", None, "weird")
        self.assertIn("device error", text)


class ParseBulkTest(unittest.TestCase):
    def test_mixed_input(self):
        valid, invalid = App._parse_bulk_ips(
            "10.0.0.1\n  \n999.1.1.1\n10.0.0.2, \n10.0.0.1\n;abc\n")
        self.assertEqual(valid, ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(invalid, ["999.1.1.1", "abc"])

    def test_empty(self):
        self.assertEqual(App._parse_bulk_ips("  \n\n"), ([], []))


class BulkWorkerTest(unittest.TestCase):
    """Bulk repeats manual Trace clicks: same start, caller's settings."""

    def _bulk_stub(self, run_fn):
        stub = types.SimpleNamespace(
            msg_queue=queue.Queue(),
            T=lambda k: STRINGS["en"].get(k, k),
            _track_stop=threading.Event(),
        )
        stub._track_run = types.MethodType(run_fn, stub)
        stub._track_worker = types.MethodType(App._track_worker, stub)
        stub._track_hop_run = types.MethodType(App._track_hop_run, stub)
        return stub

    def _drain_bulk(self, stub, ips, dev, devices, use_parent):
        calls = []

        orig = stub._track_run

        def counting(self_, d, cmd, dbg):
            calls.append((d.get("host", ""), cmd))
            return orig(d, cmd, dbg)

        stub._track_run = types.MethodType(counting, stub)
        App._bulk_worker(stub, ips, dev, devices, use_parent, None)
        msgs = []
        while not stub.msg_queue.empty():
            msgs.append(stub.msg_queue.get_nowait())
        return msgs, calls

    def _script(self):
        mac_line = ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                    "Vlan10")
        mactab = ("  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5")
        cdp = ("--------------------------\nDevice ID: sw2\n"
               "IP address: 10.0.0.2\n"
               "Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Gi1/0/1\n"
               "Platform: cisco WS-C2960X\n"
               "--------------------------\n")

        def run(_self, _dev, cmd, _dbg):
            if "ip arp" in cmd:
                return mac_line
            if "mac address-table" in cmd:
                return mactab
            return cdp
        return run

    def _devices(self):
        return [{"host": "10.0.0.1", "partner": "10.0.0.2"},
                {"host": "10.0.0.2", "partner": "10.0.0.1",
                 "ha_role": "secondary"}]

    def test_manual_mode_stays_on_start_device(self):
        devices = self._devices()
        msgs, calls = self._drain_bulk(
            self._bulk_stub(self._script()), ["10.9.9.9"],
            dict(devices[0]), devices, False)
        # single hop on .1 only (arp + mac + cdp), no chaining to .2
        self.assertEqual([h for h, _c in calls],
                         ["10.0.0.1"] * 3)
        founds = [p for k, p in msgs if k == "track_found"]
        self.assertEqual(len(founds), 1)
        self.assertEqual(founds[0][2], "step")
        self.assertEqual(_kinds(msgs).count("track_done"), 2)

    def test_auto_mode_chains(self):
        devices = self._devices()
        msgs, calls = self._drain_bulk(
            self._bulk_stub(self._script()), ["10.9.9.9"],
            dict(devices[0]), devices, True)
        hosts = {h for h, _c in calls}
        self.assertIn("10.0.0.2", hosts)  # hopped further

    def test_parallel_batch_all_report(self):
        def run(_self, _dev, cmd, _dbg):
            if "ip arp" in cmd:
                return ("Internet  10.9.9.9   5   aaaa.bbbb.cccc  ARPA  "
                        "Vlan10")
            return ""
        devices = [{"host": "10.0.0.1"}]
        stub = self._bulk_stub(run)
        App._bulk_worker(stub, ["10.9.9.1", "10.9.9.2", "10.9.9.3"],
                         dict(devices[0]), devices, False, None)
        msgs = []
        while not stub.msg_queue.empty():
            msgs.append(stub.msg_queue.get_nowait())
        founds = [p for k, p in msgs if k == "track_found"]
        self.assertEqual(len(founds), 3)
        self.assertEqual({p[0] for p in founds},
                         {"10.9.9.1", "10.9.9.2", "10.9.9.3"})
        # one track_done per trace (suppressed mid-batch) + one final
        self.assertEqual(_kinds(msgs).count("track_done"), 4)


if __name__ == "__main__":
    unittest.main()
