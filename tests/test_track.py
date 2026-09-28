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


if __name__ == "__main__":
    unittest.main()
