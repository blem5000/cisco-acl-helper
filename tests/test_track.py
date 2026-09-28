"""Tests for HA partner tracking helpers (headless-safe)."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import track
from app import App


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


if __name__ == "__main__":
    unittest.main()
