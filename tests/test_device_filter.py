"""Device list ordering and the persisted 'L3 only' filter. Headless-safe."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from i18n import STRINGS
from tab_gen import GeneratorTabMixin


class _Var:
    def __init__(self, value=""):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class _Host(GeneratorTabMixin):
    pass


def _host(devices, only_l3=False):
    h = _Host()
    h.devices = [dict(d) for d in devices]
    h.only_l3_var = _Var(only_l3)
    h.dev_label = lambda d: (
        f"{d.get('hostname')} {d.get('host')}".strip()
        if d.get("hostname") else d.get("host", ""))
    return h


DEVS = [
    {"host": "10.0.0.3", "hostname": "zz-l2"},
    {"host": "10.0.0.1", "hostname": "core-l3", "l3": True},
    {"host": "10.0.0.2", "hostname": "aa-l2"},
    {"host": "10.0.0.9", "hostname": "edge-l3", "l3": True},
    {"host": "", "hostname": "no-host"},
]


class VisibleDevicesTest(unittest.TestCase):
    def test_l3_devices_come_first(self):
        out = _host(DEVS)._visible_devices()
        self.assertEqual([d["hostname"] for d in out],
                         ["core-l3", "edge-l3", "aa-l2", "zz-l2"])

    def test_sorted_within_each_group(self):
        out = _host(DEVS)._visible_devices()
        self.assertEqual([d["hostname"] for d in out if not d.get("l3")],
                         ["aa-l2", "zz-l2"])

    def test_devices_without_host_are_dropped(self):
        out = _host(DEVS)._visible_devices()
        self.assertNotIn("no-host", [d["hostname"] for d in out])

    def test_filter_hides_l2(self):
        out = _host(DEVS, only_l3=True)._visible_devices()
        self.assertEqual([d["hostname"] for d in out],
                         ["core-l3", "edge-l3"])

    def test_filter_with_no_l3_devices_gives_empty_list(self):
        out = _host([{"host": "10.0.0.1", "hostname": "sw"}],
                    only_l3=True)._visible_devices()
        self.assertEqual(out, [])

    def test_filter_off_by_default(self):
        h = _host(DEVS)
        self.assertFalse(h.only_l3_var.get())

    def test_missing_var_does_not_crash(self):
        # some tests/stubs build the mixin without the checkbox
        h = _Host()
        h.devices = [dict(d) for d in DEVS]
        h.dev_label = lambda d: f"{d.get('hostname')} {d.get('host')}".strip()
        self.assertEqual(len(h._visible_devices()), 4)


class TrackingStartListTest(unittest.TestCase):
    """The trace start list keeps its own primary/secondary rule."""

    DEVS = [
        {"host": "10.0.0.1", "hostname": "p1", "l3": True},
        {"host": "10.0.0.2", "hostname": "s1", "l3": True,
         "ha_role": "secondary"},
        {"host": "10.0.0.3", "hostname": "l2sw"},
    ]

    def _h(self, only_l3=False, show_all=False):
        h = _host(self.DEVS, only_l3=only_l3)
        h.track_all_var = _Var(show_all)
        return h

    def test_default_shows_l3_primaries_only(self):
        out = self._h()._track_visible_devices()
        self.assertEqual([d["hostname"] for d in out], ["p1"])

    def test_show_all_includes_l2_and_secondaries(self):
        out = self._h(show_all=True)._track_visible_devices()
        self.assertEqual(len(out), 3)

    def test_l3_filter_hides_l2_even_with_show_all(self):
        out = self._h(only_l3=True, show_all=True)._track_visible_devices()
        self.assertNotIn("l2sw", [d["hostname"] for d in out])


class OnlyL3PersistenceTest(unittest.TestCase):
    """The setting must survive a restart (config.json on disk)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = os.path.join(self.tmp, "config.json")
        import app
        self._patch = mock.patch.object(app, "CONFIG_FILE", self.cfg)
        self._patch.start()
        self.app = app

    def tearDown(self):
        self._patch.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_default_is_false(self):
        self.assertFalse(self.app.load_only_l3())

    def test_round_trip_true(self):
        self.app.save_only_l3(True)
        self.assertTrue(self.app.load_only_l3())
        with open(self.cfg, encoding="utf-8") as f:
            self.assertIs(json.load(f)["only_l3"], True)

    def test_round_trip_false_after_true(self):
        self.app.save_only_l3(True)
        self.app.save_only_l3(False)
        self.assertFalse(self.app.load_only_l3())

    def test_other_settings_are_preserved(self):
        self.app.save_dhcp_server("10.0.0.5")
        self.app.save_only_l3(True)
        self.assertEqual(self.app.load_dhcp_server(), "10.0.0.5")
        self.assertTrue(self.app.load_only_l3())

    def test_garbage_value_falls_back_to_false(self):
        with open(self.cfg, "w", encoding="utf-8") as f:
            json.dump({"only_l3": "yes"}, f)
        self.assertFalse(self.app.load_only_l3())


class LabelTest(unittest.TestCase):
    def test_label_exists_in_both_languages(self):
        self.assertEqual(STRINGS["en"]["dev_only_l3"], "L3 only")
        self.assertEqual(STRINGS["pl"]["dev_only_l3"], "Tylko L3")


if __name__ == "__main__":
    unittest.main()
