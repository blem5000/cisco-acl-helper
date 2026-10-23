"""Regression: every device combo is refreshed, including the Remove-IP tab.

_refresh_gen_devices() is the single place that repopulates the per-tab
device dropdowns. When the Remove-IP tab was added, its combo was built but
never registered there, so the tab offered an empty device list while every
other tab listed devices. These tests fail if that registration is dropped.
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from i18n import STRINGS
from tab_gen import GeneratorTabMixin


class _Combo:
    """Records what a combobox was configured with."""

    def __init__(self):
        self.values = None

    def configure(self, **kw):
        if "values" in kw:
            self.values = list(kw["values"])


class _Var:
    def __init__(self, value=""):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


def _stub(devices):
    """Minimal host exposing exactly what _refresh_gen_devices touches."""
    s = types.SimpleNamespace()
    s.devices = [dict(d) for d in devices]
    s.dev_label = lambda d: (
        f"{d.get('hostname')} {d.get('host')}".strip()
        if d.get("hostname") else d.get("host", ""))

    names = ("gen", "track", "audit", "sub", "ports", "remove")
    for n in names:
        setattr(s, f"combo_{n}_dev", _Combo())
        setattr(s, f"{n}_dev_var", _Var(""))

    s._lookup_device = lambda sel: next(
        (d for d in s.devices
         if d.get("host") == (sel or "").strip()
         or s.dev_label(d) == (sel or "").strip()), None)
    s._track_visible_devices = lambda: [
        d for d in s.devices if d.get("l3") and d.get("ha_role") != "secondary"]
    s._refresh_ports_groups = lambda: None
    s._refresh_vuln_devices = lambda: None
    return s


class RefreshDeviceCombosTest(unittest.TestCase):
    def test_remove_tab_gets_the_device_list(self):
        devices = [{"host": "10.0.0.1", "hostname": "sw1"},
                   {"host": "10.0.0.2", "hostname": "sw2"}]
        s = _stub(devices)

        GeneratorTabMixin._refresh_gen_devices(s)

        self.assertEqual(s.combo_remove_dev.values, ["sw1 10.0.0.1",
                                                     "sw2 10.0.0.2"])

    def test_remove_tab_preselects_first_device(self):
        s = _stub([{"host": "10.0.0.9", "hostname": "core"}])
        GeneratorTabMixin._refresh_gen_devices(s)
        self.assertEqual(s.remove_dev_var.get(), "core 10.0.0.9")

    def test_remove_tab_keeps_a_valid_selection(self):
        devices = [{"host": "10.0.0.1", "hostname": "sw1"},
                   {"host": "10.0.0.2", "hostname": "sw2"}]
        s = _stub(devices)
        s.remove_dev_var.set("sw2 10.0.0.2")

        GeneratorTabMixin._refresh_gen_devices(s)

        self.assertEqual(s.remove_dev_var.get(), "sw2 10.0.0.2")

    def test_all_tabs_agree_on_the_list(self):
        devices = [{"host": "10.0.0.1", "hostname": "sw1"}]
        s = _stub(devices)
        GeneratorTabMixin._refresh_gen_devices(s)
        for n in ("gen", "audit", "sub", "ports", "remove"):
            self.assertEqual(getattr(s, f"combo_{n}_dev").values,
                             ["sw1 10.0.0.1"], n)

    def test_empty_device_list_is_safe(self):
        s = _stub([])
        GeneratorTabMixin._refresh_gen_devices(s)  # must not raise
        self.assertEqual(s.combo_remove_dev.values, [])
        self.assertEqual(s.remove_dev_var.get(), "")


class RemoveLabelTest(unittest.TestCase):
    def test_label_is_the_short_wording(self):
        self.assertEqual(STRINGS["pl"]["remove_ip_label"], "IP do usunięcia:")
        self.assertEqual(STRINGS["en"]["remove_ip_label"], "IP to remove:")


if __name__ == "__main__":
    unittest.main()
