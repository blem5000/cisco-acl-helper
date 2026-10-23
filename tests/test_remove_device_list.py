"""Regression: the Remove-IP device list is populated and multi-select.

_refresh_gen_devices() is the single place that repopulates the per-tab
device widgets. The Remove-IP tab uses a multi-select Listbox (so an HA
pair can be cleaned up in one go), which must be filled there and must
keep the current selection when devices change.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter as tk
    _HAS_TK = True
except Exception:  # headless container without tkinter
    _HAS_TK = False

from i18n import STRINGS
from tab_gen import GeneratorTabMixin


class _Combo:
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


class _Label:
    def __init__(self):
        self.text = ""

    def configure(self, **kw):
        if "text" in kw:
            self.text = kw["text"]


class _Listbox:
    """Minimal Listbox stand-in (works without a display)."""

    def __init__(self, labels=(), selected=()):
        self.labels = list(labels)
        self.sel = list(selected)

    def curselection(self):
        return tuple(self.sel)

    def get(self, i):
        return self.labels[i]

    def delete(self, *_a):
        self.labels = []

    def insert(self, _index, value):
        self.labels.append(value)

    def selection_set(self, i):
        if i not in self.sel:
            self.sel.append(i)


def _stub(devices, selected=()):
    from tab_gen import GeneratorTabMixin
    from tab_remove import RemoveTabMixin

    class Host(RemoveTabMixin, GeneratorTabMixin):
        pass

    s = Host()
    s.devices = [dict(d) for d in devices]
    s.only_l3_var = _Var(False)
    s.dev_label = lambda d: (
        f"{d.get('hostname')} {d.get('host')}".strip()
        if d.get("hostname") else d.get("host", ""))
    for n in ("gen", "track", "audit", "sub", "ports"):
        setattr(s, f"combo_{n}_dev", _Combo())
        setattr(s, f"{n}_dev_var", _Var(""))
    s.list_remove_dev = _Listbox(selected=selected)
    s._remove_dev_labels = []
    s.lbl_remove_sel = _Label()
    s.lang = "pl"
    s.T = lambda key: STRINGS[s.lang].get(key, key)
    s._lookup_device = lambda sel: next(
        (d for d in s.devices
         if d.get("host") == (sel or "").strip()
         or s.dev_label(d) == (sel or "").strip()), None)
    s._track_visible_devices = lambda: [
        d for d in s.devices if d.get("l3") and d.get("ha_role") != "secondary"]
    s._refresh_ports_groups = lambda: None
    s._refresh_vuln_devices = lambda: None
    return s


class RefreshRemoveDevicesTest(unittest.TestCase):
    def test_list_is_filled(self):
        s = _stub([{"host": "10.0.0.1", "hostname": "sw1"},
                   {"host": "10.0.0.2", "hostname": "sw2"}])
        GeneratorTabMixin._refresh_gen_devices(s)
        self.assertEqual(s.list_remove_dev.labels,
                         ["sw1 10.0.0.1", "sw2 10.0.0.2"])
        self.assertEqual(s._remove_dev_labels,
                         ["sw1 10.0.0.1", "sw2 10.0.0.2"])

    def test_selection_survives_a_refresh(self):
        devs = [{"host": "10.0.0.1", "hostname": "sw1"},
                {"host": "10.0.0.2", "hostname": "sw2"}]
        s = _stub(devs)
        GeneratorTabMixin._refresh_gen_devices(s)
        # user picks the second switch (an HA pair in practice)
        s.list_remove_dev.sel = [1]
        GeneratorTabMixin._refresh_gen_devices(s)
        self.assertEqual(s.list_remove_dev.sel, [1])
        self.assertEqual(s.list_remove_dev.get(1), "sw2 10.0.0.2")

    def test_hint_shows_selection_count(self):
        s = _stub([{"host": "10.0.0.1", "hostname": "sw1"}])
        GeneratorTabMixin._refresh_gen_devices(s)
        self.assertIn("nic nie wybrano", s.lbl_remove_sel.text)
        s.list_remove_dev.sel = [0]
        GeneratorTabMixin._refresh_gen_devices(s)
        self.assertIn("1", s.lbl_remove_sel.text)

    def test_empty_device_list_is_safe(self):
        s = _stub([])
        GeneratorTabMixin._refresh_gen_devices(s)  # must not raise
        self.assertEqual(s.list_remove_dev.labels, [])

    def test_other_tabs_still_filled(self):
        s = _stub([{"host": "10.0.0.1", "hostname": "sw1"}])
        GeneratorTabMixin._refresh_gen_devices(s)
        for n in ("gen", "audit", "sub", "ports"):
            self.assertEqual(getattr(s, f"combo_{n}_dev").values,
                             ["sw1 10.0.0.1"], n)


class RemoveLabelTest(unittest.TestCase):
    def test_label_is_the_short_wording(self):
        self.assertEqual(STRINGS["pl"]["remove_ip_label"], "IP do usunięcia:")
        self.assertEqual(STRINGS["en"]["remove_ip_label"], "IP to remove:")


if __name__ == "__main__":
    unittest.main()
