"""Regression: the Remove-IP preview must match the selected device.

Reported: fetch ACLs from switch A, enter an IP, switch the device dropdown
to switch B and press "Preview" - the app still showed A's removals, i.e. a
script for the wrong switch. Fetched ACLs live in memory and changing the
dropdown never re-fetched them, so nothing tied the data to a device.
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from i18n import STRINGS
from tab_remove import RemoveTabMixin


class _Var:
    def __init__(self, value=""):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class _Widget:
    def __init__(self):
        self.state = "normal"

    def configure(self, **kw):
        if "state" in kw:
            self.state = kw["state"]

    def cget(self, key):
        return ""


class _Labels(_Widget):
    def __init__(self):
        super().__init__()
        self.text = ""

    def configure(self, **kw):
        super().configure(**kw)
        if "text" in kw:
            self.text = kw["text"]


def _host(devices, current="sw-a 10.0.0.1"):
    """Host exposing what the preview/state logic touches."""
    h = types.SimpleNamespace()
    h.devices = [dict(d) for d in devices]
    h.dev_label = lambda d: f"{d.get('hostname')} {d.get('host')}".strip()
    h._lookup_device = lambda sel: next(
        (d for d in h.devices
         if d.get("host") == (sel or "").strip()
         or h.dev_label(d) == (sel or "").strip()), None)
    h.remove_dev_var = _Var(current)
    h.remove_acl_var = _Var("CAM-IN")
    h.remove_all_var = _Var(False)
    h.ent_remove_ip = types.SimpleNamespace(get=lambda: "10.0.0.50")
    h.combo_remove_acl = _Widget()
    h.lbl_remove_stats = _Labels()
    h.lbl_remove_warn = _Labels()
    h._remove_acls = {}
    h._remove_host = ""
    h._remove_proposal = ""
    h._remove_previewing = False
    h._remove_fetching = False
    h._dhcp_cache = {}
    h.dhcp_var = _Var("")
    h.lang = "pl"
    h.T = lambda key: STRINGS[h.lang].get(key, key)
    h._set_remove_cur = lambda _c: None
    h._set_remove_prop = lambda c: setattr(h, "_remove_proposal", c)
    h._toggle_remove_all = lambda: None
    h._valid_ip = lambda s: s.count(".") == 3
    h._require_unlocked = lambda: True
    return h


DEVS = [{"host": "10.0.0.1", "hostname": "sw-a"},
        {"host": "10.0.0.2", "hostname": "sw-b"}]


class StaleDeviceTest(unittest.TestCase):
    def _fetched_from_a(self):
        h = _host(DEVS)
        h._remove_acls = {
            "CAM-IN": ["10 remark Jan Kowalski",
                       "20 permit ip host 10.0.0.50 host 10.0.0.201",
                       "30 remark Jan Kowalski (koniec)"]}
        h._remove_host = "10.0.0.1"  # fetched from switch A
        return h

    def test_state_is_current_for_the_same_device(self):
        h = self._fetched_from_a()
        self.assertTrue(RemoveTabMixin._remove_state_is_current(h))

    def test_state_is_stale_after_switching_device(self):
        h = self._fetched_from_a()
        h.remove_dev_var.set("sw-b 10.0.0.2")
        self.assertFalse(RemoveTabMixin._remove_state_is_current(h))

    def test_preview_refuses_stale_state(self):
        h = self._fetched_from_a()
        h.remove_dev_var.set("sw-b 10.0.0.2")

        shown = []
        import tab_remove
        real = tab_remove.messagebox.showwarning
        tab_remove.messagebox.showwarning = lambda *a, **k: shown.append(a)
        try:
            RemoveTabMixin.preview_remove(h)
        finally:
            tab_remove.messagebox.showwarning = real

        self.assertTrue(shown, "expected a warning, preview must not run")
        self.assertEqual(h._remove_proposal, "")

    def test_switching_device_clears_stale_preview(self):
        h = self._fetched_from_a()
        h._remove_proposal = "ip access-list extended CAM-IN\nno 20\n"
        h.remove_dev_var.set("sw-b 10.0.0.2")

        RemoveTabMixin._on_remove_dev_change(h)

        self.assertEqual(h._remove_acls, {})
        self.assertEqual(h._remove_host, "")
        self.assertEqual(h._remove_proposal, "")
        self.assertIn("pobierz ACL", h.lbl_remove_warn.text)

    def test_staying_on_the_same_device_keeps_state(self):
        h = self._fetched_from_a()
        RemoveTabMixin._on_remove_dev_change(h)
        self.assertTrue(h._remove_acls)          # not wiped
        self.assertEqual(h._remove_host, "10.0.0.1")

    def test_blocked_before_any_fetch(self):
        h = _host(DEVS)
        self.assertFalse(RemoveTabMixin._remove_state_is_current(h))

    def test_preview_works_for_the_fetched_device(self):
        h = self._fetched_from_a()

        class _Entry:
            def get(self):
                return "10.0.0.50"

        h.ent_remove_ip = _Entry()
        RemoveTabMixin.preview_remove(h)
        self.assertIn("CAM-IN", h._remove_proposal)
        self.assertIn("no 20", h._remove_proposal)


class StaleMessageTest(unittest.TestCase):
    def test_message_exists_in_both_languages(self):
        for lang in ("en", "pl"):
            self.assertIn("remove_stale_device", STRINGS[lang])
            self.assertTrue(STRINGS[lang]["remove_stale_device"].strip())


if __name__ == "__main__":
    unittest.main()
