"""Regression: the Remove-IP preview must match the selected devices.

Reported: fetch ACLs from switch A, enter an IP, select switch B and press
"Preview" - the app still showed A's removals, i.e. a script for the wrong
switch. Fetched ACLs live in memory and changing the selection never
re-fetched them, so nothing tied the data to a device.
"""

import os
import sys
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


class _Label:
    def __init__(self):
        self.text = ""

    def configure(self, **kw):
        if "text" in kw:
            self.text = kw["text"]


class _Frame:
    def winfo_children(self):
        return []


class _Listbox:
    def __init__(self, labels, selected=()):
        self.labels = list(labels)
        self.sel = list(selected)

    def curselection(self):
        return tuple(self.sel)

    def get(self, i):
        return self.labels[i]


class _Host(RemoveTabMixin):
    """Real mixin instance: state helpers resolve through the class."""


DEVS = [{"host": "10.0.0.1", "hostname": "sw-a"},
        {"host": "10.0.0.2", "hostname": "sw-b"}]
LABELS = ["sw-a 10.0.0.1", "sw-b 10.0.0.2"]


def _host(selected=(0,), ip="10.0.0.50"):
    h = _Host()
    h.devices = [dict(d) for d in DEVS]
    h.dev_label = lambda d: f"{d.get('hostname')} {d.get('host')}".strip()
    h._lookup_device = lambda sel: next(
        (d for d in h.devices
         if d.get("host") == (sel or "").strip()
         or h.dev_label(d) == (sel or "").strip()), None)
    h._remove_dev_labels = list(LABELS)
    h.list_remove_dev = _Listbox(LABELS, selected)
    h.lbl_remove_sel = _Label()
    h.remove_acl_var = _Var("CAM-IN")
    h.remove_all_var = _Var(False)
    h.remove_owner_var = _Var(False)
    h.remove_block_var = _Var(False)
    h.dhcp_var = _Var("")
    h.ent_remove_ip = type("E", (), {"get": staticmethod(lambda: ip)})()
    h.combo_remove_acl = _Widget()
    h.lbl_remove_stats = _Label()
    h.lbl_remove_warn = _Label()
    h._remove_blocks_frame = _Frame()
    h._remove_fetched = {}
    h._remove_blocks = []
    h._remove_previewing = False
    h._remove_fetching = False
    h._dhcp_cache = {}
    h.lang = "pl"
    h.T = lambda key: STRINGS[h.lang].get(key, key)
    h._set_remove_cur = lambda _c: None
    h._toggle_remove_all = lambda: None
    h._clear_remove_blocks = lambda: None
    h._valid_ip = lambda s: s.count(".") == 3
    h._require_unlocked = lambda: True
    return h


ACLS = {"CAM-IN": ["10 remark Jan Kowalski",
                   "20 permit ip host 10.0.0.50 host 10.0.0.201",
                   "30 remark Jan Kowalski (koniec)"]}


def _fetched_from(host, label):
    return {host: {"label": label, "acls": {k: list(v) for k, v in ACLS.items()}}}


class StaleDeviceTest(unittest.TestCase):
    def test_current_for_the_fetched_device(self):
        h = _host(selected=(0,))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        self.assertTrue(RemoveTabMixin._remove_state_is_current(h))

    def test_stale_after_selecting_another_device(self):
        h = _host(selected=(1,))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        self.assertFalse(RemoveTabMixin._remove_state_is_current(h))

    def test_stale_when_selection_adds_a_device(self):
        h = _host(selected=(0, 1))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        self.assertFalse(RemoveTabMixin._remove_state_is_current(h))

    def test_current_for_an_ha_pair(self):
        h = _host(selected=(0, 1))
        h._remove_fetched = {
            "10.0.0.1": {"label": "sw-a 10.0.0.1", "acls": dict(ACLS)},
            "10.0.0.2": {"label": "sw-b 10.0.0.2", "acls": dict(ACLS)},
        }
        self.assertTrue(RemoveTabMixin._remove_state_is_current(h))

    def test_preview_refuses_stale_state(self):
        h = _host(selected=(1,))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        shown = []
        import tab_remove
        real = tab_remove.messagebox.showwarning
        tab_remove.messagebox.showwarning = lambda *a, **k: shown.append(a)
        try:
            RemoveTabMixin.preview_remove(h)
        finally:
            tab_remove.messagebox.showwarning = real
        self.assertTrue(shown, "expected a warning, preview must not run")

    def test_switching_device_clears_stale_state(self):
        h = _host(selected=(1,))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        h._remove_blocks = [{"host": "10.0.0.1"}]
        RemoveTabMixin._on_remove_dev_change(h)
        self.assertEqual(h._remove_fetched, {})
        self.assertEqual(h._remove_blocks, [])
        self.assertIn("pobierz ACL", h.lbl_remove_warn.text)

    def test_same_selection_keeps_state(self):
        h = _host(selected=(0,))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        RemoveTabMixin._on_remove_dev_change(h)
        self.assertTrue(h._remove_fetched)

    def test_blocked_before_any_fetch(self):
        h = _host(selected=(0,))
        self.assertFalse(RemoveTabMixin._remove_state_is_current(h))

    def test_preview_runs_for_the_fetched_device(self):
        h = _host(selected=(0,))
        h._remove_fetched = _fetched_from("10.0.0.1", "sw-a 10.0.0.1")
        captured = []
        h._render_remove_result = lambda res, ip: captured.append((res, ip))
        RemoveTabMixin.preview_remove(h)
        self.assertTrue(captured, "preview should render")
        res = captured[0][0]
        self.assertEqual(len(res["blocks"]), 1)
        self.assertIn("no 20", res["blocks"][0]["script"])

    def test_preview_builds_one_block_per_device(self):
        h = _host(selected=(0, 1))
        h._remove_fetched = {
            "10.0.0.1": {"label": "sw-a 10.0.0.1", "acls": dict(ACLS)},
            "10.0.0.2": {"label": "sw-b 10.0.0.2", "acls": dict(ACLS)},
        }
        captured = []
        h._render_remove_result = lambda res, ip: captured.append((res, ip))
        RemoveTabMixin.preview_remove(h)
        blocks = captured[0][0]["blocks"]
        self.assertEqual([b["label"] for b in blocks],
                         ["sw-a 10.0.0.1", "sw-b 10.0.0.2"])
        for b in blocks:
            self.assertIn("no 20", b["script"])


class StaleMessageTest(unittest.TestCase):
    def test_message_exists_in_both_languages(self):
        for lang in ("en", "pl"):
            self.assertIn("remove_stale_device", STRINGS[lang])
            self.assertTrue(STRINGS[lang]["remove_stale_device"].strip())


if __name__ == "__main__":
    unittest.main()
