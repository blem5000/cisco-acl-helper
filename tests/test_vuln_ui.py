"""Tests for the vuln results coloring and the audit-toggle click handler.

Needs a display; skipped headlessly (CI) via HAS_DISPLAY.
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter as tk
    from tkinter import ttk
    _root = tk.Tk()
    _root.withdraw()
    _root.destroy()
    HAS_DISPLAY = True
except Exception:
    HAS_DISPLAY = False
    tk = None
    ttk = None

if HAS_DISPLAY:
    from app import App


@unittest.skipUnless(HAS_DISPLAY, "no display")
class AuditClickTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.geometry("600x300+5000+5000")
        self.root.deiconify()
        self.tree = ttk.Treeview(
            self.root, columns=("audit", "hostname", "host"),
            show="headings", height=5)
        self.tree.pack(fill="both", expand=True)
        self.tree.column("audit", width=44, minwidth=44, stretch=False,
                         anchor="center")
        self.tree.heading("audit", text="\u2713")
        for c in ("hostname", "host"):
            self.tree.heading(c, text=c)
        self.devices = [{"hostname": f"sw{i}", "host": f"10.0.0.{i + 1}"}
                        for i in range(3)]
        for d in self.devices:
            mark = "\u2611" if d.get("audit", True) else "\u2610"
            self.tree.insert("", "end",
                             values=(mark, d["hostname"], d["host"]))
        self.root.update_idletasks()
        self.root.update()
        self.calls = []
        self.fake = types.SimpleNamespace(
            tree=self.tree, devices=self.devices,
            persist_store=lambda: None,
            refresh_tree=lambda: self.calls.append("refresh"),
        )
        self.fake._toggle_audit_at = types.MethodType(
            App._toggle_audit_at, self.fake)
        self.ev = types.SimpleNamespace(x=0, y=0)

    def tearDown(self):
        self.root.destroy()

    def _click(self, row_idx, column):
        row = self.tree.get_children()[row_idx]
        bb = self.tree.bbox(row, column)
        self.assertTrue(bb, "no cell geometry")
        self.ev.x, self.ev.y = bb[0] + 3, bb[1] + 3
        App._on_dev_click(self.fake, self.ev)

    def test_audit_cell_toggles(self):
        self._click(1, "audit")
        self.assertIs(self.devices[1].get("audit"), False)
        self.assertEqual(self.calls, ["refresh"])

    def test_other_cell_ignored(self):
        self._click(1, "hostname")
        self.assertNotIn("audit", self.devices[1])
        self.assertEqual(self.calls, [])


@unittest.skipUnless(HAS_DISPLAY, "no display")
class ProgressStyleTest(unittest.TestCase):
    def test_custom_styles_apply(self):
        root = tk.Tk()
        root.geometry("400x200+5000+5000")
        root.deiconify()
        try:
            st = ttk.Style(root)
            st.configure("VulnWork.Horizontal.TProgressbar",
                         background="gold", thickness=18)
            st.configure("VulnDone.Horizontal.TProgressbar",
                         background="green", thickness=18)
            pb = ttk.Progressbar(root, mode="indeterminate", length=220,
                                 style="VulnWork.Horizontal.TProgressbar")
            pb.pack()
            pb.start(12)
            root.update()
            pb.stop()
            pb.configure(mode="determinate",
                         style="VulnDone.Horizontal.TProgressbar",
                         maximum=3, value=3)
            root.update()
            self.assertEqual(pb.cget("value"), 3)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
