"""GUI smoke test for the Remove-IP tab. Skips without tkinter/display."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter as tk
    from tkinter import ttk
    _HAS_TK = True
except Exception:  # headless container without tkinter
    _HAS_TK = False

from i18n import STRINGS


@unittest.skipUnless(_HAS_TK, "tkinter not available")
class RemoveTabBuildTest(unittest.TestCase):
    """Build the tab on a bare root and check every widget gets a label."""

    def _host(self, root):
        from tab_remove import RemoveTabMixin

        class Host(RemoveTabMixin):
            pass

        h = Host()
        h.nb = ttk.Notebook(root)
        h.lang = "en"
        h.dhcp_var = tk.StringVar(value="")
        h._remove_acls = {}
        h._remove_host = ""
        h._remove_proposal = ""
        h._remove_fetching = False
        h._remove_previewing = False
        h._dhcp_cache = {}
        h.T = lambda key: STRINGS[h.lang].get(key, key)
        h.status = tk.StringVar(value="")
        h.clipboard_clear = lambda: None
        h.clipboard_append = lambda _t: None
        h._toast = lambda *_a: None
        return h

    def test_builds_and_labels_in_both_languages(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"no display: {exc}")
        try:
            root.withdraw()
            h = self._host(root)

            for lang in ("en", "pl"):
                h.lang = lang
                if not hasattr(h, "tab_remove"):
                    h._build_remove_tab()
                h._apply_remove_language()

                self.assertTrue(h.btn_remove_fetch.cget("text"))
                self.assertTrue(h.btn_remove_preview.cget("text"))
                self.assertTrue(h.lbl_remove_ip.cget("text"))
                self.assertTrue(h.chk_remove_owner.cget("text"))
                self.assertTrue(h.lbl_remove_cur.cget("text"))
                self.assertTrue(h.lbl_remove_prop.cget("text"))

            # tab registered in the notebook with a non-empty title
            self.assertIn(h.tab_remove, h.nb.tabs())
            self.assertTrue(h.nb.tab(h.tab_remove, "text"))
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    def test_strings_exist_in_both_languages(self):
        need = ("tab_remove", "remove_dev_label", "remove_acl_label",
                "remove_all_label", "remove_ip_label", "remove_owner_label",
                "remove_current_label", "remove_proposal_label",
                "remove_preview_btn", "remove_need_dev", "remove_need_fetch",
                "remove_need_acl", "remove_fetching", "remove_stats",
                "remove_stats_noowner", "remove_nothing", "remove_warn_hdr",
                "remove_unsequenced")
        for lang in ("en", "pl"):
            for key in need:
                self.assertIn(key, STRINGS[lang], f"{lang}: {key}")
                self.assertTrue(STRINGS[lang][key].strip(), f"{lang}: {key}")

    def test_render_summary_uses_owner(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"no display: {exc}")
        try:
            root.withdraw()
            h = self._host(root)
            h._build_remove_tab()
            h._apply_remove_language()
            h._render_remove({"script": "ip access-list extended X\nno 20\n",
                              "removed": 1, "removed_remarks": 2,
                              "acls_hit": ["X"], "owner": "Jan Kowalski",
                              "covers": [], "unsequenced": []}, "10.0.0.5")
            self.assertIn("Jan Kowalski", h.lbl_remove_stats.cget("text"))
            self.assertIn("10.0.0.5", h.lbl_remove_stats.cget("text"))
            self.assertEqual(h.lbl_remove_warn.cget("text"), "")

            h._render_remove({"script": "", "removed": 0,
                              "removed_remarks": 0, "acls_hit": [],
                              "owner": "", "covers": ["X: permit ip 10.0.0.0 0.0.0.255"],
                              "unsequenced": []}, "10.0.0.5")
            self.assertIn("10.0.0.5", h.lbl_remove_stats.cget("text"))
            self.assertIn("0.0.0.255", h.lbl_remove_warn.cget("text"))
        finally:
            try:
                root.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
