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
        h._remove_fetched = {}
        h._remove_blocks = []
        h._remove_fetching = False
        h._remove_previewing = False
        h._dhcp_cache = {}
        h.devices = [{"host": "10.0.0.1", "hostname": "sw-a"},
                     {"host": "10.0.0.2", "hostname": "sw-b"}]
        h.dev_label = lambda d: f"{d.get('hostname')} {d.get('host')}".strip()
        h._lookup_device = lambda sel: next(
            (d for d in h.devices if d.get("host") == (sel or "").strip()
             or h.dev_label(d) == (sel or "").strip()), None)
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
                self.assertTrue(h.btn_remove_copy.cget("text"))
                self.assertTrue(h.lbl_remove_ip.cget("text"))
                self.assertTrue(h.chk_remove_owner.cget("text"))
                self.assertTrue(h.lbl_remove_cur.cget("text"))
                self.assertTrue(h.lbl_remove_prop.cget("text"))

            self.assertIn(str(h.tab_remove), h.nb.tabs())
            self.assertTrue(h.nb.tab(h.tab_remove, "text"))
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    def test_device_list_is_multi_select(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"no display: {exc}")
        try:
            root.withdraw()
            h = self._host(root)
            h._build_remove_tab()
            self.assertEqual(str(h.list_remove_dev.cget("selectmode")),
                             "extended")
        finally:
            try:
                root.destroy()
            except Exception:
                pass

    def test_builds_one_block_per_device_with_own_copy(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"no display: {exc}")
        try:
            root.withdraw()
            h = self._host(root)
            h._build_remove_tab()
            h._apply_remove_language()

            res = {"blocks": [
                {"host": "10.0.0.1", "label": "sw-a 10.0.0.1",
                 "script": "ip access-list extended CAM-IN\nno 20\n",
                 "removed": 1, "removed_remarks": 2,
                 "acls_hit": ["CAM-IN"], "covers": [], "unsequenced": []},
                {"host": "10.0.0.2", "label": "sw-b 10.0.0.2",
                 "script": "ip access-list extended CAM-IN\nno 30\n",
                 "removed": 1, "removed_remarks": 2,
                 "acls_hit": ["CAM-IN"], "covers": [], "unsequenced": []},
            ], "removed": 2, "removed_remarks": 4, "covers": [],
                "unsequenced": [], "owner": "Jan Kowalski",
                "hosts_hit": ["10.0.0.1", "10.0.0.2"], "skipped": []}

            h._render_remove_result(res, "10.0.0.50")
            root.update_idletasks()

            frames = [w for w in h._remove_blocks_frame.winfo_children()
                      if isinstance(w, ttk.LabelFrame)]
            self.assertEqual(len(frames), 2)
            self.assertIn("sw-a", str(frames[0].cget("text")))
            self.assertIn("sw-b", str(frames[1].cget("text")))
            # each block owns a Copy button
            for fr in frames:
                btns = [w for w in fr.winfo_children()
                        if isinstance(w, ttk.Frame)]
                self.assertTrue(btns)
                self.assertTrue(any(isinstance(c, ttk.Button)
                                    for c in btns[0].winfo_children()))
            self.assertIn("Jan Kowalski", h.lbl_remove_stats.cget("text"))
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
                "remove_unsequenced", "remove_copy_all", "remove_copy_block",
                "remove_block_stats", "remove_selected_n",
                "remove_no_selection", "remove_skipped", "remove_acl_absent",
                "remove_partial_fail")
        for lang in ("en", "pl"):
            for key in need:
                self.assertIn(key, STRINGS[lang], f"{lang}: {key}")
                self.assertTrue(STRINGS[lang][key].strip(), f"{lang}: {key}")

    def test_render_summary_reports_nothing_to_do(self):
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"no display: {exc}")
        try:
            root.withdraw()
            h = self._host(root)
            h._build_remove_tab()
            h._apply_remove_language()
            h._render_remove_result(
                {"blocks": [], "removed": 0, "removed_remarks": 0,
                 "covers": ["sw-a: permit ip 10.0.0.0 0.0.0.255"],
                 "unsequenced": [], "owner": "", "hosts_hit": [],
                 "skipped": []}, "10.0.0.5")
            self.assertIn("10.0.0.5", h.lbl_remove_stats.cget("text"))
            self.assertIn("0.0.0.255", h.lbl_remove_warn.cget("text"))
        finally:
            try:
                root.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
