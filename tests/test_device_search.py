"""Tests for device quick-search (mRemoteNG style). Headless-safe."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tab_devices import DevicesTabMixin

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SearchHitsTest(unittest.TestCase):
    DEVS = [{"hostname": "MA1_2F_S1", "group": "MA1_2F_3",
             "host": "10.207.96.2", "username": "admin"},
            {"hostname": "LGEMA_CORE_P", "group": "", "host": "10.207.96.5",
             "username": "admin"},
            {"hostname": "kamerka", "group": "MA1_2F_3", "host": "10.0.0.9",
             "username": "user"}]

    def test_substring_case_insensitive(self):
        hits = DevicesTabMixin.search_device_hits
        self.assertEqual(hits(self.DEVS, "ma1"), [0, 2])
        self.assertEqual(hits(self.DEVS, "10.207.96"), [0, 1])
        self.assertEqual(hits(self.DEVS, "LGEMA"), [1])
        self.assertEqual(hits(self.DEVS, "user"), [2])
        self.assertEqual(hits(self.DEVS, "brak"), [])
        self.assertEqual(hits(self.DEVS, ""), [])
        self.assertEqual(hits([], "ma1"), [])


class TabStructureTest(unittest.TestCase):
    def test_apply_only_uses_widgets_built_at_startup(self):
        # same regression class as the ports tab crash: everything
        # _apply_devices_language touches must exist after _build_devices_tab
        with open(os.path.join(REPO, "tab_devices.py"),
                  encoding="utf-8") as f:
            tree = ast.parse(f.read())
        methods = {n.name: n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)}
        built = set()
        for n in ast.walk(methods["_build_devices_tab"]):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and n.value.id == "self" and isinstance(n.ctx, ast.Store):
                built.add(n.attr)
        used = set()
        for n in ast.walk(methods["_apply_devices_language"]):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                    and n.value.id == "self" and isinstance(n.ctx, ast.Load):
                used.add(n.attr)
        self.assertEqual(used - built, {"lang"})


if __name__ == "__main__":
    unittest.main()
