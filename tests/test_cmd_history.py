"""Tests for the session command history (audit trail). Headless-safe."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import App
from i18n import STRINGS


def make_stub(lang="en"):
    stub = types.SimpleNamespace(lang=lang)
    stub.T = types.MethodType(App.T, stub)
    stub._log_cmds = types.MethodType(App._log_cmds, stub)
    stub._collect_cmd_history = types.MethodType(
        App._collect_cmd_history, stub)
    return stub


class LogTest(unittest.TestCase):
    def test_entries_accumulate(self):
        stub = make_stub()
        stub._log_cmds("10.0.0.1", "fix", ["conf t", "no ip http server"],
                       "tls/http")
        stub._log_cmds("10.0.0.1", "save", ["write memory"], "tls")
        self.assertEqual(len(stub.cmd_history), 2)
        first, second = stub.cmd_history
        self.assertEqual(first["host"], "10.0.0.1")
        self.assertEqual(first["kind"], "fix")
        self.assertEqual(first["detail"], "tls/http")
        self.assertEqual(first["cmds"], ["conf t", "no ip http server"])
        self.assertRegex(first["ts"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        self.assertEqual(second["kind"], "save")

    def test_missing_history_attr_created(self):
        stub = types.SimpleNamespace()
        stub._log_cmds = types.MethodType(App._log_cmds, stub)
        stub._log_cmds("h", "rollback", ["no ip http server"])
        self.assertEqual(len(stub.cmd_history), 1)


class CollectTest(unittest.TestCase):
    def test_empty_history(self):
        self.assertEqual(make_stub()._collect_cmd_history(), "")

    def test_paste_ready_format(self):
        stub = make_stub()
        stub._log_cmds("10.0.0.1", "fix", ["no ip http server"], "tls/http")
        stub._log_cmds("10.0.0.2", "rollback", ["ip http server"])
        text = stub._collect_cmd_history()
        lines = text.splitlines()
        self.assertRegex(lines[0],
                         r"^# \d{4}-\d{2}-\d{2} .* \| 10\.0\.0\.1 \| fix "
                         r"\(tls/http\)$")
        self.assertEqual(lines[1], "no ip http server")
        self.assertIn("| 10.0.0.2 | rollback", lines[2])
        self.assertNotIn("(", lines[2].split("|")[-1])
        self.assertEqual(lines[3], "ip http server")


class I18nTest(unittest.TestCase):
    def test_history_keys_both_languages(self):
        for lang in ("en", "pl"):
            for key in ("cmd_hist_btn", "cmd_hist_title", "cmd_hist_empty"):
                self.assertTrue(STRINGS[lang].get(key, "").strip(), key)


if __name__ == "__main__":
    unittest.main()
