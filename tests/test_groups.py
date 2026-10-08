"""Tests for automatic grouping by regex. Headless-safe."""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import groups


class SuggestRegexTest(unittest.TestCase):
    def test_default_pattern(self):
        pat = groups.DEFAULT_PATTERN
        self.assertEqual(groups.suggest_group_regex(
            "MA1_2F_3_5_96105_O.lgema.local", pat), "MA1_2F_3")
        self.assertEqual(groups.suggest_group_regex(
            "LGEMA_CORE_P", pat), "LGEMA_CORE_P")

    def test_group1_else_whole_match(self):
        self.assertEqual(groups.suggest_group_regex("ab-12-cd", r"^(\w+)"),
                         "ab")
        self.assertEqual(groups.suggest_group_regex("ab-12-cd", r"^\w+"),
                         "ab")

    def test_no_match_and_bad_pattern(self):
        self.assertEqual(groups.suggest_group_regex("abc", r"^Z+"), "")
        with self.assertRaises(re.error):
            groups.suggest_group_regex("abc", r"([unclosed")


class AutoAssignRegexTest(unittest.TestCase):
    DEVS = [{"host": "10.0.0.1", "hostname": "MA1_2F_3_S1", "group": ""},
            {"host": "10.0.0.2", "hostname": "MA1_2F_3_S2",
             "group": "Recznie"},
            {"host": "10.0.0.3", "hostname": "inne", "group": ""},
            {"host": "", "hostname": "MA1_2F_3_S4", "group": ""}]

    def test_only_empty_keeps_manual(self):
        got = groups.auto_assign_regex(self.DEVS, "hostname",
                                       groups.DEFAULT_PATTERN, True)
        self.assertEqual(got, {"10.0.0.1": "MA1_2F_3"})

    def test_overwrite_all(self):
        got = groups.auto_assign_regex(self.DEVS, "hostname",
                                       groups.DEFAULT_PATTERN, False)
        self.assertEqual(got, {"10.0.0.1": "MA1_2F_3",
                               "10.0.0.2": "MA1_2F_3"})

    def test_bad_pattern_raises(self):
        with self.assertRaises(re.error):
            groups.auto_assign_regex(self.DEVS, "hostname", r"([", True)


if __name__ == "__main__":
    unittest.main()
