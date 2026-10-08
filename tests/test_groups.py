"""Tests for automatic grouping by hostname/label. Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import groups


class SuggestGroupTest(unittest.TestCase):
    def test_prefix_parts(self):
        self.assertEqual(groups.suggest_group(
            "MA1_2F_3_5_96105_O.lgema.local", "._-", 2), "MA1_2F")
        self.assertEqual(groups.suggest_group(
            "MA1_2F_3_5_96105_O.lgema.local", "._-", 1), "MA1")
        self.assertEqual(groups.suggest_group(
            "LGEMA_CORE_P", "_", 2), "LGEMA_CORE")

    def test_short_and_empty(self):
        self.assertEqual(groups.suggest_group("SW1", "._-", 3), "SW1")
        self.assertEqual(groups.suggest_group("", "._-", 2), "")
        self.assertEqual(groups.suggest_group("___", "._-", 2), "")
        self.assertEqual(groups.suggest_group("SW1", "._-", 0), "")

    def test_ip_source(self):
        self.assertEqual(groups.suggest_group("10.207.96.2", ".", 2),
                         "10_207")


class AutoAssignTest(unittest.TestCase):
    DEVS = [{"host": "10.0.0.1", "hostname": "MA1_2F_S1", "group": ""},
            {"host": "10.0.0.2", "hostname": "MA1_2F_S2",
             "group": "Recznie"},
            {"host": "10.0.0.3", "hostname": "", "group": ""},
            {"host": "", "hostname": "MA1_2F_S4", "group": ""}]

    def test_only_empty_keeps_manual(self):
        got = groups.auto_assign(self.DEVS, "hostname", "_", 2, True)
        self.assertEqual(got, {"10.0.0.1": "MA1_2F"})
        # no suggestion for empty hostname, no host, manual kept

    def test_overwrite_all(self):
        got = groups.auto_assign(self.DEVS, "hostname", "_", 2, False)
        self.assertEqual(got, {"10.0.0.1": "MA1_2F",
                               "10.0.0.2": "MA1_2F"})

    def test_host_source(self):
        devs = [{"host": "10.207.96.2", "hostname": "x", "group": ""}]
        got = groups.auto_assign(devs, "host", ".", 2, True)
        self.assertEqual(got, {"10.207.96.2": "10_207"})


if __name__ == "__main__":
    unittest.main()
