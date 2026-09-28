"""Tests for the unsecured HTTP(S) server check (vuln_tls). Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vuln_tls as v
from i18n import STRINGS

BOTH_ON = "ip http server\nip http secure-server\n"
HTTP_ONLY = "ip http server\n"
NONE_ON = "no ip http server\nno ip http secure-server\n"
FLIP_FLOP = "ip http server\nno ip http server\nip http secure-server\n"

IOS_SW = ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
          "Version 15.2(2)E7, RELEASE SOFTWARE (fc4)")
WLC_VER = ("Cisco Catalyst 9800 Series Wireless Controller, "
           "Version 17.06.01")


class AnalyzeTest(unittest.TestCase):
    def test_compliant_when_off(self):
        r = v.analyze_tls(NONE_ON, IOS_SW)
        self.assertTrue(r["compliant"])
        self.assertEqual(r["proposal"], "")
        self.assertFalse(v.needs_apply(r))

    def test_empty_config_compliant(self):
        r = v.analyze_tls("", "")
        self.assertTrue(r["compliant"])
        self.assertFalse(v.needs_apply(r))

    def test_both_on(self):
        r = v.analyze_tls(BOTH_ON, IOS_SW)
        self.assertFalse(r["compliant"])
        self.assertTrue(v.needs_apply(r))
        self.assertIn("no ip http server", r["proposal"])
        self.assertIn("no ip http secure-server", r["proposal"])
        self.assertEqual([t["service"] for t in v.apply_targets(r)],
                         ["http", "secure"])

    def test_last_occurrence_wins(self):
        r = v.analyze_tls(FLIP_FLOP, IOS_SW)
        self.assertFalse(r["compliant"])
        self.assertEqual([t["service"] for t in v.apply_targets(r)],
                         ["secure"])

    def test_negated_lines_ignored(self):
        r = v.analyze_tls("no ip http server\n", IOS_SW)
        self.assertTrue(r["compliant"])


class WlcTest(unittest.TestCase):
    def test_wlc_skipped_with_note(self):
        r = v.analyze_tls(BOTH_ON, WLC_VER)
        self.assertTrue(r["wlc"])
        self.assertFalse(r["compliant"])
        self.assertFalse(v.needs_apply(r))
        self.assertEqual(r["proposal"], "")
        self.assertIn("wlc_excluded", r["issues"])

    def test_wlc_clean_is_compliant(self):
        r = v.analyze_tls(NONE_ON, WLC_VER)
        self.assertTrue(r["compliant"])

    def test_non_wlc_markers(self):
        for ver in ("Cisco IOS XE Software, Version 17.06.01",
                    "Cisco IOS Software, C3560 Software, Version 15.0",
                    ""):
            r = v.analyze_tls(BOTH_ON, ver)
            self.assertFalse(r["wlc"], ver)


class FixRollbackTest(unittest.TestCase):
    def test_fix_commands(self):
        r = v.analyze_tls(BOTH_ON, IOS_SW)
        cmds = v.build_fix_commands(v.apply_targets(r), r)
        self.assertEqual(cmds, ["no ip http server",
                                "no ip http secure-server"])

    def test_rollback_restores_originals(self):
        r = v.analyze_tls(HTTP_ONLY, IOS_SW)
        cmds = v.build_rollback_commands(v.apply_targets(r), r)
        self.assertEqual(cmds, ["ip http server"])

    def test_fix_and_rollback_verified(self):
        dirty = v.analyze_tls(BOTH_ON, IOS_SW)
        targets = v.apply_targets(dirty)
        clean = v.analyze_tls(NONE_ON, IOS_SW)
        self.assertTrue(v.fix_verified(clean, targets))
        self.assertTrue(v.rollback_verified(targets, dirty))
        partial = v.analyze_tls(HTTP_ONLY, IOS_SW)
        self.assertFalse(v.rollback_verified(targets, partial))

    def test_single_group(self):
        r = v.analyze_tls(BOTH_ON, IOS_SW)
        groups = v.split_fix_groups(v.apply_targets(r), r)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "http")


class ExactTitleTest(unittest.TestCase):
    def test_scanner_title_identical_both_languages(self):
        self.assertEqual(v.TITLE, "TLS Version 1.0 Protocol Detection")


class NoteTest(unittest.TestCase):
    def T(self, key):
        return STRINGS["en"].get(key, key)

    def test_wlc_note(self):
        r = v.analyze_tls(BOTH_ON, WLC_VER)
        note = v.openproject_note("10.0.0.9", r, self.T)
        self.assertIn("10.0.0.9", note)
        self.assertIn("WLC", note)
        self.assertIn("ip http secure-server", note)

    def test_no_note_when_fixable(self):
        r = v.analyze_tls(BOTH_ON, IOS_SW)
        self.assertEqual(v.openproject_note("10.0.0.9", r, self.T), "")


if __name__ == "__main__":
    unittest.main()
