"""Tests for the Unencrypted-Telnet analysis (vuln_telnet). Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vuln_telnet as v


OK_CFG = """line con 0
 exec-timeout 5 0
 logging synchronous
line vty 0 4
 login local
 transport input ssh
line vty 5 15
 login local
 transport input ssh"""

BAD_CFG = """line con 0
line vty 0 4
 login
 transport input all
line vty 5 15
 login local"""


class AnalyzeTest(unittest.TestCase):
    def test_compliant(self):
        r = v.analyze_telnet(OK_CFG, "SSH Enabled - version 2.0")
        self.assertTrue(r["compliant"])
        self.assertEqual(r["proposal"], "")
        self.assertTrue(v.needs_apply(r) is False)

    def test_all_plus_missing(self):
        r = v.analyze_telnet(BAD_CFG, "SSH Enabled - version 2.0")
        self.assertFalse(r["compliant"])
        self.assertIn("vty_telnet:0 4:all", r["issues"])
        self.assertIn("vty_missing:5 15", r["issues"])
        self.assertIn("line vty 0 4", r["proposal"])
        self.assertIn("line vty 5 15", r["proposal"])
        self.assertTrue(v.needs_apply(r))

    def test_mixed_ssh_telnet(self):
        r = v.analyze_telnet("line vty 0 4\n transport input telnet ssh",
                             "SSH Enabled - version 2.0")
        self.assertFalse(r["compliant"])
        self.assertTrue(v.needs_apply(r))

    def test_blocked_is_not_compliant_but_has_no_proposal(self):
        r = v.analyze_telnet("line vty 0 4\n transport input none",
                             "SSH Disabled")
        self.assertFalse(r["compliant"])
        self.assertEqual(r["proposal"], "")
        self.assertFalse(v.needs_apply(r))  # nothing auto-appliable

    def test_ssh_disabled_refuses_apply(self):
        r = v.analyze_telnet(BAD_CFG, "SSH Disabled")
        self.assertFalse(r["compliant"])
        self.assertIn("ssh_disabled", r["issues"])
        self.assertFalse(v.needs_apply(r))

    def test_empty(self):
        r = v.analyze_telnet("", "")
        self.assertFalse(r["compliant"])
        self.assertIn("no_vty_found", r["issues"])

    def test_case_insensitive_and_single_range(self):
        r = v.analyze_telnet("LINE VTY 0 15\n TRANSPORT INPUT SSH",
                             "SSH Enabled")
        self.assertTrue(r["compliant"])

    def test_con_aux_telnet_flagged_but_compliant(self):
        r = v.analyze_telnet(
            "line con 0\n transport input telnet\n"
            "line aux 0\n transport input all\n"
            "line vty 0 4\n transport input ssh",
            "SSH Enabled")
        self.assertTrue(r["compliant"])
        self.assertIn("con_telnet:0:telnet", r["issues"])
        self.assertIn("aux_telnet:0:all", r["issues"])

    def test_fallback_from_include_output(self):
        r = v.analyze_telnet("", "SSH Enabled",
                             include_out="line vty 0 4\ntransport input all")
        self.assertFalse(r["compliant"])


class CommandsTest(unittest.TestCase):
    def test_fix_and_rollback(self):
        r = v.analyze_telnet(BAD_CFG, "SSH Enabled")
        targets = v.apply_targets(r)
        self.assertEqual([e["range"] for e in targets], ["0 4", "5 15"])
        self.assertEqual(v.build_fix_commands(targets),
                         ["line vty 0 4", "transport input ssh",
                          "line vty 5 15", "transport input ssh"])
        # rollback restores originals: "all" value and missing line
        self.assertEqual(v.build_rollback_commands(targets),
                         ["line vty 0 4", "transport input all",
                          "line vty 5 15", "no transport input"])


if __name__ == "__main__":
    unittest.main()
