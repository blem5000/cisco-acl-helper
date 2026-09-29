"""Tests for the NTP mode 6 bundle (vuln_ntp + ntp_probe). Headless-safe."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ntp_probe
import vuln_ntp as v
from i18n import STRINGS

NO_NTP = ""
WITH_GROUP = "ntp access-group query-only OLD-GROUP\nntp server 10.0.0.1\n"


class AnalyzeTest(unittest.TestCase):
    def test_silent_probe_compliant(self):
        r = v.analyze_ntp(False, "no mode 6 reply (timeout)", NO_NTP)
        self.assertTrue(r["compliant"])
        self.assertEqual(r["proposal"], "")
        self.assertFalse(v.needs_apply(r))
        self.assertEqual(v.apply_targets(r), [])

    def test_responding_probe_vulnerable(self):
        r = v.analyze_ntp(True, "12-byte mode 6 reply", NO_NTP)
        self.assertFalse(r["compliant"])
        self.assertTrue(v.needs_apply(r))
        self.assertIn("ntp access-group query-only NTP-QUERY-BLOCK",
                      r["proposal"])
        self.assertIsNone(r["query_acl"])

    def test_existing_group_recorded(self):
        r = v.analyze_ntp(True, "12-byte mode 6 reply", WITH_GROUP)
        self.assertEqual(r["query_acl"], "OLD-GROUP")
        targets = v.apply_targets(r)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["orig_query_acl"], "OLD-GROUP")

    def test_query_only_parsing(self):
        self.assertIsNone(v._parse_query_only(NO_NTP))
        self.assertEqual(v._parse_query_only(WITH_GROUP), "OLD-GROUP")
        self.assertEqual(
            v._parse_query_only("ntp access-group query-only  FOO \n"), "FOO")

    def test_all_groups_parsing(self):
        out = ("ntp access-group peer PEER-ACL\n"
               "ntp access-group serve-only SO-ACL\n"
               "ntp access-group serve SERVE-ACL\n"
               "ntp access-group query-only Q-ACL\n"
               "ntp server 10.0.0.1\n")
        groups = v._parse_groups(out)
        self.assertEqual(groups, {"peer": "PEER-ACL", "serve-only": "SO-ACL",
                                  "serve": "SERVE-ACL", "query-only": "Q-ACL"})
        self.assertEqual(v._parse_groups(NO_NTP),
                         {"peer": None, "serve-only": None,
                          "serve": None, "query-only": None})

    def test_groups_exposed_in_result(self):
        out = "ntp access-group serve SERVE-ACL\n"
        r = v.analyze_ntp(True, "x", out)
        self.assertEqual(r["groups"]["serve"], "SERVE-ACL")
        self.assertIsNone(r["groups"]["query-only"])
        self.assertIsNone(r["query_acl"])


class FixRollbackTest(unittest.TestCase):
    def test_fix_commands(self):
        r = v.analyze_ntp(True, "x", NO_NTP)
        cmds = v.build_fix_commands(v.apply_targets(r), r)
        self.assertEqual(cmds, [
            "ip access-list standard NTP-QUERY-BLOCK",
            " remark Block unauthenticated NTP mode 6 control queries",
            " deny   any log",
            " exit",
            "ntp access-group query-only NTP-QUERY-BLOCK",
        ])

    def test_rollback_without_original(self):
        r = v.analyze_ntp(True, "x", NO_NTP)
        cmds = v.build_rollback_commands(v.apply_targets(r), r)
        self.assertEqual(cmds, ["no ip access-list standard NTP-QUERY-BLOCK",
                                "no ntp access-group query-only "
                                "NTP-QUERY-BLOCK"])

    def test_rollback_restores_original_from_target_snapshot(self):
        # _try_rollback calls build_rollback_commands WITHOUT result -
        # the original must come from the target snapshot.
        r = v.analyze_ntp(True, "x", WITH_GROUP)
        cmds = v.build_rollback_commands(v.apply_targets(r))
        self.assertEqual(cmds, ["no ntp access-group peer NTP-SERVERS",
                                "no ip access-list standard NTP-SERVERS",
                                "no ip access-list standard NTP-QUERY-BLOCK",
                                "ntp access-group query-only OLD-GROUP"])

    def test_fix_and_rollback_verified(self):
        dirty = v.analyze_ntp(True, "reply", NO_NTP)
        targets = v.apply_targets(dirty)
        clean = v.analyze_ntp(False, "timeout", NO_NTP)
        self.assertTrue(v.fix_verified(clean, targets))
        self.assertTrue(v.rollback_verified(targets, dirty))
        self.assertFalse(v.rollback_verified(targets, clean))

    def test_single_group(self):
        r = v.analyze_ntp(True, "x", NO_NTP)
        groups = v.split_fix_groups(v.apply_targets(r), r)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "ntp")


class ExactTitleTest(unittest.TestCase):
    def test_scanner_title_identical_both_languages(self):
        self.assertEqual(v.TITLE, "Network Time Protocol (NTP) Mode 6 Scanner")


class NoteTest(unittest.TestCase):
    def T(self, key):
        return STRINGS["en"].get(key, key)

    def test_no_note_ever(self):
        for r in (v.analyze_ntp(True, "x", NO_NTP),
                  v.analyze_ntp(False, "timeout", NO_NTP)):
            self.assertEqual(v.openproject_note("10.0.0.9", r, self.T), "")

    def test_note_names_peer_serve_groups(self):
        out = ("ntp access-group serve SERVE-ACL\n"
               "ntp access-group query-only NTP-QUERY-BLOCK\n")
        r = v.analyze_ntp(True, "284-byte mode 6 reply (vn4/readvar)", out)
        note = v.openproject_note("10.207.96.61", r, self.T)
        self.assertIn("10.207.96.61", note)
        self.assertIn("serve SERVE-ACL", note)

    def test_note_when_interface_unscoppable(self):
        out = "ntp access-group query-only NTP-QUERY-BLOCK\n"
        r = v.analyze_ntp(True, "284-byte mode 6 reply (vn4/readvar)", out)
        note = v.openproject_note("10.207.96.61", r, self.T)
        self.assertIn("10.207.96.61", note)
        self.assertIn("NTP-QUERY-BLOCK", note)

    def test_no_note_when_fallback_appliable(self):
        out = ("ntp access-group query-only NTP-QUERY-BLOCK\n"
               "ntp server 172.26.56.2 prefer\n"
               "ntp server 172.26.56.3\n")
        brief = ("Interface              IP-Address  OK? Method Status "
                 "Protocol\n"
                 "Vlan1                  10.207.96.61 YES manual up up\n")
        r = v.analyze_ntp(True, "x", out, brief, "10.207.96.61")
        self.assertTrue(r["fallback_ok"])
        self.assertEqual(v.openproject_note("10.207.96.61", r, self.T), "")

    def test_other_groups_shown_in_result(self):
        out = ("ntp access-group peer PEER-ACL\n"
               "ntp access-group query-only NTP-QUERY-BLOCK\n")
        r = v.analyze_ntp(True, "x", out)
        text = "\n".join(t for t, _tag in v.format_result("h", r, self.T))
        self.assertIn("peer PEER-ACL", text)
        self.assertIn("NTP-QUERY-BLOCK", text)


class FallbackTest(unittest.TestCase):
    INCLUDE = ("ntp access-group query-only NTP-QUERY-BLOCK\n"
               "ntp server 172.26.115.1\n"
               "ntp server 172.26.60.1\n"
               "ntp server 172.26.56.2 prefer\n"
               "ntp server 172.26.56.3\n")
    BRIEF = ("Interface              IP-Address      OK? Method Status "
             "Protocol\n"
             "Vlan1                  10.207.96.61    YES manual up up\n"
             "Gi1/0/1                unassigned      YES unset  up up\n")
    SERVERS = ["172.26.115.1", "172.26.60.1", "172.26.56.2", "172.26.56.3"]

    def test_secondary_mode_selected(self):
        r = v.analyze_ntp(True, "x", self.INCLUDE, self.BRIEF,
                           "10.207.96.61")
        self.assertTrue(r["secondary"])
        self.assertTrue(r["fallback_ok"])
        self.assertEqual(r["mgmt_if"], "Vlan1")
        self.assertEqual(r["servers"], self.SERVERS)
        self.assertTrue(v.needs_apply(r))
        self.assertIn("NTP-CTRL-IN", r["proposal"])
        self.assertIn("interface Vlan1", r["proposal"])

    def test_primary_mode_without_our_block(self):
        r = v.analyze_ntp(True, "x", "ntp server 10.0.0.1\n")
        self.assertFalse(r["secondary"])
        self.assertFalse(r["fallback_ok"])
        self.assertIn("NTP-QUERY-BLOCK", r["proposal"])

    def test_servers_parsing(self):
        servers, ok = v._parse_servers(self.INCLUDE)
        self.assertEqual(servers, self.SERVERS)
        self.assertTrue(ok)
        self.assertEqual(v._parse_servers("ntp server 10.0.0.1\n"),
                         (["10.0.0.1"], True))
        _s, ok = v._parse_servers("ntp server 10.0.0.1\n"
                                  "ntp server time.example.com\n")
        self.assertFalse(ok)  # hostname would leave a hole
        _s, ok = v._parse_servers("ntp server vrf MGMT 10.0.0.1\n")
        self.assertFalse(ok)
        _s, ok = v._parse_servers("")
        self.assertFalse(ok)

    def test_interface_matching(self):
        self.assertEqual(v._find_mgmt_interface(self.BRIEF, "10.207.96.61"),
                         "Vlan1")
        self.assertIsNone(v._find_mgmt_interface(self.BRIEF, "10.9.9.9"))
        self.assertIsNone(v._find_mgmt_interface(self.BRIEF, "switch1"))
        self.assertIsNone(v._find_mgmt_interface("", "10.207.96.61"))

    def test_no_fallback_without_interface(self):
        r = v.analyze_ntp(True, "x", self.INCLUDE, self.BRIEF, "10.9.9.9")
        self.assertTrue(r["secondary"])
        self.assertFalse(r["fallback_ok"])
        self.assertEqual(v.apply_targets(r), [])
        self.assertFalse(v.needs_apply(r))
        self.assertEqual(r["proposal"], "")

    def test_no_fallback_without_servers(self):
        include = "ntp access-group query-only NTP-QUERY-BLOCK\n"
        r = v.analyze_ntp(True, "x", include, self.BRIEF, "10.207.96.61")
        self.assertFalse(r["fallback_ok"])
        self.assertEqual(v.apply_targets(r), [])

    def test_fallback_fix_commands(self):
        r = v.analyze_ntp(True, "x", self.INCLUDE, self.BRIEF,
                           "10.207.96.61")
        targets = v.apply_targets(r)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["sub"], "ntp-if")
        cmds = v.build_fix_commands(targets, r)
        self.assertEqual(cmds, [
            "ip access-list extended NTP-CTRL-IN",
            "permit udp host 172.26.115.1 eq ntp any",
            "permit udp host 172.26.60.1 eq ntp any",
            "permit udp host 172.26.56.2 eq ntp any",
            "permit udp host 172.26.56.3 eq ntp any",
            "deny udp any any eq ntp log",
            "permit ip any any",
            "exit",
            "interface Vlan1",
            "ip access-group NTP-CTRL-IN in",
            "exit",
        ])
        groups = v.split_fix_groups(targets, r)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "ntp-if")

    def test_fallback_rollback(self):
        r = v.analyze_ntp(True, "x", self.INCLUDE, self.BRIEF,
                           "10.207.96.61")
        # worker calls rollback WITHOUT result - snapshot must suffice
        cmds = v.build_rollback_commands(v.apply_targets(r))
        self.assertEqual(cmds, [
            "interface Vlan1",
            "no ip access-group NTP-CTRL-IN in",
            "exit",
            "no ip access-list extended NTP-CTRL-IN",
        ])

    def test_fallback_info_shown(self):
        def T(key):
            return STRINGS["en"].get(key, key)

        r = v.analyze_ntp(True, "x", self.INCLUDE, self.BRIEF,
                           "10.207.96.61")
        text = "\n".join(t for t, _tag in v.format_result("h", r, T))
        self.assertIn("NTP-CTRL-IN", text)
        self.assertIn("Vlan1", text)
        self.assertIn("172.26.56.2", text)


class PrimaryPeerTest(unittest.TestCase):
    INCLUDE = ("ntp server 172.26.56.2 prefer\n"
               "ntp server 172.26.56.3\n")

    def test_proposal_permits_servers(self):
        r = v.analyze_ntp(True, "x", self.INCLUDE)
        self.assertFalse(r["secondary"])
        self.assertIn("ntp access-group peer NTP-SERVERS", r["proposal"])
        self.assertIn("permit host 172.26.56.2", r["proposal"])
        self.assertIn("ntp access-group query-only NTP-QUERY-BLOCK",
                      r["proposal"])

    def test_no_peer_without_servers(self):
        r = v.analyze_ntp(True, "x", NO_NTP)
        self.assertNotIn("NTP-SERVERS", r["proposal"])
        self.assertFalse(v.apply_targets(r)[0].get("peer_added"))

    def test_fix_and_rollback_with_peer(self):
        r = v.analyze_ntp(True, "x", self.INCLUDE)
        targets = v.apply_targets(r)
        self.assertTrue(targets[0]["peer_added"])
        self.assertEqual(targets[0]["servers"],
                         ["172.26.56.2", "172.26.56.3"])
        cmds = v.build_fix_commands(targets, r)
        self.assertEqual(cmds, [
            "ip access-list standard NTP-SERVERS",
            " permit host 172.26.56.2",
            " permit host 172.26.56.3",
            " deny   any",
            " exit",
            "ntp access-group peer NTP-SERVERS",
            "ip access-list standard NTP-QUERY-BLOCK",
            " remark Block unauthenticated NTP mode 6 control queries",
            " deny   any log",
            " exit",
            "ntp access-group query-only NTP-QUERY-BLOCK",
        ])
        rb = v.build_rollback_commands(targets, r)
        self.assertEqual(rb, [
            "no ntp access-group peer NTP-SERVERS",
            "no ip access-list standard NTP-SERVERS",
            "no ip access-list standard NTP-QUERY-BLOCK",
            "no ntp access-group query-only NTP-QUERY-BLOCK",
        ])

    def test_rollback_restores_admin_peer_group(self):
        include = self.INCLUDE + "ntp access-group peer ADMIN-PEERS\n"
        r = v.analyze_ntp(True, "x", include)
        rb = v.build_rollback_commands(v.apply_targets(r))
        self.assertIn("ntp access-group peer ADMIN-PEERS", rb)
        self.assertLess(rb.index("no ntp access-group peer NTP-SERVERS"),
                        rb.index("ntp access-group peer ADMIN-PEERS"))

    def test_own_peer_group_not_warned(self):
        def T(key):
            return STRINGS["en"].get(key, key)

        include = (self.INCLUDE
                   + "ntp access-group peer NTP-SERVERS\n"
                   + "ntp access-group query-only NTP-QUERY-BLOCK\n")
        r = v.analyze_ntp(True, "x", include)
        self.assertEqual(v._query_granting_others(r), [])
        text = "\n".join(t for t, _tag in v.format_result("h", r, T))
        self.assertNotIn("NTP-SERVERS", text)


class ProbePacketTest(unittest.TestCase):
    def test_default_request_is_full_header_vn4_readvar(self):
        req = ntp_probe.build_mode6_request()
        self.assertEqual(len(req), 12)       # truncated packets get dropped
        self.assertEqual(req[0] & 0x07, 6)   # mode
        self.assertEqual((req[0] >> 3) & 0x07, 4)  # version
        self.assertEqual(req[1], 2)          # READVAR opcode
        self.assertEqual(req[2:], b"\x00" * 10)

    def test_variants_cover_vn2_vn3_vn4(self):
        vns = {(label, vn) for label, vn, _op in ntp_probe.REQUEST_VARIANTS
               for _ in [0]}
        self.assertTrue({2, 3, 4} <= {vn for _label, vn in vns})
        for label, vn, op in ntp_probe.REQUEST_VARIANTS:
            req = ntp_probe.build_mode6_request(vn, op)
            self.assertEqual(len(req), 12, label)
            self.assertEqual(req[0] & 0x07, 6, label)
            self.assertEqual((req[0] >> 3) & 0x07, vn, label)
            self.assertEqual(req[1], op, label)

    def test_response_recognition(self):
        self.assertTrue(ntp_probe.is_mode6_response(b"\x1e\x02\x00\x00"))
        self.assertFalse(ntp_probe.is_mode6_response(b"\x1c\x02\x00\x00"))
        self.assertFalse(ntp_probe.is_mode6_response(b"\x1e\x02"))


class ProbeVariantsTest(unittest.TestCase):
    """probe() tries every variant; a stack answering only an older
    version (like the one Nessus caught while our 4-byte VN3 packet
    stayed silent) must still be reported vulnerable."""

    def _run_probe(self, answer_vn):
        import socket as sockmod
        sent = []

        class FakeSock:
            def __init__(self, *a, **k):
                pass

            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                sent.append(data)

            def recvfrom(self, n):
                vn = (sent[-1][0] >> 3) & 0x07
                if vn == answer_vn:
                    return b"\x16\x02\x00\x00" + b"v" * 20, ("1.2.3.4", 123)
                raise sockmod.timeout()

            def close(self):
                pass

        with mock.patch.object(sockmod, "socket", FakeSock):
            return ntp_probe.probe("1.2.3.4", tries=1), sent

    def test_stack_answering_only_vn2_is_vulnerable(self):
        (responded, detail), sent = self._run_probe(2)
        self.assertTrue(responded)
        self.assertIn("vn2/readvar", detail)
        # newest version tried first
        self.assertEqual((sent[0][0] >> 3) & 0x07, 4)

    def test_silent_stack_stays_compliant(self):
        (responded, detail), sent = self._run_probe(99)
        self.assertFalse(responded)
        self.assertEqual(detail, "no mode 6 reply (timeout)")
        self.assertEqual(len(sent), len(ntp_probe.REQUEST_VARIANTS))


if __name__ == "__main__":
    unittest.main()
