"""Tests for the SSH hardening bundle (vuln_ssh). Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vuln_ssh as s

XE_VER = "Cisco IOS XE Software, Version 17.06.01\nCisco IOS Software ..."
CLASSIC_VER = ("Cisco IOS Software, C2960S Software (C2960S-UNIVERSALK9-M), "
               "Version 15.0(2)SE11, RELEASE SOFTWARE")


def scan(banner="SSH-2.0-Cisco-1.25", kex=(), ciphers=(), macs=(),
         strict=False):
    return {"banner": banner, "sshv1": banner.startswith("SSH-1."),
            "kex": list(kex), "ciphers": list(ciphers), "macs": list(macs),
            "strict_kex": strict}


WEAK = scan(
    banner="SSH-1.99-Cisco-1.25",
    kex=["diffie-hellman-group-exchange-sha1",
         "diffie-hellman-group14-sha1",
         "diffie-hellman-group1-sha1"],
    ciphers=["aes128-ctr", "aes128-cbc", "3des-cbc"],
    macs=["hmac-sha1", "hmac-sha1-96"])


class FindingsTest(unittest.TestCase):
    def test_full_weak_like_nessus(self):
        r = s.analyze_ssh(WEAK, "SSH Enabled - version 1.99", "", XE_VER)
        subs = r["subs"]
        self.assertFalse(r["compliant"])
        self.assertEqual(subs["mac"]["status"], "fail")
        self.assertEqual(subs["mac"]["found"], ["hmac-sha1-96"])
        self.assertEqual(subs["mac"]["kept"], ["hmac-sha1"])
        self.assertEqual(subs["kex"]["found"],
                         ["diffie-hellman-group-exchange-sha1",
                          "diffie-hellman-group1-sha1"])
        self.assertNotIn("diffie-hellman-group14-sha1",
                         subs["kex"]["found"])  # not in scanner list
        self.assertEqual(subs["cbc"]["found"], ["aes128-cbc", "3des-cbc"])
        self.assertEqual(subs["cbc"]["kept"], ["aes128-ctr"])
        # no EtM MACs and no ChaCha -> Terrapin NOT flagged here
        self.assertEqual(subs["terrapin"]["status"], "ok")
        self.assertEqual(subs["sshv1"]["status"], "fail")
        self.assertEqual(r["capability"]["level"], "supported")
        self.assertTrue(s.needs_apply(r))

    def test_terrapin_matrix(self):
        base = dict(kex=["curve25519-sha256"], ciphers=["aes128-ctr"],
                    macs=["hmac-sha2-256"])
        # chacha without strict kex -> fail
        r = s.analyze_ssh(scan(ciphers=["aes128-ctr",
                                        "chacha20-poly1305@openssh.com"],
                               **{k: v for k, v in base.items()
                                  if k not in ("ciphers",)}),
                          "", "", XE_VER)
        self.assertEqual(r["subs"]["terrapin"]["status"], "fail")
        # chacha WITH strict kex -> ok
        r = s.analyze_ssh(scan(ciphers=["aes128-ctr",
                                        "chacha20-poly1305@openssh.com"],
                               kex=["curve25519-sha256",
                                    "kex-strict-s-v00@openssh.com"],
                               macs=["hmac-sha2-256"], strict=True),
                          "", "", XE_VER)
        self.assertEqual(r["subs"]["terrapin"]["status"], "ok")
        # CBC + EtM MAC without strict -> fail
        r = s.analyze_ssh(scan(ciphers=["aes128-ctr", "aes128-cbc"],
                               macs=["hmac-sha2-256-etm@openssh.com"]),
                          "", "", XE_VER)
        self.assertEqual(r["subs"]["terrapin"]["status"], "fail")
        # CBC + plain MAC without strict -> ok (no EtM, no ChaCha)
        r = s.analyze_ssh(scan(ciphers=["aes128-ctr", "aes128-cbc"],
                               macs=["hmac-sha2-256"]),
                          "", "", XE_VER)
        self.assertEqual(r["subs"]["terrapin"]["status"], "ok")

    def test_weak_name_rules(self):
        r = s.analyze_ssh(
            scan(kex=["gss-group14-sha1-", "rsa1024-sha1",
                      "diffie-hellman-group14-sha256"],
                 macs=["hmac-md5", "umac-64@openssh.com", "hmac-sha2-256"],
                 ciphers=["aes256-ctr"]),
            "", "", XE_VER)
        self.assertEqual(sorted(r["subs"]["kex"]["found"]),
                         ["gss-group14-sha1-", "rsa1024-sha1"])
        self.assertEqual(sorted(r["subs"]["mac"]["found"]),
                         ["hmac-md5", "umac-64@openssh.com"])


class CapabilityTest(unittest.TestCase):
    def test_classic_ios_unsupported_but_sshv1_appliable(self):
        r = s.analyze_ssh(WEAK, "", "", CLASSIC_VER)
        self.assertEqual(r["capability"]["level"], "unsupported")
        for sub in ("mac", "kex", "cbc"):
            self.assertFalse(r["subs"][sub]["appliable"])
            self.assertIn(f"{sub}_manual", r["issues"])
        self.assertTrue(r["subs"]["sshv1"]["appliable"])
        self.assertTrue(s.needs_apply(r))
        targets = s.apply_targets(r)
        self.assertEqual([t["sub"] for t in targets], ["sshv1"])
        self.assertEqual(s.build_fix_commands(targets, r),
                         ["ip ssh version 2"])

    def test_empty_kept_impossible(self):
        r = s.analyze_ssh(scan(macs=["hmac-sha1-96"],
                               ciphers=["aes128-ctr"],
                               kex=["curve25519-sha256"]),
                          "", "", XE_VER)
        self.assertEqual(r["subs"]["mac"]["status"], "fail")
        self.assertFalse(r["subs"]["mac"]["appliable"])
        self.assertFalse(s.needs_apply(r))

    def test_unknown_version(self):
        r = s.analyze_ssh(WEAK, "", "", "")
        self.assertEqual(r["capability"]["level"], "unknown")
        self.assertTrue(s.needs_apply(r))  # attempt will reveal support


class FixRollbackTest(unittest.TestCase):
    def test_fix_commands_minimal(self):
        r = s.analyze_ssh(WEAK, "", "", XE_VER)
        targets = s.apply_targets(r)
        self.assertEqual([t["sub"] for t in targets],
                         ["mac", "kex", "cbc", "sshv1"])
        cmds = s.build_fix_commands(targets, r)
        self.assertIn("ip ssh server algorithm mac hmac-sha1", cmds)
        self.assertIn("ip ssh server algorithm kex "
                      "diffie-hellman-group14-sha1", cmds)
        self.assertIn("ip ssh server algorithm encryption aes128-ctr", cmds)
        self.assertIn("ip ssh version 2", cmds)
        self.assertTrue(r["proposal"].startswith("conf t"))
        self.assertTrue(r["proposal"].strip().endswith("wr"))

    def test_rollback_defaults_and_originals(self):
        r = s.analyze_ssh(WEAK, "", "", XE_VER)
        targets = s.apply_targets(r)
        rb = s.build_rollback_commands(targets, r)
        self.assertIn("no ip ssh server algorithm mac", rb)
        self.assertIn("no ip ssh server algorithm kex", rb)
        self.assertIn("no ip ssh server algorithm encryption", rb)
        self.assertIn("no ip ssh version 2", rb)

        inc = ("ip ssh server algorithm mac hmac-sha1 hmac-sha1-96\n"
               "ip ssh version 1\n")
        r2 = s.analyze_ssh(WEAK, "", inc, XE_VER)
        targets2 = [t for t in s.apply_targets(r2) if t["sub"] == "mac"]
        rb2 = s.build_rollback_commands(targets2, r2)
        self.assertIn("ip ssh server algorithm mac hmac-sha1 hmac-sha1-96",
                      rb2)

    def test_fix_and_rollback_verified(self):
        dirty = s.analyze_ssh(WEAK, "", "", XE_VER)
        targets = s.apply_targets(dirty)
        clean_scan = scan(kex=["diffie-hellman-group14-sha1"],
                          ciphers=["aes128-ctr"], macs=["hmac-sha1"])
        clean = s.analyze_ssh(clean_scan, "SSH Enabled - version 2.0", "",
                              XE_VER)
        self.assertTrue(clean["compliant"])
        self.assertTrue(s.fix_verified(clean, targets))
        self.assertTrue(s.rollback_verified(targets, dirty))
        tampered = s.analyze_ssh(
            scan(kex=["diffie-hellman-group14-sha1"],
                 ciphers=["aes128-ctr", "aes128-cbc"], macs=["hmac-sha1"]),
            "", "", XE_VER)
        self.assertFalse(s.rollback_verified(targets, tampered))


USER_HELP = ("  encryption  Encrytption algorithms advertised to other party\n"
             "  mac         MAC algorithms advertised to other party\n")


class AlgoHelpTest(unittest.TestCase):
    def test_keywords_parsed(self):
        self.assertEqual(s._parse_algo_help(USER_HELP), {"encryption", "mac"})
        self.assertEqual(s._parse_algo_help("% Invalid input detected"),
                         set())
        self.assertEqual(s._parse_algo_help(""), set())

    def test_help_drives_per_kind_capability(self):
        # classic-style box WITH mac+encryption support, kex missing
        # (the reported incident): kex goes to OpenProject, rest applies.
        r = s.analyze_ssh(WEAK, "", "", CLASSIC_VER, USER_HELP)
        self.assertEqual(r["capability"]["level"], "supported")
        self.assertTrue(r["subs"]["mac"]["appliable"])
        self.assertTrue(r["subs"]["cbc"]["appliable"])
        self.assertFalse(r["subs"]["kex"]["appliable"])
        self.assertIn("kex_manual", r["issues"])
        subs = [t["sub"] for t in s.apply_targets(r)]
        self.assertEqual(subs, ["mac", "cbc", "sshv1"])
        groups = s.split_fix_groups(s.apply_targets(r), r)
        self.assertEqual([g for g, _t in groups],
                         ["mac", "encryption", "version"])
        rb = s.build_rollback_commands(
            [t for t in s.apply_targets(r) if t["sub"] in ("mac", "cbc")],
            r)
        self.assertNotIn("kex", " ".join(rb))

    def test_split_groups_telnet_single(self):
        import vuln_telnet as t

        r = t.analyze_telnet("line vty 0 4\n transport input all", "")
        targets = t.apply_targets(r)
        self.assertEqual(t.split_fix_groups(targets, r)[0][0], "vty")


if __name__ == "__main__":
    unittest.main()
