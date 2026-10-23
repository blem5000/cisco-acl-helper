"""The copied script must be self-explanatory and per-device.

Reported: 'Copy all blocks' produced one blob where identical ACL names from
two switches sat next to each other with no way to tell which list belongs
to which device, and `no <seq>` lines carried no clue what they delete.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acl_parser

PC = "172.26.56.119"
ACLS = {"ACL-BCS-IN": [
    "960 remark Michal Zasina",
    "980 permit ip 10.207.156.0 0.0.1.255 host 172.26.56.119",
    "1000 remark Michal Zasina (koniec)",
]}
DEVICES = [("10.0.0.1", "sw-a 10.0.0.1", ACLS),
           ("10.0.0.2", "sw-b 10.0.0.2", ACLS)]


class DeviceHeaderTest(unittest.TestCase):
    def test_each_block_names_its_device(self):
        out = acl_parser.build_removal_blocks(DEVICES, PC)
        for block in out["blocks"]:
            self.assertIn(f"! === {block['label']} ===", block["script"])

    def test_blocks_are_distinguishable_when_concatenated(self):
        out = acl_parser.build_removal_blocks(DEVICES, PC)
        joined = "\n\n".join(b["script"] for b in out["blocks"])
        self.assertIn("sw-a 10.0.0.1", joined)
        self.assertIn("sw-b 10.0.0.2", joined)

    def test_header_absent_when_nothing_to_do(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", {"X": ["10 permit ip any any"]})], PC)
        self.assertEqual(out["blocks"], [])


class EntryTextTest(unittest.TestCase):
    def test_every_no_line_has_its_acl_text_above_it(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        script = out["blocks"][0]["script"]
        comments = [ln for ln in script.splitlines() if ln.startswith("! ACL")]
        # one comment per removed entry
        self.assertEqual(len(comments), 3)
        self.assertTrue(any("980 permit ip" in c for c in comments))
        self.assertTrue(any("960 remark Michal Zasina" in c for c in comments))

    def test_comments_come_before_any_acl_header(self):
        # a '!' inside an ACL submode is platform-dependent - keep them out
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        lines = out["blocks"][0]["script"].splitlines()
        first_acl = next(i for i, ln in enumerate(lines)
                         if ln.startswith("ip access-list"))
        for i, ln in enumerate(lines):
            if ln.startswith("!"):
                self.assertLess(i, first_acl, ln)

    def test_comment_count_matches_no_lines(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        script = out["blocks"][0]["script"]
        nos = [ln for ln in script.splitlines() if ln.startswith("no ")]
        comments = [ln for ln in script.splitlines() if ln.startswith("! ACL")]
        self.assertEqual(len(nos), len(comments))

    def test_full_line_not_duplicated_number(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        script = out["blocks"][0]["script"]
        self.assertNotIn("! ACL-BCS-IN: 980: 980", script)
        self.assertIn("! ACL-BCS-IN: 980 permit ip", script)


class OrphanHeaderTest(unittest.TestCase):
    ORPH = {"ACL-BCS-IN": ["1000 remark Jan Kowalski (koniec)"]}

    def test_orphan_blocks_name_their_device(self):
        out = acl_parser.build_orphan_removal_blocks([
            ("10.0.0.1", "sw-a 10.0.0.1", self.ORPH),
            ("10.0.0.2", "sw-b 10.0.0.2", self.ORPH)])
        for block in out["blocks"]:
            self.assertIn(f"! === {block['label']} ===", block["script"])

    def test_orphan_blocks_carry_entry_text(self):
        out = acl_parser.build_orphan_removal_blocks(
            [("10.0.0.1", "sw-a", self.ORPH)])
        script = out["blocks"][0]["script"]
        self.assertIn("Jan Kowalski (koniec)", script)
        self.assertIn("no 1000", script)

    def test_orphan_comments_precede_acl_header(self):
        out = acl_parser.build_orphan_removal_blocks(
            [("10.0.0.1", "sw-a", self.ORPH)])
        lines = out["blocks"][0]["script"].splitlines()
        first_acl = next(i for i, ln in enumerate(lines)
                         if ln.startswith("ip access-list"))
        for i, ln in enumerate(lines):
            if ln.startswith("! ACL"):
                self.assertLess(i, first_acl, ln)


if __name__ == "__main__":
    unittest.main()
