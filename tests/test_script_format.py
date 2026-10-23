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
    """Each `no` line carries the entry it removes, on the same line.

    IOS keys off the sequence number and ignores the rest, so `no 980 permit
    ip ...` deletes entry 980 exactly like `no 980` - and stays readable in
    the paste buffer without a separate comment block.
    """

    def test_every_no_line_carries_its_entry_text(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        script = out["blocks"][0]["script"]
        self.assertIn("no 960 remark Michal Zasina", script)
        self.assertIn(
            "no 980 permit ip 10.207.156.0 0.0.1.255 host 172.26.56.119",
            script)
        self.assertIn("no 1000 remark Michal Zasina (koniec)", script)

    def test_no_line_without_known_text_stays_bare(self):
        # a seq with no recorded text must not become 'no 980 None'
        self.assertEqual(acl_parser._no_line(980, ""), "no 980")
        self.assertEqual(acl_parser._no_line(980, "980 permit ip any any"),
                         "no 980 permit ip any any")

    def test_sequence_number_not_repeated(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        script = out["blocks"][0]["script"]
        self.assertNotIn("no 980 980", script)
        self.assertIn("no 980 permit ip", script)

    def test_one_no_line_per_removed_entry(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        nos = [ln for ln in out["blocks"][0]["script"].splitlines()
               if ln.startswith("no ")]
        self.assertEqual(len(nos), 3)
        for ln in nos:
            # seq followed by the entry text, never the seq alone or twice
            self.assertRegex(ln, r"^no \d+ \S+")

    def test_no_entry_comments_outside_the_blocks(self):
        # entry text lives on the `no` line now - no '! ACL:' block remains
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", ACLS)], PC)
        script = out["blocks"][0]["script"]
        self.assertNotIn("! ACL-BCS-IN:", script)


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
