"""Tests for orphaned-remark cleanup. Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acl_parser


class FindOrphansTest(unittest.TestCase):
    """Only unambiguous orphans may be removed."""

    def test_closing_without_opening(self):
        res = acl_parser.find_orphan_remarks(
            ["1000 remark Jan Kowalski (koniec)"])
        self.assertEqual(res["deletes"], [1000])
        self.assertEqual(res["removed_remarks"], 1)

    def test_dangling_open_without_entries_or_close(self):
        res = acl_parser.find_orphan_remarks(["960 remark Jan Kowalski"])
        self.assertEqual(res["deletes"], [960])

    def test_empty_bracket(self):
        res = acl_parser.find_orphan_remarks([
            "960 remark Jan Kowalski",
            "1000 remark Jan Kowalski (koniec)"])
        self.assertEqual(res["deletes"], [960, 1000])
        self.assertEqual(res["removed_remarks"], 2)

    def test_bracket_with_entries_is_untouched(self):
        res = acl_parser.find_orphan_remarks([
            "960 remark Jan Kowalski",
            "980 permit ip host 10.0.0.5 host 10.0.0.6",
            "1000 remark Jan Kowalski (koniec)"])
        self.assertEqual(res["deletes"], [])
        self.assertEqual(res["removed_remarks"], 0)

    def test_descriptive_note_is_never_an_orphan(self):
        res = acl_parser.find_orphan_remarks([
            "10 remark OUT: 10.0.0.5 -> cameras",
            "20 permit ip host 10.0.0.5 host 10.0.0.6"])
        self.assertEqual(res["deletes"], [])

    def test_plain_header_with_entries_is_untouched(self):
        res = acl_parser.find_orphan_remarks([
            "10 remark Goscie",
            "20 permit ip any host 10.0.0.6"])
        self.assertEqual(res["deletes"], [])

    def test_mixed_acl_only_removes_the_orphan(self):
        res = acl_parser.find_orphan_remarks([
            "10 remark OUT: x",
            "100 remark Anna Nowak (koniec)",
            "960 remark Jan Kowalski",
            "980 permit ip host 1.1.1.1 host 2.2.2.2",
            "1000 remark Jan Kowalski (koniec)"])
        self.assertEqual(res["deletes"], [100])
        self.assertIn("980 permit ip host 1.1.1.1 host 2.2.2.2", res["keep"])
        self.assertIn("1000 remark Jan Kowalski (koniec)", res["keep"])

    def test_orphans_carry_reason(self):
        res = acl_parser.find_orphan_remarks(
            ["1000 remark Jan Kowalski (koniec)"])
        self.assertEqual(len(res["orphans"]), 1)
        seq, text, why = res["orphans"][0]
        self.assertEqual(seq, 1000)
        self.assertIn("Kowalski", text)
        self.assertTrue(why)

    def test_unsequenced_orphan_is_reported_not_deleted(self):
        res = acl_parser.find_orphan_remarks(["remark Jan Kowalski (koniec)"])
        self.assertEqual(res["deletes"], [])
        self.assertEqual(len(res["unsequenced"]), 1)

    def test_empty_acl(self):
        res = acl_parser.find_orphan_remarks([])
        self.assertEqual(res["deletes"], [])
        self.assertEqual(res["keep"], [])


class OrphanBlocksTest(unittest.TestCase):
    ACLS = {"ACL-BCS-IN": [
        "1000 remark Jan Kowalski (koniec)",
        "2000 permit ip host 1.1.1.1 host 2.2.2.2",
    ]}

    def test_one_block_per_device(self):
        out = acl_parser.build_orphan_removal_blocks([
            ("h1", "sw-a", self.ACLS),
            ("h2", "sw-b", self.ACLS),
        ])
        self.assertEqual(len(out["blocks"]), 2)
        self.assertEqual(out["removed_remarks"], 2)
        for b in out["blocks"]:
            self.assertIn("ip access-list extended ACL-BCS-IN", b["script"])
            self.assertIn("no 1000", b["script"])

    def test_device_without_orphans_is_skipped(self):
        out = acl_parser.build_orphan_removal_blocks([
            ("h1", "sw-a", self.ACLS),
            ("h2", "sw-b", {"X": ["10 permit ip any any"]}),
        ])
        self.assertEqual(len(out["blocks"]), 1)
        self.assertEqual(out["skipped"], ["sw-b"])

    def test_only_filters_one_acl(self):
        acls = dict(self.ACLS)
        acls["OTHER"] = ["500 remark Anna Nowak (koniec)"]
        out = acl_parser.build_orphan_removal_blocks(
            [("h1", "sw-a", acls)], only="other")
        self.assertEqual(out["blocks"][0]["acls_hit"], ["OTHER"])
        self.assertNotIn("ACL-BCS-IN", out["blocks"][0]["script"])

    def test_nothing_to_do(self):
        out = acl_parser.build_orphan_removal_blocks([
            ("h1", "sw-a", {"X": ["10 permit ip any any"]})])
        self.assertEqual(out["blocks"], [])
        self.assertEqual(out["skipped"], ["sw-a"])

    def test_orphan_list_names_the_lines(self):
        out = acl_parser.build_orphan_removal_blocks(
            [("h1", "sw-a", self.ACLS)])
        self.assertTrue(out["orphans"])
        self.assertIn("ACL-BCS-IN", out["orphans"][0])
        self.assertIn("Kowalski", out["orphans"][0])


if __name__ == "__main__":
    unittest.main()
