"""Tests for removing one computer's ACL entries. Headless-safe."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acl_parser


PC = "10.20.30.40"
CAM1 = "10.20.30.201"
CAM2 = "10.20.30.202"


def _acl_with_block(owner="Jan Kowalski", pc=PC, cams=(CAM1, CAM2)):
    """An ACL: infrastructure lines, one person's bracketed block."""
    return [
        f"10 remark Jan Kowalski",
        f"20 permit ip host {cams[0]} host {pc}",
        f"30 permit ip host {cams[1]} host {pc}",
        f"40 permit ip host {pc} host {cams[0]}",
        f"50 remark Jan Kowalski (koniec)",
        f"60 permit ip host 10.20.30.250 host {CAM1}",
        f"70 remark OUT: 10.20.30.40 -> cameras",
    ]


class RemoveExactTest(unittest.TestCase):
    def test_removes_every_line_with_the_host_both_directions(self):
        res = acl_parser.remove_ip_entries(_acl_with_block(), PC)
        # the person's bracket goes with them: nothing of theirs is left
        self.assertEqual(res["deletes"], [10, 20, 30, 40, 50])
        self.assertEqual(res["removed"], 3)
        # infrastructure and descriptive remarks survive
        self.assertIn(f"60 permit ip host 10.20.30.250 host {CAM1}", res["keep"])
        self.assertIn("70 remark OUT: 10.20.30.40 -> cameras", res["keep"])

    def test_bracket_removed_when_person_has_nothing_left(self):
        res = acl_parser.remove_ip_entries(_acl_with_block(), PC)
        self.assertIn(10, res["deletes"])
        self.assertIn(50, res["deletes"])
        self.assertEqual(res["removed_remarks"], 2)
        self.assertEqual(res["kept_bracket"], "")

    def test_bracket_kept_when_person_has_other_computers(self):
        entries = _acl_with_block()
        # a second computer of the same person, still permitted
        entries.insert(4, "45 permit ip host 10.20.30.77 host 10.20.30.201")
        res = acl_parser.remove_ip_entries(entries, PC)
        self.assertEqual(res["deletes"], [20, 30, 40])
        self.assertNotIn(10, res["deletes"])
        self.assertNotIn(50, res["deletes"])
        self.assertEqual(res["kept_bracket"], "Jan Kowalski")

    def test_owner_from_dhcp_resolves_bracket(self):
        res = acl_parser.remove_ip_entries(
            _acl_with_block(), PC, owner_of=lambda ip: "Jan Kowalski")
        self.assertEqual(res["owner"], "Jan Kowalski")
        self.assertIn(10, res["deletes"])

    def test_descriptive_remark_is_never_deleted(self):
        entries = [
            "10 remark OUT: 10.20.30.40 -> cameras",
            f"20 permit ip host {PC} host {CAM1}",
            "30 remark Goscie",
        ]
        res = acl_parser.remove_ip_entries(entries, PC)
        self.assertEqual(res["deletes"], [20])
        self.assertIn("10 remark OUT: 10.20.30.40 -> cameras", res["keep"])
        self.assertIn("30 remark Goscie", res["keep"])
        self.assertEqual(res["removed_remarks"], 0)


class RemoveSafetyTest(unittest.TestCase):
    def test_wider_network_is_reported_not_deleted(self):
        # .32/.28 covers .32-.47, so it contains PC (.40) but also others
        entries = [
            "10 permit ip 10.20.30.32 0.0.0.15 host 10.20.30.201",
            f"20 permit ip host {PC} host {CAM1}",
        ]
        res = acl_parser.remove_ip_entries(entries, PC)
        self.assertEqual(res["deletes"], [20])
        self.assertEqual(len(res["covers"]), 1)
        self.assertIn("0.0.0.15", res["covers"][0])

    def test_host_outside_the_network_untouched(self):
        entries = [
            "10 permit ip 10.20.30.32 0.0.0.7 host 10.20.30.201",
        ]  # covers .32-.39 only
        res = acl_parser.remove_ip_entries(entries, "10.20.99.99")
        self.assertEqual(res["deletes"], [])
        self.assertEqual(res["covers"], [])

    def test_any_and_object_groups_untouched(self):
        entries = [
            "10 permit ip any host 10.20.30.201",
            "20 permit ip object-group G1 host 10.20.30.202",
            "30 deny ip host 10.20.30.5 any",
        ]
        res = acl_parser.remove_ip_entries(entries, "10.20.30.5")
        self.assertEqual(res["deletes"], [30])
        self.assertIn("10 permit ip any host 10.20.30.201", res["keep"])

    def test_address_inside_remark_text_not_matched(self):
        entries = ["10 remark rezerwacja dla 10.20.30.40 (BCS)"]
        res = acl_parser.remove_ip_entries(entries, PC)
        self.assertEqual(res["deletes"], [])
        self.assertIn("10 remark rezerwacja dla 10.20.30.40 (BCS)", res["keep"])

    def test_unsequenced_entry_flagged(self):
        entries = [f"permit ip host {PC} host {CAM1}"]
        res = acl_parser.remove_ip_entries(entries, PC)
        self.assertEqual(res["deletes"], [])
        self.assertEqual(len(res["unsequenced"]), 1)

    def test_invalid_ip_raises(self):
        with self.assertRaises(ValueError):
            acl_parser.remove_ip_entries([], "not-an-ip")

    def test_whole_token_match_only(self):
        # .40 must not match .400 or .4
        entries = [
            "10 permit ip host 10.20.30.400 host 10.20.30.201",
            "20 permit ip host 10.20.30.4 host 10.20.30.201",
        ]
        res = acl_parser.remove_ip_entries(entries, PC)
        self.assertEqual(res["deletes"], [])


class RemoveScriptTest(unittest.TestCase):
    def test_script_has_header_and_deletes_per_acl(self):
        acls = {
            "CAM-IN": _acl_with_block(),
            "CAM-OUT": [f"10 permit ip host {PC} host {CAM1}"],
        }
        out = acl_parser.build_removal_script(acls, PC)
        script = out["script"]
        self.assertIn("ip access-list extended CAM-IN", script)
        self.assertIn("ip access-list extended CAM-OUT", script)
        self.assertIn("no 20", script)
        self.assertEqual(out["removed"], 4)
        self.assertEqual(out["acls_hit"], ["CAM-IN", "CAM-OUT"])

    def test_only_filters_to_one_acl(self):
        acls = {
            "CAM-IN": _acl_with_block(),
            "CAM-OUT": [f"10 permit ip host {PC} host {CAM1}"],
        }
        out = acl_parser.build_removal_script(acls, PC, only="cam-out")
        self.assertEqual(out["acls_hit"], ["CAM-OUT"])
        self.assertNotIn("CAM-IN", out["script"])

    def test_no_hits_gives_empty_script(self):
        out = acl_parser.build_removal_script(
            {"CAM-IN": ["10 permit ip host 1.1.1.1 host 2.2.2.2"]}, PC)
        self.assertEqual(out["script"], "")
        self.assertEqual(out["acls_hit"], [])


class RemovalBlocksTest(unittest.TestCase):
    """Multi-device (HA pair) removal: one separated block per switch."""

    def _pair(self, second_entries=None):
        return [
            ("10.0.0.1", "sw-a 10.0.0.1", {"CAM-IN": _acl_with_block()}),
            ("10.0.0.2", "sw-b 10.0.0.2",
             {"CAM-IN": second_entries
              if second_entries is not None else _acl_with_block()}),
        ]

    def test_one_block_per_device(self):
        out = acl_parser.build_removal_blocks(self._pair(), PC)
        self.assertEqual(len(out["blocks"]), 2)
        self.assertEqual([b["label"] for b in out["blocks"]],
                         ["sw-a 10.0.0.1", "sw-b 10.0.0.2"])
        self.assertEqual(out["hosts_hit"], ["10.0.0.1", "10.0.0.2"])

    def test_each_block_has_its_own_script(self):
        out = acl_parser.build_removal_blocks(self._pair(), PC)
        for b in out["blocks"]:
            self.assertIn("ip access-list extended CAM-IN", b["script"])
            self.assertIn("no 20", b["script"])
            self.assertIn("no 30", b["script"])
            self.assertIn("no 40", b["script"])
        # scripts are independent strings, not one merged blob
        self.assertIsNot(out["blocks"][0]["script"],
                         out["blocks"][1]["script"])

    def test_totals_are_summed_across_devices(self):
        out = acl_parser.build_removal_blocks(self._pair(), PC)
        self.assertEqual(out["removed"], 6)          # 3 entries x 2 devices
        self.assertEqual(out["removed_remarks"], 4)  # 2 remarks x 2 devices

    def test_device_without_hits_is_skipped_not_faked(self):
        pair = self._pair(second_entries=[
            "10 permit ip host 10.9.9.9 host 10.9.9.10"])
        out = acl_parser.build_removal_blocks(pair, PC)
        self.assertEqual(len(out["blocks"]), 1)
        self.assertEqual(out["hosts_hit"], ["10.0.0.1"])
        self.assertEqual(out["skipped"], ["sw-b 10.0.0.2"])

    def test_only_filters_on_every_device(self):
        pair = [
            ("10.0.0.1", "sw-a", {"CAM-IN": _acl_with_block(),
                                    "CAM-OUT": [f"10 permit ip host {PC} host {CAM1}"]}),
            ("10.0.0.2", "sw-b", {"CAM-IN": _acl_with_block(),
                                    "CAM-OUT": [f"10 permit ip host {PC} host {CAM1}"]}),
        ]
        out = acl_parser.build_removal_blocks(pair, PC, only="cam-out")
        for b in out["blocks"]:
            self.assertEqual(b["acls_hit"], ["CAM-OUT"])
            self.assertNotIn("CAM-IN", b["script"])

    def test_no_devices_or_no_hits(self):
        self.assertEqual(acl_parser.build_removal_blocks([], PC)["blocks"], [])
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "sw-a", {"X": ["10 permit ip host 1.1.1.1 host 2.2.2.2"]})],
            PC)
        self.assertEqual(out["blocks"], [])
        self.assertEqual(out["skipped"], ["sw-a"])

    def test_owner_resolved_once_and_shared(self):
        out = acl_parser.build_removal_blocks(
            self._pair(), PC, owner_of=lambda ip: "Jan Kowalski")
        self.assertEqual(out["owner"], "Jan Kowalski")
        self.assertEqual(len(out["blocks"]), 2)

    def test_blank_label_falls_back_to_host(self):
        out = acl_parser.build_removal_blocks(
            [("10.0.0.1", "", {"CAM-IN": _acl_with_block()})], PC)
        self.assertEqual(out["blocks"][0]["label"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
