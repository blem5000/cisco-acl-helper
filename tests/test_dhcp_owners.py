"""Tests for DHCP owner resolution + audit grouping. Headless-safe."""

import json
import os
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import acl_parser
import dhcp_check


class OwnerFromDescriptionTest(unittest.TestCase):
    def test_all_bcs_formats(self):
        for desc in ("BCS - Jan Kowalski",
                     "BCS Jan Kowalski",
                     "BCS - JAN.KOWALSKI",
                     "Jan Kowalski BCS",
                     "jan.kowalski BCS"):
            self.assertEqual(dhcp_check.owner_from_description(desc),
                             "Jan Kowalski", desc)

    def test_empty_and_bare_marker(self):
        for desc in ("", "BCS", "bcs - ", "  -  "):
            self.assertEqual(dhcp_check.owner_from_description(desc), "")

    def test_diacritics_and_double_name(self):
        self.assertEqual(
            dhcp_check.owner_from_description("BCS - anna nowak-kowalska"),
            "Anna Nowak Kowalska")
        # no Polish characters in remarks, Title Case
        self.assertEqual(
            dhcp_check.owner_from_description("BCS - Łukasz Żółć BCS"),
            "Lukasz Zolc")
        self.assertEqual(
            dhcp_check.owner_from_description("BCS - ŁUKASZ.ŻÓŁĆ"),
            "Lukasz Zolc")


class FetchAllReservationsTest(unittest.TestCase):
    def _fake(self, returncode=0, stdout="", stderr=""):
        return types.SimpleNamespace(returncode=returncode,
                                     stdout=stdout, stderr=stderr)

    def test_list_and_single_object(self):
        rows = [{"IP": "10.0.0.5", "MAC": "aa-bb-cc-dd-ee-ff",
                 "Name": "PC5", "Description": "BCS - Jan Kowalski"},
                {"IP": "10.0.0.6", "MAC": "", "Name": "", "Description": ""}]
        with patch.object(dhcp_check, "_run_utf8",
                          return_value=self._fake(0, json.dumps(rows))):
            resmap, err = dhcp_check.fetch_all_reservations("srv")
        self.assertEqual(err, "")
        self.assertEqual(resmap["10.0.0.5"]["description"],
                         "BCS - Jan Kowalski")
        self.assertEqual(resmap["10.0.0.6"]["mac"], "")
        with patch.object(dhcp_check, "_run_utf8",
                          return_value=self._fake(0, json.dumps(rows[0]))):
            resmap, err = dhcp_check.fetch_all_reservations("srv")
        self.assertEqual(err, "")
        self.assertIn("10.0.0.5", resmap)

    def test_empty_and_errors(self):
        with patch.object(dhcp_check, "_run_utf8",
                          return_value=self._fake(0, "")):
            resmap, err = dhcp_check.fetch_all_reservations("srv")
        self.assertEqual((resmap, err), ({}, ""))
        with patch.object(dhcp_check, "_run_utf8",
                          return_value=self._fake(1, "", "Access denied")):
            resmap, err = dhcp_check.fetch_all_reservations("srv")
        self.assertEqual(resmap, {})
        self.assertIn("Access denied", err)
        resmap, err = dhcp_check.fetch_all_reservations("")
        self.assertEqual((resmap, err), ({}, "no server"))


class GroupByOwnerTest(unittest.TestCase):
    def test_brackets_unknowns_first_stable(self):
        entries = ["10 permit ip host 10.0.0.30 host 10.9.9.1",
                   "20 permit ip host 10.0.0.10 host 10.9.9.1",
                   "30 permit ip any any",
                   "40 permit ip host 10.9.9.1 host 10.0.0.20",
                   "50 permit ip host 10.9.9.1 host 10.0.0.21"]
        owners = {"10.0.0.30": "Jan Kowalski", "10.0.0.10": "Jan Kowalski",
                  "10.0.0.20": "Ewa Nowak", "10.0.0.21": "Ewa Nowak"}
        res = acl_parser.optimize_acl_by_owner(entries, owners.get, "src")
        self.assertEqual(res["deletes"], [10, 20, 30, 40, 50])
        self.assertEqual(res["owners"], ["Jan Kowalski", "Ewa Nowak"])
        self.assertEqual(res["stats"]["owners"], 2)
        texts = [l.split(None, 1)[1] for l in res["lines"]]
        # unknowns first, then stable groups with brackets, sorted inside
        self.assertEqual(texts[0], "permit ip any any")
        self.assertEqual(texts[1], "remark Jan Kowalski")
        self.assertEqual(texts[2], "permit ip host 10.0.0.10 host 10.9.9.1")
        self.assertEqual(texts[3], "permit ip host 10.0.0.30 host 10.9.9.1")
        self.assertEqual(texts[4], "remark Jan Kowalski (koniec)")
        self.assertEqual(texts[5], "remark Ewa Nowak")
        self.assertIn("remark Ewa Nowak (koniec)", texts)
        seqs = [int(l.split()[0]) for l in res["lines"]]
        self.assertEqual(seqs, list(range(10, 10 * (len(seqs) + 1), 10)))

    def test_aggregated_supernet_has_no_owner(self):
        entries = ["10 permit ip host 10.0.0.10 host 10.9.9.1",
                   "20 permit ip host 10.0.0.11 host 10.9.9.1"]
        owners = {"10.0.0.10": "Jan Kowalski", "10.0.0.11": "Jan Kowalski"}
        res = acl_parser.optimize_acl(entries, "src")
        self.assertEqual(len(res["lines"]), 1)  # collapsed to /31
        grouped = acl_parser.optimize_acl_by_owner(entries, owners.get,
                                                    "src")
        self.assertEqual(grouped["owners"], [])
        self.assertIn("0.0.0.1", grouped["lines"][0])  # wildcard, ungrouped


if __name__ == "__main__":
    unittest.main()
