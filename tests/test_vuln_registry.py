"""Tests for the vulnerability registry: "Check all" default and mapping."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import App, VULN_ALL_ID
from i18n import STRINGS
import vuln_ssh
import vuln_telnet


def make_app_like(lang):
    stub = types.SimpleNamespace(lang=lang)
    stub.T = types.MethodType(App.T, stub)
    return stub


class RegistryTest(unittest.TestCase):
    def test_all_is_first_in_both_languages(self):
        for lang in ("en", "pl"):
            stub = make_app_like(lang)
            reg = App._vuln_registry(stub)
            self.assertGreaterEqual(len(reg), 3)
            self.assertEqual(reg[0][0], VULN_ALL_ID)
            self.assertTrue(reg[0][1].strip())
            self.assertTrue(reg[0][2].strip())

    def test_all_name_differs_from_providers(self):
        stub = make_app_like("pl")
        reg = App._vuln_registry(stub)
        names = [name for _vid, name, _desc in reg]
        self.assertEqual(len(set(names)), len(names))


class ModsMappingTest(unittest.TestCase):
    def test_all_maps_to_both_providers_in_order(self):
        self.assertEqual(App._vuln_mods(VULN_ALL_ID),
                         [vuln_telnet, vuln_ssh])

    def test_single_ids_map_to_one(self):
        self.assertEqual(App._vuln_mods(vuln_telnet.VULN_ID), [vuln_telnet])
        self.assertEqual(App._vuln_mods(vuln_ssh.VULN_ID), [vuln_ssh])

    def test_unknown_id_falls_back_to_telnet(self):
        self.assertEqual(App._vuln_mods("nope"), [vuln_telnet])


class SelectedIdTest(unittest.TestCase):
    def _stub(self, lang, selected):
        stub = make_app_like(lang)
        stub._vuln_registry = types.MethodType(App._vuln_registry, stub)
        stub.vuln_id_var = types.SimpleNamespace(get=lambda: selected)
        return stub

    def test_roundtrip_all_name_to_id(self):
        stub = self._stub("en", STRINGS["en"]["vuln_all_name"])
        self.assertEqual(App._selected_vuln_id(stub), VULN_ALL_ID)

    def test_unknown_selection_falls_back_to_first_registry_id(self):
        stub = self._stub("en", "???")
        self.assertEqual(App._selected_vuln_id(stub), VULN_ALL_ID)


if __name__ == "__main__":
    unittest.main()
