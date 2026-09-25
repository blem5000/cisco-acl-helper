"""Tests for paste-ready OpenProject notes (unfixable findings)."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import App
from i18n import STRINGS
import vuln_ssh
import vuln_telnet

OK_SUBS = {s: {"status": "ok"}
           for s in ("mac", "kex", "cbc", "terrapin", "sshv1")}


def ssh_res(**over):
    subs = dict(OK_SUBS)
    subs.update(over.get("subs", {}))
    return {"vuln": "ssh",
            "ios": over.get("ios", ""),
            "capability": over.get("capability", {}),
            "subs": subs}


class SshNoteTest(unittest.TestCase):
    def T(self, key):
        return STRINGS["en"].get(key, key)

    def test_kex_no_keyword(self):
        subs = dict(OK_SUBS)
        subs["kex"] = {"status": "fail", "appliable": False,
                       "found": ["diffie-hellman-group1-sha1"],
                       "kept": ["diffie-hellman-group14-sha1"]}
        note = vuln_ssh.openproject_note(
            "10.0.0.1",
            ssh_res(subs=subs, ios="Cisco IOS Software, Version 15.2(2)E7",
                    capability={"keywords": ["encryption", "mac"]}), self.T)
        self.assertIn("10.0.0.1", note)
        self.assertIn("15.2(2)E7", note)
        self.assertIn("diffie-hellman-group1-sha1", note)
        self.assertIn("algorithm kex", note)
        self.assertIn("OpenProject", note)

    def test_empty_kept_branch(self):
        subs = dict(OK_SUBS)
        subs["mac"] = {"status": "fail", "appliable": False,
                       "found": ["hmac-sha1-96"], "kept": []}
        note = vuln_ssh.openproject_note(
            "10.0.0.3", ssh_res(subs=subs), self.T)
        self.assertIn("nothing would remain", note)

    def test_unsupported_branch(self):
        subs = dict(OK_SUBS)
        subs["cbc"] = {"status": "fail", "appliable": False,
                       "found": ["3des-cbc"], "kept": ["aes128-ctr"]}
        note = vuln_ssh.openproject_note(
            "10.0.0.4", ssh_res(subs=subs), self.T)
        self.assertIn("classic IOS", note)

    def test_clean_no_note(self):
        self.assertEqual(
            vuln_ssh.openproject_note("h", ssh_res(), self.T), "")

    def test_polish_note(self):
        Tpl = lambda k: STRINGS["pl"].get(k, k)  # noqa: E731
        subs = dict(OK_SUBS)
        subs["kex"] = {"status": "fail", "appliable": False,
                       "found": ["diffie-hellman-group1-sha1"],
                       "kept": ["diffie-hellman-group14-sha1"]}
        note = vuln_ssh.openproject_note(
            "10.0.0.1", ssh_res(subs=subs), Tpl)
        self.assertIn("automatyczna poprawka niewdrożona", note)
        self.assertIn("OpenProject", note)


class TelnetNoteTest(unittest.TestCase):
    def T(self, key):
        return STRINGS["en"].get(key, key)

    def test_blocked(self):
        note = vuln_telnet.openproject_note(
            "10.0.0.2",
            {"vuln": "telnet",
             "vty": [{"header": "line vty 0 4", "status": "blocked"}]},
            self.T)
        self.assertIn("line vty 0 4", note)
        self.assertIn("transport input none", note)

    def test_novty(self):
        note = vuln_telnet.openproject_note(
            "h", {"vuln": "telnet", "vty": []}, self.T)
        self.assertIn("no `line vty` blocks", note)

    def test_clean_no_note(self):
        self.assertEqual(vuln_telnet.openproject_note(
            "h", {"vuln": "telnet",
                  "vty": [{"header": "line vty 0 4", "status": "ok",
                           "compliant": True}]}, self.T), "")


class CollectNotesTest(unittest.TestCase):
    def test_gather_mixed_results(self):
        subs = dict(OK_SUBS)
        subs["kex"] = {"status": "fail", "appliable": False,
                       "found": ["diffie-hellman-group1-sha1"],
                       "kept": ["diffie-hellman-group14-sha1"]}
        stub = types.SimpleNamespace(
            T=lambda k: STRINGS["en"].get(k, k),
            vuln_results=[
                ("10.0.0.1", ssh_res(subs=subs), None),
                ("10.0.0.2", {"vuln": "ssh", "capability": {},
                              "subs": dict(OK_SUBS)}, None),
                ("10.0.0.9", None, "boom"),
            ])
        stub._vuln_mod = App._vuln_mod
        text = App._collect_vuln_notes(stub)
        self.assertIn("10.0.0.1", text)
        self.assertNotIn("10.0.0.2", text)
        self.assertNotIn("boom", text)

    def test_gather_empty(self):
        stub = types.SimpleNamespace(
            T=lambda k: STRINGS["en"].get(k, k), vuln_results=[])
        self.assertEqual(App._collect_vuln_notes(stub), "")


if __name__ == "__main__":
    unittest.main()
