"""Worker-level tests for the SSH bundle on a scripted fake switch.

Scenario A: `algorithm ?` offers mac+encryption (no kex) -> kex goes to
the OpenProject note upfront, the rest applies and is saved.
Scenario B: the help probe fails on an XE box -> kex is attempted, the
switch rejects it with "% Invalid input" (the reported incident) ->
kex is skipped gracefully while mac/encryption/version still apply.
"""

import os
import queue
import sys
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cisco_ssh
import ssh_scan
import vuln_ssh
from app import App
from i18n import STRINGS

XE_VER = ("Cisco IOS XE Software, Version 17.06.01\n"
          "Cisco IOS Software, Catalyst L3 Switch Software")
HELP_MAC_ENC = ("  encryption  Encrytption algorithms advertised "
                "to other party\n"
                "  mac         MAC algorithms advertised to other party\n")


class FakeSwitch:
    """State = offered sets; `kex` keyword rejected like older IOS."""

    def __init__(self, help_text):
        self.help_text = help_text
        self.macs = ["hmac-sha1", "hmac-sha1-96"]
        self.kex = ["diffie-hellman-group14-sha1",
                    "diffie-hellman-group1-sha1"]
        self.ciphers = ["aes128-ctr", "aes128-cbc"]
        self.log = []

    # -- scripted scan + show outputs reflecting current state --
    def scan(self):
        return {"banner": "SSH-2.0-Cisco-1.25", "sshv1": False,
                "kex": list(self.kex),
                "ciphers": list(self.ciphers), "macs": list(self.macs),
                "strict_kex": False}

    def show(self, cmd):
        if cmd == "show ip ssh":
            return "SSH Enabled - version 2.0"
        if cmd.startswith("show running-config | include"):
            return ""
        if cmd.startswith("show version"):
            return XE_VER
        if cmd == "configure terminal":
            return "Enter configuration commands.  End with CNTL/Z."
        if cmd == "ip ssh server algorithm ?":
            return self.help_text
        if cmd == "end":
            return ""
        raise AssertionError(f"unexpected show cmd: {cmd!r}")

    # -- config session surface --
    def config_line(self, cmd):
        self.log.append(cmd)
        if "algorithm kex" in cmd:
            return "% Invalid input detected at '^' marker."
        if cmd.startswith("ip ssh server algorithm mac "):
            self.macs = cmd.split("ip ssh server algorithm mac ",
                                   1)[1].split()
            return ""
        if cmd.startswith("ip ssh server algorithm encryption "):
            self.ciphers = cmd.split(
                "ip ssh server algorithm encryption ", 1)[1].split()
            return ""
        if cmd == "ip ssh version 2":
            return ""
        if cmd.startswith("no ip ssh server algorithm "):
            kind = cmd.rsplit(" ", 1)[1]
            if kind == "kex":
                return "% Invalid input detected at '^' marker."
            if kind == "mac":
                self.macs = ["hmac-sha1", "hmac-sha1-96"]
            elif kind == "encryption":
                self.ciphers = ["aes128-ctr", "aes128-cbc"]
            return ""
        raise AssertionError(f"unexpected config cmd: {cmd!r}")


class FakeSess(cisco_ssh.ConfigSession):
    switches = {}

    def __init__(self, host, *a, **k):
        super().__init__(host, *a, **k)
        self.sw = FakeSess.switches[host]

    def open(self):
        pass

    def close(self):
        pass

    def alive(self):
        return True

    def ensure_privileged(self):
        pass

    def exec(self, command, wait=2.5):
        if command == "":
            return "sw#"
        if command == "write memory":
            return "Building configuration...\n[OK]"
        if command in vuln_ssh.CHECK_COMMANDS:
            return self.sw.show(command)
        # config sub-commands: raw IOS output (a "% ..." line means reject,
        # detected by the real ConfigSession.configure)
        return self.sw.config_line(command)


DEV = {"hostname": "sw", "host": "10.9.9.9", "port": 22,
       "username": "a", "password": "p", "enable": "e"}


class ApplySSHTest(unittest.TestCase):
    @staticmethod
    def fake_run_commands(host, username, password, enable=None,
                          port=22, timeout=15, commands=(), debug_log=None):
        return {"show clock": "12:00:00"}

    def _run_worker(self, help_text):
        FakeSess.switches = {"10.9.9.9": FakeSwitch(help_text)}
        stub = types.SimpleNamespace(
            msg_queue=queue.Queue(),
            _vuln_stop=threading.Event(),
            lang="en",
            T=lambda key: STRINGS["en"].get(key, key),
            _ssh_debug_log=lambda: None,
        )
        stub._try_rollback = types.MethodType(App._try_rollback, stub)
        stub._put_apply = types.MethodType(App._put_apply, stub)
        stub._apply_worker = types.MethodType(App._apply_worker, stub)
        stub._refresh_and_residual = types.MethodType(
            App._refresh_and_residual, stub)
        with mock.patch.object(cisco_ssh, "ConfigSession", FakeSess), \
                mock.patch.object(cisco_ssh, "run_commands",
                                  ApplySSHTest.fake_run_commands), \
                mock.patch.object(ssh_scan, "scan",
                                  lambda h, p=22, timeout=10.0:
                                  FakeSess.switches[h].scan()):
            worker = threading.Thread(
                target=types.MethodType(App._apply_all_worker, stub),
                args=([([dict(DEV)], vuln_ssh)],), daemon=True)
            worker.start()
            chunks, confirms, refreshes, done = [], [], [], None
            while True:
                kind, payload = stub.msg_queue.get(timeout=60)
                if kind == "vuln_apply_confirm":
                    _title, _text, box, ev = payload
                    confirms.append(True)
                    box["ok"] = True
                    ev.set()
                elif kind == "vuln_apply_chunk":
                    chunks.append(payload)
                elif kind == "vuln_apply_refresh":
                    refreshes.append(payload)
                elif kind == "vuln_apply_done":
                    done = payload
                    break
            worker.join(timeout=60)
            self.assertFalse(worker.is_alive())
        text = "\n".join(t for segs in chunks for t, _tag in segs)
        return done, text, confirms, refreshes

    def test_help_without_kex_excludes_it_upfront(self):
        done, text, confirms, refreshes = self._run_worker(HELP_MAC_ENC)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 1, "rb": 0, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertEqual(sw.macs, ["hmac-sha1"])
        self.assertEqual(sw.ciphers, ["aes128-ctr"])
        self.assertEqual(sw.kex, ["diffie-hellman-group14-sha1",
                                  "diffie-hellman-group1-sha1"])  # untouched
        self.assertNotIn("kex", " ".join(sw.log))  # never even attempted
        self.assertNotIn("Skipped kex", text)
        # final verdict: mac/cbc clean, kex still failing (OpenProject note)
        self.assertEqual(len(refreshes), 1)
        _host, fresh = refreshes[0]
        self.assertFalse(fresh["compliant"])
        self.assertEqual(fresh["subs"]["mac"]["status"], "ok")
        self.assertEqual(fresh["subs"]["kex"]["status"], "fail")
        self.assertIn("SSH Weak Key Exchange Algorithms Enabled", text)

    def test_rejected_kex_group_skipped_rest_saved(self):
        done, text, confirms, refreshes = self._run_worker("% Invalid input detected")
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 1, "rb": 0, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertIn("Skipped kex", text)  # graceful, no UNVERIFIED rollback
        self.assertNotIn("UNVERIFIED", text)
        self.assertEqual(sw.macs, ["hmac-sha1"])
        self.assertEqual(sw.ciphers, ["aes128-ctr"])
        self.assertEqual(len(refreshes), 1)


if __name__ == "__main__":
    unittest.main()
