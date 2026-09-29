"""Worker-level tests for the TLS bundle on a scripted fake switch.

Scenario A: both HTTP services on -> fix applied, verified off, saved.
Scenario B: operator answers No -> rollback re-enables both services.
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
import vuln_tls
from app import App
from i18n import STRINGS

IOS_SW = ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
          "Version 15.2(2)E7, RELEASE SOFTWARE (fc4)")


class FakeSwitch:
    """State = which HTTP services are on."""

    def __init__(self):
        self.http = True
        self.secure = True
        self.log = []

    def show(self, cmd):
        if cmd == "show running-config | include ^ip http":
            lines = []
            if self.http:
                lines.append("ip http server")
            if self.secure:
                lines.append("ip http secure-server")
            return "\n".join(lines)
        if cmd.startswith("show version"):
            return IOS_SW
        if cmd == "configure terminal":
            return "Enter configuration commands.  End with CNTL/Z."
        if cmd == "end":
            return ""
        raise AssertionError(f"unexpected show cmd: {cmd!r}")

    def config_line(self, cmd):
        self.log.append(cmd)
        if cmd == "no ip http server":
            self.http = False
            return ""
        if cmd == "no ip http secure-server":
            self.secure = False
            return ""
        if cmd == "ip http server":
            self.http = True
            return ""
        if cmd == "ip http secure-server":
            self.secure = True
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
        self.sw.log.append(command)
        if command == "":
            return "sw#"
        if command == "write memory":
            return "Building configuration...\n[OK]"
        if command in ("configure terminal", "end"):
            return self.sw.show(command)
        if command in vuln_tls.CHECK_COMMANDS:
            return self.sw.show(command)
        # config sub-commands: raw IOS output (a "% ..." line means reject,
        # detected by the real ConfigSession.configure)
        return self.sw.config_line(command)


DEV = {"hostname": "sw", "host": "10.9.9.9", "port": 22,
       "username": "a", "password": "p", "enable": "e"}


class ApplyTLSTest(unittest.TestCase):
    @staticmethod
    def fake_run_commands(host, username, password, enable=None,
                          port=22, timeout=15, commands=(), debug_log=None):
        return {"show clock": "12:00:00"}

    def _run_worker(self, answer):
        FakeSess.switches = {"10.9.9.9": FakeSwitch()}
        stub = types.SimpleNamespace(
            msg_queue=queue.Queue(),
            _vuln_stop=threading.Event(),
            lang="en",
            T=lambda key: STRINGS["en"].get(key, key),
            _ssh_debug_log=lambda: None,
        )
        stub._try_rollback = types.MethodType(App._try_rollback, stub)
        stub._log_cmds = types.MethodType(App._log_cmds, stub)
        stub._put_apply = types.MethodType(App._put_apply, stub)
        stub._apply_worker = types.MethodType(App._apply_worker, stub)
        stub._refresh_and_residual = types.MethodType(
            App._refresh_and_residual, stub)
        with mock.patch.object(cisco_ssh, "ConfigSession", FakeSess), \
                mock.patch.object(cisco_ssh, "run_commands",
                                  ApplyTLSTest.fake_run_commands):
            worker = threading.Thread(
                target=types.MethodType(App._apply_all_worker, stub),
                args=([([dict(DEV)], vuln_tls)],), daemon=True)
            worker.start()
            chunks, confirms, refreshes, done = [], [], [], None
            while True:
                kind, payload = stub.msg_queue.get(timeout=60)
                if kind == "vuln_apply_confirm":
                    _title, _text, box, ev, _creds = payload
                    confirms.append(True)
                    box["ok"] = answer
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

    def test_apply_both_services_saved(self):
        done, text, confirms, refreshes = self._run_worker(True)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 1, "rb": 0, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertFalse(sw.http)
        self.assertFalse(sw.secure)
        self.assertIn("no ip http server", " ".join(sw.log))
        self.assertIn("write memory", " ".join(sw.log))
        _host, fresh = refreshes[0]
        self.assertTrue(fresh["compliant"])
        self.assertIn("HTTP(S) server disabled", text)

    def test_no_answer_rolls_back(self):
        done, text, confirms, refreshes = self._run_worker(False)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 0, "rb": 1, "fail": 0, "skip": 0})
        self.assertTrue(sw.http)
        self.assertTrue(sw.secure)
        self.assertNotIn("write memory", " ".join(sw.log))
        _host, fresh = refreshes[0]
        self.assertFalse(fresh["compliant"])


if __name__ == "__main__":
    unittest.main()
