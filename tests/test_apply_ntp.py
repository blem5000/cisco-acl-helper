"""Worker-level tests for the NTP bundle on a scripted fake switch.

The UDP mode 6 probe is mocked to answer while the switch is unprotected
and to stay silent once the query-only group is applied.

Scenario A: probe answers -> fix applied, probe silent, saved.
Scenario B: operator answers No -> rollback removes our lines, probe loud.
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
import ntp_probe
import vuln_ntp
from app import App
from i18n import STRINGS


class FakeSwitch:
    """State = whether mode 6 queries are blocked."""

    def __init__(self):
        self.blocked = False
        self.log = []

    def show(self, cmd):
        if cmd == "show running-config | include ^ntp":
            if self.blocked:
                return ("ntp access-group query-only NTP-QUERY-BLOCK\n"
                        "ntp server 10.0.0.1\n")
            return "ntp server 10.0.0.1\n"
        if cmd == "configure terminal":
            return "Enter configuration commands.  End with CNTL/Z."
        if cmd == "end":
            return ""
        raise AssertionError(f"unexpected show cmd: {cmd!r}")

    def config_line(self, cmd):
        self.log.append(cmd)
        if cmd == "ntp access-group query-only NTP-QUERY-BLOCK":
            self.blocked = True
            return ""
        if cmd in ("no ip access-list standard NTP-QUERY-BLOCK",
                   "no ntp access-group query-only NTP-QUERY-BLOCK"):
            self.blocked = False
            return ""
        if cmd.startswith("ip access-list standard NTP-QUERY-BLOCK"):
            return ""
        if cmd.startswith(" remark") or cmd.startswith(" deny") \
                or cmd == " exit":
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
        if command in vuln_ntp.CHECK_COMMANDS:
            return self.sw.show(command)
        return self.sw.config_line(command)


def fake_probe(host, port=123, timeout=2.0, tries=3):
    sw = FakeSess.switches[host]
    if sw.blocked:
        return False, "no mode 6 reply (timeout)"
    return True, "12-byte mode 6 reply"


DEV = {"hostname": "sw", "host": "10.9.9.9", "port": 22,
       "username": "a", "password": "p", "enable": "e"}


class ApplyNTPTest(unittest.TestCase):
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
        stub._put_apply = types.MethodType(App._put_apply, stub)
        stub._apply_worker = types.MethodType(App._apply_worker, stub)
        stub._refresh_and_residual = types.MethodType(
            App._refresh_and_residual, stub)
        with mock.patch.object(cisco_ssh, "ConfigSession", FakeSess), \
                mock.patch.object(cisco_ssh, "run_commands",
                                  ApplyNTPTest.fake_run_commands), \
                mock.patch.object(ntp_probe, "probe", fake_probe):
            worker = threading.Thread(
                target=types.MethodType(App._apply_all_worker, stub),
                args=([([dict(DEV)], vuln_ntp)],), daemon=True)
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

    def test_apply_probe_silent_saved(self):
        done, text, confirms, refreshes = self._run_worker(True)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 1, "rb": 0, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertTrue(sw.blocked)
        self.assertIn("ntp access-group query-only NTP-QUERY-BLOCK",
                      " ".join(sw.log))
        self.assertIn("write memory", " ".join(sw.log))
        _host, fresh = refreshes[0]
        self.assertTrue(fresh["compliant"])
        self.assertIn("mode 6 queries blocked", text)

    def test_no_answer_rolls_back(self):
        done, text, confirms, refreshes = self._run_worker(False)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 0, "rb": 1, "fail": 0, "skip": 0})
        self.assertFalse(sw.blocked)
        self.assertNotIn("write memory", " ".join(sw.log))
        _host, fresh = refreshes[0]
        self.assertFalse(fresh["compliant"])


if __name__ == "__main__":
    unittest.main()
