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
    """State = whether mode 6 queries are blocked.

    query_only: the primary block is configured. ignores_query_only:
    platform defect simulation - the block is present but queries still
    get answers (like 2960S on 15.2(1)E1).
    """

    INCLUDE = "show running-config | include ^ntp"
    BRIEF = "show ip interface brief"

    def __init__(self, query_only=False, ignores_query_only=False,
                 brief_has_host=True):
        self.blocked = False
        self.query_only = query_only
        self.ignores_query_only = ignores_query_only
        self.brief_has_host = brief_has_host
        self.log = []

    def show(self, cmd):
        if cmd == self.INCLUDE:
            lines = []
            if self.query_only:
                lines.append("ntp access-group query-only NTP-QUERY-BLOCK")
            lines.append("ntp server 172.26.56.2 prefer")
            lines.append("ntp server 172.26.56.3")
            return "\n".join(lines) + "\n"
        if cmd == self.BRIEF:
            lines = ["Interface              IP-Address      OK? Method "
                     "Status Protocol"]
            if self.brief_has_host:
                lines.append("Vlan1                  10.9.9.9          "
                             "YES manual up up")
            lines.append("Gi1/0/1                unassigned      "
                         "YES unset  up up")
            return "\n".join(lines)
        if cmd == "configure terminal":
            return "Enter configuration commands.  End with CNTL/Z."
        if cmd == "end":
            return ""
        raise AssertionError(f"unexpected show cmd: {cmd!r}")

    def config_line(self, cmd):
        self.log.append(cmd)
        s = cmd.strip()
        if cmd == "ntp access-group query-only NTP-QUERY-BLOCK":
            self.query_only = True
            if not self.ignores_query_only:
                self.blocked = True
            return ""
        if cmd == "ip access-group NTP-CTRL-IN in":
            self.blocked = True
            return ""
        if cmd in ("no ip access-group NTP-CTRL-IN in",
                   "no ip access-list standard NTP-QUERY-BLOCK",
                   "no ntp access-group query-only NTP-QUERY-BLOCK"):
            self.blocked = False
            return ""
        if cmd == "no ip access-list extended NTP-CTRL-IN":
            self.blocked = False
            return ""
        if cmd in ("ntp access-group peer NTP-SERVERS",
                   "no ntp access-group peer NTP-SERVERS",
                   "no ip access-list standard NTP-SERVERS"):
            return ""
        if s.startswith("interface ") or s == "exit":
            return ""
        if s.startswith("ip access-list standard NTP-QUERY-BLOCK") \
                or s.startswith("ip access-list extended NTP-CTRL-IN") \
                or s.startswith("ip access-list standard NTP-SERVERS"):
            return ""
        if s.startswith("permit ") or s.startswith("deny ") \
                or s.startswith("remark"):
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

    def _run_worker(self, answer, switch=None):
        FakeSess.switches = {"10.9.9.9": switch or FakeSwitch()}
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
        self._last_stub = stub
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
        hist = self._last_stub.cmd_history
        kinds = [e["kind"] for e in hist]
        self.assertIn("fix", kinds)
        self.assertIn("save", kinds)
        self.assertNotIn("rollback", kinds)
        self.assertTrue(all(e["host"] == "10.9.9.9" for e in hist))
        self.assertIn("ntp access-group query-only NTP-QUERY-BLOCK",
                      " ".join(c for e in hist for c in e["cmds"]))

    def test_no_answer_rolls_back(self):
        done, text, confirms, refreshes = self._run_worker(False)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 0, "rb": 1, "fail": 0, "skip": 0})
        self.assertFalse(sw.blocked)
        self.assertNotIn("write memory", " ".join(sw.log))
        _host, fresh = refreshes[0]
        self.assertFalse(fresh["compliant"])
        kinds = [e["kind"] for e in self._last_stub.cmd_history]
        self.assertIn("fix", kinds)
        self.assertIn("rollback", kinds)
        self.assertNotIn("save", kinds)

    def test_fallback_applied_when_primary_ignored(self):
        sw0 = FakeSwitch(query_only=True, ignores_query_only=True)
        done, text, confirms, refreshes = self._run_worker(True, sw0)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 1, "rb": 0, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertTrue(sw.blocked)
        log = " ".join(sw.log)
        self.assertIn("ip access-list extended NTP-CTRL-IN", log)
        self.assertIn("permit udp host 172.26.56.2 eq ntp any", log)
        self.assertIn("deny udp any any eq ntp log", log)
        self.assertIn("ip access-group NTP-CTRL-IN in", log)
        self.assertIn("write memory", log)
        _host, fresh = refreshes[0]
        self.assertTrue(fresh["compliant"])
        self.assertIn("mode 6 queries blocked", text)

    def test_fallback_rolls_back(self):
        sw0 = FakeSwitch(query_only=True, ignores_query_only=True)
        done, _text, _confirms, refreshes = self._run_worker(False, sw0)
        sw = FakeSess.switches["10.9.9.9"]
        self.assertEqual(done, {"ok": 0, "rb": 1, "fail": 0, "skip": 0})
        self.assertFalse(sw.blocked)
        self.assertTrue(sw.query_only)  # primary block left untouched
        self.assertNotIn("write memory", " ".join(sw.log))
        _host, fresh = refreshes[0]
        self.assertFalse(fresh["compliant"])

    def test_unscoppable_fallback_skips(self):
        sw0 = FakeSwitch(query_only=True, ignores_query_only=True,
                         brief_has_host=False)
        done, _text, confirms, _refreshes = self._run_worker(True, sw0)
        self.assertEqual(done, {"ok": 0, "rb": 0, "fail": 0, "skip": 1})
        self.assertEqual(confirms, [])
        self.assertNotIn("NTP-CTRL-IN", " ".join(sw0.log))


if __name__ == "__main__":
    unittest.main()
