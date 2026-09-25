"""End-to-end tests of the vuln apply worker on a scripted fake device."""

import os
import queue
import sys
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cisco_ssh
import vuln_telnet
from app import App
from i18n import STRINGS


class PromptChan:
    """Minimal channel: every newline is answered with a '#' prompt."""

    closed = False

    def __init__(self):
        self._n = 0

    def send(self, s):
        self._n += 1

    def recv_ready(self):
        return self._n > 0

    def recv(self, n):
        self._n = 0
        return b"sw#\n"

    def close(self):
        pass


class FakeSess(cisco_ssh.ConfigSession):
    """Scripted IOS: state maps vty range -> transport (None = missing)."""

    created = []

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.state = {"0 4": "all", "5 15": None}
        self.log = []
        self._alive = True
        self._cur = ""
        FakeSess.created.append(self)

    def open(self):
        self.log.append("open")
        self._chan = PromptChan()

    def close(self):
        self.log.append("close")
        self._chan = None

    def alive(self):
        return self._alive

    def exec(self, command, wait=2.5):
        self.log.append(command)
        if command == "":
            return "sw#"
        if command == "configure terminal":
            return "sw(config)#"
        if command.startswith("line vty"):
            self._cur = command.split("line vty", 1)[1].strip()
            return "sw(config-line)#"
        if command.startswith("transport input"):
            self.state[self._cur] = command.split("transport input", 1)[1].strip()
            return "sw(config-line)#"
        if command == "no transport input":
            self.state[self._cur] = None
            return "sw(config-line)#"
        if command == "end":
            return "sw#"
        if command == "write memory":
            return "Building configuration...\n[OK]"
        if command.startswith("show running-config | section"):
            lines = []
            for rng, t in self.state.items():
                lines.append(f"line vty {rng}")
                if t:
                    lines.append(f" transport input {t}")
            return "\n".join(lines)
        if command.startswith("show running-config | include"):
            return ""
        if command == "show ip ssh":
            return "SSH Enabled - version 2.0"
        raise AssertionError(f"unexpected cmd: {command!r}")

DEV = {"hostname": "sw", "host": "10.0.0.1", "port": 22,
       "username": "a", "password": "p", "enable": "e"}


class ApplyWorkerTest(unittest.TestCase):
    posttest_fail = False
    calls = []

    @staticmethod
    def fake_run_commands(host, username, password, enable=None,
                          port=22, timeout=15, commands=(), debug_log=None):
        ApplyWorkerTest.calls.append(tuple(commands or ()))
        if len(ApplyWorkerTest.calls) % 2 == 1:
            return {"show clock": "12:00:00"}  # pre-flight always works
        sess = FakeSess.created[-1]  # post-test reflects fixed state
        if (ApplyWorkerTest.posttest_fail
                or any(v != "ssh" for v in sess.state.values())):
            raise RuntimeError("Connection refused")
        return {"show clock": "12:00:00"}

    def _run_worker(self, answer):
        FakeSess.created.clear()
        ApplyWorkerTest.calls = []
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
        # scoped patches: restored after the worker joins, no leakage
        with mock.patch.object(cisco_ssh, "ConfigSession", FakeSess), \
                mock.patch.object(cisco_ssh, "run_commands",
                                  ApplyWorkerTest.fake_run_commands):
            worker = threading.Thread(
                target=types.MethodType(App._apply_all_worker, stub),
                args=([([dict(DEV)], vuln_telnet)],), daemon=True)
            worker.start()
            chunks, confirms, refreshes, done = [], [], [], None
            while True:
                kind, payload = stub.msg_queue.get(timeout=30)
                if kind == "vuln_apply_confirm":
                    _title, _text, box, ev = payload
                    confirms.append(_title)
                    box["ok"] = answer
                    ev.set()
                elif kind == "vuln_apply_chunk":
                    chunks.append(payload)
                elif kind == "vuln_apply_refresh":
                    refreshes.append(payload)
                elif kind == "vuln_apply_done":
                    done = payload
                    break
            worker.join(timeout=30)
            self.assertFalse(worker.is_alive())
        text = "\n".join(t for segs in chunks for t, _tag in segs)
        return done, text, confirms, refreshes

    def test_confirm_yes_writes_memory(self):
        ApplyWorkerTest.posttest_fail = False
        done, text, confirms, refreshes = self._run_worker(True)
        sess = FakeSess.created[-1]
        self.assertEqual(done, {"ok": 1, "rb": 0, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertIn("10.0.0.1", confirms[0])
        self.assertIn("write memory", sess.log)
        self.assertEqual(sess.state, {"0 4": "ssh", "5 15": "ssh"})
        self.assertIn("pre-flight OK", text)
        self.assertIn("New SSH login works", text)
        self.assertIn("write memory done", text)
        # final verdict: device fully clean, refresh carries compliant result
        self.assertEqual(len(refreshes), 1)
        host, fresh = refreshes[0]
        self.assertEqual(host, "10.0.0.1")
        self.assertTrue(fresh["compliant"])
        self.assertIn("OK: Telnet disabled", text)

    def test_confirm_no_rolls_back(self):
        ApplyWorkerTest.posttest_fail = False
        done, text, confirms, refreshes = self._run_worker(False)
        sess = FakeSess.created[-1]
        self.assertEqual(done, {"ok": 0, "rb": 1, "fail": 0, "skip": 0})
        self.assertEqual(len(confirms), 1)
        self.assertIn("10.0.0.1", confirms[0])
        self.assertNotIn("write memory", sess.log)
        self.assertEqual(sess.state, {"0 4": "all", "5 15": None})
        self.assertIn("Rolled back", text)
        self.assertEqual(len(refreshes), 1)
        _host, fresh = refreshes[0]
        self.assertFalse(fresh["compliant"])

    def test_failed_posttest_auto_rolls_back_without_dialog(self):
        ApplyWorkerTest.posttest_fail = True
        done, text, confirms, refreshes = self._run_worker(True)
        sess = FakeSess.created[-1]
        self.assertEqual(done, {"ok": 0, "rb": 0, "fail": 1, "skip": 0})
        self.assertEqual(confirms, [])
        self.assertNotIn("write memory", sess.log)
        self.assertEqual(sess.state, {"0 4": "all", "5 15": None})
        self.assertIn("New SSH login FAILED", text)
        self.assertEqual(len(refreshes), 1)


if __name__ == "__main__":
    unittest.main()
