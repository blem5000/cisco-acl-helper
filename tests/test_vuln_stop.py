"""Tests for responsive Stop in the vulnerability check worker."""

import os
import queue
import sys
import threading
import time
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import App
from i18n import STRINGS


def _stub(**kw):
    base = dict(msg_queue=queue.Queue(),
                _vuln_stop=threading.Event(),
                lang="en",
                T=lambda key: STRINGS["en"].get(key, key),
                _ssh_debug_log=lambda: None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def _instant_mod(results):
    """Fake provider: instant {host: result-dict} lookup."""
    return types.SimpleNamespace(
        fetch_check_run=lambda host, *a, **k: dict(results[host]))


class StopFeedbackTest(unittest.TestCase):
    def test_stop_acknowledged_immediately(self):
        calls = {}
        stub = _stub()
        stub.btn_vuln_stop = types.SimpleNamespace(
            configure=lambda **kw: calls.update(kw))
        stub.status = types.SimpleNamespace(
            set=lambda v: calls.setdefault("status", []).append(v))
        App.stop_vuln_check(stub)
        self.assertTrue(stub._vuln_stop.is_set())
        self.assertEqual(calls.get("state"), "disabled")
        self.assertTrue(any("Stopping" in s for s in calls["status"]))


class StopWorkerTest(unittest.TestCase):
    def _run_worker(self, stub, devs, mods):
        App._vuln_worker(stub, devs, mods)
        out = []
        while not stub.msg_queue.empty():
            out.append(stub.msg_queue.get_nowait())
        return out

    def test_all_chunks_then_done(self):
        devs = [{"host": "h1", "username": "u"},
                {"host": "h2", "username": "u"}]
        mod = _instant_mod({"h1": {"vuln": "telnet", "n": 1},
                            "h2": {"vuln": "telnet", "n": 2}})
        msgs = self._run_worker(_stub(), devs, [mod])
        kinds = [k for k, _p in msgs]
        self.assertEqual(kinds.count("vuln_chunk"), 2)
        self.assertEqual(kinds[-1], "vuln_done")

    def test_stop_abandons_straggler(self):
        release = threading.Event()
        started = threading.Event()

        def slow_fetch(host, *a, **k):
            if host == "slow":
                started.set()
                release.wait(timeout=60)
                return {"vuln": "telnet", "n": 9}
            return {"vuln": "telnet", "n": 1}

        stub = _stub()
        mod = types.SimpleNamespace(fetch_check_run=slow_fetch)
        devs = [{"host": "fast", "username": "u"},
                {"host": "slow", "username": "u"}]
        worker = threading.Thread(target=App._vuln_worker,
                                  args=(stub, devs, [mod]), daemon=True)
        worker.start()
        self.assertTrue(started.wait(timeout=10))
        time.sleep(0.3)  # let the fast chunk land
        stub._vuln_stop.set()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())  # did NOT wait out the straggler
        kinds = []
        while not stub.msg_queue.empty():
            kinds.append(stub.msg_queue.get_nowait()[0])
        self.assertIn("vuln_chunk", kinds)  # fast result kept
        self.assertEqual(kinds[-1], "vuln_done")
        release.set()  # let the abandoned op finish, no hang at exit


if __name__ == "__main__":
    unittest.main()
