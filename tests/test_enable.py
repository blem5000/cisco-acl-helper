"""Tests for ConfigSession.ensure_privileged with a fake IOS channel."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cisco_ssh import ConfigSession


class FakeChan:
    """Emulates an IOS shell. mode: priv15 | nopass | secret | wrongsecret."""

    closed = False

    def __init__(self, mode, secret="enpw"):
        self.mode = mode
        self.secret = secret
        self.priv = (mode == "priv15")
        self.buf = b""

    def send(self, s):
        if isinstance(s, str):
            s = s.encode()
        cmd = s.decode(errors="replace").strip()
        if cmd == "":
            self.buf += ("sw#\n" if self.priv else "sw>\n").encode()
        elif cmd == "enable":
            if self.mode in ("secret", "wrongsecret"):
                self.buf += b"Password: "
            else:
                self.priv = True
                self.buf += b"sw#\n"
        elif self.mode in ("secret", "wrongsecret") and not self.priv:
            if cmd == self.secret and self.mode == "secret":
                self.priv = True
                self.buf += b"sw#\n"
            else:
                self.buf += b"% Access denied\nsw>\n"

    def recv_ready(self):
        return bool(self.buf)

    def recv(self, n):
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def close(self):
        pass


class EnsurePrivilegedTest(unittest.TestCase):
    def _check(self, mode, secret=""):
        sess = ConfigSession("10.0.0.1", "a", "p", secret or None)
        sess._chan = FakeChan(mode)
        sess.ensure_privileged()

    def test_already_privileged(self):
        self._check("priv15")

    def test_bare_enable_without_secret(self):
        self._check("nopass")

    def test_enable_with_secret(self):
        self._check("secret", "enpw")

    def test_missing_secret_fails_clearly(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._check("secret", "")
        self.assertIn("sw>", str(ctx.exception))

    def test_wrong_secret_fails_clearly(self):
        with self.assertRaises(RuntimeError):
            sess = ConfigSession("10.0.0.1", "a", "p", "bad")
            sess._chan = FakeChan("wrongsecret")
            sess.ensure_privileged()


if __name__ == "__main__":
    unittest.main()
