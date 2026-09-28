"""Tests for PuTTY launching (headless-safe, all OS/dialogs mocked)."""

import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as appmod
from app import App
from i18n import STRINGS

EXE = r"C:\Program Files\PuTTY\putty.exe"
CREDS = {"host": "10.0.0.1", "port": 22, "username": "a", "password": "p"}


def make_stub(exe_path):
    stub = types.SimpleNamespace(
        T=lambda key: STRINGS["en"].get(key, key),
        putty_var=types.SimpleNamespace(get=lambda: exe_path),
    )
    stub._putty_exe = types.MethodType(App._putty_exe, stub)
    stub.open_putty_for_device = types.MethodType(
        App.open_putty_for_device, stub)
    return stub


class OpenPuttyTest(unittest.TestCase):
    def test_launches_with_device_credentials(self):
        stub = make_stub(EXE)
        with mock.patch.object(appmod, 'messagebox') as mbox, \
                mock.patch("subprocess.Popen") as popen, \
                mock.patch.object(os.path, "exists", return_value=True):
            self.assertTrue(stub.open_putty_for_device(dict(CREDS)))
        mbox.showwarning.assert_not_called()
        mbox.showerror.assert_not_called()
        popen.assert_called_once_with(
            [EXE, "-ssh", "a@10.0.0.1", "-P", "22", "-pw", "p"])

    def test_missing_exe_warns_and_does_not_launch(self):
        stub = make_stub("")
        with mock.patch.object(appmod, 'messagebox') as mbox, \
                mock.patch("subprocess.Popen") as popen:
            self.assertFalse(stub.open_putty_for_device(dict(CREDS)))
        mbox.showwarning.assert_called_once()
        popen.assert_not_called()

    def test_popen_failure_shows_error(self):
        stub = make_stub(EXE)
        with mock.patch.object(appmod, 'messagebox') as mbox, \
                mock.patch("subprocess.Popen",
                           side_effect=OSError("nope")), \
                mock.patch.object(os.path, "exists", return_value=True):
            self.assertFalse(stub.open_putty_for_device(dict(CREDS)))
        mbox.showerror.assert_called_once()


if __name__ == "__main__":
    unittest.main()
