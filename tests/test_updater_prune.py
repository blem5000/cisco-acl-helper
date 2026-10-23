"""Tests for update-time orphan pruning. Headless-safe (no Tk, no network)."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import updater


def _write(path: str, data: bytes = b"x") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


class PruneOrphansTest(unittest.TestCase):
    """A file the new release no longer ships must not survive an update."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stale_module_removed(self):
        # old install has a leftover yaml package; new release does not
        _write(os.path.join(self.dst, "_internal", "yaml", "_yaml.pyd"))
        _write(os.path.join(self.dst, "_internal", "paramiko", "transport.py"))
        _write(os.path.join(self.src, "_internal", "paramiko", "transport.py"))

        removed = updater._prune_orphans(self.src, self.dst, set())

        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "_internal", "yaml", "_yaml.pyd")))
        # the empty leftover directory goes too
        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "_internal", "yaml")))
        # a file the release still ships stays
        self.assertTrue(os.path.exists(
            os.path.join(self.dst, "_internal", "paramiko", "transport.py")))
        self.assertEqual(len(removed), 1)

    def test_user_files_are_never_dropped(self):
        for name in updater.PRESERVED_FILES:
            _write(os.path.join(self.dst, name), b"keep me")
        _write(os.path.join(self.src, "_internal", "x.dll"))

        updater._prune_orphans(self.src, self.dst,
                               set(updater.PRESERVED_FILES))

        for name in updater.PRESERVED_FILES:
            path = os.path.join(self.dst, name)
            self.assertTrue(os.path.exists(path), name)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"keep me")

    def test_file_inside_release_tree_kept(self):
        _write(os.path.join(self.dst, "CiscoACLHelper.exe"), b"exe")
        _write(os.path.join(self.src, "CiscoACLHelper.exe"), b"exe")
        updater._prune_orphans(self.src, self.dst, set())
        self.assertTrue(os.path.exists(
            os.path.join(self.dst, "CiscoACLHelper.exe")))

    def test_nothing_to_prune(self):
        _write(os.path.join(self.src, "a.txt"))
        _write(os.path.join(self.dst, "a.txt"))
        self.assertEqual(updater._prune_orphans(self.src, self.dst, set()), [])

    def test_locked_file_does_not_abort_update(self):
        _write(os.path.join(self.dst, "old.dll"))
        _write(os.path.join(self.src, "new.dll"))
        real_remove = os.remove

        def _deny(path, *a, **kw):
            if path.endswith("old.dll"):
                raise OSError("in use")
            return real_remove(path, *a, **kw)

        with mock.patch("os.remove", _deny):
            removed = updater._prune_orphans(self.src, self.dst, set())

        self.assertEqual(removed, [])  # not reported, but no exception either


class CopyTreePrunesTest(unittest.TestCase):
    """copy_tree must prune as part of a normal update."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "src")
        self.dst = os.path.join(self.tmp, "dst")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_update_removes_orphan_from_previous_version(self):
        _write(os.path.join(self.dst, "_internal", "yaml", "_yaml.pyd"))
        _write(os.path.join(self.dst, "devices.enc"), b"secret")
        _write(os.path.join(self.src, "_internal", "paramiko", "x.py"))
        _write(os.path.join(self.src, "app.exe"), b"exe")

        updater.copy_tree(self.src, self.dst, updater.PRESERVED_FILES)

        self.assertFalse(os.path.exists(
            os.path.join(self.dst, "_internal", "yaml", "_yaml.pyd")))
        self.assertTrue(os.path.exists(os.path.join(self.dst, "app.exe")))
        self.assertTrue(os.path.exists(os.path.join(self.dst, "devices.enc")))


if __name__ == "__main__":
    unittest.main()
