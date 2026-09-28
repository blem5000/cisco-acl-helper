"""Tests for devices.enc backup rotation (headless-safe)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import prune_backups


class PruneBackupsTest(unittest.TestCase):
    def _make_tree(self, names):
        tmp = tempfile.mkdtemp()
        base = os.path.join(tmp, "devices.enc")
        open(base, "w").close()
        for name in names:
            open(os.path.join(tmp, name), "w").close()
        return base

    def test_keeps_newest_five(self):
        names = [f"devices.enc.bak-2026010{i}-120000" for i in range(1, 8)]
        base = self._make_tree(names)
        removed = prune_backups(base, keep=5)
        self.assertEqual(removed, 2)
        left = sorted(os.listdir(os.path.dirname(base)))
        self.assertEqual(left, ["devices.enc"] + names[-5:])

    def test_fewer_than_keep_removes_nothing(self):
        names = ["devices.enc.bak-20260101-120000",
                 "devices.enc.bak-20260102-120000"]
        base = self._make_tree(names)
        self.assertEqual(prune_backups(base, keep=5), 0)
        self.assertEqual(len(os.listdir(os.path.dirname(base))), 3)

    def test_other_files_untouched(self):
        base = self._make_tree(["devices.enc.bak-20260101-120000",
                                "notes.txt"])
        self.assertEqual(prune_backups(base, keep=0), 1)
        left = sorted(os.listdir(os.path.dirname(base)))
        self.assertEqual(left, ["devices.enc", "notes.txt"])


if __name__ == "__main__":
    unittest.main()
