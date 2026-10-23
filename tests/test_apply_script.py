"""The generated fallback .bat must also clean _internal orphans."""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import updater


class ApplyScriptTest(unittest.TestCase):
    def test_bat_contains_scoped_mirror(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(updater.tempfile, "gettempdir",
                                   return_value=tmp), \
                 mock.patch.object(updater, "exe_path",
                                   return_value=os.path.join(tmp, "a.exe")):
                path = updater.write_apply_script(
                    os.path.join(tmp, "r.zip"), os.path.join(tmp, "dst"), 4242)
                with open(path, "r", encoding="utf-8") as f:
                    bat = f.read()

        # mirrors _internal only, and only when the source exists
        self.assertIn("_internal", bat)
        self.assertIn("/MIR", bat)
        self.assertIn('if exist "%DST%\\_internal" if exist "%SRC%\\_internal"',
                      bat)
        # the blind /MIR must never run against the whole install dir
        self.assertNotIn('robocopy "%SRC%" "%DST%" /MIR', bat)
        # user files stay excluded from the plain copy
        for name in updater.PRESERVED_FILES:
            self.assertIn(name, bat)


if __name__ == "__main__":
    unittest.main()
