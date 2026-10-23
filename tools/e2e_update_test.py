"""End-to-end proof that an update repairs an install poisoned by orphans.

Scenario (exactly the reported bug):
  1. take a freshly built app folder as the "new release",
  2. build an "old install" from it, then inject the leftover
     _internal/yaml/_yaml*.pyd that a previous version left behind,
  3. run the real update path (updater.copy_tree),
  4. launch the updated exe and require a real app window.

Before the fix step 3 left the orphan in place and step 4 died with
"module 'yaml' has no attribute 'error'". Usage:

    python tools/e2e_update_test.py <built-app-dir> <orphan-pyd>
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import updater  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: e2e_update_test.py <built-app-dir> <orphan-pyd>")
        return 2
    release = argv[1]
    orphan = argv[2]
    exe_name = "CiscoACLHelper.exe"
    if not os.path.isfile(os.path.join(release, exe_name)):
        print(f"FAIL: {exe_name} not found in {release}")
        return 2

    work = tempfile.mkdtemp(prefix="acl_e2e_")
    installed = os.path.join(work, "installed")
    print(f"work dir: {work}")

    # 1+2: "old install" = current build + the stale yaml package
    shutil.copytree(release, installed)
    poison_dir = os.path.join(installed, "_internal", "yaml")
    os.makedirs(poison_dir, exist_ok=True)
    shutil.copy2(orphan, os.path.join(poison_dir, os.path.basename(orphan)))
    user_file = os.path.join(installed, "devices.enc")
    with open(user_file, "wb") as f:
        f.write(b"USER SECRET - must survive")

    poisoned_pyd = os.path.join(poison_dir, os.path.basename(orphan))
    if not os.path.isfile(poisoned_pyd):
        print("FAIL: could not stage the orphan")
        return 1
    print(f"staged orphan: {os.path.relpath(poisoned_pyd, installed)}")

    # 3: the real update path
    updater.copy_tree(release, installed, updater.PRESERVED_FILES)
    print("update applied")

    ok = True
    if os.path.exists(poison_dir):
        print(f"FAIL: orphan package still present: {poison_dir}")
        ok = False
    else:
        print("PASS: orphan _internal/yaml removed by the update")

    if not os.path.isfile(user_file):
        print("FAIL: user file devices.enc was deleted")
        ok = False
    else:
        with open(user_file, "rb") as f:
            if f.read() != b"USER SECRET - must survive":
                print("FAIL: user file devices.enc was altered")
                ok = False
            else:
                print("PASS: user file devices.enc preserved")

    # 4: does the updated app actually start?
    smoke = os.path.join(HERE, "smoke_test.py")
    exe = os.path.join(installed, exe_name)
    print(f"smoke testing: {exe}")
    rc = subprocess.call([sys.executable, smoke, exe, "--wait", "25"])
    if rc != 0:
        print("FAIL: updated app did not start")
        ok = False
    else:
        print("PASS: updated app starts")

    if ok:
        shutil.rmtree(work, ignore_errors=True)
    else:
        print(f"left for inspection: {work}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
