"""Smoke test for a built Windows exe: does it start and stay up?

Usage:
    python tools/smoke_test.py <path-to-exe> [--wait SECONDS]

Exit code 0 = PASS (process alive, app window found),
          1 = FAIL (crashed, or only an error dialog appeared),
          2 = usage error.

Why not just "is the process alive": PyInstaller windowed builds show a
message box on an import error and then WAIT for the user to dismiss it, so
a crashed app also looks alive. We therefore inspect the windows owned by
the process: a real start shows Tk's window; a crash shows a plain
Windows dialog (#32770) and nothing else. The dialog text is printed, so
the traceback is visible in CI logs.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
import time

user32 = ctypes.windll.user32

EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

DIALOG_CLASS = "#32770"


def _windows_of(pid: int) -> list[dict]:
    """Top-level windows owned by pid: {hwnd, cls, title, text}."""
    found: list[dict] = []

    def _cb(hwnd, _lparam):
        wpid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value != pid:
            return True
        buf = ctypes.create_unicode_buffer(512)
        user32.GetClassNameW(hwnd, buf, 512)
        cls = buf.value
        user32.GetWindowTextW(hwnd, buf, 512)
        title = buf.value

        # dialog body text: concatenate static/text children
        parts: list[str] = []
        if cls == DIALOG_CLASS:
            def _child(ch, _l):
                cb2 = ctypes.create_unicode_buffer(4096)
                user32.GetWindowTextW(ch, cb2, 4096)
                if cb2.value.strip():
                    parts.append(cb2.value.strip())
                return True
            user32.EnumChildWindows(
                hwnd, ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)(_child), 0)

        found.append({"hwnd": hwnd, "cls": cls, "title": title,
                      "text": "\n".join(parts)})
        return True

    user32.EnumWindows(EnumWindowsProc(_cb), 0)
    return found


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: smoke_test.py <exe> [--wait SECONDS]")
        return 2
    exe = argv[1]
    wait = 12
    if "--wait" in argv:
        wait = int(argv[argv.index("--wait") + 1])

    print(f"launching: {exe}")
    proc = subprocess.Popen([exe], cwd=None)
    deadline = time.time() + wait
    app_windows: list[dict] = []
    while time.time() < deadline:
        time.sleep(0.5)
        if proc.poll() is not None:
            break
        wins = _windows_of(proc.pid)
        real = [w for w in wins if w["cls"] != DIALOG_CLASS]
        if real:
            app_windows = real
            time.sleep(2.0)  # let the window settle
            break

    rc = proc.poll()
    wins = _windows_of(proc.pid) if rc is None else []
    dialogs = [w for w in wins if w["cls"] == DIALOG_CLASS]

    if rc is not None:
        print(f"FAIL: process exited early with code {rc}")
        return 1

    if dialogs:
        print("FAIL: error dialog shown instead of the app window")
        for d in dialogs:
            print(f"  title: {d['title']}")
            if d["text"]:
                print("  " + d["text"].replace("\n", "\n  ")[:4000])
        try:
            proc.terminate()
        except Exception:
            pass
        return 1

    if not app_windows:
        print("FAIL: no application window appeared")
        try:
            proc.terminate()
        except Exception:
            pass
        return 1

    print("PASS: app window is up and no error dialog")
    for w in app_windows:
        print(f"  window: class={w['cls']!r} title={w['title']!r}")
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
