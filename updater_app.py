"""CiscoACLHelperUpdater - separate update-installer program (own window).

Started by the main app (updater.launch_gui_updater) AFTER the release zip
was downloaded. Shows a small Tk window with phase + progress bar, so no
cmd/powershell windows are ever needed:

  1. wait for the main app PID to exit (PID-reuse guarded),
  2. extract the zip to a staging dir (zipfile, with progress),
  3. copy files over the app dir, preserving user files (shutil, progress),
  4. restart the main exe, clean up temp files, show success, quit.

Usage (all args required):
  CiscoACLHelperUpdater.exe --zip <zip> --target <dir> --exe <name>
      --pid <pid> --pid-start <unix> --tag <tag>

No Cancel button on purpose: interrupting the copy would leave a half
updated install. On error the window stays open with the log path.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import traceback
from tkinter import ttk

try:
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)
except NameError:
    pass  # frozen (PyInstaller): modules are bundled

import updater

STR = {
    "pl": {
        "title": "Aktualizacja Cisco ACL Helper",
        "heading": "Instalowanie aktualizacji {tag}...",
        "wait": "Oczekiwanie na zamknięcie programu...",
        "extract": "Rozpakowywanie... {pct}",
        "copy": "Kopiowanie plików... {pct}",
        "restart": "Uruchamianie nowej wersji...",
        "done": "Gotowe — nowa wersja uruchomiona.",
        "error": "Błąd aktualizacji.",
        "close": "Zamknij",
        "log_hint": "Szczegóły zapisano w:\n{path}",
    },
    "en": {
        "title": "Cisco ACL Helper Update",
        "heading": "Installing update {tag}...",
        "wait": "Waiting for the app to close...",
        "extract": "Extracting... {pct}",
        "copy": "Copying files... {pct}",
        "restart": "Starting the new version...",
        "done": "Done — new version started.",
        "error": "Update failed.",
        "close": "Close",
        "log_hint": "Details saved in:\n{path}",
    },
}


def detect_lang(target_dir: str) -> str:
    try:
        with open(os.path.join(target_dir, "config.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
        lang = data.get("lang", "en") if isinstance(data, dict) else "en"
        return lang if lang in STR else "en"
    except Exception:
        return "en"


class UpdaterApp(tk.Tk):
    def __init__(self, args):
        super().__init__()
        self.args = args
        self.S = STR[detect_lang(args.target)]
        self.tag = args.tag
        self.title(self.S["title"])
        self.geometry("480x300")
        self.minsize(440, 280)
        self.resizable(False, False)
        self._center()

        self.log_path = os.path.join(
            tempfile.gettempdir(), f"acl_update_{os.getpid()}.log")
        self._log_fh = open(self.log_path, "w", encoding="utf-8")
        self.log(f"tag={self.tag} target={args.target} pid={args.pid}")

        self.msg_queue: queue.Queue = queue.Queue()
        self.failed = False

        ttk.Label(self, text=self.S["heading"].format(tag=self.tag),
                  font=("TkDefaultFont", 11, "bold")).pack(
                      anchor="w", padx=14, pady=(14, 4))
        self.phase_var = tk.StringVar(value=self.S["wait"])
        ttk.Label(self, textvariable=self.phase_var).pack(
            anchor="w", padx=14)
        self.prog = ttk.Progressbar(self, mode="determinate", maximum=1000,
                                    length=440)
        self.prog.pack(fill="x", padx=14, pady=(6, 8))
        self.txt = tk.Text(self, height=7, font=("Consolas", 9),
                           state="disabled")
        self.txt.pack(fill="both", expand=True, padx=14)
        self.btn_close = ttk.Button(self, text=self.S["close"],
                                    command=self.destroy, state="disabled")
        self.btn_close.pack(anchor="e", padx=14, pady=10)

        self.after(100, self._poll)
        threading.Thread(target=self._worker, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._on_close_attempt)

    # ---------- helpers ----------
    def _center(self):
        self.update_idletasks()
        w, h = 480, 300
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")

    def _on_close_attempt(self):
        # refuse to close while working - a half-copied install is worse
        if not self.failed:
            return
        self.destroy()

    def log(self, msg: str):
        try:
            self._log_fh.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            self._log_fh.flush()
        except Exception:
            pass

    def _ui_log(self, msg: str):
        self.txt.configure(state="normal")
        self.txt.insert(tk.END, msg + "\n")
        self.txt.see(tk.END)
        self.txt.configure(state="disabled")

    def _set_phase(self, text: str, value: int | None = None):
        self.phase_var.set(text)
        if value is not None:
            self.prog.configure(value=value)

    def _poll(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "phase":
                    text, value = payload
                    self._set_phase(text, value)
                elif kind == "log":
                    self._ui_log(payload)
                elif kind == "error":
                    self.failed = True
                    self._set_phase(self.S["error"])
                    self._ui_log(payload)
                    self._ui_log(self.S["log_hint"].format(path=self.log_path))
                    self.btn_close.configure(state="normal")
                    self.lift()
                    self.focus_force()
                elif kind == "done":
                    self._set_phase(self.S["done"], 1000)
                    self.after(2000, self.destroy)
        except queue.Empty:
            pass
        if not self.failed:
            self.after(100, self._poll)

    # ---------- worker ----------
    def _emit_phase(self, key: str, frac: float):
        pct = f"{int(frac * 100)}%"
        self.msg_queue.put(("phase", (self.S[key].format(pct=pct),
                                      int(frac * 1000))))

    def _worker(self):
        a = self.args
        try:
            self.log("waiting for PID "
                     f"{a.pid} (start {a.pid_start})")
            updater.wait_for_exit(a.pid, a.pid_start)
            self.log("process gone")

            staging = os.path.join(tempfile.gettempdir(),
                                   f"acl_update_stage_{a.pid}")

            def _ex(done, total):
                self._emit_phase("extract", 0.40 * done / max(total, 1))
            self.log(f"extracting {a.zip}")
            updater.extract_zip(a.zip, staging, _ex)
            src = updater.resolve_source(staging, a.exe)
            self.log(f"source dir: {src}")

            def _cp(done, total):
                self._emit_phase("copy",
                                 0.40 + 0.55 * done / max(total, 1))
            self.log(f"copying -> {a.target}")
            updater.copy_tree(src, a.target, updater.PRESERVED_FILES, _cp)
            updater.clear_skipped_version(a.target)

            self.msg_queue.put(("phase", (self.S["restart"], 980)))
            exe_full = os.path.join(a.target, a.exe)
            self.log(f"starting {exe_full}")
            subprocess.Popen(
                [exe_full], cwd=a.target,
                creationflags=getattr(subprocess, "DETACHED_PROCESS", 0),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, close_fds=True)

            for p in (a.zip,):
                try:
                    os.remove(p)
                except OSError:
                    pass
            try:
                shutil.rmtree(staging, ignore_errors=True)
            except Exception:
                pass
            self.log("done")
            self.msg_queue.put(("done", None))
        except Exception:
            self.log("FAILED\n" + traceback.format_exc())
            self.msg_queue.put(("error", traceback.format_exc(limit=3)))
        finally:
            try:
                self._log_fh.close()
            except Exception:
                pass


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--zip", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--exe", required=True)
    p.add_argument("--pid", required=True, type=int)
    p.add_argument("--pid-start", required=True, type=int)
    p.add_argument("--tag", required=True)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not os.path.isfile(args.zip):
        raise SystemExit(f"zip not found: {args.zip}")
    if not os.path.isdir(args.target):
        raise SystemExit(f"target dir not found: {args.target}")
    app = UpdaterApp(args)
    app.mainloop()


if __name__ == "__main__":
    main()
