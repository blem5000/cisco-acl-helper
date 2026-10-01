"""Cisco ACL Helper - Tkinter app, PL/EN, SSH, encrypted device store."""

from __future__ import annotations

import glob
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import acl_parser
import crypto_store
import track
import updater
import vuln_ssh
import vuln_telnet
from dialogs import MasterDialog
from tab_audit import AuditTabMixin
from tab_devices import DevicesTabMixin
from tab_gen import GeneratorTabMixin
from tab_search import SearchTabMixin
from tab_subnets import SubnetsTabMixin
from tab_track import TrackTabMixin
from tab_vuln import VulnTabMixin, VULN_ALL_ID, VULN_MODS
from i18n import STRINGS, VALID_LANGS
from version import __version__ as APP_VERSION


#: How many timestamped devices.enc backups to keep (oldest pruned on import).
STORE_BACKUP_KEEP = 5


def prune_backups(base_path: str, keep: int = STORE_BACKUP_KEEP) -> int:
    """Delete oldest `base_path.bak-*` files, keep newest `keep`.

    Names carry `%Y%m%d-%H%M%S` timestamps, so plain sorting is newest-last.
    Returns the number of removed files; unreadable entries are skipped.
    """
    paths = sorted(glob.glob(base_path + ".bak-*"))
    doomed = paths[:max(0, len(paths) - keep)]
    removed = 0
    for path in doomed:
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
    return removed


#: Vulnerability providers behind the shared check/apply workers.

#: Synthetic registry id running every provider; must stay out of VULN_MODS.


def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


APP_DIR = app_dir()
DEVICES_FILE = os.path.join(APP_DIR, "devices.enc")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
SSH_DEBUG_LOG = os.path.join(APP_DIR, "ssh_debug.log")


def load_lang() -> str:
    lang = _read_config().get("lang", "en")
    return lang if lang in VALID_LANGS else "en"


def save_lang(lang: str) -> None:
    cfg = _read_config()
    cfg["lang"] = lang
    _write_config(cfg)


def load_dhcp_server() -> str:
    return str(_read_config().get("dhcp_server", "") or "")


def save_dhcp_server(server: str) -> None:
    cfg = _read_config()
    cfg["dhcp_server"] = server
    _write_config(cfg)


def load_putty_path() -> str:
    return str(_read_config().get("putty_path", "") or "")


def save_putty_path(path: str) -> None:
    cfg = _read_config()
    cfg["putty_path"] = path
    _write_config(cfg)


def load_ssh_debug() -> bool:
    return bool(_read_config().get("ssh_debug", False))


def save_ssh_debug(enabled: bool) -> None:
    cfg = _read_config()
    cfg["ssh_debug"] = bool(enabled)
    _write_config(cfg)


def load_update_auto() -> bool:
    v = _read_config().get("update_auto", True)
    return bool(v) if isinstance(v, bool) else True


def save_update_auto(enabled: bool) -> None:
    cfg = _read_config()
    cfg["update_auto"] = bool(enabled)
    _write_config(cfg)


def load_skipped_version() -> str:
    return str(_read_config().get("update_skipped", "") or "")


def save_skipped_version(tag: str) -> None:
    cfg = _read_config()
    cfg["update_skipped"] = tag
    _write_config(cfg)


def _read_config() -> dict:
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_config(data: dict) -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


class App(tk.Tk, SearchTabMixin, DevicesTabMixin, SubnetsTabMixin,
          GeneratorTabMixin, TrackTabMixin, AuditTabMixin, VulnTabMixin):

    def __init__(self):
        super().__init__()
        self.lang = load_lang()
        self.master_pw: str | None = None
        self._weak_warned = False  # warn once per session about weak master pw
        self.devices: list[dict] = []
        self.subnets: list[dict] = []  # {"subnet": ..., "acl_in": ..., "acl_out": ...}
        self.gen_script: str = ""
        self.generating = False
        self.tracking = False
        self._track_cont: dict | None = None  # effective creds for Continue
        self._track_stop = threading.Event()
        self._gen_start_vars: dict[str, tk.StringVar] = {}
        self._gen_auto: dict[str, int] = {}
        self._gen_taken: dict[str, set[int]] = {}
        self._gen_fetch_key = None
        self._gen_aces: dict[str, list[tuple[int, str, bool]]] = {}
        self._gen_aces_key = None
        self._audit_acls: dict[str, list[str]] = {}
        self._audit_host = ""
        self._audit_proposal = ""
        self._audit_fetching = False
        self._vuln_fetching = False
        self.vuln_results: list[tuple] = []  # (host, result_dict|None, err|None)
        self.vuln_proposal = ""
        self._vuln_stop = threading.Event()
        self._vuln_applying = False
        self._vlan_fetching = False
        self.last_results: list[tuple] = []  # (host, found_dict, err|None)
        self._dev_sort: tuple | None = None  # (column, reverse)
        self._sub_sort: tuple | None = None  # (column, reverse)
        self.last_ip: str = ""
        self.searching = False
        self.stop_event = threading.Event()
        self.msg_queue: queue.Queue = queue.Queue()
        # --- self-update state ---
        self._checking_update = False
        self._update_info: dict | None = None
        self._update_dialog: tk.Toplevel | None = None
        self._update_prog: ttk.Progressbar | None = None
        self._update_prog_var: tk.StringVar | None = None
        self._update_cancel = threading.Event()
        self._update_zip_path: str | None = None
        # --- silent pre-unlock update state ---
        self._boot_dlg: tk.Toplevel | None = None
        self._boot_phase: tk.StringVar | None = None
        self._boot_prog: ttk.Progressbar | None = None
        self._boot_update_finished = False
        self._boot_update_done = False

        self.title(STRINGS[self.lang]["app_title"])
        self.geometry("860x620")
        self.minsize(760, 540)

        self._build_widgets()
        self.apply_language()
        self.after(100, self._poll_queue)
        self.after(100, self._startup_update_check)
        # NOTE: the password unlock runs after the silent pre-startup update
        # check (see _startup_update_check), so a fresh update never asks
        # for the password twice. The post-unlock auto check is a fallback
        # for when the pre-startup one did not run.

    # ---------- helpers ----------

    def T(self, key: str) -> str:
        return STRINGS[self.lang].get(key, key)

    # ---------- UI construction ----------

    def _build_widgets(self):
        # top bar: language quick switch
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=(8, 0))
        ttk.Label(top, text="🌐").pack(side="left")
        self.lang_var = tk.StringVar(value=self.lang)
        self.lang_combo = ttk.Combobox(top, textvariable=self.lang_var, values=["en", "pl"],
                                       state="readonly", width=6)
        self.lang_combo.pack(side="left", padx=6)
        self.lang_combo.bind("<<ComboboxSelected>>", lambda _e: self.set_language(self.lang_var.get()))
        self.lock_label = ttk.Label(top, text="", foreground="gray")
        self.lock_label.pack(side="right")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=8)

        self._build_search_tab()

        self._build_devices_tab()

        self._build_subnets_tab()

        self._build_gen_tab()

        self._build_track_tab()

        self._build_audit_tab()

        self._build_vuln_tab()

        # --- Tab 5: settings ---
        self.tab_set = ttk.Frame(self.nb)
        self.nb.add(self.tab_set, text="settings")
        self.lbl_lang = ttk.Label(self.tab_set, text="")
        self.lbl_lang.pack(anchor="w", padx=14, pady=(16, 4))
        self.lang_var2 = tk.StringVar(value=self.lang)
        fr_lang = ttk.Frame(self.tab_set)
        fr_lang.pack(anchor="w", padx=14)
        ttk.Radiobutton(fr_lang, text="English", value="en", variable=self.lang_var2,
                        command=lambda: self.set_language("en")).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(fr_lang, text="Polski", value="pl", variable=self.lang_var2,
                        command=lambda: self.set_language("pl")).pack(side="left")
        self.lbl_master = ttk.Label(self.tab_set, text="")
        self.lbl_master.pack(anchor="w", padx=14, pady=(18, 6))
        self.btn_chmaster = ttk.Button(self.tab_set, text="", command=self.change_master)
        self.btn_chmaster.pack(anchor="w", padx=14)
        self.lbl_dhcp = ttk.Label(self.tab_set, text="")
        self.lbl_dhcp.pack(anchor="w", padx=14, pady=(18, 0))
        self.dhcp_var = tk.StringVar(value=load_dhcp_server())
        self.dhcp_var.trace_add("write", lambda *_a: save_dhcp_server(self.dhcp_var.get().strip()))
        self.ent_dhcp = ttk.Entry(self.tab_set, textvariable=self.dhcp_var,
                                  width=24, font=("Consolas", 10))
        self.ent_dhcp.pack(anchor="w", padx=14, pady=(4, 0))
        self.lbl_putty = ttk.Label(self.tab_set, text="")
        self.lbl_putty.pack(anchor="w", padx=14, pady=(18, 0))
        putty_fr = ttk.Frame(self.tab_set)
        putty_fr.pack(anchor="w", padx=14, pady=(4, 0))
        self.putty_var = tk.StringVar(value=load_putty_path())
        self.putty_var.trace_add(
            "write", lambda *_a: save_putty_path(self.putty_var.get().strip()))
        self.ent_putty = ttk.Entry(putty_fr, textvariable=self.putty_var,
                                   width=40, font=("Consolas", 10))
        self.ent_putty.pack(side="left")
        self.btn_putty_browse = ttk.Button(putty_fr, text="",
                                           command=self.browse_putty)
        self.btn_putty_browse.pack(side="left", padx=(6, 0))
        self.ssh_debug_var = tk.BooleanVar(value=load_ssh_debug())
        self.chk_ssh_debug = ttk.Checkbutton(
            self.tab_set, text="", variable=self.ssh_debug_var,
            command=lambda: save_ssh_debug(self.ssh_debug_var.get()))
        self.chk_ssh_debug.pack(anchor="w", padx=14, pady=(14, 0))
        # --- self-update section ---
        ttk.Separator(self.tab_set, orient="horizontal").pack(fill="x", padx=14, pady=(18, 8))
        self.lbl_upd = ttk.Label(self.tab_set, text="")
        self.lbl_upd.pack(anchor="w", padx=14)
        self.lbl_upd_ver = ttk.Label(self.tab_set, text="", foreground="gray")
        self.lbl_upd_ver.pack(anchor="w", padx=14, pady=(2, 6))
        self.upd_auto_var = tk.BooleanVar(value=load_update_auto())
        self.chk_upd_auto = ttk.Checkbutton(
            self.tab_set, text="", variable=self.upd_auto_var,
            command=lambda: save_update_auto(self.upd_auto_var.get()))
        self.chk_upd_auto.pack(anchor="w", padx=14)
        self.btn_upd_check = ttk.Button(
            self.tab_set, text="", command=lambda: self.check_for_updates(manual=True))
        self.btn_upd_check.pack(anchor="w", padx=14, pady=(8, 0))

        # tab order: search, generator, tracking, audit, vuln, devices, subnets, settings
        for _tab in (self.tab_search, self.tab_gen, self.tab_track, self.tab_audit,
                      self.tab_vuln, self.tab_dev, self.tab_sub, self.tab_set):
            self.nb.forget(_tab)
        for _tab in (self.tab_search, self.tab_gen, self.tab_track, self.tab_audit,
                      self.tab_vuln, self.tab_dev, self.tab_sub, self.tab_set):
            self.nb.add(_tab, text="")

        # status bar + small version stamp on the right
        self.status = tk.StringVar(value="")
        status_fr = ttk.Frame(self)
        status_fr.pack(fill="x", side="bottom", padx=2, pady=2)
        ttk.Label(status_fr, textvariable=self.status, relief="sunken", anchor="w").pack(
            side="left", fill="x", expand=True)
        ttk.Label(status_fr, text=f"v{APP_VERSION}", foreground="gray",
                  font=("TkDefaultFont", 8)).pack(side="right", padx=6)
        self.ent_ip.bind("<Return>", lambda _e: self.start_search())
        self.ent_track_ip.bind("<Return>", lambda _e: self.trace_ip())
        self.ent_gen_pc.bind("<FocusOut>", lambda _e: self._dhcp_check_async())
        self.ent_gen_pc.bind("<Return>", lambda _e: self.generate_acl())

    def apply_language(self):
        S = STRINGS[self.lang]
        self.title(S["app_title"])
        self.nb.tab(self.tab_search, text=S["tab_search"])
        self.nb.tab(self.tab_gen, text=S["tab_gen"])
        self.nb.tab(self.tab_track, text=S["tab_track"])
        self.nb.tab(self.tab_audit, text=S["tab_audit"])
        self.nb.tab(self.tab_vuln, text=S["tab_vuln"])
        self.nb.tab(self.tab_dev, text=S["tab_devices"])
        self.nb.tab(self.tab_sub, text=S["tab_subnets"])
        self.nb.tab(self.tab_gen, text=S["tab_gen"])
        self.nb.tab(self.tab_set, text=S["tab_settings"])
        self._apply_search_language()
        self._apply_devices_language()
        self._apply_subnets_language()
        self._apply_gen_language()
        self._apply_track_language()
        self._apply_audit_language()
        self._apply_vuln_language()
        self.lbl_lang.configure(text=S["lang_label"])
        self.lbl_master.configure(text=S["master_label"])
        self.btn_chmaster.configure(text=S["change_master_btn"])
        self.lbl_dhcp.configure(text=S["dhcp_label"])
        self.lbl_putty.configure(text=S["putty_label"])
        self.btn_putty_browse.configure(text=S["putty_browse"])
        self.chk_ssh_debug.configure(text=S["ssh_debug_label"])
        self.lbl_upd.configure(text=S["upd_section"])
        self.lbl_upd_ver.configure(text=S["upd_current"].format(ver=APP_VERSION))
        self.chk_upd_auto.configure(text=S["upd_auto"])
        self.btn_upd_check.configure(text=S["upd_check_btn"])
        self.ent_ip.delete(0, tk.END) if False else None
        # placeholder-ish: set status ready if empty
        if not self.status.get():
            self.status.set(S["status_ready"])
        self.lang_var.set(self.lang)
        self.lang_var2.set(self.lang)
        self._update_lock_label()
        self.refresh_tree()
        self.refresh_subnets()

    def set_language(self, lang: str):
        if lang not in VALID_LANGS:
            return
        self.lang = lang
        save_lang(lang)
        self.apply_language()

    def _update_lock_label(self):
        if self.master_pw:
            self.lock_label.configure(text="🔓", foreground="green")
        else:
            self.lock_label.configure(text="🔒 " + self.T("need_unlock"), foreground="red")

    def _ssh_debug_log(self) -> str | None:
        """Paramiko debug log path when enabled in Settings, else None."""
        return SSH_DEBUG_LOG if self.ssh_debug_var.get() else None

    # ---------- self-update (GitHub Releases) ----------

    def _auto_update_check(self):
        # skipped when the silent pre-startup check already ran this session
        if getattr(self, "_boot_update_done", False):
            return
        try:
            if self.upd_auto_var.get() and not self._checking_update:
                self.check_for_updates(manual=False)
        except Exception:
            pass

    def _startup_update_check(self):
        """Silent pre-unlock update: if a newer release exists, download and
        install it without asking, then exit into the updater program.
        Otherwise continue to the password unlock. Respects the auto-update
        setting and the skipped version; failures fall through to unlock."""
        if not updater.is_frozen() or not self.upd_auto_var.get():
            self._startup_unlock()
            return
        self._checking_update = True
        self._boot_update_finished = False
        self._update_cancel.clear()
        dlg = tk.Toplevel(self)
        self._boot_dlg = dlg
        dlg.title(self.T("boot_upd_title"))
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()
        self._boot_phase = tk.StringVar(value=self.T("boot_upd_checking"))
        ttk.Label(dlg, textvariable=self._boot_phase).pack(
            anchor="w", padx=14, pady=(12, 4))
        self._boot_prog = ttk.Progressbar(dlg, mode="determinate", length=340,
                                          maximum=1000)
        self._boot_prog.pack(fill="x", padx=14)
        ttk.Button(dlg, text=self.T("cancel_btn"),
                   command=self._cancel_boot_update).pack(
                       anchor="e", padx=14, pady=10)
        dlg.protocol("WM_DELETE_WINDOW", self._cancel_boot_update)
        try:
            dlg.geometry("+%d+%d" % (self.winfo_x() + 200, self.winfo_y() + 150))
        except tk.TclError:
            pass
        threading.Thread(target=self._boot_update_worker, daemon=True).start()

    def _cancel_boot_update(self):
        if self._boot_update_finished:
            return
        self._update_cancel.set()
        try:
            if self._boot_phase is not None:
                self._boot_phase.set(self.T("boot_upd_checking"))
        except tk.TclError:
            pass

    def _boot_update_worker(self):
        try:
            info = updater.fetch_latest_release(timeout=10)
        except Exception:
            self.msg_queue.put(("boot_upd_none", None))
            return
        try:
            newer = updater.is_newer(info["tag"], APP_VERSION)
        except Exception:
            newer = False
        if not newer:
            self.msg_queue.put(("boot_upd_none", None))
            return
        if self._update_cancel.is_set() or info["tag"] == load_skipped_version():
            self.msg_queue.put(("boot_upd_none", None))
            return
        try:
            dest = updater.temp_download_path(info["tag"])

            def _cb(done: int, total: int):
                self.msg_queue.put(("boot_upd_prog", (done, total, info["tag"])))

            updater.download_asset(info["zip_url"], dest, progress_cb=_cb,
                                   cancel_event=self._update_cancel, timeout=30)
        except Exception:
            # cancelled downloads land here too ("cancelled") -> just unlock
            self.msg_queue.put(("boot_upd_none", None))
            return
        if self._update_cancel.is_set():
            try:
                os.remove(dest)
            except OSError:
                pass
            self.msg_queue.put(("boot_upd_none", None))
            return
        try:
            exe_name = os.path.basename(updater.exe_path())
            if not exe_name.lower().endswith(".exe"):
                exe_name = "CiscoACLHelper.exe"
            bundled = os.path.join(updater.app_dir(), "CiscoACLHelperUpdater.exe")
            if not os.path.isfile(bundled):
                # old install without the updater program: unlock, the
                # post-unlock dialog flow will handle the update instead
                self.msg_queue.put(("boot_upd_none", None))
                return
            staged = updater.stage_gui_updater(bundled)
            updater.launch_gui_updater(staged, dest, updater.app_dir(),
                                       exe_name, os.getpid(),
                                       updater.proc_start_unix(os.getpid()),
                                       info["tag"])
        except Exception:
            self.msg_queue.put(("boot_upd_none", None))
            return
        self.msg_queue.put(("boot_upd_exit", None))

    def _close_boot_dlg(self):
        try:
            if self._boot_dlg is not None and self._boot_dlg.winfo_exists():
                self._boot_dlg.destroy()
        except tk.TclError:
            pass
        finally:
            self._boot_dlg = None
            try:
                self.grab_release()
            except tk.TclError:
                pass

    def _finish_boot_update(self):
        """Proceed to unlock (once) after the silent check completes."""
        self._checking_update = False
        self._close_boot_dlg()
        if self._boot_update_finished:
            return
        self._boot_update_finished = True
        self._boot_update_done = True
        self._startup_unlock()

    def check_for_updates(self, manual: bool = True):
        if self._checking_update:
            return
        self._checking_update = True
        if manual:
            self.status.set(self.T("upd_downloading").format(tag="...", pct=""))
        threading.Thread(target=self._update_worker,
                         args=(manual,), daemon=True).start()

    def _update_worker(self, manual: bool):
        try:
            info = updater.fetch_latest_release()
        except Exception as e:
            self.msg_queue.put(("update_error", (str(e), manual)))
            return
        try:
            newer = updater.is_newer(info["tag"], APP_VERSION)
        except Exception:
            newer = False
        if not newer:
            self.msg_queue.put(("update_uptodate", manual))
            return
        if not manual and info["tag"] == load_skipped_version():
            self.msg_queue.put(("update_silent_skip", None))
            return
        self.msg_queue.put(("update_available", (info, manual)))

    def _show_update_dialog(self, info: dict):
        # close previous dialog if any
        try:
            if self._update_dialog is not None and self._update_dialog.winfo_exists():
                self._update_dialog.destroy()
        except tk.TclError:
            pass
        self._update_info = info
        self._update_zip_path = None
        self._update_cancel.clear()
        dlg = tk.Toplevel(self)
        self._update_dialog = dlg
        dlg.title(self.T("upd_available_title"))
        dlg.resizable(True, True)
        dlg.transient(self)
        notes = (info.get("body") or "").strip()
        if len(notes) > 2000:
            notes = notes[:2000] + "..."
        if not updater.is_frozen():
            notes = self.T("upd_devmode") + ("\n\n" + notes if notes else "")
        msg = self.T("upd_available_msg").format(
            latest=info["tag"], cur=APP_VERSION, notes=notes or "-")
        ttk.Label(dlg, text=msg, justify="left", wraplength=520).pack(
            anchor="w", padx=14, pady=(14, 6))
        self._update_prog_var = tk.StringVar(value="")
        ttk.Label(dlg, textvariable=self._update_prog_var).pack(
            anchor="w", padx=14)
        self._update_prog = ttk.Progressbar(dlg, mode="determinate", length=480)
        self._update_prog.pack(fill="x", padx=14, pady=(4, 10))
        fr = ttk.Frame(dlg)
        fr.pack(fill="x", padx=14, pady=(0, 14))
        self._btn_upd_install = ttk.Button(
            fr, text=self.T("upd_install_btn"),
            command=self._start_update_download)
        self._btn_upd_install.pack(side="left", padx=(0, 6))
        ttk.Button(fr, text=self.T("upd_skip_btn"),
                   command=lambda: self._skip_update_version(info["tag"])).pack(
                       side="left", padx=6)
        ttk.Button(fr, text=self.T("upd_later_btn"),
                   command=dlg.destroy).pack(side="left", padx=6)
        if not updater.is_frozen():
            self._btn_upd_install.configure(state="disabled")
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        try:
            dlg.geometry("+%d+%d" % (self.winfo_x() + 60, self.winfo_y() + 60))
        except tk.TclError:
            pass

    def _skip_update_version(self, tag: str):
        try:
            save_skipped_version(tag)
        except Exception:
            pass
        try:
            if self._update_dialog is not None:
                self._update_dialog.destroy()
        except tk.TclError:
            pass

    def _start_update_download(self):
        info = self._update_info
        if not info:
            return
        try:
            self._btn_upd_install.configure(state="disabled")
        except (tk.TclError, AttributeError):
            pass
        self._update_cancel.clear()
        threading.Thread(target=self._update_download_worker,
                         args=(dict(info),), daemon=True).start()

    def _update_download_worker(self, info: dict):
        try:
            dest = updater.temp_download_path(info["tag"])
            def _cb(done: int, total: int):
                self.msg_queue.put(("update_progress", (done, total, info["tag"])))
            updater.download_asset(info["zip_url"], dest, progress_cb=_cb,
                                   cancel_event=self._update_cancel)
            self.msg_queue.put(("update_downloaded", (dest, info)))
        except Exception as e:
            self.msg_queue.put(("update_download_error", str(e)))

    def _finish_update_download(self, zip_path: str, info: dict):
        # No extra confirmation here: the user already chose
        # "Download & Install", and the app cannot be used while the
        # updater replaces its files -- install straight away.
        self._update_zip_path = zip_path
        try:
            if self._update_prog_var is not None:
                self._update_prog_var.set(self.T("upd_download_done"))
            if self._update_prog is not None:
                self._update_prog.configure(value=100)
        except tk.TclError:
            pass
        try:
            self._launch_installer(zip_path, info["tag"])
        except Exception as e:
            messagebox.showerror("ACL", self.T("upd_error").format(err=e),
                                 parent=self._update_dialog)
            return
        self.destroy()
        os._exit(0)

    def _launch_installer(self, zip_path: str, tag: str):
        """Prefer the separate GUI updater window; fall back to hidden .bat
        when its exe is missing (e.g. updating from an older version)."""
        exe_name = os.path.basename(updater.exe_path())
        if not exe_name.lower().endswith(".exe"):
            exe_name = "CiscoACLHelper.exe"
        bundled = os.path.join(updater.app_dir(), "CiscoACLHelperUpdater.exe")
        if updater.is_frozen() and os.path.isfile(bundled):
            staged = updater.stage_gui_updater(bundled)
            updater.launch_gui_updater(staged, zip_path, updater.app_dir(),
                                       exe_name, os.getpid(),
                                       updater.proc_start_unix(os.getpid()), tag)
            return
        bat = updater.write_apply_script(zip_path, updater.app_dir(), os.getpid())
        updater.launch_apply_and_exit(bat)

    # ---------- master / store ----------

    def _startup_unlock(self):
        try:
            self._startup_unlock_inner()
        finally:
            # only now is it safe to show the update dialog (no modal grab open)
            self.after(2000, self._auto_update_check)

    def _startup_unlock_inner(self):
        is_new = not os.path.exists(DEVICES_FILE)
        dlg = MasterDialog(self, self.lang, is_new)
        self.wait_window(dlg)
        if not dlg.result:
            self.status.set(self.T("need_unlock"))
            self._update_lock_label()
            return
        if is_new:
            self.master_pw = dlg.result
            self.devices = []
            self.subnets = []
            try:
                crypto_store.save_store(DEVICES_FILE,
                                        {"devices": [], "subnets": []}, self.master_pw)
            except Exception as e:
                messagebox.showerror("ACL", str(e))
                self.master_pw = None
        else:
            try:
                store = crypto_store.load_store(DEVICES_FILE, dlg.result)
                self.devices = store["devices"]
                self.subnets = store["subnets"]
                self.master_pw = dlg.result
                # one-time migration of legacy {"subnet","acl"} entries
                norm = [acl_parser.normalize_subnet(s) for s in self.subnets
                        if isinstance(s, dict)]
                if norm != self.subnets:
                    self.subnets = norm
                    self.persist_store()
            except ValueError:
                messagebox.showerror("ACL", self.T("wrong_master"))
                self.master_pw = None
        if self.master_pw and not self._weak_warned:
            if crypto_store.password_missing(self.master_pw):
                self._weak_warned = True
                messagebox.showwarning("ACL", self.T("pwd_weak_warn"))
        self._update_lock_label()
        self.refresh_tree()
        self.refresh_subnets()
        self.status.set(self.T("status_ready"))

    def _require_unlocked(self) -> bool:
        if not self.master_pw:
            messagebox.showwarning("ACL", self.T("need_unlock"))
            self._startup_unlock()
            return self.master_pw is not None
        return True

    def persist_store(self):
        if self.master_pw:
            crypto_store.save_store(DEVICES_FILE,
                                    {"devices": self.devices,
                                     "subnets": self.subnets}, self.master_pw)

    def _backup_store(self) -> str | None:
        """Timestamped copy of devices.enc before a bulk rewrite (import).

        Returns the backup path, or None when there is nothing to back up
        (first run) or the copy failed (import still proceeds).
        """
        if not self.master_pw or not os.path.exists(DEVICES_FILE):
            return None
        dst = DEVICES_FILE + ".bak-" + time.strftime("%Y%m%d-%H%M%S")
        try:
            shutil.copy2(DEVICES_FILE, dst)
        except OSError:
            return None
        prune_backups(DEVICES_FILE)
        return dst

    def change_master(self):
        if not self._require_unlocked():
            return
        dlg = MasterDialog(self, self.lang, True)
        self.wait_window(dlg)
        if dlg.result:
            self.master_pw = dlg.result
            self.persist_store()
            messagebox.showinfo("ACL", self.T("master_changed"))
            self._update_lock_label()

    # ---------- subnets tab actions ----------

    def _toast(self, text: str, ms: int = 3000):
        """Small non-modal confirmation that closes itself after `ms`."""
        try:
            tip = tk.Toplevel(self)
        except tk.TclError:
            return
        tip.title("ACL")
        tip.resizable(False, False)
        tip.transient(self)
        ttk.Label(tip, text=text).pack(padx=16, pady=14)
        try:
            tip.geometry("+%d+%d" % (self.winfo_x() + 200, self.winfo_y() + 150))
        except tk.TclError:
            pass

        def _close():
            try:
                tip.destroy()
            except tk.TclError:
                pass

        tip.after(ms, _close)

    def browse_putty(self):
        path = filedialog.askopenfilename(
            title=self.T("putty_label"),
            filetypes=[("putty.exe", "putty*.exe"), ("All files", "*.*")])
        if path:
            self.putty_var.set(path)

    def _putty_exe(self) -> str:
        var = getattr(self, "putty_var", None)
        if var is not None:
            try:
                return var.get().strip()
            except (tk.TclError, AttributeError):
                pass
        return load_putty_path().strip()

    def open_putty_for_device(self, creds: dict) -> bool:
        """Launch PuTTY (from Settings path) logged in as the device user.

        Returns True when PuTTY was started. The verify dialog stays open;
        the operator confirms or rolls back only after checking in PuTTY.
        """
        exe = self._putty_exe()
        if not exe or not os.path.exists(exe):
            messagebox.showwarning("ACL", self.T("putty_missing"))
            return False
        try:
            port = int(creds.get("port", 22) or 22)
        except (TypeError, ValueError):
            port = 22
        try:
            subprocess.Popen([exe, "-ssh",
                              f'{creds.get("username", "")}@{creds.get("host", "")}',
                              "-P", str(port),
                              "-pw", creds.get("password", "")])
            return True
        except Exception as e:
            messagebox.showerror("ACL", self.T("putty_failed").format(err=e))
            return False

    def _ask_vuln_verify(self, title: str, text: str, creds: dict) -> bool:
        """Verify-fix dialog: Yes=write memory, PuTTY=check now (no close),
        No/X=roll back. Blocks like the old askyesno (nested event loop)."""
        box: dict = {}

        def _close(ok: bool):
            box["ok"] = ok
            try:
                dlg.destroy()
            except tk.TclError:
                pass

        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.transient(self)
        dlg.grab_set()
        dlg.resizable(True, True)
        ttk.Label(dlg, text=text, justify="left",
                  wraplength=520).pack(anchor="w", padx=14, pady=(14, 6))
        fr = ttk.Frame(dlg)
        fr.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(fr, text=self.T("vuln_verify_yes"),
                   command=lambda: _close(True)).pack(side="left", padx=(0, 6))
        ttk.Button(fr, text=self.T("vuln_verify_putty"),
                   command=lambda: self.open_putty_for_device(creds)).pack(
                       side="left", padx=6)
        ttk.Button(fr, text=self.T("vuln_verify_no"),
                   command=lambda: _close(False)).pack(side="left", padx=6)
        dlg.protocol("WM_DELETE_WINDOW", lambda: _close(False))
        try:
            dlg.geometry("+%d+%d" % (self.winfo_x() + 80, self.winfo_y() + 80))
        except tk.TclError:
            pass
        self.wait_window(dlg)
        return bool(box.get("ok", False))

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "chunk":
                    host, found, err = payload
                    self.last_results.append((host, found, err))
                    negate = self.negate_var.get()
                    chunk_parts = [self.T("device_hdr").format(host=host)]
                    if err:
                        chunk_parts.append(self.T("err_hdr").format(host=host, err=err))
                    elif not found:
                        chunk_parts.append(self.T("no_results").format(ip=self.last_ip))
                    else:
                        chunk_parts.append(acl_parser.format_results(found, negate=negate))
                    chunk_parts.append("")
                    # first chunk replaces empty text cleanly
                    if len(self.last_results) == 1 and not self.txt.get("1.0", tk.END).strip():
                        self._set_text("\n".join(chunk_parts).rstrip() + "\n")
                    else:
                        self._append_text("\n".join(chunk_parts).rstrip() + "\n")
                    total = int(self.prog.cget("maximum") or 0)
                    self.prog.configure(value=len(self.last_results))
                    self._refresh_copy_combo()
                    if total:
                        self.status.set(self.T("status_progress").format(
                            done=len(self.last_results), total=total))
                elif kind == "done":
                    self.searching = False
                    self.btn_search.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.prog.configure(value=len(self.last_results))
                    hits = sum(len(v) for _, f, e in self.last_results for v in f.values()) if self.last_results else 0
                    devs = sum(1 for _, f, e in self.last_results if f)
                    if not self.last_results:
                        self.status.set(self.T("status_ready"))
                    else:
                        self.status.set(self.T("status_done").format(hits=hits, devs=devs))
                elif kind == "track_prog":
                    try:
                        self.prog_track.configure(value=payload)
                    except tk.TclError:
                        pass
                elif kind == "track_chunk":
                    host, text = payload
                    try:
                        ext = bool(self.track_ext_var.get())
                    except (tk.TclError, AttributeError):
                        ext = True
                    if ext:
                        if not self.txt_track.get("1.0", tk.END).strip():
                            self._set_track_text(text)
                        else:
                            self._append_track_text(text)
                    if host:
                        self.status.set(self.T("track_working").format(
                            ip=self.ent_track_ip.get().strip(), host=host))
                elif kind == "track_found":
                    ip, found, reason, fail_host = payload
                    if reason != "step":
                        line = self._format_track_summary(ip, found, reason,
                                                          fail_host)
                        if not self.txt_track.get("1.0", tk.END).strip():
                            self._set_track_text(line + "\n")
                        else:
                            self._append_track_text(line + "\n")
                elif kind == "track_done":
                    if getattr(self, "_bulk_active", False):
                        self.status.set(self.T("status_ready"))
                        continue
                    cont = payload
                    self.tracking = False
                    self.btn_track.configure(state="normal")
                    self.btn_track_stop.configure(state="disabled")
                    try:
                        self.prog_track.stop()
                    except tk.TclError:
                        pass
                    self.prog_track.configure(mode="determinate", value=3)
                    self._track_cont = cont
                    if cont:
                        self.btn_track_cont.configure(
                            text=self.T("track_continue").format(host=cont["host"]))
                        self.btn_track_cont.pack(side="left", padx=6)
                    else:
                        self.btn_track_cont.pack_forget()
                    self.status.set(self.T("status_ready"))
                elif kind == "info":
                    self.status.set(self.T("status_ready"))
                    messagebox.showinfo("ACL", payload)
                elif kind == "audit_list":
                    host, acls = payload
                    self._finish_audit_fetch(host, acls)
                elif kind == "audit_error":
                    host, err = payload
                    self._audit_fetching = False
                    self.btn_audit_fetch.configure(state="normal")
                    try:
                        self.audit_prog.stop()
                    except tk.TclError:
                        pass
                    self.audit_prog.pack_forget()
                    self.status.set(self.T("status_ready"))
                    messagebox.showerror(
                        "ACL", self.T("gen_fetch_fail").format(host=host, err=err))
                elif kind == "vlan_list":
                    host, rows = payload
                    self._finish_vlan_fetch(host, rows)
                elif kind == "vlan_error":
                    host, err = payload
                    self._vlan_fetching = False
                    self.btn_sub_fetch.configure(state="normal")
                    try:
                        self.sub_prog.stop()
                    except tk.TclError:
                        pass
                    self.sub_prog.pack_forget()
                    self.status.set(self.T("status_ready"))
                    messagebox.showerror(
                        "ACL", self.T("gen_fetch_fail").format(host=host, err=err))
                elif kind == "vuln_chunk":
                    host, res, err = payload
                    self._finish_vuln_chunk(host, res, err)
                elif kind == "vuln_done":
                    self._finish_vuln_done()
                elif kind == "vuln_apply_chunk":
                    segs = payload
                    if not self.txt_vuln.get("1.0", tk.END).strip():
                        self._insert_vuln_segments(segs, clear=True)
                    else:
                        self._insert_vuln_segments(segs, clear=False)
                elif kind == "vuln_apply_confirm":
                    title, text, box, ev, creds = payload
                    try:
                        ok = self._ask_vuln_verify(title, text, creds)
                    except tk.TclError:
                        ok = False
                    box["ok"] = bool(ok)
                    ev.set()
                elif kind == "vuln_apply_refresh":
                    host, fresh = payload
                    for i, (h, _r, e) in enumerate(self.vuln_results):
                        if h == host and not e:
                            self.vuln_results[i] = (host, fresh, None)
                            break
                    self._rebuild_vuln_proposal()
                elif kind == "vuln_apply_done":
                    self._finish_apply_done(payload)
                elif kind == "gen_done":
                    (pc, host, grouped, do_in, do_out, fetch_key, taken, err,
                     dhcp_status, dhcp_detail, owner, aces, group) = payload
                    self.generating = False
                    self.btn_gen.configure(state="normal")
                    try:
                        self.gen_prog.stop()
                    except tk.TclError:
                        pass
                    self.gen_prog.pack_forget()
                    self._set_dhcp_indicator(pc, dhcp_status, dhcp_detail)
                    if err or taken is None:
                        self.status.set(self.T("status_ready"))
                        messagebox.showerror(
                            "ACL", self.T("gen_fetch_fail").format(host=host, err=err))
                    else:
                        self._gen_taken = taken
                        self._gen_fetch_key = fetch_key
                        if aces is not None:
                            self._gen_aces = aces
                            self._gen_aces_key = fetch_key
                        relocate = (self._gen_aces
                                    if group and self._gen_aces_key == fetch_key
                                    else {})
                        involved = self._involved_acls(grouped, do_in, do_out)
                        self._update_starts_frame(involved, taken)
                        starts = self._read_gen_starts(involved)
                        self.status.set(self.T("status_ready"))
                        if starts is None:
                            continue
                        self.gen_script = acl_parser.build_full_script(
                            pc, grouped, do_in, do_out, starts, taken,
                            owner=owner, relocate=relocate)
                        self._set_gen_text(self.gen_script)
                        if dhcp_status == "none":
                            messagebox.showwarning(
                                "ACL", self.T("dhcp_none").format(ip=pc))
                elif kind == "update_error":
                    self._checking_update = False
                    err, manual = payload
                    self.status.set(self.T("status_ready"))
                    if manual:
                        messagebox.showerror(
                            "ACL", self.T("upd_error").format(err=err))
                elif kind == "update_uptodate":
                    self._checking_update = False
                    manual = payload
                    self.status.set(self.T("status_ready"))
                    if manual:
                        messagebox.showinfo(
                            "ACL", self.T("upd_up_to_date").format(ver=APP_VERSION))
                elif kind == "update_silent_skip":
                    self._checking_update = False
                    self.status.set(self.T("status_ready"))
                elif kind == "update_available":
                    self._checking_update = False
                    self.status.set(self.T("status_ready"))
                    info, _manual = payload
                    self._show_update_dialog(info)
                elif kind == "update_progress":
                    done, total, tag = payload
                    try:
                        if self._update_prog is not None:
                            if total:
                                self._update_prog.configure(
                                    maximum=total, value=done)
                            else:
                                self._update_prog.configure(
                                    mode="indeterminate")
                                self._update_prog.start(10)
                        if self._update_prog_var is not None:
                            pct = f"{done * 100 // total}%" if total else f"{done // 1024} KB"
                            self._update_prog_var.set(
                                self.T("upd_downloading").format(tag=tag, pct=pct))
                    except tk.TclError:
                        pass
                elif kind == "update_downloaded":
                    dest, info = payload
                    try:
                        if self._update_prog is not None:
                            self._update_prog.stop()
                            self._update_prog.configure(mode="determinate")
                    except tk.TclError:
                        pass
                    self._finish_update_download(dest, info)
                elif kind == "update_download_error":
                    try:
                        if self._btn_upd_install is not None:
                            self._btn_upd_install.configure(state="normal")
                        if self._update_prog_var is not None:
                            self._update_prog_var.set("")
                    except (tk.TclError, AttributeError):
                        pass
                    messagebox.showerror(
                        "ACL", self.T("upd_error").format(err=payload),
                        parent=self._update_dialog)
                elif kind == "boot_upd_prog":
                    done, total, tag = payload
                    try:
                        if self._boot_prog is not None:
                            if total:
                                self._boot_prog.configure(value=done * 1000 // total)
                            else:
                                self._boot_prog.configure(mode="indeterminate")
                                self._boot_prog.start(10)
                        if self._boot_phase is not None:
                            pct = f"{done * 100 // total}%" if total else f"{done // 1024} KB"
                            self._boot_phase.set(
                                self.T("upd_downloading").format(tag=tag, pct=pct))
                    except tk.TclError:
                        pass
                elif kind == "boot_upd_none":
                    self._finish_boot_update()
                elif kind == "boot_upd_exit":
                    self._close_boot_dlg()
                    self.destroy()
                    os._exit(0)
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()