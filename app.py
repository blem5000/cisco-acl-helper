"""Cisco ACL Helper - Tkinter app, PL/EN, SSH, encrypted device store."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import queue
import re
import shutil
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import acl_parser
import cisco_ssh
import crypto_store
import device_import
import dhcp_check
import track
import updater
import vuln_telnet
from i18n import STRINGS, VALID_LANGS
from version import __version__ as APP_VERSION


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


class MasterDialog(tk.Toplevel):
    """Modal dialog: create new master password or enter existing one."""

    def __init__(self, parent, lang: str, is_new: bool):
        super().__init__(parent)
        self.result: str | None = None
        self._is_new = is_new
        self._lang = lang if lang in VALID_LANGS else "en"
        S = STRINGS[self._lang]
        self.title(S["master_new_title"] if is_new else S["master_enter_title"])
        self.resizable(False, False)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        ttk.Label(self, text=S["master_prompt"]).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))
        self.e1 = ttk.Entry(self, show="*", width=32)
        self.e1.grid(row=1, column=0, padx=12, pady=2)
        if is_new:
            ttk.Label(self, text=S["master_repeat"]).grid(row=2, column=0, sticky="w", padx=12, pady=(8, 4))
            self.e2 = ttk.Entry(self, show="*", width=32)
            self.e2.grid(row=3, column=0, padx=12, pady=2)
            ttk.Label(self, text=S["pwd_req_hint"], foreground="gray",
                      wraplength=300, justify="left").grid(
                          row=4, column=0, sticky="w", padx=12, pady=(6, 0))
        else:
            self.e2 = None
        btns = ttk.Frame(self)
        btns.grid(row=5, column=0, pady=12)
        ttk.Button(btns, text=S["unlock_btn"], command=self._on_ok).pack(side="left", padx=6)
        ttk.Button(btns, text=S["cancel_btn"], command=self._on_cancel).pack(side="left", padx=6)

        self.e1.focus_set()
        self.bind("<Return>", lambda _e: self._on_ok())
        self.transient(parent)
        self.wait_visibility()
        x = parent.winfo_x() + 60
        y = parent.winfo_y() + 60
        self.geometry(f"+{x}+{y}")

    def _on_ok(self):
        S = STRINGS[self._lang]
        p1 = self.e1.get()
        if not p1:
            messagebox.showwarning("ACL", S["master_empty"])
            return
        if self._is_new:
            if self.e2 and self.e2.get() != p1:
                messagebox.showwarning("ACL", S["master_mismatch"])
                return
            missing = crypto_store.password_missing(p1)
            if missing:
                items = "\n".join(S[f"pwd_req_{m}"] for m in missing)
                messagebox.showwarning(
                    "ACL", S["pwd_not_met"].format(items=items))
                return
        self.result = p1
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class DeviceDialog(tk.Toplevel):
    def __init__(self, parent, lang: str, title: str, initial: dict | None = None):
        super().__init__(parent)
        S = STRINGS[lang]
        self.title(title)
        self.resizable(False, False)
        self.result: dict | None = None
        init = initial or {"hostname": "", "host": "", "port": 22, "username": "",
                         "password": "", "enable": ""}
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        ttk.Label(self, text=S["fld_hostname"]).grid(row=0, column=0, sticky="w",
                                                     padx=12, pady=(12, 2))
        self.e_hostname = ttk.Entry(self, width=32)
        self.e_hostname.grid(row=1, column=0, columnspan=2, padx=12)
        self.e_hostname.insert(0, init.get("hostname", ""))

        ttk.Label(self, text=S["fld_host"]).grid(row=2, column=0, sticky="w", padx=12, pady=(8, 2))
        self.e_host = ttk.Entry(self, width=32)
        self.e_host.grid(row=3, column=0, columnspan=2, padx=12)
        self.e_host.insert(0, init.get("host", ""))

        ttk.Label(self, text=S["fld_port"]).grid(row=4, column=0, sticky="w", padx=12, pady=(8, 2))
        self.e_port = ttk.Entry(self, width=10)
        self.e_port.grid(row=5, column=0, sticky="w", padx=12)
        self.e_port.insert(0, str(init.get("port", 22)))

        ttk.Label(self, text=S["fld_user"]).grid(row=6, column=0, sticky="w", padx=12, pady=(8, 2))
        self.e_user = ttk.Entry(self, width=32)
        self.e_user.grid(row=7, column=0, columnspan=2, padx=12)
        self.e_user.insert(0, init.get("username", ""))

        ttk.Label(self, text=S["fld_pass"]).grid(row=8, column=0, sticky="w", padx=12, pady=(8, 2))
        self.e_pass = ttk.Entry(self, show="*", width=26)
        self.e_pass.grid(row=9, column=0, sticky="w", padx=12)
        self.e_pass.insert(0, init.get("password", ""))
        self.btn_show1 = ttk.Button(self, text=S["show_pass"], width=8,
                                    command=lambda: self._toggle(self.e_pass))
        self.btn_show1.grid(row=9, column=1, padx=(0, 12))

        ttk.Label(self, text=S["fld_enable"]).grid(row=10, column=0, sticky="w", padx=12, pady=(8, 2))
        self.e_enable = ttk.Entry(self, show="*", width=26)
        self.e_enable.grid(row=11, column=0, sticky="w", padx=12)
        self.e_enable.insert(0, init.get("enable", ""))
        ttk.Button(self, text=S["show_pass"], width=8,
                   command=lambda: self._toggle(self.e_enable)).grid(row=11, column=1, padx=(0, 12))

        fr = ttk.Frame(self)
        fr.grid(row=12, column=0, columnspan=2, pady=14)
        ttk.Button(fr, text=S["ok_btn"], command=self._on_ok).pack(side="left", padx=6)
        ttk.Button(fr, text=S["cancel_btn"], command=self.destroy).pack(side="left", padx=6)
        self.transient(parent)
        self.e_host.focus_set()

    @staticmethod
    def _toggle(entry: ttk.Entry):
        entry.configure(show="" if entry.cget("show") == "*" else "*")

    def _on_ok(self):
        host = self.e_host.get().strip()
        if not host:
            messagebox.showwarning("ACL", "Host is empty.")
            return
        try:
            port = int(self.e_port.get().strip() or "22")
        except ValueError:
            messagebox.showwarning("ACL", "Bad port.")
            return
        self.result = {
            "hostname": self.e_hostname.get().strip(),
            "host": host,
            "port": port,
            "username": self.e_user.get().strip(),
            "password": self.e_pass.get(),
            "enable": self.e_enable.get(),
        }
        self.destroy()


class ImportDialog(tk.Toplevel):
    """Import-wide credentials: one username/password/enable applied to
    every imported device (fills missing values, or overwrites all)."""

    def __init__(self, parent, lang: str, fname: str, fmt: str, count: int):
        super().__init__(parent)
        S = STRINGS[lang]
        self.title(S["import_title"])
        self.resizable(False, False)
        self.result: dict | None = None
        self._is_mr = (fmt == "mremoteng")
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        n = str(count) if count >= 0 else S["import_found_unknown"]
        fmt_name = S["import_fmt_mremoteng"] if self._is_mr else S["import_fmt_generic"]
        ttk.Label(self, text=S["import_found"].format(file=fname, fmt=fmt_name, n=n),
                  justify="left").grid(row=0, column=0, columnspan=2,
                                       sticky="w", padx=12, pady=(12, 4))
        ttk.Label(self, text=S["import_note"], wraplength=360, justify="left",
                  foreground="gray").grid(row=1, column=0, columnspan=2,
                                          sticky="w", padx=12, pady=(0, 6))

        ttk.Label(self, text=S["fld_user"]).grid(row=2, column=0, sticky="w",
                                                 padx=12, pady=(4, 2))
        self.e_user = ttk.Entry(self, width=32)
        self.e_user.grid(row=3, column=0, columnspan=2, padx=12)

        ttk.Label(self, text=S["fld_pass"]).grid(row=4, column=0, sticky="w",
                                                 padx=12, pady=(8, 2))
        self.e_pass = ttk.Entry(self, show="*", width=26)
        self.e_pass.grid(row=5, column=0, sticky="w", padx=12)
        ttk.Button(self, text=S["show_pass"], width=8,
                   command=lambda: self._toggle(self.e_pass)).grid(
                       row=5, column=1, padx=(0, 12))

        ttk.Label(self, text=S["fld_enable"]).grid(row=6, column=0, sticky="w",
                                                   padx=12, pady=(8, 2))
        self.e_enable = ttk.Entry(self, show="*", width=26)
        self.e_enable.grid(row=7, column=0, sticky="w", padx=12)
        ttk.Button(self, text=S["show_pass"], width=8,
                   command=lambda: self._toggle(self.e_enable)).grid(
                       row=7, column=1, padx=(0, 12))

        next_row = 8
        if self._is_mr:
            ttk.Label(self, text=S["import_mrpass"]).grid(
                row=8, column=0, columnspan=2, sticky="w", padx=12, pady=(8, 2))
            self.e_master = ttk.Entry(self, show="*", width=26)
            self.e_master.grid(row=9, column=0, sticky="w", padx=12)
            ttk.Button(self, text=S["show_pass"], width=8,
                       command=lambda: self._toggle(self.e_master)).grid(
                           row=9, column=1, padx=(0, 12))
            next_row = 10
        else:
            self.e_master = None

        self.overwrite_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text=S["import_overwrite"],
                        variable=self.overwrite_var).grid(
                            row=next_row, column=0, columnspan=2,
                            sticky="w", padx=12, pady=(10, 0))

        fr = ttk.Frame(self)
        fr.grid(row=next_row + 1, column=0, columnspan=2, pady=14)
        ttk.Button(fr, text=S["ok_btn"], command=self._on_ok).pack(
            side="left", padx=6)
        ttk.Button(fr, text=S["cancel_btn"], command=self.destroy).pack(
            side="left", padx=6)
        self.transient(parent)
        self.e_user.focus_set()

    @staticmethod
    def _toggle(entry: ttk.Entry):
        entry.configure(show="" if entry.cget("show") == "*" else "*")

    def _on_ok(self):
        self.result = {
            "username": self.e_user.get().strip(),
            "password": self.e_pass.get(),
            "enable": self.e_enable.get(),
            "master": self.e_master.get() if self.e_master is not None else "",
            "overwrite": bool(self.overwrite_var.get()),
        }
        self.destroy()


class SubnetDialog(tk.Toplevel):
    def __init__(self, parent, lang: str, title: str, initial: dict | None = None):
        super().__init__(parent)
        S = STRINGS[lang]
        self._lang = lang
        self.title(title)
        self.resizable(False, False)
        self.result: dict | None = None
        init = initial or {"subnet": "", "acl_in": "", "acl_out": ""}
        if "acl" in init and not (init.get("acl_in") or init.get("acl_out")):
            init = dict(init, acl_in=init.get("acl", ""), acl_out=init.get("acl", ""))
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        ttk.Label(self, text=S["fld_subnet"]).grid(row=0, column=0, sticky="w",
                                                   padx=12, pady=(12, 2))
        self.e_subnet = ttk.Entry(self, width=32, font=("Consolas", 10))
        self.e_subnet.grid(row=1, column=0, padx=12)
        self.e_subnet.insert(0, init.get("subnet", ""))

        ttk.Label(self, text=S["fld_acl_in"]).grid(row=2, column=0, sticky="w",
                                                   padx=12, pady=(8, 2))
        self.e_acl_in = ttk.Entry(self, width=32, font=("Consolas", 10))
        self.e_acl_in.grid(row=3, column=0, padx=12)
        self.e_acl_in.insert(0, init.get("acl_in", ""))

        ttk.Label(self, text=S["fld_acl_out"]).grid(row=4, column=0, sticky="w",
                                                    padx=12, pady=(8, 2))
        self.e_acl_out = ttk.Entry(self, width=32, font=("Consolas", 10))
        self.e_acl_out.grid(row=5, column=0, padx=12)
        self.e_acl_out.insert(0, init.get("acl_out", ""))

        fr = ttk.Frame(self)
        fr.grid(row=6, column=0, pady=14)
        ttk.Button(fr, text=S["ok_btn"], command=self._on_ok).pack(side="left", padx=6)
        ttk.Button(fr, text=S["cancel_btn"], command=self.destroy).pack(side="left", padx=6)
        self.transient(parent)

    def _on_ok(self):
        import ipaddress as _ip
        S = STRINGS[self._lang]
        subnet = self.e_subnet.get().strip()
        acl_in = self.e_acl_in.get().strip()
        acl_out = self.e_acl_out.get().strip()
        try:
            net = _ip.ip_network(subnet, strict=False)
            subnet = str(net)
        except ValueError:
            messagebox.showwarning("ACL", S["bad_subnet"])
            return
        if not (acl_in or acl_out):
            messagebox.showwarning("ACL", S["need_one_acl"])
            return
        self.result = {"subnet": subnet, "acl_in": acl_in, "acl_out": acl_out}
        self.destroy()


class App(tk.Tk):
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

        # --- Tab 1: search ---
        self.tab_search = ttk.Frame(self.nb)
        self.nb.add(self.tab_search, text="search")
        sf = ttk.Frame(self.tab_search)
        sf.pack(fill="x", padx=10, pady=10)
        self.lbl_ip = ttk.Label(sf, text="")
        self.lbl_ip.grid(row=0, column=0, sticky="w")
        self.ent_ip = ttk.Entry(sf, width=24, font=("Consolas", 11))
        self.ent_ip.grid(row=1, column=0, sticky="w", pady=4)
        self.ent_ip.insert(0, "")
        self.btn_search = ttk.Button(sf, text="", command=self.start_search)
        self.btn_search.grid(row=1, column=1, padx=8)
        self.btn_stop = ttk.Button(sf, text="", command=self.stop_search, state="disabled")
        self.btn_stop.grid(row=1, column=2, padx=4)
        self.negate_var = tk.BooleanVar(value=False)
        self.chk_neg = ttk.Checkbutton(sf, text="", variable=self.negate_var,
                                       command=self.rerender_results)
        self.chk_neg.grid(row=2, column=0, columnspan=2, sticky="w", pady=4)

        btns = ttk.Frame(self.tab_search)
        btns.pack(fill="x", padx=10)
        self.btn_copy = ttk.Button(btns, text="", command=self.copy_results)
        self.btn_copy.pack(side="left", padx=(0, 6))
        self.btn_export = ttk.Button(btns, text="", command=self.export_results)
        self.btn_export.pack(side="left", padx=6)
        self.btn_clear = ttk.Button(btns, text="", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=6)
        self.lbl_copy_from = ttk.Label(btns, text="")
        self.lbl_copy_from.pack(side="left", padx=(18, 4))
        self.copy_host_var = tk.StringVar(value="")
        self.copy_combo = ttk.Combobox(btns, textvariable=self.copy_host_var,
                                       state="readonly", width=20, values=[])
        self.copy_combo.pack(side="left")

        self.prog = ttk.Progressbar(self.tab_search, mode="determinate")
        self.prog.pack(fill="x", padx=10, pady=(6, 0))

        self.lbl_results = ttk.Label(self.tab_search, text="")
        self.lbl_results.pack(anchor="w", padx=10, pady=(8, 2))
        txt_fr = ttk.Frame(self.tab_search)
        txt_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt = tk.Text(txt_fr, wrap="none", font=("Consolas", 10), state="disabled")
        ys = ttk.Scrollbar(txt_fr, orient="vertical", command=self.txt.yview)
        xs = ttk.Scrollbar(txt_fr, orient="horizontal", command=self.txt.xview)
        self.txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.txt.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        txt_fr.grid_rowconfigure(0, weight=1)
        txt_fr.grid_columnconfigure(0, weight=1)

        # --- Tab 2: devices ---
        self.tab_dev = ttk.Frame(self.nb)
        self.nb.add(self.tab_dev, text="devices")
        self.lbl_dev = ttk.Label(self.tab_dev, text="")
        self.lbl_dev.pack(anchor="w", padx=10, pady=(10, 4))
        cols = ("audit", "hostname", "host", "user", "port")
        self.tree = ttk.Treeview(self.tab_dev, columns=cols, show="headings", height=14)
        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<Double-1>", lambda _e: self.edit_device())
        self.tree.bind("<ButtonRelease-1>", self._on_dev_click)
        self.tree.bind("<space>", self._on_dev_space)
        self.tree.column("audit", width=44, minwidth=44, stretch=False, anchor="center")
        self.tree.heading("audit", text="\u2713", command=self.toggle_all_audit)
        for _c in ("hostname", "host", "user", "port"):
            self.tree.heading(_c, command=lambda c=_c: self.sort_devices(c))
        dbtns = ttk.Frame(self.tab_dev)
        dbtns.pack(fill="x", padx=10, pady=10)
        self.btn_add = ttk.Button(dbtns, text="", command=self.add_device)
        self.btn_add.pack(side="left", padx=(0, 6))
        self.btn_edit = ttk.Button(dbtns, text="", command=self.edit_device)
        self.btn_edit.pack(side="left", padx=6)
        self.btn_dup = ttk.Button(dbtns, text="", command=self.dup_device)
        self.btn_dup.pack(side="left", padx=6)
        self.btn_del = ttk.Button(dbtns, text="", command=self.del_device)
        self.btn_del.pack(side="left", padx=6)
        self.btn_test = ttk.Button(dbtns, text="", command=self.test_device)
        self.btn_test.pack(side="left", padx=6)
        self.btn_import = ttk.Button(dbtns, text="", command=self.import_devices)
        self.btn_import.pack(side="left", padx=6)

        # --- Tab 3: subnets ---
        self.tab_sub = ttk.Frame(self.nb)
        self.nb.add(self.tab_sub, text="subnets")
        subv = ttk.Frame(self.tab_sub)
        subv.pack(fill="x", padx=10, pady=(10, 0))
        self.lbl_sub_dev = ttk.Label(subv, text="")
        self.lbl_sub_dev.pack(side="left")
        self.sub_dev_var = tk.StringVar(value="")
        self.combo_sub_dev = ttk.Combobox(subv, textvariable=self.sub_dev_var,
                                          state="readonly", width=24, values=[])
        self.combo_sub_dev.pack(side="left", padx=(6, 0))
        self.btn_sub_fetch = ttk.Button(subv, text="",
                                        command=self.fetch_vlan_subnets)
        self.btn_sub_fetch.pack(side="left", padx=8)
        self.sub_prog = ttk.Progressbar(subv, mode="indeterminate", length=120)
        self.lbl_sub = ttk.Label(self.tab_sub, text="")
        self.lbl_sub.pack(anchor="w", padx=10, pady=(10, 4))
        subcols = ("subnet", "acl_in", "acl_out")
        self.subtree = ttk.Treeview(self.tab_sub, columns=subcols, show="headings", height=14)
        self.subtree.pack(fill="both", expand=True, padx=10)
        self.subtree.bind("<Double-1>", lambda _e: self.edit_subnet())
        for _c in subcols:
            self.subtree.heading(_c, command=lambda c=_c: self.sort_subnets(c))
        sbtns = ttk.Frame(self.tab_sub)
        sbtns.pack(fill="x", padx=10, pady=10)
        self.btn_sub_add = ttk.Button(sbtns, text="", command=self.add_subnet)
        self.btn_sub_add.pack(side="left", padx=(0, 6))
        self.btn_sub_edit = ttk.Button(sbtns, text="", command=self.edit_subnet)
        self.btn_sub_edit.pack(side="left", padx=6)
        self.btn_sub_del = ttk.Button(sbtns, text="", command=self.del_subnet)
        self.btn_sub_del.pack(side="left", padx=6)

        # --- Tab 4: ACL generator (PC -> cameras, IN+OUT) ---
        self.tab_gen = ttk.Frame(self.nb)
        self.nb.add(self.tab_gen, text="generator")
        gf = ttk.Frame(self.tab_gen)
        gf.pack(fill="x", padx=10, pady=10)
        self.lbl_gen_pc = ttk.Label(gf, text="")
        self.lbl_gen_pc.grid(row=0, column=0, sticky="w")
        self.ent_gen_pc = ttk.Entry(gf, width=20, font=("Consolas", 11))
        self.ent_gen_pc.grid(row=1, column=0, sticky="w", pady=4)
        self.lbl_gen_acl_in = ttk.Label(gf, text="")
        self.lbl_gen_acl_in.grid(row=0, column=1, sticky="w", padx=(16, 0))
        self.ent_gen_acl_in = ttk.Entry(gf, width=24, font=("Consolas", 11))
        self.ent_gen_acl_in.grid(row=1, column=1, sticky="w", padx=(16, 0), pady=4)
        self.lbl_gen_acl_out = ttk.Label(gf, text="")
        self.lbl_gen_acl_out.grid(row=0, column=2, sticky="w", padx=(16, 0))
        self.ent_gen_acl_out = ttk.Entry(gf, width=24, font=("Consolas", 11))
        self.ent_gen_acl_out.grid(row=1, column=2, sticky="w", padx=(16, 0), pady=4)
        self.lbl_gen_dhcp = ttk.Label(gf, text="", foreground="gray")
        self.lbl_gen_dhcp.grid(row=2, column=0, columnspan=3, sticky="w", pady=(2, 0))
        self.lbl_gen_owner = ttk.Label(gf, text="")
        self.lbl_gen_owner.grid(row=3, column=0, sticky="w", pady=(6, 0))
        self.ent_gen_owner = ttk.Entry(gf, width=40, font=("Consolas", 11))
        self.ent_gen_owner.grid(row=3, column=1, columnspan=2, sticky="w",
                                padx=(16, 0), pady=(6, 0))

        self.lbl_gen_cams = ttk.Label(self.tab_gen, text="")
        self.lbl_gen_cams.pack(anchor="w", padx=10)
        cam_fr = ttk.Frame(self.tab_gen)
        cam_fr.pack(fill="x", padx=10, pady=(0, 6))
        self.txt_cams = tk.Text(cam_fr, height=5, font=("Consolas", 10))
        cam_ys = ttk.Scrollbar(cam_fr, orient="vertical", command=self.txt_cams.yview)
        self.txt_cams.configure(yscrollcommand=cam_ys.set)
        self.txt_cams.pack(side="left", fill="x", expand=True)
        cam_ys.pack(side="left", fill="y")

        gopts = ttk.Frame(self.tab_gen)
        gopts.pack(fill="x", padx=10)
        self.gen_in_var = tk.BooleanVar(value=True)
        self.gen_out_var = tk.BooleanVar(value=True)
        self.gen_agg_var = tk.BooleanVar(value=True)
        self.gen_group_var = tk.BooleanVar(value=True)
        self.chk_gen_in = ttk.Checkbutton(gopts, text="", variable=self.gen_in_var)
        self.chk_gen_in.pack(side="left", padx=(0, 12))
        self.chk_gen_out = ttk.Checkbutton(gopts, text="", variable=self.gen_out_var)
        self.chk_gen_out.pack(side="left", padx=12)
        self.chk_gen_agg = ttk.Checkbutton(gopts, text="", variable=self.gen_agg_var)
        self.chk_gen_agg.pack(side="left", padx=(18, 0))
        self.chk_gen_group = ttk.Checkbutton(gopts, text="", variable=self.gen_group_var)
        self.chk_gen_group.pack(side="left", padx=(18, 0))

        grow = ttk.Frame(self.tab_gen)
        grow.pack(fill="x", padx=10, pady=(6, 0))
        self.lbl_gen_dev = ttk.Label(grow, text="")
        self.lbl_gen_dev.pack(side="left")
        self.gen_dev_var = tk.StringVar(value="")
        self.combo_gen_dev = ttk.Combobox(grow, textvariable=self.gen_dev_var,
                                          state="readonly", width=24, values=[])
        self.combo_gen_dev.pack(side="left", padx=(6, 0))

        self.lbl_gen_starts = ttk.Label(self.tab_gen, text="")
        self.lbl_gen_starts.pack(anchor="w", padx=10, pady=(6, 0))
        self.starts_fr = ttk.Frame(self.tab_gen)
        self.starts_fr.pack(fill="x", padx=10)

        gbtns = ttk.Frame(self.tab_gen)
        gbtns.pack(fill="x", padx=10, pady=8)
        self.btn_gen = ttk.Button(gbtns, text="", command=self.generate_acl)
        self.btn_gen.pack(side="left", padx=(0, 6))
        self.btn_gen_copy = ttk.Button(gbtns, text="", command=self.copy_gen)
        self.btn_gen_copy.pack(side="left", padx=6)
        self.btn_gen_clear = ttk.Button(gbtns, text="", command=self.clear_gen)
        self.btn_gen_clear.pack(side="left", padx=6)
        # shown only while generating (hidden when idle)
        self.gen_prog = ttk.Progressbar(gbtns, mode="indeterminate", length=150)

        self.lbl_gen_results = ttk.Label(self.tab_gen, text="")
        self.lbl_gen_results.pack(anchor="w", padx=10, pady=(2, 2))
        gen_fr = ttk.Frame(self.tab_gen)
        gen_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_gen = tk.Text(gen_fr, wrap="none", font=("Consolas", 10), state="disabled")
        gen_ys = ttk.Scrollbar(gen_fr, orient="vertical", command=self.txt_gen.yview)
        gen_xs = ttk.Scrollbar(gen_fr, orient="horizontal", command=self.txt_gen.xview)
        self.txt_gen.configure(yscrollcommand=gen_ys.set, xscrollcommand=gen_xs.set)
        self.txt_gen.grid(row=0, column=0, sticky="nsew")
        gen_ys.grid(row=0, column=1, sticky="ns")
        gen_xs.grid(row=1, column=0, sticky="ew")
        gen_fr.grid_rowconfigure(0, weight=1)
        gen_fr.grid_columnconfigure(0, weight=1)

        # --- Tab: IP tracking (ARP -> MAC -> port -> CDP) ---
        self.tab_track = ttk.Frame(self.nb)
        self.nb.add(self.tab_track, text="track")
        tf = ttk.Frame(self.tab_track)
        tf.pack(fill="x", padx=10, pady=10)
        self.lbl_track_ip = ttk.Label(tf, text="")
        self.lbl_track_ip.grid(row=0, column=0, sticky="w")
        self.ent_track_ip = ttk.Entry(tf, width=24, font=("Consolas", 11))
        self.ent_track_ip.grid(row=1, column=0, sticky="w", pady=4)
        self.lbl_track_dev = ttk.Label(tf, text="")
        self.lbl_track_dev.grid(row=0, column=1, sticky="w", padx=(16, 0))
        self.track_dev_var = tk.StringVar(value="")
        self.combo_track_dev = ttk.Combobox(tf, textvariable=self.track_dev_var,
                                            state="readonly", width=24, values=[])
        self.combo_track_dev.grid(row=1, column=1, sticky="w", padx=(16, 0), pady=4)

        tbtns = ttk.Frame(self.tab_track)
        tbtns.pack(fill="x", padx=10, pady=(0, 8))
        self.btn_track = ttk.Button(tbtns, text="", command=self.trace_ip)
        self.btn_track.pack(side="left", padx=(0, 6))
        self.btn_track_stop = ttk.Button(tbtns, text="", command=self.stop_track,
                                         state="disabled")
        self.btn_track_stop.pack(side="left", padx=6)
        self.btn_track_clear = ttk.Button(tbtns, text="", command=self.clear_track)
        self.btn_track_clear.pack(side="left", padx=6)
        self.btn_track_cont = ttk.Button(tbtns, text="", command=self.continue_track)
        self.prog_track = ttk.Progressbar(tbtns, mode="determinate", length=150)
        self.prog_track.pack(side="left", padx=(14, 0))
        self.track_parent_var = tk.BooleanVar(value=False)
        self.chk_track_parent = ttk.Checkbutton(tbtns, text="",
                                                variable=self.track_parent_var)
        self.chk_track_parent.pack(side="left", padx=(14, 0))

        self.lbl_track_results = ttk.Label(self.tab_track, text="")
        self.lbl_track_results.pack(anchor="w", padx=10, pady=(2, 2))
        track_fr = ttk.Frame(self.tab_track)
        track_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_track = tk.Text(track_fr, wrap="none", font=("Consolas", 10),
                                 state="disabled")
        trk_ys = ttk.Scrollbar(track_fr, orient="vertical", command=self.txt_track.yview)
        trk_xs = ttk.Scrollbar(track_fr, orient="horizontal", command=self.txt_track.xview)
        self.txt_track.configure(yscrollcommand=trk_ys.set, xscrollcommand=trk_xs.set)
        self.txt_track.grid(row=0, column=0, sticky="nsew")
        trk_ys.grid(row=0, column=1, sticky="ns")
        trk_xs.grid(row=1, column=0, sticky="ew")
        track_fr.grid_rowconfigure(0, weight=1)
        track_fr.grid_columnconfigure(0, weight=1)

        # --- Tab: ACL audit (fetch one ACL, propose optimized version) ---
        self.tab_audit = ttk.Frame(self.nb)
        self.nb.add(self.tab_audit, text="audit")
        af = ttk.Frame(self.tab_audit)
        af.pack(fill="x", padx=10, pady=10)
        self.lbl_audit_dev = ttk.Label(af, text="")
        self.lbl_audit_dev.grid(row=0, column=0, sticky="w")
        self.audit_dev_var = tk.StringVar(value="")
        self.combo_audit_dev = ttk.Combobox(af, textvariable=self.audit_dev_var,
                                            state="readonly", width=24, values=[])
        self.combo_audit_dev.grid(row=1, column=0, sticky="w", pady=4)
        self.btn_audit_fetch = ttk.Button(af, text="", command=self.fetch_audit_acls)
        self.btn_audit_fetch.grid(row=1, column=1, padx=8)
        self.lbl_audit_acl = ttk.Label(af, text="")
        self.lbl_audit_acl.grid(row=0, column=2, sticky="w", padx=(16, 0))
        self.audit_acl_var = tk.StringVar(value="")
        self.combo_audit_acl = ttk.Combobox(af, textvariable=self.audit_acl_var,
                                            state="readonly", width=30, values=[])
        self.combo_audit_acl.grid(row=1, column=2, sticky="w", padx=(16, 0), pady=4)
        self.combo_audit_acl.bind("<<ComboboxSelected>>",
                                  lambda _e: self.show_audit_acl())

        abtns = ttk.Frame(self.tab_audit)
        abtns.pack(fill="x", padx=10, pady=(0, 8))
        self.lbl_audit_sort = ttk.Label(abtns, text="")
        self.lbl_audit_sort.pack(side="left")
        self.audit_sort_side = "src"
        self.audit_sort_var = tk.StringVar(value="")
        self.combo_audit_sort = ttk.Combobox(abtns, textvariable=self.audit_sort_var,
                                             state="readonly", width=16, values=[])
        self.combo_audit_sort.pack(side="left", padx=(6, 14))
        self.combo_audit_sort.bind("<<ComboboxSelected>>",
                                   lambda _e: self._sync_audit_sort())
        self.btn_audit_optimize = ttk.Button(abtns, text="",
                                             command=self.optimize_audit)
        self.btn_audit_optimize.pack(side="left", padx=(0, 6))
        self.btn_audit_copy = ttk.Button(abtns, text="", command=self.copy_audit)
        self.btn_audit_copy.pack(side="left", padx=6)
        self.btn_audit_clear = ttk.Button(abtns, text="", command=self.clear_audit)
        self.btn_audit_clear.pack(side="left", padx=6)
        self.audit_prog = ttk.Progressbar(abtns, mode="indeterminate", length=120)

        self.lbl_audit_cur = ttk.Label(self.tab_audit, text="")
        self.lbl_audit_cur.pack(anchor="w", padx=10, pady=(2, 2))
        cur_fr = ttk.Frame(self.tab_audit)
        cur_fr.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.txt_audit_cur = tk.Text(cur_fr, wrap="none", font=("Consolas", 10),
                                     height=8, state="disabled")
        aud_ys = ttk.Scrollbar(cur_fr, orient="vertical",
                               command=self.txt_audit_cur.yview)
        aud_xs = ttk.Scrollbar(cur_fr, orient="horizontal",
                               command=self.txt_audit_cur.xview)
        self.txt_audit_cur.configure(yscrollcommand=aud_ys.set,
                                     xscrollcommand=aud_xs.set)
        self.txt_audit_cur.grid(row=0, column=0, sticky="nsew")
        aud_ys.grid(row=0, column=1, sticky="ns")
        aud_xs.grid(row=1, column=0, sticky="ew")
        cur_fr.grid_rowconfigure(0, weight=1)
        cur_fr.grid_columnconfigure(0, weight=1)

        self.lbl_audit_stats = ttk.Label(self.tab_audit, text="",
                                         foreground="blue")
        self.lbl_audit_stats.pack(anchor="w", padx=10)
        self.lbl_audit_prop = ttk.Label(self.tab_audit, text="")
        self.lbl_audit_prop.pack(anchor="w", padx=10, pady=(2, 2))
        prop_fr = ttk.Frame(self.tab_audit)
        prop_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_audit_prop = tk.Text(prop_fr, wrap="none", font=("Consolas", 10),
                                      height=8, state="disabled")
        aup_ys = ttk.Scrollbar(prop_fr, orient="vertical",
                               command=self.txt_audit_prop.yview)
        aup_xs = ttk.Scrollbar(prop_fr, orient="horizontal",
                               command=self.txt_audit_prop.xview)
        self.txt_audit_prop.configure(yscrollcommand=aup_ys.set,
                                      xscrollcommand=aup_xs.set)
        self.txt_audit_prop.grid(row=0, column=0, sticky="nsew")
        aup_ys.grid(row=0, column=1, sticky="ns")
        aup_xs.grid(row=1, column=0, sticky="ew")
        prop_fr.grid_rowconfigure(0, weight=1)
        prop_fr.grid_columnconfigure(0, weight=1)

        # --- Tab: vulnerabilities (check config, propose fix, apply later) ---
        self.tab_vuln = ttk.Frame(self.nb)
        self.nb.add(self.tab_vuln, text="vuln")
        vf = ttk.Frame(self.tab_vuln)
        vf.pack(fill="x", padx=10, pady=10)
        self.lbl_vuln_dev = ttk.Label(vf, text="")
        self.lbl_vuln_dev.grid(row=0, column=0, sticky="w")
        self.lbl_vuln_name = ttk.Label(vf, text="")
        self.lbl_vuln_name.grid(row=0, column=1, sticky="w", padx=(16, 0))
        dev_list_fr = ttk.Frame(vf)
        dev_list_fr.grid(row=1, column=0, sticky="w", pady=4)
        self.vuln_listbox = tk.Listbox(dev_list_fr, selectmode="extended",
                                       width=38, height=8,
                                       font=("Consolas", 10),
                                       exportselection=False)
        vuln_dev_ys = ttk.Scrollbar(dev_list_fr, orient="vertical",
                                    command=self.vuln_listbox.yview)
        self.vuln_listbox.configure(yscrollcommand=vuln_dev_ys.set)
        self.vuln_listbox.pack(side="left", fill="y")
        vuln_dev_ys.pack(side="left", fill="y")
        right_fr = ttk.Frame(vf)
        right_fr.grid(row=1, column=1, sticky="nw", padx=(16, 0), pady=4)
        self.vuln_id_var = tk.StringVar(value="")
        self.combo_vuln = ttk.Combobox(right_fr, textvariable=self.vuln_id_var,
                                       state="readonly", width=34, values=[])
        self.combo_vuln.pack(anchor="w")
        self.combo_vuln.bind("<<ComboboxSelected>>",
                             lambda _e: self._sync_vuln_desc())
        self.lbl_vuln_desc = ttk.Label(right_fr, text="", wraplength=420,
                                       justify="left", foreground="gray")
        self.lbl_vuln_desc.pack(anchor="w", pady=(6, 0))

        vbtns = ttk.Frame(self.tab_vuln)
        vbtns.pack(fill="x", padx=10, pady=(0, 8))
        self.btn_vuln_check = ttk.Button(vbtns, text="",
                                         command=self.start_vuln_check)
        self.btn_vuln_check.pack(side="left", padx=(0, 6))
        self.btn_vuln_stop = ttk.Button(vbtns, text="", command=self.stop_vuln_check,
                                        state="disabled")
        self.btn_vuln_stop.pack(side="left", padx=6)
        self.btn_vuln_copy = ttk.Button(vbtns, text="", command=self.copy_vuln)
        self.btn_vuln_copy.pack(side="left", padx=6)
        self.btn_vuln_clear = ttk.Button(vbtns, text="", command=self.clear_vuln)
        self.btn_vuln_clear.pack(side="left", padx=6)
        self.btn_vuln_apply = ttk.Button(vbtns, text="",
                                          command=self.start_vuln_apply)
        self.btn_vuln_apply.pack(side="left", padx=6)
        self.btn_vuln_all = ttk.Button(vbtns, text="",
                                       command=lambda: self.vuln_listbox.select_set(0, tk.END))
        self.btn_vuln_all.pack(side="left", padx=(18, 2))
        self.btn_vuln_none = ttk.Button(vbtns, text="",
                                        command=lambda: self.vuln_listbox.select_clear(0, tk.END))
        self.btn_vuln_none.pack(side="left", padx=2)
        self.btn_vuln_marked = ttk.Button(vbtns, text="",
                                          command=self.vuln_select_marked)
        self.btn_vuln_marked.pack(side="left", padx=2)
        self.vuln_style = ttk.Style(self)
        self.vuln_style.configure("VulnWork.Horizontal.TProgressbar",
                                  background="gold", thickness=18)
        self.vuln_style.configure("VulnDone.Horizontal.TProgressbar",
                                  background="green", thickness=18)
        self.vuln_prog = ttk.Progressbar(vbtns, mode="determinate", length=220)
        self.vuln_prog.pack(side="left", padx=(14, 0))

        self.lbl_vuln_results = ttk.Label(self.tab_vuln, text="")
        self.lbl_vuln_results.pack(anchor="w", padx=10, pady=(2, 2))
        vuln_fr = ttk.Frame(self.tab_vuln)
        vuln_fr.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.txt_vuln = tk.Text(vuln_fr, wrap="none", font=("Consolas", 10),
                                height=8, state="disabled")
        vuln_ys = ttk.Scrollbar(vuln_fr, orient="vertical",
                                command=self.txt_vuln.yview)
        vuln_xs = ttk.Scrollbar(vuln_fr, orient="horizontal",
                                command=self.txt_vuln.xview)
        self.txt_vuln.configure(yscrollcommand=vuln_ys.set,
                                xscrollcommand=vuln_xs.set)
        self.txt_vuln.tag_configure("vuln_ok", foreground="green")
        self.txt_vuln.tag_configure("vuln_fail", foreground="red")
        self.txt_vuln.tag_configure("vuln_warn", foreground="dark orange")
        self.txt_vuln.grid(row=0, column=0, sticky="nsew")
        vuln_ys.grid(row=0, column=1, sticky="ns")
        vuln_xs.grid(row=1, column=0, sticky="ew")
        vuln_fr.grid_rowconfigure(0, weight=1)
        vuln_fr.grid_columnconfigure(0, weight=1)

        self.lbl_vuln_prop = ttk.Label(self.tab_vuln, text="")
        self.lbl_vuln_prop.pack(anchor="w", padx=10, pady=(2, 2))
        vprop_fr = ttk.Frame(self.tab_vuln)
        vprop_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_vuln_prop = tk.Text(vprop_fr, wrap="none", font=("Consolas", 10),
                                     height=8, state="disabled")
        vprop_ys = ttk.Scrollbar(vprop_fr, orient="vertical",
                                 command=self.txt_vuln_prop.yview)
        vprop_xs = ttk.Scrollbar(vprop_fr, orient="horizontal",
                                 command=self.txt_vuln_prop.xview)
        self.txt_vuln_prop.configure(yscrollcommand=vprop_ys.set,
                                     xscrollcommand=vprop_xs.set)
        self.txt_vuln_prop.grid(row=0, column=0, sticky="nsew")
        vprop_ys.grid(row=0, column=1, sticky="ns")
        vprop_xs.grid(row=1, column=0, sticky="ew")
        vprop_fr.grid_rowconfigure(0, weight=1)
        vprop_fr.grid_columnconfigure(0, weight=1)

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
        self.lbl_ip.configure(text=S["search_ip_label"])
        self.btn_search.configure(text=S["search_btn"])
        self.btn_stop.configure(text=S["stop_btn"])
        self.chk_neg.configure(text=S["negate_label"])
        self.btn_copy.configure(text=S["copy_btn"])
        self.lbl_copy_from.configure(text=S["copy_from_label"])
        self.btn_export.configure(text=S["export_btn"])
        self.btn_clear.configure(text=S["clear_btn"])
        self.lbl_results.configure(text=S["results_label"])
        self.lbl_dev.configure(text=S["devices_label"])
        self.tree.heading("hostname", text=S["col_hostname"])
        self.tree.heading("host", text=S["col_host"])
        self.tree.heading("user", text=S["col_user"])
        self.tree.heading("port", text=S["col_port"])
        self.btn_add.configure(text=S["add_btn"])
        self.btn_edit.configure(text=S["edit_btn"])
        self.btn_dup.configure(text=S["dup_btn"])
        self.btn_del.configure(text=S["del_btn"])
        self.btn_test.configure(text=S["test_btn"])
        self.btn_import.configure(text=S["import_btn"])
        self.lbl_sub.configure(text=S["subnets_label"])
        self.lbl_sub_dev.configure(text=S["subnet_dev_label"])
        self.btn_sub_fetch.configure(text=S["subnet_fetch_btn"])
        self.subtree.heading("subnet", text=S["col_subnet"])
        self.subtree.heading("acl_in", text=S["col_acl_in"])
        self.subtree.heading("acl_out", text=S["col_acl_out"])
        self.btn_sub_add.configure(text=S["add_btn"])
        self.btn_sub_edit.configure(text=S["edit_btn"])
        self.btn_sub_del.configure(text=S["del_btn"])
        self.lbl_gen_pc.configure(text=S["gen_pc_label"])
        self.lbl_gen_owner.configure(text=S["gen_owner_label"])
        self.lbl_gen_acl_in.configure(text=S["gen_acl_in_label"])
        self.lbl_gen_acl_out.configure(text=S["gen_acl_out_label"])
        self.lbl_gen_cams.configure(text=S["gen_cams_label"])
        self.chk_gen_in.configure(text=S["gen_in"])
        self.chk_gen_out.configure(text=S["gen_out"])
        self.chk_gen_agg.configure(text=S["gen_agg"])
        self.chk_gen_group.configure(text=S["gen_group"])
        self.lbl_gen_dev.configure(text=S["gen_dev_label"])
        self.lbl_gen_starts.configure(text=S["gen_starts"])
        self.lbl_gen_dhcp.configure(text=S["dhcp_idle"], foreground="gray")
        self.btn_gen.configure(text=S["gen_btn"])
        self.btn_gen_copy.configure(text=S["copy_btn"])
        self.btn_gen_clear.configure(text=S["clear_btn"])
        self.lbl_gen_results.configure(text=S["results_label"])
        self.lbl_track_ip.configure(text=S["track_ip_label"])
        self.lbl_track_dev.configure(text=S["track_dev_label"])
        self.btn_track.configure(text=S["track_btn"])
        self.btn_track_stop.configure(text=S["stop_btn"])
        self.btn_track_clear.configure(text=S["clear_btn"])
        self.chk_track_parent.configure(text=S["track_parent_creds"])
        self.lbl_track_results.configure(text=S["results_label"])
        self.lbl_audit_dev.configure(text=S["audit_dev_label"])
        self.btn_audit_fetch.configure(text=S["audit_fetch_btn"])
        self.lbl_audit_acl.configure(text=S["audit_acl_label"])
        self.lbl_audit_sort.configure(text=S["audit_sort_label"])
        self.combo_audit_sort.configure(values=[S["audit_sort_src"],
                                                S["audit_sort_dst"]])
        self.audit_sort_var.set(S["audit_sort_src"] if self.audit_sort_side == "src"
                                else S["audit_sort_dst"])
        self.btn_audit_optimize.configure(text=S["audit_optimize_btn"])
        self.btn_audit_copy.configure(text=S["copy_btn"])
        self.btn_audit_clear.configure(text=S["clear_btn"])
        self.lbl_audit_cur.configure(text=S["audit_current_label"])
        self.lbl_audit_prop.configure(text=S["audit_proposal_label"])
        self.lbl_vuln_dev.configure(text=S["vuln_devices_label"])
        self.lbl_vuln_name.configure(text=S["vuln_name_label"])
        self.btn_vuln_check.configure(text=S["vuln_check_btn"])
        self.btn_vuln_stop.configure(text=S["stop_btn"])
        self.btn_vuln_copy.configure(text=S["copy_btn"])
        self.btn_vuln_clear.configure(text=S["clear_btn"])
        self.btn_vuln_apply.configure(text=S["vuln_apply_btn"])
        self.btn_vuln_all.configure(text=S["vuln_select_all"])
        self.btn_vuln_none.configure(text=S["vuln_select_none"])
        self.btn_vuln_marked.configure(text=S["vuln_marked_btn"])
        self.lbl_vuln_results.configure(text=S["vuln_results_label"])
        self.lbl_vuln_prop.configure(text=S["vuln_proposal_label"])
        self._refresh_vuln_combo()
        self.lbl_lang.configure(text=S["lang_label"])
        self.lbl_master.configure(text=S["master_label"])
        self.btn_chmaster.configure(text=S["change_master_btn"])
        self.lbl_dhcp.configure(text=S["dhcp_label"])
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
            return dst
        except OSError:
            return None

    @staticmethod
    def _host_key(host: str) -> tuple:
        """Sort key: real IPs numerically (10.0.0.9 < 10.0.0.10), then names."""
        h = (host or "").strip()
        try:
            return (0, int(ipaddress.ip_address(h)), "")
        except ValueError:
            return (1, 0, h.lower())

    @staticmethod
    def _subnet_key(subnet: str) -> tuple:
        try:
            net = ipaddress.ip_network((subnet or "").strip(), strict=False)
            return (0, int(net.network_address), net.prefixlen, "")
        except ValueError:
            return (1, 0, 0, (subnet or "").lower())

    def sort_devices(self, col: str):
        """Sort the device list by column click; toggles direction."""
        if self._dev_sort and self._dev_sort[0] == col:
            reverse = not self._dev_sort[1]
        else:
            reverse = False
        keys = {
            "hostname": lambda d: (d.get("hostname", "") or "").lower(),
            "host": lambda d: self._host_key(d.get("host", "")),
            "user": lambda d: (d.get("username", "") or "").lower(),
            "port": lambda d: (int(d.get("port", 22) or 22)
                               if str(d.get("port", 22)).strip().isdigit()
                               else 10 ** 9),
        }
        self.devices.sort(key=keys.get(col, keys["host"]), reverse=reverse)
        self._dev_sort = (col, reverse)
        self.persist_store()
        self.refresh_tree()

    def sort_subnets(self, col: str):
        if self._sub_sort and self._sub_sort[0] == col:
            reverse = not self._sub_sort[1]
        else:
            reverse = False
        keys = {
            "subnet": lambda s: self._subnet_key(s.get("subnet", "")),
            "acl_in": lambda s: (s.get("acl_in", "") or "").lower(),
            "acl_out": lambda s: (s.get("acl_out", "") or "").lower(),
        }
        self.subnets.sort(key=keys.get(col, keys["subnet"]), reverse=reverse)
        self._sub_sort = (col, reverse)
        self.persist_store()
        self.refresh_subnets()

    def _update_sort_headers(self):
        """Arrow (asc/desc) on the sorted column; plain text otherwise."""
        dev_heads = {"hostname": self.T("col_hostname"), "host": self.T("col_host"),
                     "user": self.T("col_user"), "port": self.T("col_port")}
        for col, base in dev_heads.items():
            try:
                if self._dev_sort and self._dev_sort[0] == col:
                    arrow = " \u25bc" if self._dev_sort[1] else " \u25b2"
                    self.tree.heading(col, text=base + arrow)
                else:
                    self.tree.heading(col, text=base)
            except tk.TclError:
                pass
        sub_heads = {"subnet": self.T("col_subnet"),
                     "acl_in": self.T("col_acl_in"),
                     "acl_out": self.T("col_acl_out")}
        for col, base in sub_heads.items():
            try:
                if self._sub_sort and self._sub_sort[0] == col:
                    arrow = " \u25bc" if self._sub_sort[1] else " \u25b2"
                    self.subtree.heading(col, text=base + arrow)
                else:
                    self.subtree.heading(col, text=base)
            except tk.TclError:
                pass

    def refresh_tree(self):
        try:
            sel_hosts = set()
            for r in self.tree.selection():
                i = self.tree.index(r)
                if 0 <= i < len(self.devices):
                    sel_hosts.add(self.devices[i].get("host", ""))
        except (tk.TclError, AttributeError):
            sel_hosts = set()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for d in self.devices:
            mark = "\u2611" if d.get("audit", True) else "\u2610"
            self.tree.insert("", "end", values=(mark, d.get("hostname", ""), d.get("host", ""),
                                                d.get("username", ""), d.get("port", 22)))
        if sel_hosts:
            try:
                for iid in self.tree.get_children():
                    i = self.tree.index(iid)
                    if (0 <= i < len(self.devices)
                            and self.devices[i].get("host", "") in sel_hosts):
                        self.tree.selection_add(iid)
            except tk.TclError:
                pass
        self._update_sort_headers()
        self._refresh_gen_devices()

    def refresh_subnets(self):
        for i in self.subtree.get_children():
            self.subtree.delete(i)
        for s in self.subnets:
            n = acl_parser.normalize_subnet(s)
            self.subtree.insert("", "end",
                                values=(n["subnet"], n["acl_in"], n["acl_out"]))
        self._update_sort_headers()

    # ---------- audit tab ----------
    def _set_audit_cur(self, content: str):
        self.txt_audit_cur.configure(state="normal")
        self.txt_audit_cur.delete("1.0", tk.END)
        self.txt_audit_cur.insert("1.0", content)
        self.txt_audit_cur.configure(state="disabled")

    def _set_audit_prop(self, content: str):
        self.txt_audit_prop.configure(state="normal")
        self.txt_audit_prop.delete("1.0", tk.END)
        self.txt_audit_prop.insert("1.0", content)
        self.txt_audit_prop.configure(state="disabled")

    def _sync_audit_sort(self):
        S = STRINGS[self.lang]
        self.audit_sort_side = ("dst" if self.audit_sort_var.get() == S["audit_sort_dst"]
                                else "src")

    def fetch_audit_acls(self):
        if self._audit_fetching:
            return
        if not self._require_unlocked():
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        dev = self._lookup_device(self.audit_dev_var.get().strip())
        if dev is None:
            messagebox.showwarning("ACL", self.T("audit_need_dev"))
            return
        self._audit_fetching = True
        self.btn_audit_fetch.configure(state="disabled")
        self.audit_prog.pack(side="left", padx=(14, 0))
        self.audit_prog.start(12)
        self.status.set(self.T("audit_fetching").format(host=dev["host"]))
        threading.Thread(target=self._audit_worker, args=(dev,),
                         daemon=True).start()

    def _audit_worker(self, dev: dict):
        try:
            cfg = cisco_ssh.fetch_config(
                dev["host"], dev["username"], dev.get("password", ""),
                dev.get("enable") or None, int(dev.get("port", 22)),
                debug_log=self._ssh_debug_log())
            acls = acl_parser.parse_running_config(cfg)
            self.msg_queue.put(("audit_list", (dev["host"], acls)))
        except Exception as e:
            self.msg_queue.put(("audit_error", (dev["host"], str(e))))

    def _finish_audit_fetch(self, host: str, acls: dict):
        self._audit_fetching = False
        self.btn_audit_fetch.configure(state="normal")
        try:
            self.audit_prog.stop()
        except tk.TclError:
            pass
        self.audit_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        self._audit_acls = acls
        self._audit_host = host
        names = sorted(acls)
        self.combo_audit_acl.configure(values=names)
        if self.audit_acl_var.get() not in names:
            self.audit_acl_var.set(names[0] if names else "")
        self.show_audit_acl()

    def show_audit_acl(self):
        name = self.audit_acl_var.get().strip()
        entries = self._audit_acls.get(name, [])
        if not name or (name not in self._audit_acls):
            self._set_audit_cur("")
            return
        if entries:
            self._set_audit_cur(f"ip access-list extended {name}\n"
                                + "\n".join(f"    {e}" for e in entries) + "\n")
        else:
            self._set_audit_cur(f"ip access-list extended {name}\n"
                                f"    {self.T('audit_empty')}\n")

    def optimize_audit(self):
        name = self.audit_acl_var.get().strip()
        if not name or name not in self._audit_acls:
            messagebox.showwarning("ACL", self.T("audit_need_acl"))
            return
        self._sync_audit_sort()
        entries = self._audit_acls[name]
        res = acl_parser.optimize_acl(entries, self.audit_sort_side)
        new_count = len(res["lines"])
        used = set(range(10, 10 * (new_count + 1), 10))
        out = [f"ip access-list extended {name}"]
        for seq in res["deletes"]:
            if seq not in used:
                out.append(f"no {seq}")
        out.extend(res["lines"])
        self._audit_proposal = "\n".join(out) + "\n"
        self._set_audit_prop(self._audit_proposal)
        st = res["stats"]
        self.lbl_audit_stats.configure(text=self.T("audit_stats").format(
            before=st["before"], after=st["after"], dup=st["dup"],
            agg=st["merged"], rem=st["remarks"]))

    def copy_audit(self):
        if not self._audit_proposal.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self._audit_proposal)
        self._toast(self.T("copied"))

    def clear_audit(self):
        self._audit_proposal = ""
        self._set_audit_prop("")
        self.lbl_audit_stats.configure(text="")

    # ---------- vulnerabilities tab (telnet first, registry-ready) ----------
    def _vuln_registry(self) -> list[tuple[str, str, str]]:
        """Available checks: [(id, display name, description)]."""
        S = STRINGS[self.lang]
        return [(vuln_telnet.VULN_ID, S["vuln_telnet_name"],
                 S["vuln_telnet_desc"])]

    def _refresh_vuln_combo(self):
        reg = self._vuln_registry()
        names = [name for _vid, name, _desc in reg]
        self.combo_vuln.configure(values=names)
        if self.vuln_id_var.get() not in names:
            self.vuln_id_var.set(names[0] if names else "")
        self._sync_vuln_desc()

    def _sync_vuln_desc(self):
        reg = self._vuln_registry()
        sel = self.vuln_id_var.get()
        for _vid, name, desc in reg:
            if name == sel:
                self.lbl_vuln_desc.configure(text=desc)
                return
        self.lbl_vuln_desc.configure(text="")

    def _selected_vuln_id(self) -> str:
        reg = self._vuln_registry()
        sel = self.vuln_id_var.get()
        for vid, name, _desc in reg:
            if name == sel:
                return vid
        return reg[0][0] if reg else ""

    def _refresh_vuln_devices(self):
        labels = [self.dev_label(d) for d in self.devices if d.get("host")]
        try:
            sel = {self.vuln_listbox.get(i)
                   for i in self.vuln_listbox.curselection()}
        except (tk.TclError, AttributeError):
            sel = set()
        try:
            self.vuln_listbox.delete(0, tk.END)
            for lb in labels:
                self.vuln_listbox.insert(tk.END, lb)
            for i, lb in enumerate(labels):
                if lb in sel:
                    self.vuln_listbox.select_set(i)
        except (tk.TclError, AttributeError):
            pass
        self._refresh_vuln_combo()

    def vuln_select_marked(self):
        """Select rows of devices marked ✓ on the Devices tab."""
        try:
            self.vuln_listbox.select_clear(0, tk.END)
            for i in range(self.vuln_listbox.size()):
                try:
                    label = self.vuln_listbox.get(i)
                except tk.TclError:
                    continue
                dev = self._lookup_device(label.strip())
                if dev is not None and dev.get("audit", True):
                    self.vuln_listbox.select_set(i)
        except tk.TclError:
            pass

    def _selected_vuln_devices(self) -> list[dict]:
        try:
            idxs = list(self.vuln_listbox.curselection())
        except tk.TclError:
            return []
        out = []
        for i in idxs:
            try:
                label = self.vuln_listbox.get(i)
            except tk.TclError:
                continue
            dev = self._lookup_device(label.strip())
            if dev is not None:
                out.append(dev)
        return out

    def _set_vuln_text(self, content: str):
        self.txt_vuln.configure(state="normal")
        self.txt_vuln.delete("1.0", tk.END)
        self.txt_vuln.insert("1.0", content)
        self.txt_vuln.configure(state="disabled")

    def _append_vuln_text(self, chunk: str):
        self.txt_vuln.configure(state="normal")
        self.txt_vuln.insert(tk.END, chunk)
        self.txt_vuln.see(tk.END)
        self.txt_vuln.configure(state="disabled")

    def _insert_vuln_segments(self, segs: list[tuple[str, str | None]],
                              clear: bool = False):
        """Insert pre-tagged lines; tags: vuln_ok (green), vuln_fail (red),
        vuln_warn (orange), None = default color."""
        self.txt_vuln.configure(state="normal")
        if clear:
            self.txt_vuln.delete("1.0", tk.END)
        for text, tag in segs:
            if tag:
                self.txt_vuln.insert(tk.END, text, tag)
            else:
                self.txt_vuln.insert(tk.END, text)
        self.txt_vuln.see(tk.END)
        self.txt_vuln.configure(state="disabled")

    def _set_vuln_prop(self, content: str):
        self.txt_vuln_prop.configure(state="normal")
        self.txt_vuln_prop.delete("1.0", tk.END)
        self.txt_vuln_prop.insert("1.0", content)
        self.txt_vuln_prop.configure(state="disabled")

    def start_vuln_check(self):
        if self._vuln_fetching or self._vuln_applying:
            return
        if not self._require_unlocked():
            return
        devs = self._selected_vuln_devices()
        if not devs:
            # empty list -> fall back to devices marked on the Devices tab
            self.vuln_select_marked()
            devs = self._selected_vuln_devices()
        if not devs:
            messagebox.showwarning("ACL", self.T("vuln_need_dev"))
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        vuln_id = self._selected_vuln_id()
        if vuln_id != vuln_telnet.VULN_ID:
            return
        self.vuln_results = []
        self.vuln_proposal = ""
        self._set_vuln_text("")
        self._set_vuln_prop("")
        self._vuln_fetching = True
        self._vuln_stop.clear()
        self.btn_vuln_check.configure(state="disabled")
        self.btn_vuln_apply.configure(state="disabled")
        self.btn_vuln_stop.configure(state="normal")
        self.vuln_prog.configure(maximum=len(devs), value=0,
                                   mode="indeterminate",
                                   style="VulnWork.Horizontal.TProgressbar")
        self.vuln_prog.start(12)
        self.status.set(self.T("status_searching").format(n=len(devs)))
        snapshot = [dict(d) for d in devs]
        threading.Thread(target=self._vuln_worker, args=(snapshot,),
                         daemon=True).start()

    def stop_vuln_check(self):
        self._vuln_stop.set()

    def _vuln_worker(self, devs: list[dict]):
        """Check all selected switches in parallel (up to 5 SSH sessions)."""
        def one_device(d: dict):
            host = d.get("host", "?")
            try:
                out = cisco_ssh.run_commands(
                    host, d["username"], d.get("password", ""),
                    d.get("enable") or None, int(d.get("port", 22)),
                    timeout=15, commands=vuln_telnet.TELNET_COMMANDS,
                    debug_log=self._ssh_debug_log())
                res = vuln_telnet.analyze_telnet(
                    out.get(vuln_telnet.TELNET_COMMANDS[0], ""),
                    out.get(vuln_telnet.TELNET_COMMANDS[2], ""),
                    out.get(vuln_telnet.TELNET_COMMANDS[1], ""))
                return (host, res, None)
            except Exception as e:
                return (host, None, str(e))

        # keep original order: submit in order, collect in order
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(5, len(devs))) as ex:
            futs = [ex.submit(one_device, d) for d in devs]
            for fut in futs:
                if self._vuln_stop.is_set():
                    for f in futs:
                        f.cancel()
                    break
                try:
                    payload = fut.result()
                except Exception as e:
                    payload = ("?", None, str(e))
                self.msg_queue.put(("vuln_chunk", payload))
        self.msg_queue.put(("vuln_done", None))

    def _finish_vuln_chunk(self, host: str, res: dict | None, err: str | None):
        self.vuln_results.append((host, res, err))
        if err:
            segs = [(self.T("device_hdr").format(host=host) + "\n", None),
                    (self.T("vuln_fetch_fail").format(host=host, err=err)
                     + "\n", "vuln_fail")]
        else:
            segs = self._format_vuln_result(host, res or {})
        empty = not self.txt_vuln.get("1.0", tk.END).strip()
        self._insert_vuln_segments(segs, clear=empty)
        try:
            total = int(self.vuln_prog.cget("maximum") or 0)
            if total:
                self.status.set(self.T("status_progress").format(
                    done=len(self.vuln_results), total=total))
        except tk.TclError:
            pass
        self._rebuild_vuln_proposal()

    def _format_vuln_result(self, host: str, res: dict
                            ) -> list[tuple[str, str | None]]:
        """Per-device findings as (line, tag) segments for colored display."""
        segs = [(self.T("device_hdr").format(host=host) + "\n", None)]
        vty = res.get("vty", [])
        if not vty:
            segs.append((self.T("vuln_no_vty") + "\n", "vuln_warn"))
        else:
            for e in vty:
                val = e.get("transport") or "(missing)"
                if e.get("compliant"):
                    mark, tag = "OK ", "vuln_ok"
                else:
                    mark, tag = "FAIL", "vuln_fail"
                segs.append((f"[{mark}] {e.get('header')}: "
                             f"transport input {val}\n", tag))
            for e in res.get("con_aux", []):
                if e.get("status") == "vulnerable":
                    segs.append((f"[WARN] {e.get('header')}: "
                                 f"transport input {e.get('transport')}\n",
                                 "vuln_warn"))
        if res.get("compliant"):
            segs.append((self.T("vuln_ok") + "\n", "vuln_ok"))
        else:
            segs.append((self.T("vuln_bad") + "\n", "vuln_fail"))
        if res.get("ssh_enabled") is False:
            segs.append((self.T("vuln_warn_ssh") + "\n", "vuln_warn"))
        for e in vty:
            if e.get("status") == "blocked":
                segs.append((self.T("vuln_warn_blocked").format(
                    header=e.get("header")) + "\n", "vuln_warn"))
        return segs

    def _rebuild_vuln_proposal(self):
        """Combined paste-ready fix, per-device sections as '! ' comments."""
        parts: list[str] = []
        for host, res, err in self.vuln_results:
            if err or not res:
                continue
            prop = (res.get("proposal") or "").strip()
            if res.get("compliant") or not prop:
                continue
            parts.append(f"! ==== {host} ====")
            if res.get("ssh_enabled") is False:
                parts.append(f"! {self.T('vuln_warn_ssh')}")
            parts.append(prop)
        self.vuln_proposal = ("\n".join(parts) + "\n") if parts else ""
        if self.vuln_proposal:
            self._set_vuln_prop(self.vuln_proposal)
            return
        good = [(h, r, e) for h, r, e in self.vuln_results if not e and r]
        if good and all(r.get("compliant") for _h, r, _e in good):
            self._set_vuln_prop(self.T("vuln_no_proposal") + "\n")
        elif any(not r.get("compliant") and not (r.get("proposal") or "").strip()
                 for _h, r, _e in good):
            self._set_vuln_prop(self.T("vuln_manual_inspect") + "\n")
        else:
            self._set_vuln_prop("")

    def _finish_vuln_done(self):
        self._vuln_fetching = False
        try:
            self.btn_vuln_check.configure(state="normal")
            self.btn_vuln_apply.configure(state="normal")
            self.btn_vuln_stop.configure(state="disabled")
            self.vuln_prog.stop()
            total = int(self.vuln_prog.cget("maximum") or 0)
            if total and len(self.vuln_results) >= total:
                # everything reported -> solid green bar
                self.vuln_prog.configure(mode="determinate",
                                         style="VulnDone.Horizontal.TProgressbar",
                                         maximum=total, value=total)
            else:
                # stopped early -> back to neutral determinate bar
                self.vuln_prog.configure(mode="determinate",
                                         style="Horizontal.TProgressbar",
                                         value=len(self.vuln_results))
        except tk.TclError:
            pass
        ok = sum(1 for _h, r, e in self.vuln_results
                 if not e and r and r.get("compliant"))
        bad = sum(1 for _h, r, e in self.vuln_results
                  if not e and r and not r.get("compliant"))
        errs = sum(1 for _h, _r, e in self.vuln_results if e)
        stopped = self._vuln_stop.is_set()
        base = self.T("vuln_summary").format(n=len(self.vuln_results),
                                             ok=ok, bad=bad, err=errs)
        self.status.set(base + (" " + self.T("vuln_stopped") if stopped else ""))

    def copy_vuln(self):
        if not self.vuln_proposal.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self.vuln_proposal)
        self._toast(self.T("copied"))

    def clear_vuln(self):
        self.vuln_results = []
        self.vuln_proposal = ""
        self._set_vuln_text("")
        self._set_vuln_prop("")
        try:
            self.vuln_prog.stop()
            self.vuln_prog.configure(mode="determinate",
                                     style="Horizontal.TProgressbar", value=0)
        except tk.TclError:
            pass

    # ---------- vulnerabilities: apply the fix (one open session per device)
    def start_vuln_apply(self):
        """Apply proposals with a safe protocol per device: fresh re-check
        -> configure -> verify in running-config -> operator confirmation
        (session held open) -> write memory, else rollback."""
        if self._vuln_fetching or self._vuln_applying:
            return
        if not self._require_unlocked():
            return
        cands = [(h, r) for h, r, e in self.vuln_results
                 if not e and r and vuln_telnet.needs_apply(r)]
        if not cands:
            messagebox.showinfo("ACL", self.T("vuln_apply_none"))
            return
        hosts = [h for h, _r in cands]
        shown = ", ".join(hosts[:10]) + (", ..." if len(hosts) > 10 else "")
        if not messagebox.askyesno(
                "ACL", self.T("vuln_apply_overview").format(n=len(hosts),
                                                            hosts=shown)):
            return
        devs = []
        for h in hosts:
            d = self._lookup_device(h)
            if d is not None:
                devs.append(d)
        if not devs:
            return
        self._vuln_applying = True
        self._vuln_stop.clear()
        self.btn_vuln_check.configure(state="disabled")
        self.btn_vuln_apply.configure(state="disabled")
        self.btn_vuln_stop.configure(state="normal")
        self.vuln_prog.configure(mode="indeterminate",
                                 style="VulnWork.Horizontal.TProgressbar")
        self.vuln_prog.start(12)
        self.status.set(self.T("vuln_apply_status").format(n=len(devs)))
        threading.Thread(target=self._apply_worker, args=(devs,),
                         daemon=True).start()

    @staticmethod
    def _analyze_session(sess) -> dict:
        out = {cmd: sess.exec(cmd, 2.5) for cmd in vuln_telnet.TELNET_COMMANDS}
        return vuln_telnet.analyze_telnet(
            out[vuln_telnet.TELNET_COMMANDS[0]],
            out[vuln_telnet.TELNET_COMMANDS[2]],
            out[vuln_telnet.TELNET_COMMANDS[1]])

    def _try_rollback(self, sess, changed: list[dict]) -> bool:
        """Restore original transports; True only if verified in config."""
        if not changed or not sess.alive():
            return False
        try:
            sess.configure(vuln_telnet.build_rollback_commands(changed))
            res = self._analyze_session(sess)
        except Exception:
            return False
        want = {(e.get("range") or ""): (e.get("transport") or "")
                for e in changed}
        got = {(e.get("range") or ""): (e.get("transport") or "")
               for e in res.get("vty", [])}
        return bool(want) and all(got.get(r) == t for r, t in want.items())

    def _put_apply(self, lines: list[tuple[str, str | None]]):
        self.msg_queue.put(("vuln_apply_chunk", lines))

    def _apply_worker(self, devs: list[dict]):
        ok = rb = fail = skip = 0
        for d in devs:
            if self._vuln_stop.is_set():
                self._put_apply([(self.T("vuln_apply_stopped") + "\n",
                                  "vuln_warn")])
                break
            host = d.get("host", "?")
            hdr = [(self.T("device_hdr").format(host=host) + "\n", None)]
            sess = cisco_ssh.ConfigSession(
                host, d["username"], d.get("password", ""),
                d.get("enable") or None, int(d.get("port", 22)),
                debug_log=self._ssh_debug_log())
            changed: list[dict] = []
            try:
                self._put_apply(
                    hdr + [(self.T("vuln_st_recheck").format(host=host)
                            + "\n", None)])
                sess.open()
                sess.ensure_privileged()
                res = self._analyze_session(sess)
                if res.get("compliant"):
                    self._put_apply([(self.T("vuln_apply_already") + "\n",
                                      "vuln_ok")])
                    skip += 1
                    continue
                if res.get("ssh_enabled") is False:
                    self._put_apply([(self.T("vuln_apply_nossh") + "\n",
                                      "vuln_warn")])
                    skip += 1
                    continue
                targets = vuln_telnet.apply_targets(res)
                if not targets:
                    self._put_apply([(self.T("vuln_apply_manual") + "\n",
                                      "vuln_warn")])
                    skip += 1
                    continue
                changed = [dict(e) for e in targets]
                # Pre-flight: a FRESH login must work before we touch
                # transport (the main session alone does not prove that a
                # new login with these credentials succeeds right now).
                self._put_apply(
                    [(self.T("vuln_st_preflight").format(host=host) + "\n",
                      None)])
                try:
                    cisco_ssh.run_commands(
                        host, d["username"], d.get("password", ""),
                        d.get("enable") or None, int(d.get("port", 22)),
                        timeout=15, commands=["show clock"],
                        debug_log=self._ssh_debug_log())
                except Exception as e:
                    self._put_apply(
                        [(self.T("vuln_preflight_fail").format(err=e) + "\n",
                          "vuln_fail")])
                    skip += 1
                    continue
                self._put_apply([(self.T("vuln_preflight_ok") + "\n",
                                  "vuln_ok")])
                self._put_apply(
                    [(self.T("vuln_st_applying").format(host=host) + "\n",
                      None)])
                sess.configure(vuln_telnet.build_fix_commands(targets))
                res2 = self._analyze_session(sess)
                if not res2.get("compliant"):
                    detail = (self.T("vuln_rb_ok") if self._try_rollback(
                        sess, changed) else self.T("vuln_rb_bad"))
                    self._put_apply(
                        [(self.T("vuln_apply_postfail").format(detail=detail)
                          + "\n", "vuln_fail")])
                    fail += 1
                    continue
                # Fix is in running-config (NOT saved). First OUR OWN test:
                # a brand-new SSH login must work, or the change is rolled
                # back immediately without bothering the operator.
                self._put_apply(
                    [(self.T("vuln_st_posttest").format(host=host) + "\n",
                      None)])
                try:
                    cisco_ssh.run_commands(
                        host, d["username"], d.get("password", ""),
                        d.get("enable") or None, int(d.get("port", 22)),
                        timeout=15, commands=["show clock"],
                        debug_log=self._ssh_debug_log())
                except Exception as e:
                    detail = (self.T("vuln_rb_ok") if self._try_rollback(
                        sess, changed) else self.T("vuln_rb_bad"))
                    self._put_apply(
                        [(self.T("vuln_posttest_fail").format(
                            err=e, detail=detail) + "\n", "vuln_fail")])
                    fail += 1
                    continue
                self._put_apply([(self.T("vuln_posttest_ok") + "\n",
                                  "vuln_ok")])
                # New logins proven working. Ask the operator to verify from
                # a NEW session; hold this one open meanwhile.
                box: dict = {}
                ev = threading.Event()
                self.msg_queue.put((
                    "vuln_apply_confirm",
                    (host, self.T("vuln_verify_msg").format(host=host),
                     box, ev)))
                alive = True
                while not ev.is_set():
                    if self._vuln_stop.is_set():
                        box["ok"] = False
                        ev.set()
                        break
                    if not sess.alive():
                        alive = False
                        break
                    try:
                        sess.exec("", 1.0)
                    except Exception:
                        alive = False
                        break
                    ev.wait(30)
                if not alive:
                    self._put_apply(
                        [(self.T("vuln_apply_sesslost").format(host=host)
                          + "\n", "vuln_fail")])
                    fail += 1
                    continue
                if box.get("ok"):
                    wout = sess.exec("write memory", 8.0)
                    if re.search(r"^%|command rejected", wout,
                                 re.M | re.IGNORECASE):
                        raise RuntimeError(f"write memory failed: {wout}")
                    last = [ln for ln in wout.splitlines() if ln.strip()]
                    self._put_apply(
                        [(self.T("vuln_apply_saved").format(
                            line=last[-1] if last else "OK") + "\n",
                          "vuln_ok")])
                    ok += 1
                else:
                    detail = (self.T("vuln_rb_ok") if self._try_rollback(
                        sess, changed) else self.T("vuln_rb_bad"))
                    tag = ("vuln_warn" if detail == self.T("vuln_rb_ok")
                           else "vuln_fail")
                    self._put_apply(
                        [(self.T("vuln_apply_rb_user").format(detail=detail)
                          + "\n", tag)])
                    rb += 1
            except cisco_ssh.ConfigFailed as e:
                detail = (self.T("vuln_rb_ok") if self._try_rollback(
                    sess, changed) else self.T("vuln_rb_bad"))
                self._put_apply(
                    [(self.T("vuln_apply_error").format(err=e) + "\n",
                      "vuln_fail"),
                     (self.T("vuln_apply_postfail").format(detail=detail)
                      + "\n", "vuln_fail")])
                fail += 1
            except Exception as e:
                if changed:
                    self._try_rollback(sess, changed)
                self._put_apply([(self.T("vuln_apply_error").format(err=e)
                                  + "\n", "vuln_fail")])
                fail += 1
            finally:
                sess.close()
        self.msg_queue.put(("vuln_apply_done",
                            {"ok": ok, "rb": rb, "fail": fail,
                             "skip": skip}))

    def _finish_apply_done(self, stats: dict):
        self._vuln_applying = False
        try:
            self.btn_vuln_check.configure(state="normal")
            self.btn_vuln_apply.configure(state="normal")
            self.btn_vuln_stop.configure(state="disabled")
            self.vuln_prog.stop()
            self.vuln_prog.configure(mode="determinate",
                                     style="VulnDone.Horizontal.TProgressbar",
                                     value=self.vuln_prog.cget("maximum"))
        except tk.TclError:
            pass
        self.status.set(self.T("vuln_apply_done").format(
            ok=stats.get("ok", 0), rb=stats.get("rb", 0),
            fail=stats.get("fail", 0), skip=stats.get("skip", 0)))

    def _toggle_audit_at(self, idx: int):
        """Flip the audit flag of one device (devices-tab checkbox column)."""
        if 0 <= idx < len(self.devices):
            d = self.devices[idx]
            d["audit"] = not d.get("audit", True)
            self.persist_store()
            self.refresh_tree()

    def _on_dev_click(self, event):
        """Single click on the ✓ column toggles audit marking for that row.

        Uses the checkbox cell geometry (bbox), not identify_column(),
        which mis-reports columns on some Tk builds.
        """
        try:
            if self.tree.identify("region", event.x, event.y) != "cell":
                return
            row = self.tree.identify_row(event.y)
            if not row:
                return
            bb = self.tree.bbox(row, "audit")
            if not bb:
                return
            if bb[0] <= event.x <= bb[0] + bb[2]:
                self._toggle_audit_at(self.tree.index(row))
        except tk.TclError:
            pass

    def _on_dev_space(self, _event):
        """Space toggles audit marking for all currently selected rows."""
        sel = self.tree.selection()
        if not sel:
            return "break"
        idxs = sorted(self.tree.index(r) for r in sel)
        vals = [bool(self.devices[i].get("audit", True)) for i in idxs
                if 0 <= i < len(self.devices)]
        target = not all(vals) if vals else True
        for i in idxs:
            if 0 <= i < len(self.devices):
                self.devices[i]["audit"] = target
        self.persist_store()
        self.refresh_tree()
        # re-select the same rows (refresh rebuilds the tree)
        try:
            kids = self.tree.get_children()
            for i in idxs:
                if i < len(kids):
                    self.tree.selection_add(kids[i])
        except tk.TclError:
            pass
        return "break"

    def toggle_all_audit(self):
        """Header ✓ click: mark all when any is unmarked, else clear all."""
        target = not all(d.get("audit", True) for d in self.devices)
        for d in self.devices:
            d["audit"] = target
        self.persist_store()
        self.refresh_tree()

    # ---------- devices tab actions ----------
    def _selected_device_idx(self) -> int | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.tree.index(sel[0])

    def add_device(self):
        if not self._require_unlocked():
            return
        dlg = DeviceDialog(self, self.lang, self.T("dlg_add_title"))
        self.wait_window(dlg)
        if dlg.result:
            self.devices.append(dlg.result)
            self.persist_store()
            self.refresh_tree()

    def edit_device(self):
        if not self._require_unlocked():
            return
        idx = self._selected_device_idx()
        if idx is None:
            return
        dlg = DeviceDialog(self, self.lang, self.T("dlg_edit_title"), self.devices[idx])
        self.wait_window(dlg)
        if dlg.result:
            dlg.result["audit"] = self.devices[idx].get("audit", True)
            self.devices[idx] = dlg.result
            self.persist_store()
            self.refresh_tree()

    def del_device(self):
        if not self._require_unlocked():
            return
        idx = self._selected_device_idx()
        if idx is None:
            return
        host = self.devices[idx].get("host", "")
        if messagebox.askyesno("ACL", self.T("confirm_del").format(host=host)):
            del self.devices[idx]
            self.persist_store()
            self.refresh_tree()

    def dup_device(self):
        """Duplicate credentials: same login data, empty host/hostname to fill in."""
        if not self._require_unlocked():
            return
        idx = self._selected_device_idx()
        if idx is None:
            return
        src = dict(self.devices[idx])
        src["host"] = ""
        src["hostname"] = ""
        dlg = DeviceDialog(self, self.lang, self.T("dlg_dup_title"), src)
        self.wait_window(dlg)
        if dlg.result:
            self.devices.append(dlg.result)
            self.persist_store()
            self.refresh_tree()

    def test_device(self):
        if not self._require_unlocked():
            return
        idx = self._selected_device_idx()
        if idx is None:
            return
        d = self.devices[idx]
        self.status.set(self.T("status_searching").format(n=1))
        threading.Thread(target=self._test_worker, args=(dict(d),), daemon=True).start()

    def _test_worker(self, d: dict):
        try:
            cfg = cisco_ssh.fetch_config(d["host"], d["username"], d.get("password", ""),
                                         d.get("enable") or None, int(d.get("port", 22)),
                                         debug_log=self._ssh_debug_log())
            acls = acl_parser.parse_running_config(cfg)
            self.msg_queue.put(("info", self.T("conn_ok").format(host=d["host"], n=len(acls))))
        except Exception as e:
            self.msg_queue.put(("info", self.T("conn_fail").format(host=d["host"], err=e)))

    def import_devices(self):
        """Import devices from mRemoteNG confCons.xml or a generic XML file.

        One username/password/enable from the dialog covers the whole
        import; hosts already on the list are skipped (never duplicated).
        """
        import os as _os

        if not self._require_unlocked():
            return
        path = filedialog.askopenfilename(
            title=self.T("import_file_title"),
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                text = f.read()
        except Exception as e:
            messagebox.showerror("ACL", self.T("import_bad").format(err=e))
            return
        try:
            fmt = device_import.detect_format(text)
        except ValueError as e:
            messagebox.showerror("ACL", self.T("import_bad").format(err=e))
            return
        try:
            # full-file-encrypted mRemoteNG with a custom password cannot be
            # counted yet (the password comes from the dialog) -> show "?"
            count = device_import.count_entries(text, fmt)
        except ValueError:
            count = -1
        dlg = ImportDialog(self, self.lang, _os.path.basename(path), fmt,
                           count)
        self.wait_window(dlg)
        if not dlg.result:
            return
        cred = dlg.result
        try:
            if fmt == "mremoteng":
                imported, info = device_import.parse_mremoteng(
                    text, cred["master"])
            else:
                imported, info = device_import.parse_generic(text)
        except ValueError as e:
            messagebox.showerror("ACL", self.T("import_bad").format(err=e))
            return
        backup = self._backup_store()
        merged = device_import.merge_devices(
            self.devices, imported, cred["username"], cred["password"],
            cred["enable"], cred["overwrite"])
        self.devices = merged["devices"]
        self.persist_store()
        self.refresh_tree()
        msg = self.T("import_summary").format(
            added=merged["added"], dup=merged["duplicates"],
            inv=merged["invalid"] + info.get("invalid", 0),
            nssh=info.get("skipped_non_ssh", 0),
            dec=info.get("decrypted", 0), frm=merged["from_form"])
        if backup:
            msg += "\n" + self.T("import_backup").format(path=backup)
        if merged["dup_hosts"]:
            shown = ", ".join(merged["dup_hosts"][:8])
            if merged["duplicates"] > 8:
                shown += ", ..."
            msg += "\n" + self.T("import_dups").format(hosts=shown)
        messagebox.showinfo("ACL", msg)

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
    def fetch_vlan_subnets(self):
        if self._vlan_fetching:
            return
        if not self._require_unlocked():
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        dev = self._lookup_device(self.sub_dev_var.get().strip())
        if dev is None:
            messagebox.showwarning("ACL", self.T("audit_need_dev"))
            return
        self._vlan_fetching = True
        self.btn_sub_fetch.configure(state="disabled")
        self.sub_prog.pack(side="left", padx=(14, 0))
        self.sub_prog.start(12)
        self.status.set(self.T("vlan_fetching").format(host=dev["host"]))
        threading.Thread(target=self._vlan_worker, args=(dev,),
                         daemon=True).start()

    def _vlan_worker(self, dev: dict):
        try:
            out = cisco_ssh.run_commands(
                dev["host"], dev["username"], dev.get("password", ""),
                dev.get("enable") or None, int(dev.get("port", 22)),
                timeout=15,
                commands=["show running-config | section ^interface"],
                debug_log=self._ssh_debug_log())
            rows = acl_parser.parse_vlan_acls(
                out.get("show running-config | section ^interface", ""))
            self.msg_queue.put(("vlan_list", (dev["host"], rows)))
        except Exception as e:
            self.msg_queue.put(("vlan_error", (dev["host"], str(e))))

    def _finish_vlan_fetch(self, host: str, rows: list):
        self._vlan_fetching = False
        self.btn_sub_fetch.configure(state="normal")
        try:
            self.sub_prog.stop()
        except tk.TclError:
            pass
        self.sub_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        added, updated, skipped = 0, 0, 0
        for row in rows:
            subnet = row.get("subnet", "")
            if not subnet or not (row.get("acl_in") or row.get("acl_out")):
                skipped += 1
                continue
            cur = next((s for s in self.subnets if s.get("subnet") == subnet),
                       None)
            if cur is None:
                self.subnets.append({"subnet": subnet,
                                     "acl_in": row.get("acl_in", ""),
                                     "acl_out": row.get("acl_out", "")})
                added += 1
                continue
            changed = False
            for key in ("acl_in", "acl_out"):
                if row.get(key) and cur.get(key) != row[key]:
                    cur[key] = row[key]
                    changed = True
            if changed:
                updated += 1
        if added or updated:
            self.persist_store()
        self.refresh_subnets()
        messagebox.showinfo(
            "ACL", self.T("vlan_imported").format(host=host, added=added,
                                                  updated=updated,
                                                  skipped=skipped))

    def _selected_subnet_idx(self) -> int | None:
        sel = self.subtree.selection()
        if not sel:
            return None
        return self.subtree.index(sel[0])

    def add_subnet(self):
        if not self._require_unlocked():
            return
        dlg = SubnetDialog(self, self.lang, self.T("dlg_subnet_add"))
        self.wait_window(dlg)
        if dlg.result:
            if any(s.get("subnet") == dlg.result["subnet"] for s in self.subnets):
                messagebox.showwarning("ACL", self.T("dup_subnet"))
                return
            self.subnets.append(dlg.result)
            self.persist_store()
            self.refresh_subnets()

    def edit_subnet(self):
        if not self._require_unlocked():
            return
        idx = self._selected_subnet_idx()
        if idx is None:
            return
        dlg = SubnetDialog(self, self.lang, self.T("dlg_subnet_edit"), self.subnets[idx])
        self.wait_window(dlg)
        if dlg.result:
            others = [s.get("subnet") for n, s in enumerate(self.subnets) if n != idx]
            if dlg.result["subnet"] in others:
                messagebox.showwarning("ACL", self.T("dup_subnet"))
                return
            self.subnets[idx] = dlg.result
            self.persist_store()
            self.refresh_subnets()

    def del_subnet(self):
        if not self._require_unlocked():
            return
        idx = self._selected_subnet_idx()
        if idx is None:
            return
        subnet = self.subnets[idx].get("subnet", "")
        if messagebox.askyesno("ACL", self.T("confirm_del_subnet").format(subnet=subnet)):
            del self.subnets[idx]
            self.persist_store()
            self.refresh_subnets()

    # ---------- generator tab ----------
    def _set_gen_text(self, content: str):
        self.txt_gen.configure(state="normal")
        self.txt_gen.delete("1.0", tk.END)
        self.txt_gen.insert("1.0", content)
        self.txt_gen.configure(state="disabled")

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

    def clear_gen(self):
        self.gen_script = ""
        self._set_gen_text("")

    def copy_gen(self):
        if not self.gen_script.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self.gen_script)
        self._toast(self.T("copied"))

    def generate_acl(self):
        pc = self.ent_gen_pc.get().strip()
        if not self._valid_ip(pc):
            messagebox.showwarning("ACL", self.T("status_bad_ip"))
            return
        raw_lines = self.txt_cams.get("1.0", tk.END).splitlines()
        cams: list[str] = []
        bad: list[str] = []
        for line in raw_lines:
            v = line.strip()
            if not v:
                continue
            if self._valid_ip(v):
                if v not in cams:
                    cams.append(v)
            else:
                bad.append(v)
        if bad:
            messagebox.showwarning(
                "ACL", self.T("gen_bad_cams").format(lines=", ".join(bad[:8])))
            return
        if not cams:
            messagebox.showwarning("ACL", self.T("gen_need_cams"))
            return
        if not (self.gen_in_var.get() or self.gen_out_var.get()):
            messagebox.showwarning("ACL", self.T("gen_need_dir"))
            return
        do_in, do_out = self.gen_in_var.get(), self.gen_out_var.get()
        in_typed = self.ent_gen_acl_in.get().strip()
        out_typed = self.ent_gen_acl_out.get().strip()
        owner = self.ent_gen_owner.get().strip()
        groups: list[tuple[str, str, str, list[str]]] = []
        if in_typed or out_typed:
            # manual mode: typed names apply to all cameras
            if do_in and not in_typed:
                messagebox.showwarning("ACL", self.T("gen_no_acl_in"))
                return
            if do_out and not out_typed:
                messagebox.showwarning("ACL", self.T("gen_no_acl_out"))
                return
            groups.append((in_typed, out_typed, self.T("gen_src_manual"), cams))
        else:
            # auto mode: group cameras by their own subnet mapping
            by_key: dict[tuple[str, str, str], list[str]] = {}
            order: list[tuple[str, str, str]] = []
            unmapped: list[str] = []
            for cam in cams:
                hit = acl_parser.resolve_acl_for_ip(self.subnets, cam)
                if not hit or not (hit[0] or hit[1]):
                    unmapped.append(cam)
                    continue
                key = (hit[0], hit[1], hit[2])
                if key not in by_key:
                    by_key[key] = []
                    order.append(key)
                by_key[key].append(cam)
            if unmapped:
                messagebox.showwarning(
                    "ACL", self.T("gen_no_cam_acl").format(ips=", ".join(unmapped[:8])))
                return
            for acl_in, acl_out, subnet in order:
                if do_in and not acl_in:
                    messagebox.showwarning("ACL", self.T("gen_no_acl_in"))
                    return
                if do_out and not acl_out:
                    messagebox.showwarning("ACL", self.T("gen_no_acl_out"))
                    return
                note = self.T("gen_src_subnet").format(subnet=subnet)
                groups.append((acl_in, acl_out, note, by_key[(acl_in, acl_out, subnet)]))
        dev_host = self.gen_dev_var.get().strip()
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        if not dev_host:
            messagebox.showwarning("ACL", self.T("gen_need_dev"))
            return
        dev = self._lookup_device(dev_host)
        if dev is None:
            messagebox.showwarning("ACL", self.T("gen_need_dev"))
            return
        dev_host = dev["host"]
        # collapse cameras now (pure, fast); fetch seq numbers in worker
        agg = self.gen_agg_var.get()
        grouped: list[tuple] = []
        for acl_in, acl_out, note, cam_list in groups:
            if agg:
                nets = acl_parser.collapse_ips(cam_list)
            else:
                nets = [ipaddress.ip_network(c + "/32") for c in cam_list]
            grouped.append((acl_in, acl_out, note, nets))
        fetch_key = (dev_host,
                     tuple((i, o, tuple(str(n) for n in nets)) for i, o, _n, nets in grouped),
                     do_in, do_out)
        if self.generating:
            return
        self.generating = True
        self.btn_gen.configure(state="disabled")
        self.gen_prog.pack(side="left", padx=(14, 0))
        self.gen_prog.start(12)
        self.status.set(self.T("gen_fetching").format(host=dev_host))
        reuse_taken = self._gen_taken if fetch_key == self._gen_fetch_key else None
        server = self.dhcp_var.get().strip()
        group = self.gen_group_var.get()
        threading.Thread(target=self._gen_worker,
                         args=(pc, dev, grouped, do_in, do_out, fetch_key,
                               reuse_taken, server, owner, group),
                         daemon=True).start()

    def _gen_worker(self, pc, dev, grouped, do_in, do_out, fetch_key,
                    reuse_taken, server, owner="", group=True):
        dhcp_status, dhcp_detail = (dhcp_check.check_reservation(server, pc)
                                    if server else ("idle", ""))
        taken = reuse_taken
        aces: dict[str, list[tuple[int, str, bool]]] | None = None
        err = None
        if taken is None:
            try:
                cfg = cisco_ssh.fetch_config(
                    dev["host"], dev["username"], dev.get("password", ""),
                    dev.get("enable") or None, int(dev.get("port", 22)),
                    debug_log=self._ssh_debug_log())
                acls = acl_parser.parse_running_config(cfg)
                taken = {}
                aces = {}
                for name, entries in acls.items():
                    found = acl_parser.find_pc_entries(entries, pc, owner)
                    if found:
                        aces[name] = found
                for acl_in, acl_out, _note, _nets in grouped:
                    for acl in (acl_in, acl_out):
                        if acl and acl not in taken:
                            entries = acls.get(acl, [])
                            if not entries:
                                for name, aces_list in acls.items():
                                    if name.lower() == acl.lower():
                                        entries = aces_list
                                        break
                            taken[acl] = acl_parser.extract_seq_numbers(entries)
            except Exception as e:
                if "Empty response" in str(e):
                    taken = {}  # reachable, just no ACL text found
                    aces = aces or {}
                else:
                    err = str(e)
        self.msg_queue.put(("gen_done", (pc, dev["host"], grouped, do_in, do_out,
                                         fetch_key, taken, err,
                                         dhcp_status, dhcp_detail, owner,
                                         aces, group)))

    @staticmethod
    def _involved_acls(grouped, do_in, do_out) -> list:
        out = []
        for acl_in, acl_out, _note, _nets in grouped:
            if do_in and acl_in and acl_in not in out:
                out.append(acl_in)
            if do_out and acl_out and acl_out not in out:
                out.append(acl_out)
        return out

    def _update_starts_frame(self, involved: list, taken: dict):
        for child in self.starts_fr.winfo_children():
            child.destroy()
        keep = {}
        for acl in involved:
            keep[acl] = self._gen_start_vars.get(acl) or tk.StringVar(value="")
        self._gen_start_vars = keep
        auto = {}
        for acl in involved:
            used = taken.get(acl, set())
            auto[acl] = (max(used) + 1) if used else 10
            cur = self._gen_start_vars[acl].get().strip()
            if not cur or cur == str(self._gen_auto.get(acl, "")):
                self._gen_start_vars[acl].set(str(auto[acl]))
            row = ttk.Frame(self.starts_fr)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=acl, font=("Consolas", 9), width=34).pack(side="left")
            ttk.Entry(row, textvariable=self._gen_start_vars[acl], width=8).pack(side="left")
        self._gen_auto = auto

    def _read_gen_starts(self, involved: list) -> dict | None:
        starts = {}
        for acl in involved:
            try:
                n = int(self._gen_start_vars[acl].get().strip())
                if n < 1:
                    raise ValueError
                starts[acl] = n
            except (ValueError, KeyError):
                messagebox.showwarning("ACL", self.T("gen_bad_seq"))
                return None
        return starts

    def _set_dhcp_indicator(self, ip: str, status: str, detail: str):
        if status == "ok":
            txt = self.T("dhcp_ok") + (f" ({detail})" if detail else "")
            self.lbl_gen_dhcp.configure(text=txt, foreground="green")
        elif status == "none":
            self.lbl_gen_dhcp.configure(text=self.T("dhcp_none").format(ip=ip),
                                        foreground="orange")
        elif status == "idle":
            self.lbl_gen_dhcp.configure(text=self.T("dhcp_noserver"), foreground="gray")
        else:
            self.lbl_gen_dhcp.configure(
                text=self.T("dhcp_unknown").format(reason=detail or "?"),
                foreground="gray")

    def _dhcp_check_async(self):
        ip = self.ent_gen_pc.get().strip()
        if not self._valid_ip(ip):
            return
        server = self.dhcp_var.get().strip()
        if not server:
            self._set_dhcp_indicator(ip, "idle", "")
            return
        threading.Thread(target=self._dhcp_worker, args=(ip, server), daemon=True).start()

    def _dhcp_worker(self, ip: str, server: str):
        status, detail = dhcp_check.check_reservation(server, ip)
        self.after(0, lambda: (self._set_dhcp_indicator(ip, status, detail)
                               if self.ent_gen_pc.get().strip() == ip else None))

    def _refresh_gen_devices(self):
        labels = [self.dev_label(d) for d in self.devices if d.get("host")]
        self.combo_gen_dev.configure(values=labels)
        if self.gen_dev_var.get() not in labels:
            cur = self._lookup_device(self.gen_dev_var.get().strip())
            self.gen_dev_var.set(self.dev_label(cur) if cur else (labels[0] if labels else ""))
        self.combo_track_dev.configure(values=labels)
        if self.track_dev_var.get() not in labels:
            cur = self._lookup_device(self.track_dev_var.get().strip())
            self.track_dev_var.set(self.dev_label(cur) if cur else (labels[0] if labels else ""))
        self.combo_audit_dev.configure(values=labels)
        if self.audit_dev_var.get() not in labels:
            cur = self._lookup_device(self.audit_dev_var.get().strip())
            self.audit_dev_var.set(self.dev_label(cur) if cur else (labels[0] if labels else ""))
        self.combo_sub_dev.configure(values=labels)
        if self.sub_dev_var.get() not in labels:
            cur = self._lookup_device(self.sub_dev_var.get().strip())
            self.sub_dev_var.set(self.dev_label(cur) if cur else (labels[0] if labels else ""))
        self._refresh_vuln_devices()

    # ---------- IP tracking tab (ARP -> MAC -> port -> CDP) ----------
    def _set_track_text(self, content: str):
        self.txt_track.configure(state="normal")
        self.txt_track.delete("1.0", tk.END)
        self.txt_track.insert("1.0", content)
        self.txt_track.configure(state="disabled")

    def _append_track_text(self, chunk: str):
        self.txt_track.configure(state="normal")
        self.txt_track.insert(tk.END, chunk)
        self.txt_track.see(tk.END)
        self.txt_track.configure(state="disabled")

    def stop_track(self):
        self._track_stop.set()

    def clear_track(self):
        self._track_cont = None
        self.btn_track_cont.pack_forget()
        self.prog_track.configure(value=0)
        self._set_track_text("")

    @staticmethod
    def dev_label(d: dict) -> str:
        """Dropdown display: 'hostname host' when hostname set, else plain host."""
        host = d.get("host", "")
        hn = (d.get("hostname") or "").strip()
        return f"{hn} {host}".strip() if hn else host

    def _lookup_device(self, selection: str) -> dict | None:
        """Find device by dropdown label ('hostname host') or plain host."""
        s = (selection or "").strip()
        if not s:
            return None
        return next((dict(d) for d in self.devices
                     if d.get("host") == s or self.dev_label(d) == s), None)

    def trace_ip(self):
        if self.tracking:
            return
        if not self._require_unlocked():
            return
        ip = self.ent_track_ip.get().strip()
        if not self._valid_ip(ip):
            messagebox.showwarning("ACL", self.T("status_bad_ip"))
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        dev = self._lookup_device(self.track_dev_var.get().strip())
        if dev is None:
            messagebox.showwarning("ACL", self.T("track_need_dev"))
            return
        self._start_trace(ip, dev)

    def _start_trace(self, ip: str, dev: dict):
        """Begin a trace with an explicit device dict (combo or Continue)."""
        self._track_cont = None
        self.btn_track_cont.pack_forget()
        self._set_track_text("")
        self.tracking = True
        self._track_stop.clear()
        self.btn_track.configure(state="disabled")
        self.btn_track_stop.configure(state="normal")
        auto = self.track_parent_var.get()
        if auto:
            self.prog_track.configure(mode="indeterminate")
            self.prog_track.start(12)
        else:
            try:
                self.prog_track.stop()
            except tk.TclError:
                pass
            self.prog_track.configure(mode="determinate", maximum=3, value=0)
        self.status.set(self.T("track_working").format(ip=ip, host=dev["host"]))
        snapshot = [dict(d) for d in self.devices]
        threading.Thread(target=self._track_worker,
                         args=(ip, dev, snapshot, self.track_parent_var.get(),
                               self._ssh_debug_log()), daemon=True).start()

    def continue_track(self):
        if self._track_cont and not self.tracking:
            ip = self.ent_track_ip.get().strip()
            if not self._valid_ip(ip):
                messagebox.showwarning("ACL", self.T("status_bad_ip"))
                return
            self._start_trace(ip, dict(self._track_cont))

    def _track_run(self, dev: dict, cmd: str, debug_log) -> str:
        out = cisco_ssh.run_commands(
            dev["host"], dev["username"], dev.get("password", ""),
            dev.get("enable") or None, int(dev.get("port", 22)),
            timeout=15, commands=[cmd], debug_log=debug_log)
        return out.get(cmd, "")

    def _track_worker(self, ip: str, dev: dict, devices: list,
                      use_parent: bool, debug_log, max_hops: int = 10):
        auto = use_parent  # toggle ON = chain automatically, no button
        stop = self._track_stop
        visited: set = set()
        cur = dict(dev)
        hop = 0
        while True:
            if stop.is_set():
                self.msg_queue.put(("track_chunk", (None, self.T("track_stopped") + "\n")))
                break
            host = cur.get("host", "?")
            if host in visited:
                self.msg_queue.put(("track_chunk",
                                    (host, self.T("track_loop").format(host=host) + "\n")))
                break
            if hop >= max_hops:
                self.msg_queue.put(("track_chunk",
                                    (host, self.T("track_max_hops").format(n=max_hops) + "\n")))
                break
            visited.add(host)
            hop += 1
            lines = [f"=== {host} : {ip} ==="]
            cont: dict | None = None
            try:
                arp_out = self._track_run(cur, f"show ip arp {ip}", debug_log)
                self.msg_queue.put(("track_prog", 1))
                arp = track.parse_arp(arp_out, ip)
                mac, origin = track.resolve_mac(arp, cur.get("mac", ""))
                if mac is None:
                    if arp and arp.get("incomplete"):
                        lines.append(self.T("track_arp_incomplete").format(ip=ip))
                    else:
                        lines.append(self.T("track_arp_none").format(ip=ip, host=host))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                if origin == "fresh":
                    lines.append(f"ARP: {ip} -> {mac} ({arp.get('interface', '')})".rstrip())
                else:
                    lines.append(self.T("track_mac_parent").format(host=host, mac=mac))

                mac_out = self._track_run(cur, f"show mac address-table address {mac}",
                                          debug_log)
                self.msg_queue.put(("track_prog", 2))
                entries = track.parse_mac_table(mac_out, mac)
                if not entries:
                    lines.append(self.T("track_mac_none").format(mac=mac, host=host))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                port = entries[0]["port"]
                for e in entries:
                    vlan = f"VLAN {e['vlan']}, " if e.get("vlan") else ""
                    lines.append(f"MAC: {mac} -> {e['port']} ({vlan}{e.get('type', '')})".rstrip())

                cdp_out = self._track_run(cur, "show cdp neighbors detail", debug_log)
                self.msg_queue.put(("track_prog", 3))
                nb = track.find_cdp_on_port(track.parse_cdp_detail(cdp_out), port)
                if not nb:
                    lines.append(self.T("track_cdp_none").format(port=port, host=host))
                else:
                    plat = f" [{nb['platform']}]" if nb.get("platform") else ""
                    lines.append(f"CDP: {port} -> {nb['device']} ({nb.get('ip', '?')})"
                                 f" | remote {nb.get('remote', '?')}{plat}")
                    listed = track.match_known_device(devices, nb)
                    if listed is not None:
                        cont = dict(listed)
                        if use_parent:
                            # log in with the parent (current) device credentials
                            for k in ("username", "password", "enable", "port"):
                                cont[k] = cur.get(k, cont.get(k))
                    elif use_parent and nb.get("ip"):
                        # neighbor not in the list: reach it with parent creds
                        cont = {"hostname": nb.get("device", ""), "host": nb["ip"],
                                "username": cur.get("username", ""),
                                "password": cur.get("password", ""),
                                "enable": cur.get("enable", ""),
                                "port": cur.get("port", 22)}
                    if cont is not None:
                        cont["mac"] = mac  # carry over for the next hop
            except Exception as e:
                lines.append(f"*** ERROR on {host}: {e} ***")
                self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                break
            else:
                self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                if cont is None or not auto:
                    self.msg_queue.put(("track_done", cont if not auto else None))
                    break
                cur = cont
        if auto:
            self.msg_queue.put(("track_done", None))

    # ---------- search tab ----------
    def _set_text(self, content: str):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", tk.END)
        self.txt.insert("1.0", content)
        self.txt.configure(state="disabled")

    def _append_text(self, chunk: str):
        self.txt.configure(state="normal")
        self.txt.insert(tk.END, chunk)
        self.txt.see(tk.END)
        self.txt.configure(state="disabled")

    def clear_results(self):
        self.last_results = []
        self.copy_host_var.set("")
        self.copy_combo.configure(values=[])
        self.prog.configure(value=0)
        self._set_text("")

    def _refresh_copy_combo(self):
        """List only devices with actual hits; keep selection if still valid."""
        hosts = [h for h, f, e in self.last_results if f and not e]
        labels = [self._copy_label(h) for h in hosts]
        self.copy_combo.configure(values=labels)
        if self.copy_host_var.get() not in labels:
            self.copy_host_var.set(labels[0] if labels else "")

    def _copy_label(self, host: str) -> str:
        dev = self._lookup_device(host)
        return self.dev_label(dev) if dev else host

    def copy_results(self):
        # Copy ONLY the selected device's paste-safe CLI lines
        # (device context as "!" comments, ACL headers, ACE lines),
        # ending with Enter so the last line runs.
        sel = self.copy_host_var.get().strip()
        dev = self._lookup_device(sel)
        host = dev["host"] if dev else sel
        picked = [(h, f, e) for h, f, e in self.last_results if h == host and f and not e]
        if not picked:
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        script = acl_parser.format_cli_script(picked, self.negate_var.get())
        if not script.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(script)
        self._toast(self.T("copied"))

    def export_results(self):
        content = self.txt.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        path = filedialog.asksaveasfilename(
            title=self.T("export_title"),
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            messagebox.showinfo("ACL", self.T("saved").format(path=path))

    def _valid_ip(self, s: str) -> bool:
        try:
            ipaddress.ip_address(s.strip())
            return True
        except ValueError:
            return False

    def start_search(self):
        if self.searching:
            return
        if not self._require_unlocked():
            return
        ip = self.ent_ip.get().strip()
        if not ip:
            messagebox.showwarning("ACL", self.T("status_bad_query"))
            return
        by_ip = self._valid_ip(ip)
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        self.last_ip = ip
        self.last_results = []
        self.copy_host_var.set("")
        self.copy_combo.configure(values=[])
        self._set_text("")
        self.searching = True
        self.stop_event.clear()
        self.btn_search.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.prog.configure(maximum=len(self.devices), value=0)
        self.status.set(self.T("status_searching").format(n=len(self.devices)))
        threading.Thread(target=self._search_worker, args=(ip, by_ip),
                         daemon=True).start()

    def stop_search(self):
        self.stop_event.set()

    def _search_worker(self, ip: str, by_ip: bool = True):
        negate = self.negate_var.get()
        total_hits = 0
        done_devs = 0

        def one_device(d: dict):
            host = d["host"]
            try:
                cfg = cisco_ssh.fetch_config(host, d["username"], d.get("password", ""),
                                             d.get("enable") or None, int(d.get("port", 22)),
                                             debug_log=self._ssh_debug_log())
                acls = acl_parser.parse_running_config(cfg)
                if by_ip:
                    found = acl_parser.find_ip(acls, ip)
                else:
                    found = acl_parser.find_text(acls, ip)
                return (host, found, None)
            except Exception as e:
                return (host, {}, str(e))

        # keep original order: submit in order, collect in order
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(self.devices))) as ex:
            futs = [ex.submit(one_device, d) for d in self.devices]
            for fut in futs:
                if self.stop_event.is_set():
                    for f in futs:
                        f.cancel()
                    break
                try:
                    host, found, err = fut.result()
                except Exception as e:
                    host, found, err = ("?", {}, str(e))
                self.msg_queue.put(("chunk", (host, found, err)))

        self.msg_queue.put(("done", None))

    def rerender_results(self):
        """Re-render cached results when negation checkbox toggles (no reconnect)."""
        if not self.last_results:
            return
        negate = self.negate_var.get()
        parts: list[str] = []
        for host, found, err in self.last_results:
            parts.append(self.T("device_hdr").format(host=host))
            if err:
                parts.append(self.T("err_hdr").format(host=host, err=err))
            elif not found:
                parts.append(self.T("no_results").format(ip=self.last_ip))
            else:
                parts.append(acl_parser.format_results(found, negate=negate))
            parts.append("")
        self._set_text("\n".join(parts).rstrip() + "\n")

    # ---------- background msg pump ----------
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
                    if not self.txt_track.get("1.0", tk.END).strip():
                        self._set_track_text(text)
                    else:
                        self._append_track_text(text)
                    if host:
                        self.status.set(self.T("track_working").format(
                            ip=self.ent_track_ip.get().strip(), host=host))
                        try:
                            dev = self._lookup_device(host)
                            if dev is not None:
                                self.track_dev_var.set(self.dev_label(dev))
                        except tk.TclError:
                            pass
                elif kind == "track_done":
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
                    host, text, box, ev = payload
                    try:
                        ok = messagebox.askyesno(
                            self.T("vuln_verify_title").format(host=host),
                            text)
                    except tk.TclError:
                        ok = False
                    box["ok"] = bool(ok)
                    ev.set()
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
