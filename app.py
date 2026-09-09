"""Cisco ACL Helper - Tkinter app, PL/EN, SSH, encrypted device store."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import acl_parser
import cisco_ssh
import crypto_store
import dhcp_check
import track
from i18n import STRINGS, VALID_LANGS


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
        S = STRINGS[lang]
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
        else:
            self.e2 = None
        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, pady=12)
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
        S = STRINGS["en"]  # validation messages handled by caller lang
        p1 = self.e1.get()
        if not p1:
            messagebox.showwarning("ACL", "Password cannot be empty / Hasło nie może być puste.")
            return
        if self._is_new:
            if self.e2 and self.e2.get() != p1:
                messagebox.showwarning("ACL", "Passwords do not match / Hasła nie są zgodne.")
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
        self.devices: list[dict] = []
        self.subnets: list[dict] = []  # {"subnet": ..., "acl_in": ..., "acl_out": ...}
        self.gen_script: str = ""
        self.generating = False
        self.tracking = False
        self._track_cont: dict | None = None  # effective creds for Continue
        self._gen_start_vars: dict[str, tk.StringVar] = {}
        self._gen_auto: dict[str, int] = {}
        self._gen_taken: dict[str, set[int]] = {}
        self._gen_fetch_key = None
        self.last_results: list[tuple] = []  # (host, found_dict, err|None)
        self.last_ip: str = ""
        self.searching = False
        self.stop_event = threading.Event()
        self.msg_queue: queue.Queue = queue.Queue()

        self.title(STRINGS[self.lang]["app_title"])
        self.geometry("860x620")
        self.minsize(760, 540)

        self._build_widgets()
        self.apply_language()
        self.after(100, self._poll_queue)
        self.after(200, self._startup_unlock)

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
        cols = ("hostname", "host", "user", "port")
        self.tree = ttk.Treeview(self.tab_dev, columns=cols, show="headings", height=14)
        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<Double-1>", lambda _e: self.edit_device())
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

        # --- Tab 3: subnets ---
        self.tab_sub = ttk.Frame(self.nb)
        self.nb.add(self.tab_sub, text="subnets")
        self.lbl_sub = ttk.Label(self.tab_sub, text="")
        self.lbl_sub.pack(anchor="w", padx=10, pady=(10, 4))
        subcols = ("subnet", "acl_in", "acl_out")
        self.subtree = ttk.Treeview(self.tab_sub, columns=subcols, show="headings", height=14)
        self.subtree.pack(fill="both", expand=True, padx=10)
        self.subtree.bind("<Double-1>", lambda _e: self.edit_subnet())
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
        self.chk_gen_in = ttk.Checkbutton(gopts, text="", variable=self.gen_in_var)
        self.chk_gen_in.pack(side="left", padx=(0, 12))
        self.chk_gen_out = ttk.Checkbutton(gopts, text="", variable=self.gen_out_var)
        self.chk_gen_out.pack(side="left", padx=12)
        self.chk_gen_agg = ttk.Checkbutton(gopts, text="", variable=self.gen_agg_var)
        self.chk_gen_agg.pack(side="left", padx=(18, 0))

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

        # tab order: search, generator, tracking, devices, subnets, settings
        for _tab in (self.tab_search, self.tab_gen, self.tab_track, self.tab_dev,
                     self.tab_sub, self.tab_set):
            self.nb.forget(_tab)
        for _tab in (self.tab_search, self.tab_gen, self.tab_track, self.tab_dev,
                     self.tab_sub, self.tab_set):
            self.nb.add(_tab, text="")

        # status bar
        self.status = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w").pack(
            fill="x", side="bottom", padx=2, pady=2)
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
        self.lbl_sub.configure(text=S["subnets_label"])
        self.subtree.heading("subnet", text=S["col_subnet"])
        self.subtree.heading("acl_in", text=S["col_acl_in"])
        self.subtree.heading("acl_out", text=S["col_acl_out"])
        self.btn_sub_add.configure(text=S["add_btn"])
        self.btn_sub_edit.configure(text=S["edit_btn"])
        self.btn_sub_del.configure(text=S["del_btn"])
        self.lbl_gen_pc.configure(text=S["gen_pc_label"])
        self.lbl_gen_acl_in.configure(text=S["gen_acl_in_label"])
        self.lbl_gen_acl_out.configure(text=S["gen_acl_out_label"])
        self.lbl_gen_cams.configure(text=S["gen_cams_label"])
        self.chk_gen_in.configure(text=S["gen_in"])
        self.chk_gen_out.configure(text=S["gen_out"])
        self.chk_gen_agg.configure(text=S["gen_agg"])
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
        self.btn_track_clear.configure(text=S["clear_btn"])
        self.chk_track_parent.configure(text=S["track_parent_creds"])
        self.lbl_track_results.configure(text=S["results_label"])
        self.lbl_lang.configure(text=S["lang_label"])
        self.lbl_master.configure(text=S["master_label"])
        self.btn_chmaster.configure(text=S["change_master_btn"])
        self.lbl_dhcp.configure(text=S["dhcp_label"])
        self.chk_ssh_debug.configure(text=S["ssh_debug_label"])
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

    # ---------- master / store ----------
    def _startup_unlock(self):
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

    def refresh_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for d in self.devices:
            self.tree.insert("", "end", values=(d.get("hostname", ""), d.get("host", ""),
                                                d.get("username", ""), d.get("port", 22)))
        self._refresh_gen_devices()

    def refresh_subnets(self):
        for i in self.subtree.get_children():
            self.subtree.delete(i)
        for s in self.subnets:
            n = acl_parser.normalize_subnet(s)
            self.subtree.insert("", "end",
                                values=(n["subnet"], n["acl_in"], n["acl_out"]))

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

    def clear_gen(self):
        self.gen_script = ""
        self._set_gen_text("")

    def copy_gen(self):
        if not self.gen_script.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self.gen_script)
        messagebox.showinfo("ACL", self.T("copied"))

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
        dev = next((dict(d) for d in self.devices if d.get("host") == dev_host), None)
        if dev is None:
            messagebox.showwarning("ACL", self.T("gen_need_dev"))
            return
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
        threading.Thread(target=self._gen_worker,
                         args=(pc, dev, grouped, do_in, do_out, fetch_key,
                               reuse_taken, server),
                         daemon=True).start()

    def _gen_worker(self, pc, dev, grouped, do_in, do_out, fetch_key,
                    reuse_taken, server):
        dhcp_status, dhcp_detail = (dhcp_check.check_reservation(server, pc)
                                    if server else ("idle", ""))
        taken = reuse_taken
        err = None
        if taken is None:
            try:
                cfg = cisco_ssh.fetch_config(
                    dev["host"], dev["username"], dev.get("password", ""),
                    dev.get("enable") or None, int(dev.get("port", 22)),
                    debug_log=self._ssh_debug_log())
                acls = acl_parser.parse_running_config(cfg)
                taken = {}
                for acl_in, acl_out, _note, _nets in grouped:
                    for acl in (acl_in, acl_out):
                        if acl and acl not in taken:
                            entries = acls.get(acl, [])
                            if not entries:
                                for name, aces in acls.items():
                                    if name.lower() == acl.lower():
                                        entries = aces
                                        break
                            taken[acl] = acl_parser.extract_seq_numbers(entries)
            except Exception as e:
                if "Empty response" in str(e):
                    taken = {}  # reachable, just no ACL text found
                else:
                    err = str(e)
        self.msg_queue.put(("gen_done", (pc, dev["host"], grouped, do_in, do_out,
                                         fetch_key, taken, err,
                                         dhcp_status, dhcp_detail)))

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
        hosts = [d.get("host", "") for d in self.devices if d.get("host")]
        self.combo_gen_dev.configure(values=hosts)
        if self.gen_dev_var.get() not in hosts:
            self.gen_dev_var.set(hosts[0] if hosts else "")
        self.combo_track_dev.configure(values=hosts)
        if self.track_dev_var.get() not in hosts:
            self.track_dev_var.set(hosts[0] if hosts else "")

    # ---------- IP tracking tab (ARP -> MAC -> port -> CDP) ----------
    def _set_track_text(self, content: str):
        self.txt_track.configure(state="normal")
        self.txt_track.delete("1.0", tk.END)
        self.txt_track.insert("1.0", content)
        self.txt_track.configure(state="disabled")

    def clear_track(self):
        self._track_cont = None
        self.btn_track_cont.pack_forget()
        self.prog_track.configure(value=0)
        self._set_track_text("")

    def _lookup_device(self, host: str) -> dict | None:
        if not host:
            return None
        return next((dict(d) for d in self.devices if d.get("host") == host), None)

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
        self.btn_track.configure(state="disabled")
        self.prog_track.configure(maximum=3, value=0)
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
                      use_parent: bool, debug_log):
        host = dev["host"]
        lines = [f"=== {host} : {ip} ==="]
        cont: dict | None = None
        try:
            arp_out = self._track_run(dev, f"show ip arp {ip}", debug_log)
            self.msg_queue.put(("track_prog", 1))
            arp = track.parse_arp(arp_out, ip)
            mac, origin = track.resolve_mac(arp, dev.get("mac", ""))
            if mac is None:
                if arp and arp.get("incomplete"):
                    lines.append(self.T("track_arp_incomplete").format(ip=ip))
                else:
                    lines.append(self.T("track_arp_none").format(ip=ip, host=host))
                self.msg_queue.put(("track_done", ("\n".join(lines) + "\n", None)))
                return
            if origin == "fresh":
                lines.append(f"ARP: {ip} -> {mac} ({arp.get('interface', '')})".rstrip())
            else:
                lines.append(self.T("track_mac_parent").format(host=host, mac=mac))

            mac_out = self._track_run(dev, f"show mac address-table address {mac}",
                                      debug_log)
            self.msg_queue.put(("track_prog", 2))
            entries = track.parse_mac_table(mac_out, mac)
            if not entries:
                lines.append(self.T("track_mac_none").format(mac=mac, host=host))
                self.msg_queue.put(("track_done", ("\n".join(lines) + "\n", None)))
                return
            port = entries[0]["port"]
            for e in entries:
                vlan = f"VLAN {e['vlan']}, " if e.get("vlan") else ""
                lines.append(f"MAC: {mac} -> {e['port']} ({vlan}{e.get('type', '')})".rstrip())

            cdp_out = self._track_run(dev, "show cdp neighbors detail", debug_log)
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
                            cont[k] = dev.get(k, cont.get(k))
                elif use_parent and nb.get("ip"):
                    # neighbor not in the list: reach it with parent creds
                    cont = {"hostname": nb.get("device", ""), "host": nb["ip"],
                            "username": dev.get("username", ""),
                            "password": dev.get("password", ""),
                            "enable": dev.get("enable", ""),
                            "port": dev.get("port", 22)}
                if cont is not None:
                    cont["mac"] = mac  # carry over for the next hop
        except Exception as e:
            lines.append(f"*** ERROR on {host}: {e} ***")
        self.msg_queue.put(("track_done", ("\n".join(lines) + "\n", cont)))

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
        self.copy_combo.configure(values=hosts)
        if self.copy_host_var.get() not in hosts:
            self.copy_host_var.set(hosts[0] if hosts else "")

    def copy_results(self):
        # Copy ONLY the selected device's paste-safe CLI lines
        # (device context as "!" comments, ACL headers, ACE lines),
        # ending with Enter so the last line runs.
        host = self.copy_host_var.get()
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
        messagebox.showinfo("ACL", self.T("copied"))

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
        if not self._valid_ip(ip):
            messagebox.showwarning("ACL", self.T("status_bad_ip"))
            return
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
        threading.Thread(target=self._search_worker, args=(ip,), daemon=True).start()

    def stop_search(self):
        self.stop_event.set()

    def _search_worker(self, ip: str):
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
                found = acl_parser.find_ip(acls, ip)
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
                    self.prog_track.configure(value=payload)
                elif kind == "track_done":
                    text, cont = payload
                    self.tracking = False
                    self.btn_track.configure(state="normal")
                    self.prog_track.configure(value=3)
                    self._set_track_text(text)
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
                elif kind == "gen_done":
                    (pc, host, grouped, do_in, do_out, fetch_key, taken, err,
                     dhcp_status, dhcp_detail) = payload
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
                        involved = self._involved_acls(grouped, do_in, do_out)
                        self._update_starts_frame(involved, taken)
                        starts = self._read_gen_starts(involved)
                        self.status.set(self.T("status_ready"))
                        if starts is None:
                            continue
                        self.gen_script = acl_parser.build_full_script(
                            pc, grouped, do_in, do_out, starts, taken)
                        self._set_gen_text(self.gen_script)
                        if dhcp_status == "none":
                            messagebox.showwarning(
                                "ACL", self.T("dhcp_none").format(ip=pc))
        except queue.Empty:
            pass
        self.after(200, self._poll_queue)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
