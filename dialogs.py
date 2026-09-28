"""Modal dialogs (master password, device, import, subnet)."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

import crypto_store
from i18n import STRINGS, VALID_LANGS


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
