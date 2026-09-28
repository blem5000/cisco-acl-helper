"""ACL audit tab logic."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

import acl_parser
import cisco_ssh
from i18n import STRINGS


class AuditTabMixin:
    """Tab-owned App methods (mixed into App)."""

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

    def _build_audit_tab(self):
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

    def _apply_audit_language(self):
        S = STRINGS[self.lang]
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
