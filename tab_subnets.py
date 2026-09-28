"""Subnets tab logic."""

from __future__ import annotations

import ipaddress
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import acl_parser
import cisco_ssh
from dialogs import SubnetDialog
from i18n import STRINGS


class SubnetsTabMixin:
    """Tab-owned App methods (mixed into App)."""

    def refresh_subnets(self):
        for i in self.subtree.get_children():
            self.subtree.delete(i)
        for s in self.subnets:
            n = acl_parser.normalize_subnet(s)
            self.subtree.insert("", "end",
                                values=(n["subnet"], n["acl_in"], n["acl_out"]))
        self._update_sort_headers()

    # ---------- audit tab ----------

    @staticmethod
    def _subnet_key(subnet: str) -> tuple:
        try:
            net = ipaddress.ip_network((subnet or "").strip(), strict=False)
            return (0, int(net.network_address), net.prefixlen, "")
        except ValueError:
            return (1, 0, 0, (subnet or "").lower())

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

    def _build_subnets_tab(self):
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

    def _apply_subnets_language(self):
        S = STRINGS[self.lang]
        self.lbl_sub.configure(text=S["subnets_label"])
        self.lbl_sub_dev.configure(text=S["subnet_dev_label"])
        self.btn_sub_fetch.configure(text=S["subnet_fetch_btn"])
        self.subtree.heading("subnet", text=S["col_subnet"])
        self.subtree.heading("acl_in", text=S["col_acl_in"])
        self.subtree.heading("acl_out", text=S["col_acl_out"])
        self.btn_sub_add.configure(text=S["add_btn"])
        self.btn_sub_edit.configure(text=S["edit_btn"])
        self.btn_sub_del.configure(text=S["del_btn"])
