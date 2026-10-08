"""Devices tab logic."""

from __future__ import annotations

import ipaddress
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import acl_parser
import cisco_ssh
import device_import
from dialogs import DeviceDialog, GroupDialog, ImportDialog
from i18n import STRINGS


class DevicesTabMixin:
    """Tab-owned App methods (mixed into App)."""

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

    def _on_dev_double_click(self, event):
        """Double-click opens the edit dialog - except on the audit
        checkbox cell (a double-click there is two toggles, which cancel
        out) and on headers (toggle-all lives there). Same bbox geometry
        check as the single-click toggle, for the same Tk reasons."""
        try:
            region = self.tree.identify("region", event.x, event.y)
            if region == "heading":
                return
            if region == "cell":
                row = self.tree.identify_row(event.y)
                if row:
                    bb = self.tree.bbox(row, "audit")
                    if bb and bb[0] <= event.x <= bb[0] + bb[2]:
                        return
        except tk.TclError:
            pass
        self.edit_device()

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

    def _link_partner(self, idx: int, old: dict):
        """Mirror the HA pair link to the partner device.

        Setting partner P + role R on this device writes partner=self +
        opposite role on P. Stale one-sided backlinks (old partner, renamed
        hosts, removed links) are cleared.
        """
        me = self.devices[idx]
        new_host = me.get("host", "")
        new_p = (me.get("partner") or "").strip()
        old_host = (old or {}).get("host", "")
        my_role = (me.get("ha_role") or "primary").strip() or "primary"
        opp = "secondary" if my_role == "primary" else "primary"
        for i, d in enumerate(self.devices):
            if i == idx:
                continue
            dh = d.get("host", "")
            if new_p and dh == new_p:
                d["partner"] = new_host
                d["ha_role"] = opp
            elif d.get("partner") in (new_host, old_host) and dh != new_p:
                d["partner"] = ""
                d["ha_role"] = ""

    def add_device(self):
        if not self._require_unlocked():
            return
        dlg = DeviceDialog(self, self.lang, self.T("dlg_add_title"),
                           None, self.devices)
        self.wait_window(dlg)
        if dlg.result:
            self.devices.append(dlg.result)
            self._link_partner(len(self.devices) - 1, {})
            self.persist_store()
            self.refresh_tree()

    def edit_device(self):
        if not self._require_unlocked():
            return
        idx = self._selected_device_idx()
        if idx is None:
            return
        old = dict(self.devices[idx])
        dlg = DeviceDialog(self, self.lang, self.T("dlg_edit_title"), self.devices[idx],
                           self.devices)
        self.wait_window(dlg)
        if dlg.result:
            dlg.result["audit"] = self.devices[idx].get("audit", True)
            self.devices[idx] = dlg.result
            self._link_partner(idx, old)
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
            for d in self.devices:
                if d.get("partner") == host:
                    d["partner"] = ""
                    d["ha_role"] = ""
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
        src["partner"] = ""
        src["ha_role"] = ""
        dlg = DeviceDialog(self, self.lang, self.T("dlg_dup_title"), src,
                           self.devices)
        self.wait_window(dlg)
        if dlg.result:
            self.devices.append(dlg.result)
            self._link_partner(len(self.devices) - 1, {})
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

    def group_devices(self):
        """Auto-assign groups from hostname/label via preview dialog."""
        if not self._require_unlocked():
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        dlg = GroupDialog(self, self.lang, self.devices)
        self.wait_window(dlg)
        if not dlg.result:
            return
        n = 0
        for d in self.devices:
            g = dlg.result.get(str(d.get("host", "") or "").strip())
            if g:
                d["group"] = g
                n += 1
        self.persist_store()
        self.refresh_tree()
        messagebox.showinfo("ACL", self.T("grp_applied").format(n=n))

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
            self.tree.insert("", "end", values=(mark, d.get("hostname", ""),
                                                d.get("group", ""), d.get("host", ""),
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

    @staticmethod
    def _host_key(host: str) -> tuple:
        """Sort key: real IPs numerically (10.0.0.9 < 10.0.0.10), then names."""
        h = (host or "").strip()
        try:
            return (0, int(ipaddress.ip_address(h)), "")
        except ValueError:
            return (1, 0, h.lower())

    def sort_devices(self, col: str):
        """Sort the device list by column click; toggles direction."""
        if self._dev_sort and self._dev_sort[0] == col:
            reverse = not self._dev_sort[1]
        else:
            reverse = False
        keys = {
            "hostname": lambda d: (d.get("hostname", "") or "").lower(),
            "group": lambda d: (d.get("group", "") or "").lower(),
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

    def _update_sort_headers(self):
        """Arrow (asc/desc) on the sorted column; plain text otherwise."""
        dev_heads = {"hostname": self.T("col_hostname"), "group": self.T("col_group"),
                     "host": self.T("col_host"),
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

    def _build_devices_tab(self):
        # --- Tab 2: devices ---
        self.tab_dev = ttk.Frame(self.nb)
        self.nb.add(self.tab_dev, text="devices")
        self.lbl_dev = ttk.Label(self.tab_dev, text="")
        self.lbl_dev.pack(anchor="w", padx=10, pady=(10, 4))
        cols = ("audit", "hostname", "group", "host", "user", "port")
        self.tree = ttk.Treeview(self.tab_dev, columns=cols, show="headings", height=14)
        self.tree.pack(fill="both", expand=True, padx=10)
        self.tree.bind("<Double-1>", self._on_dev_double_click)
        self.tree.bind("<ButtonRelease-1>", self._on_dev_click)
        self.tree.bind("<space>", self._on_dev_space)
        self.tree.column("audit", width=44, minwidth=44, stretch=False, anchor="center")
        self.tree.heading("audit", text="\u2713", command=self.toggle_all_audit)
        for _c in ("hostname", "group", "host", "user", "port"):
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
        self.btn_group = ttk.Button(dbtns, text="", command=self.group_devices)
        self.btn_group.pack(side="left", padx=6)

    def _apply_devices_language(self):
        S = STRINGS[self.lang]
        self.lbl_dev.configure(text=S["devices_label"])
        self.tree.heading("hostname", text=S["col_hostname"])
        self.tree.heading("group", text=S["col_group"])
        self.tree.heading("host", text=S["col_host"])
        self.tree.heading("user", text=S["col_user"])
        self.tree.heading("port", text=S["col_port"])
        self.btn_add.configure(text=S["add_btn"])
        self.btn_edit.configure(text=S["edit_btn"])
        self.btn_dup.configure(text=S["dup_btn"])
        self.btn_del.configure(text=S["del_btn"])
        self.btn_test.configure(text=S["test_btn"])
        self.btn_import.configure(text=S["import_btn"])
        self.btn_group.configure(text=S["grp_btn"])
