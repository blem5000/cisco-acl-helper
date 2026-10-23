"""Remove one person's IP from ACLs (lost-access cleanup) tab logic."""

from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import acl_parser
import cisco_ssh
import dhcp_check
from i18n import STRINGS


class RemoveTabMixin:
    """Tab-owned App methods (mixed into App)."""

    def _set_remove_cur(self, content: str):
        self.txt_remove_cur.configure(state="normal")
        self.txt_remove_cur.delete("1.0", tk.END)
        self.txt_remove_cur.insert("1.0", content)
        self.txt_remove_cur.configure(state="disabled")

    def _set_remove_prop(self, content: str):
        self.txt_remove_prop.configure(state="normal")
        self.txt_remove_prop.delete("1.0", tk.END)
        self.txt_remove_prop.insert("1.0", content)
        self.txt_remove_prop.configure(state="disabled")

    # ---------- fetching ----------

    def _remove_selected_host(self) -> str:
        """Host of the device currently chosen in this tab's dropdown."""
        dev = self._lookup_device(self.remove_dev_var.get().strip())
        return (dev or {}).get("host", "") or ""

    def _remove_state_is_current(self) -> bool:
        """True only when the fetched ACLs belong to the selected device.

        The ACLs are fetched once and kept in memory; changing the device
        dropdown does not re-fetch anything. Without this check the preview
        happily produced removal lines from device A's ACLs while device B
        was selected - i.e. a script for the wrong switch.
        """
        if not self._remove_acls or not self._remove_host:
            return False
        sel = self._remove_selected_host()
        return bool(sel) and sel == self._remove_host

    def _reset_remove_state(self, note: str = ""):
        """Forget fetched ACLs and any preview built from them."""
        self._remove_acls = {}
        self._remove_host = ""
        self._remove_proposal = ""
        try:
            self.combo_remove_acl.configure(values=[])
            self.remove_acl_var.set("")
            self.remove_all_var.set(False)
            self._toggle_remove_all()
        except tk.TclError:
            pass
        self._set_remove_cur("")
        self._set_remove_prop("")
        self.lbl_remove_stats.configure(text="")
        self.lbl_remove_warn.configure(text=note)

    def _on_remove_dev_change(self):
        """Device switched: anything fetched from the previous one is stale."""
        if self._remove_state_is_current():
            return
        if self._remove_host or self._remove_acls or self._remove_proposal:
            self._reset_remove_state(self.T("remove_stale_device"))

    def fetch_remove_acls(self):
        if self._remove_fetching:
            return
        if not self._require_unlocked():
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        dev = self._lookup_device(self.remove_dev_var.get().strip())
        if dev is None:
            messagebox.showwarning("ACL", self.T("remove_need_dev"))
            return
        self._remove_fetching = True
        self.btn_remove_fetch.configure(state="disabled")
        self.remove_prog.pack(side="left", padx=(14, 0))
        self.remove_prog.start(12)
        self.status.set(self.T("remove_fetching").format(host=dev["host"]))
        threading.Thread(target=self._remove_fetch_worker, args=(dev,),
                         daemon=True).start()

    def _remove_fetch_worker(self, dev: dict):
        try:
            cfg = cisco_ssh.fetch_config(
                dev["host"], dev["username"], dev.get("password", ""),
                dev.get("enable") or None, int(dev.get("port", 22)),
                debug_log=self._ssh_debug_log())
            acls = acl_parser.parse_running_config(cfg)
            self.msg_queue.put(("remove_list", (dev["host"], acls)))
        except Exception as e:
            self.msg_queue.put(("remove_error", (dev["host"], str(e))))

    def _finish_remove_fetch(self, host: str, acls: dict):
        self._remove_fetching = False
        self.btn_remove_fetch.configure(state="normal")
        try:
            self.remove_prog.stop()
        except tk.TclError:
            pass
        self.remove_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        self._remove_acls = acls
        self._remove_host = host
        names = sorted(acls)
        self.combo_remove_acl.configure(values=names)
        if self.remove_acl_var.get() not in names:
            self.remove_acl_var.set(names[0] if names else "")
        self.show_remove_acl()

    def _finish_remove_fetch_error(self, host: str, err: str):
        self._remove_fetching = False
        self.btn_remove_fetch.configure(state="normal")
        try:
            self.remove_prog.stop()
        except tk.TclError:
            pass
        self.remove_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        messagebox.showerror(
            "ACL", self.T("gen_fetch_fail").format(host=host, err=err))

    def show_remove_acl(self):
        name = self.remove_acl_var.get().strip()
        if not name or name not in self._remove_acls:
            self._set_remove_cur("")
            return
        entries = self._remove_acls.get(name, [])
        if entries:
            self._set_remove_cur(f"ip access-list extended {name}\n"
                                 + "\n".join(f"    {e}" for e in entries) + "\n")
        else:
            self._set_remove_cur(f"ip access-list extended {name}\n"
                                 f"    {self.T('audit_empty')}\n")

    # ---------- preview ----------

    def preview_remove(self):
        if self._remove_previewing:
            return
        if not self._require_unlocked():
            return
        if not self._remove_state_is_current():
            messagebox.showwarning("ACL", self.T("remove_need_fetch"))
            return
        ip = self.ent_remove_ip.get().strip()
        if not self._valid_ip(ip):
            messagebox.showwarning("ACL", self.T("status_bad_ip"))
            return
        only = "" if self.remove_all_var.get() else self.remove_acl_var.get().strip()
        if not only and not self.remove_all_var.get():
            messagebox.showwarning("ACL", self.T("remove_need_acl"))
            return

        server = self.dhcp_var.get().strip()
        if self.remove_owner_var.get() and server:
            self._remove_previewing = True
            self.btn_remove_preview.configure(state="disabled")
            self.remove_prog.pack(side="left", padx=(14, 0))
            self.remove_prog.start(12)
            self.status.set(self.T("audit_grouping").format(server=server))
            threading.Thread(
                target=self._remove_owner_worker,
                args=(server, ip, only, dict(self._remove_acls)),
                daemon=True).start()
            return
        # no DHCP server (or owner lookup off): brackets are still detected
        # structurally, we just cannot name the person in the summary.

        res = acl_parser.build_removal_script(self._remove_acls, ip, only=only)
        self._render_remove(res, ip)

    def _remove_owner_worker(self, server: str, ip: str, only: str,
                             acls: dict):
        try:
            now = time.time()
            hit = self._dhcp_cache.get(server)
            if hit is not None and now - hit[0] < self.DHCP_CACHE_TTL:
                resmap = hit[1]
            else:
                resmap, err = dhcp_check.fetch_all_reservations(server)
                if err:
                    self.msg_queue.put(("remove_preview_error", (server, err)))
                    return
                self._dhcp_cache[server] = (now, resmap)

            def owner_of(addr: str) -> str:
                info = resmap.get((addr or "").strip())
                if not info:
                    return ""
                return dhcp_check.owner_from_description(
                    info.get("description", ""))

            res = acl_parser.build_removal_script(acls, ip, only=only,
                                                  owner_of=owner_of)
            self.msg_queue.put(("remove_preview", (ip, res)))
        except Exception as e:
            self.msg_queue.put(("remove_preview_error", (server, str(e))))

    def _finish_remove_preview(self, ip: str, res: dict):
        self._remove_previewing = False
        self.btn_remove_preview.configure(state="normal")
        try:
            self.remove_prog.stop()
        except tk.TclError:
            pass
        self.remove_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        if ip != self.ent_remove_ip.get().strip():
            return  # user edited the address meanwhile: drop stale preview
        if not self._remove_state_is_current():
            # device switched while the DHCP lookup was running
            self._reset_remove_state(self.T("remove_stale_device"))
            return
        self._render_remove(res, ip)

    def _finish_remove_preview_error(self, server: str, err: str):
        self._remove_previewing = False
        self.btn_remove_preview.configure(state="normal")
        try:
            self.remove_prog.stop()
        except tk.TclError:
            pass
        self.remove_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        messagebox.showerror(
            "ACL", self.T("audit_group_fail").format(server=server, err=err))

    def _render_remove(self, res: dict, ip: str):
        script = res.get("script", "")
        self._remove_proposal = script
        self._set_remove_prop(script)
        owner = res.get("owner", "")
        if script:
            if owner:
                self.lbl_remove_stats.configure(
                    text=self.T("remove_stats").format(
                        ip=ip, owner=owner, aces=res["removed"],
                        remarks=res["removed_remarks"],
                        acls=len(res.get("acls_hit", []))))
            else:
                self.lbl_remove_stats.configure(
                    text=self.T("remove_stats_noowner").format(
                        ip=ip, aces=res["removed"],
                        remarks=res["removed_remarks"],
                        acls=len(res.get("acls_hit", []))))
        else:
            if res.get("unsequenced"):
                self.lbl_remove_stats.configure(
                    text=self.T("remove_unsequenced").format(
                        n=len(res["unsequenced"])))
            else:
                self.lbl_remove_stats.configure(
                    text=self.T("remove_nothing").format(ip=ip))

        notes = list(res.get("covers") or [])
        if res.get("unsequenced"):
            notes.extend(res["unsequenced"])
        if notes:
            self.lbl_remove_warn.configure(
                text=self.T("remove_warn_hdr") + "\n  " + "\n  ".join(notes))
        else:
            self.lbl_remove_warn.configure(text="")

    def copy_remove(self):
        if not self._remove_proposal.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self._remove_proposal)
        self._toast(self.T("copied"))

    def clear_remove(self):
        self._remove_proposal = ""
        self._set_remove_prop("")
        self.lbl_remove_stats.configure(text="")
        self.lbl_remove_warn.configure(text="")

    # ---------- UI ----------

    def _build_remove_tab(self):
        self.tab_remove = ttk.Frame(self.nb)
        self.nb.add(self.tab_remove, text="remove")

        rf = ttk.Frame(self.tab_remove)
        rf.pack(fill="x", padx=10, pady=10)
        self.lbl_remove_dev = ttk.Label(rf, text="")
        self.lbl_remove_dev.grid(row=0, column=0, sticky="w")
        self.remove_dev_var = tk.StringVar(value="")
        self.combo_remove_dev = ttk.Combobox(
            rf, textvariable=self.remove_dev_var, state="readonly", width=24,
            values=[])
        self.combo_remove_dev.grid(row=1, column=0, sticky="w", pady=4)
        self.combo_remove_dev.bind("<<ComboboxSelected>>",
                                   lambda _e: self._on_remove_dev_change())
        self.btn_remove_fetch = ttk.Button(rf, text="",
                                           command=self.fetch_remove_acls)
        self.btn_remove_fetch.grid(row=1, column=1, padx=8)

        self.lbl_remove_acl = ttk.Label(rf, text="")
        self.lbl_remove_acl.grid(row=0, column=2, sticky="w", padx=(16, 0))
        self.remove_acl_var = tk.StringVar(value="")
        self.combo_remove_acl = ttk.Combobox(
            rf, textvariable=self.remove_acl_var, state="readonly", width=30,
            values=[])
        self.combo_remove_acl.grid(row=1, column=2, sticky="w",
                                   padx=(16, 0), pady=4)
        self.combo_remove_acl.bind("<<ComboboxSelected>>",
                                   lambda _e: self.show_remove_acl())
        self.remove_all_var = tk.BooleanVar(value=False)
        self.chk_remove_all = ttk.Checkbutton(
            rf, text="", variable=self.remove_all_var,
            command=self._toggle_remove_all)
        self.chk_remove_all.grid(row=2, column=2, sticky="w", padx=(16, 0))

        self.lbl_remove_ip = ttk.Label(rf, text="")
        self.lbl_remove_ip.grid(row=0, column=3, sticky="w", padx=(16, 0))
        self.ent_remove_ip = ttk.Entry(rf, width=20, font=("Consolas", 10))
        self.ent_remove_ip.grid(row=1, column=3, sticky="w",
                                padx=(16, 0), pady=4)
        self.ent_remove_ip.bind("<Return>", lambda _e: self.preview_remove())

        self.remove_owner_var = tk.BooleanVar(value=True)
        self.chk_remove_owner = ttk.Checkbutton(
            rf, text="", variable=self.remove_owner_var)
        self.chk_remove_owner.grid(row=2, column=3, sticky="w", padx=(16, 0))

        rb = ttk.Frame(self.tab_remove)
        rb.pack(fill="x", padx=10, pady=(0, 8))
        self.btn_remove_preview = ttk.Button(rb, text="",
                                              command=self.preview_remove)
        self.btn_remove_preview.pack(side="left", padx=(0, 6))
        self.btn_remove_copy = ttk.Button(rb, text="", command=self.copy_remove)
        self.btn_remove_copy.pack(side="left", padx=6)
        self.btn_remove_clear = ttk.Button(rb, text="", command=self.clear_remove)
        self.btn_remove_clear.pack(side="left", padx=6)
        self.remove_prog = ttk.Progressbar(rb, mode="indeterminate", length=120)

        self.lbl_remove_cur = ttk.Label(self.tab_remove, text="")
        self.lbl_remove_cur.pack(anchor="w", padx=10, pady=(2, 2))
        cur_fr = ttk.Frame(self.tab_remove)
        cur_fr.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.txt_remove_cur = tk.Text(cur_fr, wrap="none", font=("Consolas", 10),
                                      height=8, state="disabled")
        rys = ttk.Scrollbar(cur_fr, orient="vertical",
                            command=self.txt_remove_cur.yview)
        rxs = ttk.Scrollbar(cur_fr, orient="horizontal",
                            command=self.txt_remove_cur.xview)
        self.txt_remove_cur.configure(yscrollcommand=rys.set,
                                      xscrollcommand=rxs.set)
        self.txt_remove_cur.grid(row=0, column=0, sticky="nsew")
        rys.grid(row=0, column=1, sticky="ns")
        rxs.grid(row=1, column=0, sticky="ew")
        cur_fr.grid_rowconfigure(0, weight=1)
        cur_fr.grid_columnconfigure(0, weight=1)

        self.lbl_remove_stats = ttk.Label(self.tab_remove, text="",
                                          foreground="blue")
        self.lbl_remove_stats.pack(anchor="w", padx=10)
        self.lbl_remove_warn = ttk.Label(self.tab_remove, text="",
                                         foreground="#b36b00")
        self.lbl_remove_warn.pack(anchor="w", padx=10)
        self.lbl_remove_prop = ttk.Label(self.tab_remove, text="")
        self.lbl_remove_prop.pack(anchor="w", padx=10, pady=(2, 2))
        prop_fr = ttk.Frame(self.tab_remove)
        prop_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_remove_prop = tk.Text(prop_fr, wrap="none",
                                       font=("Consolas", 10), height=8,
                                       state="disabled")
        rpys = ttk.Scrollbar(prop_fr, orient="vertical",
                             command=self.txt_remove_prop.yview)
        rpxs = ttk.Scrollbar(prop_fr, orient="horizontal",
                             command=self.txt_remove_prop.xview)
        self.txt_remove_prop.configure(yscrollcommand=rpys.set,
                                       xscrollcommand=rpxs.set)
        self.txt_remove_prop.grid(row=0, column=0, sticky="nsew")
        rpys.grid(row=0, column=1, sticky="ns")
        rpxs.grid(row=1, column=0, sticky="ew")
        prop_fr.grid_rowconfigure(0, weight=1)
        prop_fr.grid_columnconfigure(0, weight=1)

    def _toggle_remove_all(self):
        state = "disabled" if self.remove_all_var.get() else "readonly"
        try:
            self.combo_remove_acl.configure(state=state)
        except tk.TclError:
            pass

    def _apply_remove_language(self):
        S = STRINGS[self.lang]
        self.lbl_remove_dev.configure(text=S["remove_dev_label"])
        self.btn_remove_fetch.configure(text=S["audit_fetch_btn"])
        self.lbl_remove_acl.configure(text=S["remove_acl_label"])
        self.chk_remove_all.configure(text=S["remove_all_label"])
        self.lbl_remove_ip.configure(text=S["remove_ip_label"])
        self.chk_remove_owner.configure(text=S["remove_owner_label"])
        self.btn_remove_preview.configure(text=S["remove_preview_btn"])
        self.btn_remove_copy.configure(text=S["copy_btn"])
        self.btn_remove_clear.configure(text=S["clear_btn"])
        self.lbl_remove_cur.configure(text=S["remove_current_label"])
        self.lbl_remove_prop.configure(text=S["remove_proposal_label"])
