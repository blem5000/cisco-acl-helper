"""Remove one person's IP from ACLs (lost-access cleanup) tab logic.

Supports several devices at once (e.g. an HA pair of switches): every
selected device is fetched, and the removal script is rendered as one
clearly separated block per device with its own Copy button, so nothing
gets pasted onto the wrong switch.
"""

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

    # ---------- small text helpers ----------

    def _set_remove_cur(self, content: str):
        self.txt_remove_cur.configure(state="normal")
        self.txt_remove_cur.delete("1.0", tk.END)
        self.txt_remove_cur.insert("1.0", content)
        self.txt_remove_cur.configure(state="disabled")

    def _copy_text(self, text: str):
        if not (text or "").strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._toast(self.T("copied"))

    # ---------- device selection ----------

    def _remove_selected_devices(self) -> list[dict]:
        """Devices currently highlighted in the multi-select list."""
        out: list[dict] = []
        try:
            idxs = self.list_remove_dev.curselection()
        except tk.TclError:
            return out
        labels = list(self._remove_dev_labels)
        for i in idxs:
            if 0 <= i < len(labels):
                dev = self._lookup_device(labels[i])
                if dev is not None:
                    out.append(dev)
        return out

    def _remove_selected_hosts(self) -> list[str]:
        return [d.get("host", "") for d in self._remove_selected_devices()]

    def _remove_state_is_current(self) -> bool:
        """True only when the fetched ACLs match the current selection.

        ACLs are fetched once and kept in memory; changing the selection
        does not re-fetch. Without this check the preview produced removal
        lines from device A while device B was selected - a script for the
        wrong switch.
        """
        if not self._remove_fetched:
            return False
        sel = {h for h in self._remove_selected_hosts() if h}
        return bool(sel) and sel == set(self._remove_fetched)

    def _reset_remove_state(self, note: str = ""):
        self._remove_fetched = {}
        self._remove_blocks = []
        try:
            self.combo_remove_acl.configure(values=[])
            self.remove_acl_var.set("")
            self.remove_all_var.set(False)
            self._toggle_remove_all()
        except tk.TclError:
            pass
        self._set_remove_cur("")
        self._clear_remove_blocks()
        self.lbl_remove_stats.configure(text="")
        self.lbl_remove_warn.configure(text=note)

    def _on_remove_dev_change(self):
        """Selection changed: anything fetched for the old set is stale."""
        if self._remove_state_is_current():
            return
        if self._remove_fetched or self._remove_blocks:
            self._reset_remove_state(self.T("remove_stale_device"))

    def _refresh_remove_hint(self):
        """Enable/disable the fetch button hint when nothing is selected."""
        try:
            n = len(self._remove_selected_hosts())
        except (tk.TclError, AttributeError):
            n = 0
        try:
            self.lbl_remove_sel.configure(
                text=self.T("remove_selected_n").format(n=n) if n else
                self.T("remove_no_selection"))
        except tk.TclError:
            pass

    def _refresh_remove_devices(self, labels: list[str]):
        """Repopulate the multi-select device list, keeping the selection.

        Selection is remembered by label so a refresh (device added/edited)
        does not silently drop a switch from the pair the user picked.
        """
        try:
            chosen = {self.list_remove_dev.get(i)
                      for i in self.list_remove_dev.curselection()}
            self.list_remove_dev.delete(0, tk.END)
            for lbl in labels:
                self.list_remove_dev.insert(tk.END, lbl)
            for i, lbl in enumerate(labels):
                if lbl in chosen:
                    self.list_remove_dev.selection_set(i)
        except (tk.TclError, AttributeError):
            return
        self._remove_dev_labels = list(labels)
        self._refresh_remove_hint()

    # ---------- fetching ----------

    def fetch_remove_acls(self):
        if self._remove_fetching:
            return
        if not self._require_unlocked():
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        devs = self._remove_selected_devices()
        if not devs:
            messagebox.showwarning("ACL", self.T("remove_need_dev"))
            return
        self._remove_fetching = True
        self.btn_remove_fetch.configure(state="disabled")
        self.remove_prog.pack(side="left", padx=(14, 0))
        self.remove_prog.start(12)
        self.status.set(self.T("remove_fetching").format(
            host=", ".join(d["host"] for d in devs)))
        threading.Thread(target=self._remove_fetch_worker, args=(devs,),
                         daemon=True).start()

    def _remove_fetch_worker(self, devs: list[dict]):
        fetched: dict[str, dict] = {}
        errors: list[tuple[str, str]] = []
        for dev in devs:
            try:
                cfg = cisco_ssh.fetch_config(
                    dev["host"], dev["username"], dev.get("password", ""),
                    dev.get("enable") or None, int(dev.get("port", 22)),
                    debug_log=self._ssh_debug_log())
                fetched[dev["host"]] = {
                    "label": self.dev_label(dev),
                    "acls": acl_parser.parse_running_config(cfg),
                }
            except Exception as e:  # one bad switch must not kill the rest
                errors.append((self.dev_label(dev), str(e)))
        self.msg_queue.put(("remove_list", (fetched, errors)))

    def _finish_remove_fetch(self, fetched: dict, errors: list):
        self._remove_fetching = False
        self.btn_remove_fetch.configure(state="normal")
        try:
            self.remove_prog.stop()
        except tk.TclError:
            pass
        self.remove_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        self._remove_fetched = fetched
        names: set[str] = set()
        for info in fetched.values():
            names.update(info["acls"])
        names_sorted = sorted(names)
        self.combo_remove_acl.configure(values=names_sorted)
        if self.remove_acl_var.get() not in names_sorted:
            self.remove_acl_var.set(names_sorted[0] if names_sorted else "")
        self._show_remove_acls()
        if errors:
            messagebox.showwarning(
                "ACL", self.T("remove_partial_fail").format(
                    detail="\n".join(f"{lbl}: {err}" for lbl, err in errors)))

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

    def _show_remove_acls(self):
        """Preview the selected ACL as fetched on each device."""
        name = self.remove_acl_var.get().strip()
        if not self._remove_fetched:
            self._set_remove_cur("")
            return
        parts: list[str] = []
        if self.remove_all_var.get():
            for info in self._remove_fetched.values():
                parts.append(f"### {info['label']}")
                for acl in sorted(info["acls"]):
                    parts.append(f"ip access-list extended {acl}")
                    entries = info["acls"].get(acl) or []
                    if entries:
                        parts.extend(f"    {e}" for e in entries)
                    else:
                        parts.append(f"    {self.T('audit_empty')}")
                parts.append("")
            self._set_remove_cur("\n".join(parts).rstrip() + "\n")
            return
        if not name:
            self._set_remove_cur("")
            return
        for info in self._remove_fetched.values():
            parts.append(f"### {info['label']}")
            entries = info["acls"].get(name) or []
            if entries:
                parts.append(f"ip access-list extended {name}")
                parts.extend(f"    {e}" for e in entries)
            else:
                parts.append(f"ip access-list extended {name}")
                parts.append(f"    {self.T('remove_acl_absent')}")
            parts.append("")
        self._set_remove_cur("\n".join(parts).rstrip() + "\n")

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

        whole_block = bool(self.remove_block_var.get())
        server = self.dhcp_var.get().strip()
        if self.remove_owner_var.get() and server:
            self._remove_previewing = True
            self.btn_remove_preview.configure(state="disabled")
            self.remove_prog.pack(side="left", padx=(14, 0))
            self.remove_prog.start(12)
            self.status.set(self.T("audit_grouping").format(server=server))
            threading.Thread(
                target=self._remove_owner_worker,
                args=(server, ip, only, {h: dict(v["acls"])
                                         for h, v in self._remove_fetched.items()},
                      {h: v["label"] for h, v in self._remove_fetched.items()},
                      whole_block),
                daemon=True).start()
            return
        # no DHCP server: brackets are still detected structurally, the
        # summary just cannot name the person.
        self._render_remove_result(
            self._build_result(ip, only, whole_block=whole_block), ip)

    def preview_orphans(self):
        """Find remark brackets that no longer describe anything.

        No IP needed - this cleans the ACL itself (closing remark without
        an opening, dangling header, or a bracket with no entries between
        its remarks).
        """
        if self._remove_previewing:
            return
        if not self._require_unlocked():
            return
        if not self._remove_state_is_current():
            messagebox.showwarning("ACL", self.T("remove_need_fetch"))
            return
        only = "" if self.remove_all_var.get() else self.remove_acl_var.get().strip()
        if not only and not self.remove_all_var.get():
            messagebox.showwarning("ACL", self.T("remove_need_acl"))
            return

        devices = [(host, info["label"], info["acls"])
                   for host, info in self._remove_fetched.items()]
        res = acl_parser.build_orphan_removal_blocks(devices, only=only)
        for block in res.get("blocks") or []:
            block["kind"] = "orphan"
        self._render_remove_result(res, self.T("orphan_subject"))

    def _build_result(self, ip: str, only: str, owner_of=None,
                      whole_block: bool = False) -> dict:
        devices = [(host, info["label"], info["acls"])
                   for host, info in self._remove_fetched.items()]
        return acl_parser.build_removal_blocks(
            devices, ip, only=only, owner_of=owner_of,
            drop_whole_block=whole_block)

    def _remove_owner_worker(self, server: str, ip: str, only: str,
                             acls: dict, labels: dict,
                             whole_block: bool = False):
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

            devices = [(host, labels.get(host, host), entries)
                       for host, entries in acls.items()]
            res = acl_parser.build_removal_blocks(
                devices, ip, only=only, owner_of=owner_of,
                drop_whole_block=whole_block)
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
            return  # address edited meanwhile: drop the stale preview
        if not self._remove_state_is_current():
            self._reset_remove_state(self.T("remove_stale_device"))
            return
        self._render_remove_result(res, ip)

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

    # ---------- rendering ----------

    def _clear_remove_blocks(self):
        for child in self._remove_blocks_frame.winfo_children():
            child.destroy()
        self._remove_blocks = []

    def _render_remove_result(self, res: dict, ip: str):
        self._clear_remove_blocks()
        self._remove_blocks = list(res.get("blocks") or [])
        owner = res.get("owner", "")
        is_orphan = any(b.get("kind") == "orphan"
                        for b in self._remove_blocks)
        if not self._remove_blocks:
            if res.get("unsequenced"):
                self.lbl_remove_stats.configure(
                    text=self.T("remove_unsequenced").format(
                        n=len(res["unsequenced"])))
            elif is_orphan or "removed" not in res:
                self.lbl_remove_stats.configure(
                    text=self.T("orphan_nothing"))
            else:
                self.lbl_remove_stats.configure(
                    text=self.T("remove_nothing").format(ip=ip))
        elif is_orphan or "removed" not in res:
            self.lbl_remove_stats.configure(
                text=self.T("orphan_stats").format(
                    remarks=res.get("removed_remarks", 0),
                    acls=len({a for b in self._remove_blocks
                              for a in b["acls_hit"]}),
                    devices=len(self._remove_blocks)))
        elif owner:
            self.lbl_remove_stats.configure(
                text=self.T("remove_stats").format(
                    ip=ip, owner=owner, aces=res["removed"],
                    remarks=res["removed_remarks"],
                    acls=len({a for b in self._remove_blocks
                              for a in b["acls_hit"]}),
                    devices=len(self._remove_blocks)))
        else:
            self.lbl_remove_stats.configure(
                text=self.T("remove_stats_noowner").format(
                    ip=ip, aces=res["removed"],
                    remarks=res["removed_remarks"],
                    acls=len({a for b in self._remove_blocks
                              for a in b["acls_hit"]}),
                    devices=len(self._remove_blocks)))

        for block in self._remove_blocks:
            self._render_one_block(block)

        notes: list[str] = list(res.get("covers") or [])
        notes.extend(res.get("unsequenced") or [])
        # Orphan run: say which remarks are going, so the paste is verifiable.
        for item in res.get("orphans") or []:
            notes.append(item)
        # The person's bracket was kept because they still have entries for
        # other machines. Say so - silently keeping it looked like the app
        # simply failed to remove remarks.
        kept = res.get("kept_brackets")
        if isinstance(kept, str):
            kept = [kept] if kept else []
        for item in kept or []:
            notes.append(self.T("remove_bracket_kept").format(where=item))
        if res.get("skipped"):
            notes.append(self.T("remove_skipped").format(
                devices=", ".join(res["skipped"])))
        if notes:
            self.lbl_remove_warn.configure(
                text=self.T("remove_warn_hdr") + "\n  " + "\n  ".join(notes))
        else:
            self.lbl_remove_warn.configure(text="")
        self._update_remove_scroll()

    def _render_one_block(self, block: dict):
        lf = ttk.LabelFrame(self._remove_blocks_frame,
                            text=block["label"], padding=(6, 4))
        lf.pack(fill="x", expand=False, padx=2, pady=(2, 8))
        head = ttk.Frame(lf)
        head.pack(fill="x")
        if block.get("kind") == "orphan":
            info = self.T("orphan_block_stats").format(
                remarks=block["removed_remarks"],
                acls=", ".join(block["acls_hit"]))
        else:
            info = self.T("remove_block_stats").format(
                aces=block["removed"], remarks=block["removed_remarks"],
                acls=", ".join(block["acls_hit"]))
        ttk.Label(head, text=info, foreground="blue").pack(side="left")
        script = block["script"]
        ttk.Button(head, text=self.T("remove_copy_block"),
                   command=lambda t=script: self._copy_text(t)).pack(side="right")

        lines = max(2, min(16, script.count("\n")))
        txt = tk.Text(lf, wrap="none", height=lines, font=("Consolas", 10))
        txt.insert("1.0", script)
        txt.configure(state="disabled")
        xs = ttk.Scrollbar(lf, orient="horizontal", command=txt.xview)
        txt.configure(xscrollcommand=xs.set)
        txt.pack(fill="x", expand=False, pady=(4, 0))
        xs.pack(fill="x")

    def _update_remove_scroll(self):
        try:
            self._remove_canvas.configure(
                scrollregion=self._remove_canvas.bbox("all"))
        except tk.TclError:
            pass

    def _on_remove_canvas_configure(self, event):
        try:
            self._remove_canvas.itemconfigure(self._remove_win,
                                              width=event.width)
        except tk.TclError:
            pass

    def _on_remove_mousewheel(self, event):
        try:
            self._remove_canvas.yview_scroll(
                int(-1 * (event.delta / 120)), "units")
        except (tk.TclError, AttributeError):
            pass

    def copy_remove(self):
        """Copy every block in one go (blocks stay individually copyable)."""
        parts = [b["script"].rstrip() for b in self._remove_blocks if b["script"]]
        if not parts:
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self._copy_text("\n\n".join(parts) + "\n")

    def clear_remove(self):
        self._clear_remove_blocks()
        self._set_remove_cur("")
        self.lbl_remove_stats.configure(text="")
        self.lbl_remove_warn.configure(text="")

    # ---------- UI ----------

    def _build_remove_tab(self):
        self.tab_remove = ttk.Frame(self.nb)
        self.nb.add(self.tab_remove, text="remove")

        rf = ttk.Frame(self.tab_remove)
        rf.pack(fill="x", padx=10, pady=(10, 4))
        rf.grid_columnconfigure(0, weight=0)
        rf.grid_columnconfigure(1, weight=0)
        rf.grid_columnconfigure(2, weight=0)
        rf.grid_columnconfigure(3, weight=1)

        # --- devices: multi-select list ---
        self.lbl_remove_dev = ttk.Label(rf, text="")
        self.lbl_remove_dev.grid(row=0, column=0, sticky="w")
        self._remove_dev_labels: list[str] = []
        self.list_remove_dev = tk.Listbox(
            rf, selectmode="extended", exportselection=False, height=5,
            width=26, font=("Consolas", 9),
            activestyle="dotbox", takefocus=True)
        self.list_remove_dev.grid(row=1, column=0, sticky="nsw", pady=4)
        self.list_remove_dev.bind("<<ListboxSelect>>",
                                  lambda _e: self._on_remove_dev_change())
        dev_scroll = ttk.Scrollbar(rf, orient="vertical",
                                   command=self.list_remove_dev.yview)
        self.list_remove_dev.configure(yscrollcommand=dev_scroll.set)
        dev_scroll.grid(row=1, column=1, sticky="ns", pady=4)

        btns_dev = ttk.Frame(rf)
        btns_dev.grid(row=1, column=2, sticky="nw", padx=(8, 0), pady=4)
        self.btn_remove_fetch = ttk.Button(btns_dev, text="",
                                           command=self.fetch_remove_acls)
        self.btn_remove_fetch.pack(anchor="w")
        self.lbl_remove_sel = ttk.Label(btns_dev, text="", foreground="gray")
        self.lbl_remove_sel.pack(anchor="w", pady=(4, 0))

        # --- ACL + IP ---
        right = ttk.Frame(rf)
        right.grid(row=1, column=3, sticky="new", padx=(16, 0), pady=4)
        self.lbl_remove_acl = ttk.Label(right, text="")
        self.lbl_remove_acl.grid(row=0, column=0, sticky="w")
        self.remove_acl_var = tk.StringVar(value="")
        self.combo_remove_acl = ttk.Combobox(
            right, textvariable=self.remove_acl_var, state="readonly",
            width=30, values=[])
        self.combo_remove_acl.grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.combo_remove_acl.bind("<<ComboboxSelected>>",
                                   lambda _e: self._show_remove_acls())
        self.remove_all_var = tk.BooleanVar(value=False)
        self.chk_remove_all = ttk.Checkbutton(
            right, text="", variable=self.remove_all_var,
            command=self._toggle_remove_all)
        self.chk_remove_all.grid(row=2, column=0, sticky="w", pady=(4, 0))

        self.lbl_remove_ip = ttk.Label(right, text="")
        self.lbl_remove_ip.grid(row=0, column=1, sticky="w", padx=(16, 0))
        self.ent_remove_ip = ttk.Entry(right, width=20, font=("Consolas", 10))
        self.ent_remove_ip.grid(row=1, column=1, sticky="w",
                                padx=(16, 0), pady=(2, 0))
        self.ent_remove_ip.bind("<Return>", lambda _e: self.preview_remove())
        self.remove_owner_var = tk.BooleanVar(value=True)
        self.chk_remove_owner = ttk.Checkbutton(
            right, text="", variable=self.remove_owner_var)
        self.chk_remove_owner.grid(row=2, column=1, sticky="w",
                                   padx=(16, 0), pady=(4, 0))
        # Removes the person's whole remark block, including entries for
        # their other computers - for someone who left for good.
        self.remove_block_var = tk.BooleanVar(value=False)
        self.chk_remove_block = ttk.Checkbutton(
            right, text="", variable=self.remove_block_var)
        self.chk_remove_block.grid(row=3, column=1, sticky="w",
                                   padx=(16, 0), pady=(2, 0))

        # --- actions ---
        rb = ttk.Frame(self.tab_remove)
        rb.pack(fill="x", padx=10, pady=(0, 6))
        self.btn_remove_preview = ttk.Button(rb, text="",
                                             command=self.preview_remove)
        self.btn_remove_preview.pack(side="left", padx=(0, 6))
        self.btn_remove_copy = ttk.Button(rb, text="", command=self.copy_remove)
        self.btn_remove_copy.pack(side="left", padx=6)
        self.btn_remove_orphans = ttk.Button(rb, text="",
                                             command=self.preview_orphans)
        self.btn_remove_orphans.pack(side="left", padx=6)
        self.btn_remove_clear = ttk.Button(rb, text="", command=self.clear_remove)
        self.btn_remove_clear.pack(side="left", padx=6)
        self.remove_prog = ttk.Progressbar(rb, mode="indeterminate", length=120)

        # --- fetched entries ---
        self.lbl_remove_cur = ttk.Label(self.tab_remove, text="")
        self.lbl_remove_cur.pack(anchor="w", padx=10, pady=(2, 2))
        cur_fr = ttk.Frame(self.tab_remove)
        cur_fr.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.txt_remove_cur = tk.Text(cur_fr, wrap="none", font=("Consolas", 10),
                                      height=7, state="disabled")
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

        # --- result: one block per device, scrollable ---
        self.lbl_remove_stats = ttk.Label(self.tab_remove, text="",
                                          foreground="blue")
        self.lbl_remove_stats.pack(anchor="w", padx=10)
        self.lbl_remove_warn = ttk.Label(self.tab_remove, text="",
                                         foreground="#b36b00",
                                         wraplength=980, justify="left")
        self.lbl_remove_warn.pack(anchor="w", fill="x", padx=10)
        self.lbl_remove_prop = ttk.Label(self.tab_remove, text="")
        self.lbl_remove_prop.pack(anchor="w", padx=10, pady=(4, 2))

        prop_fr = ttk.Frame(self.tab_remove)
        prop_fr.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self._remove_canvas = tk.Canvas(prop_fr, highlightthickness=0,
                                        borderwidth=0)
        p_ys = ttk.Scrollbar(prop_fr, orient="vertical",
                             command=self._remove_canvas.yview)
        self._remove_canvas.configure(yscrollcommand=p_ys.set)
        self._remove_canvas.grid(row=0, column=0, sticky="nsew")
        p_ys.grid(row=0, column=1, sticky="ns")
        prop_fr.grid_rowconfigure(0, weight=1)
        prop_fr.grid_columnconfigure(0, weight=1)

        self._remove_blocks_frame = ttk.Frame(self._remove_canvas)
        self._remove_win = self._remove_canvas.create_window(
            (0, 0), window=self._remove_blocks_frame, anchor="nw")
        self._remove_blocks_frame.bind(
            "<Configure>", lambda _e: self._update_remove_scroll())
        self._remove_canvas.bind("<Configure>",
                                 self._on_remove_canvas_configure)
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._remove_canvas.bind(seq, self._on_remove_mousewheel)

    def _toggle_remove_all(self):
        state = "disabled" if self.remove_all_var.get() else "readonly"
        try:
            self.combo_remove_acl.configure(state=state)
        except tk.TclError:
            pass
        self._show_remove_acls()

    def _apply_remove_language(self):
        S = STRINGS[self.lang]
        self.lbl_remove_dev.configure(text=S["remove_dev_label"])
        self.btn_remove_fetch.configure(text=S["audit_fetch_btn"])
        self.lbl_remove_acl.configure(text=S["remove_acl_label"])
        self.chk_remove_all.configure(text=S["remove_all_label"])
        self.lbl_remove_ip.configure(text=S["remove_ip_label"])
        self.chk_remove_owner.configure(text=S["remove_owner_label"])
        self.chk_remove_block.configure(text=S["remove_block_label"])
        self.btn_remove_preview.configure(text=S["remove_preview_btn"])
        self.btn_remove_orphans.configure(text=S["remove_orphans_btn"])
        self.btn_remove_copy.configure(text=S["remove_copy_all"])
        self.btn_remove_clear.configure(text=S["clear_btn"])
        self.lbl_remove_cur.configure(text=S["remove_current_label"])
        self.lbl_remove_prop.configure(text=S["remove_proposal_label"])
        self._refresh_remove_hint()
