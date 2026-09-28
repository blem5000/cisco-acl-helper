"""ACL generator tab logic."""

from __future__ import annotations

import ipaddress
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import acl_parser
import cisco_ssh
import dhcp_check
from i18n import STRINGS


class GeneratorTabMixin:
    """Tab-owned App methods (mixed into App)."""

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

    def _track_visible_devices(self) -> list[dict]:
        """Start devices for IP tracking: L3 switches, primaries by default.

        Secondaries of HA pairs are hidden unless 'all devices' is ticked
        (a trace always starts from the primary of a pair).
        """
        try:
            show_all = bool(self.track_all_var.get())
        except (tk.TclError, AttributeError):
            show_all = True
        out = []
        for d in self.devices:
            if not d.get("host"):
                continue
            if show_all:
                out.append(d)
                continue
            if not d.get("l3", True):
                continue
            if (d.get("ha_role") or "") == "secondary":
                continue
            out.append(d)
        return out

    def _refresh_gen_devices(self):
        labels = [self.dev_label(d) for d in self.devices if d.get("host")]
        self.combo_gen_dev.configure(values=labels)
        if self.gen_dev_var.get() not in labels:
            cur = self._lookup_device(self.gen_dev_var.get().strip())
            self.gen_dev_var.set(self.dev_label(cur) if cur else (labels[0] if labels else ""))
        track_devs = self._track_visible_devices()
        track_labels = [self.dev_label(d) for d in track_devs]
        self.combo_track_dev.configure(values=track_labels)
        if self.track_dev_var.get() not in track_labels:
            cur = self._lookup_device(self.track_dev_var.get().strip())
            if cur is not None and any(cur.get("host") == d.get("host")
                                       for d in track_devs):
                self.track_dev_var.set(self.dev_label(cur))
            else:
                self.track_dev_var.set(track_labels[0] if track_labels else "")
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

    def _build_gen_tab(self):
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

    def _apply_gen_language(self):
        S = STRINGS[self.lang]
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
