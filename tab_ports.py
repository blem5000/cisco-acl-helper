"""Unused switchport tab logic."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

import cisco_ssh
import ports as ports_mod
from i18n import STRINGS


class PortsTabMixin:
    """Tab-owned App methods (mixed into App)."""

    def _set_ports_text(self, content: str):
        self.txt_ports.configure(state="normal")
        self.txt_ports.delete("1.0", tk.END)
        self.txt_ports.insert("1.0", content)
        self.txt_ports.configure(state="disabled")

    def clear_ports(self):
        self._ports_report = ""
        self._set_ports_text("")
        self.lbl_ports_stats.configure(text="")

    def copy_ports(self):
        if not self._ports_report.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self._ports_report)
        self._toast(self.T("copied"))

    def check_ports(self):
        if self._ports_fetching:
            return
        if not self._require_unlocked():
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        dev = self._lookup_device(self.ports_dev_var.get().strip())
        if dev is None:
            messagebox.showwarning("ACL", self.T("ports_need_dev"))
            return
        try:
            months = int(self.ports_months_var.get().strip())
            if months < 1:
                raise ValueError
        except (ValueError, AttributeError):
            messagebox.showwarning("ACL", self.T("ports_bad_months"))
            return
        self._ports_fetching = True
        self.btn_ports_check.configure(state="disabled")
        self.ports_prog.pack(side="left", padx=(14, 0))
        self.ports_prog.start(12)
        self.status.set(self.T("ports_fetching").format(host=dev["host"]))
        threading.Thread(target=self._ports_worker,
                         args=(dev, months, self.ports_sfp_var.get()),
                         daemon=True).start()

    def _ports_worker(self, dev: dict, months: int, skip_sfp: bool):
        try:
            res = cisco_ssh.run_commands(
                dev["host"], dev["username"], dev.get("password", ""),
                dev.get("enable") or None, int(dev.get("port", 22)),
                commands=["show interfaces", "show inventory"],
                debug_log=self._ssh_debug_log())
            out = res.get("show interfaces", "")
            if not out.strip():
                raise RuntimeError("Empty response - check privileges.")
            ifs = ports_mod.parse_show_interfaces(out)
            stocked = ports_mod.parse_inventory_transceivers(
                res.get("show inventory", ""))
            physical = [e for e in ifs if ports_mod.is_physical(e.get("name", ""))]
            skipped = sum(1 for e in physical
                          if skip_sfp and (ports_mod.is_sfp(e.get("name", ""))
                                           or ports_mod.canon_name(
                                               e.get("name", "")) in stocked))
            unused = ports_mod.find_unused(physical, months, skip_sfp,
                                           stocked)
            self.msg_queue.put(("ports_list", (dev["host"], months, physical,
                                              unused, skipped,
                                              ports_mod.common_clearing(ifs))))
        except Exception as e:
            self.msg_queue.put(("ports_error", (dev["host"], str(e))))

    def _finish_ports(self, host: str, months: int, physical: list,
                      unused: list, skipped: int, clearing: str):
        self._ports_fetching = False
        self.btn_ports_check.configure(state="normal")
        try:
            self.ports_prog.stop()
        except tk.TclError:
            pass
        self.ports_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        checked = len(physical) - skipped
        lines = [self.T("device_hdr").format(host=host)]
        if clearing:
            lines.append(self.T("ports_clearing").format(v=clearing))
        lines.append(self.T("ports_summary").format(m=months, n=len(unused),
                                                    total=checked))
        if skipped:
            lines.append(self.T("ports_sfp_note").format(n=skipped))
        lines.append("")
        for e in unused:
            desc = f"  {e['description']}" if e.get("description") else ""
            lines.append(f"{e['name']:22} {e['status']:10} "
                         f"in: {e.get('last_input') or '-':12} "
                         f"out: {e.get('last_output') or '-'}{desc}")
        if not unused:
            lines.append(self.T("ports_none"))
        self._ports_report = "\n".join(lines) + "\n"
        self._set_ports_text(self._ports_report)
        self.lbl_ports_stats.configure(text=self.T("ports_summary").format(
            m=months, n=len(unused), total=checked))

    def _finish_ports_error(self, host: str, err: str):
        self._ports_fetching = False
        self.btn_ports_check.configure(state="normal")
        try:
            self.ports_prog.stop()
        except tk.TclError:
            pass
        self.ports_prog.pack_forget()
        self.status.set(self.T("status_ready"))
        messagebox.showerror(
            "ACL", self.T("gen_fetch_fail").format(host=host, err=err))

    def _build_ports_tab(self):
        # --- Tab: unused switchports (show interfaces last input/output) ---
        self.tab_ports = ttk.Frame(self.nb)
        self.nb.add(self.tab_ports, text="ports")
        pf = ttk.Frame(self.tab_ports)
        pf.pack(fill="x", padx=10, pady=10)
        self.lbl_ports_dev = ttk.Label(pf, text="")
        self.lbl_ports_dev.grid(row=0, column=0, sticky="w")
        self.ports_dev_var = tk.StringVar(value="")
        self.combo_ports_dev = ttk.Combobox(pf, textvariable=self.ports_dev_var,
                                            state="readonly", width=24, values=[])
        self.combo_ports_dev.grid(row=1, column=0, sticky="w", pady=4)
        self.lbl_ports_months = ttk.Label(pf, text="")
        self.lbl_ports_months.grid(row=0, column=1, sticky="w", padx=(16, 0))
        self.ports_months_var = tk.StringVar(value="3")
        # lazy import: app.py imports this mixin, so top-level would cycle
        from app import load_ports_months, save_ports_months
        self.ports_months_var.set(load_ports_months())
        self.ports_months_var.trace_add(
            "write", lambda *_a: save_ports_months(
                self.ports_months_var.get()))
        self.ent_ports_months = ttk.Entry(pf, textvariable=self.ports_months_var,
                                          width=8, font=("Consolas", 11))
        self.ent_ports_months.grid(row=1, column=1, sticky="w",
                                   padx=(16, 0), pady=4)
        self.btn_ports_check = ttk.Button(pf, text="",
                                          command=self.check_ports)
        self.btn_ports_check.grid(row=1, column=2, padx=8)
        self.ports_sfp_var = tk.BooleanVar(value=True)
        # lazy import: app.py imports this mixin, so top-level would cycle
        from app import load_ports_sfp, save_ports_sfp
        self.ports_sfp_var.set(load_ports_sfp())
        self.ports_sfp_var.trace_add(
            "write", lambda *_a: save_ports_sfp(self.ports_sfp_var.get()))
        self.chk_ports_sfp = ttk.Checkbutton(pf, text="",
                                             variable=self.ports_sfp_var)
        self.chk_ports_sfp.grid(row=2, column=0, columnspan=3, sticky="w",
                                pady=(6, 0))

        pbtns = ttk.Frame(self.tab_ports)
        pbtns.pack(fill="x", padx=10, pady=(0, 8))
        self.btn_ports_copy = ttk.Button(pbtns, text="",
                                         command=self.copy_ports)
        self.btn_ports_copy.pack(side="left", padx=(0, 6))
        self.btn_ports_clear = ttk.Button(pbtns, text="",
                                          command=self.clear_ports)
        self.btn_ports_clear.pack(side="left", padx=6)
        self.ports_prog = ttk.Progressbar(pbtns, mode="indeterminate",
                                          length=120)

        self.lbl_ports_stats = ttk.Label(self.tab_ports, text="",
                                         foreground="blue")
        self.lbl_ports_stats.pack(anchor="w", padx=10)
        self.lbl_ports_results = ttk.Label(self.tab_ports, text="")
        self.lbl_ports_results.pack(anchor="w", padx=10, pady=(2, 2))
        res_fr = ttk.Frame(self.tab_ports)
        res_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_ports = tk.Text(res_fr, wrap="none", font=("Consolas", 10),
                                 state="disabled")
        pys = ttk.Scrollbar(res_fr, orient="vertical",
                            command=self.txt_ports.yview)
        pxs = ttk.Scrollbar(res_fr, orient="horizontal",
                            command=self.txt_ports.xview)
        self.txt_ports.configure(yscrollcommand=pys.set,
                                 xscrollcommand=pxs.set)
        self.txt_ports.grid(row=0, column=0, sticky="nsew")
        pys.grid(row=0, column=1, sticky="ns")
        pxs.grid(row=1, column=0, sticky="ew")
        res_fr.grid_rowconfigure(0, weight=1)
        res_fr.grid_columnconfigure(0, weight=1)

    def _apply_ports_language(self):
        S = STRINGS[self.lang]
        self.lbl_ports_dev.configure(text=S["ports_dev_label"])
        self.lbl_ports_months.configure(text=S["ports_months_label"])
        self.btn_ports_check.configure(text=S["ports_check_btn"])
        self.chk_ports_sfp.configure(text=S["ports_sfp_label"])
        self.btn_ports_copy.configure(text=S["copy_btn"])
        self.btn_ports_clear.configure(text=S["clear_btn"])
        self.lbl_ports_results.configure(text=S["results_label"])
