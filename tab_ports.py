"""Unused switchport tab logic."""

from __future__ import annotations

import concurrent.futures
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import cisco_ssh
import ports as ports_mod
from i18n import STRINGS


def rack_names(devices: list[dict]) -> list[str]:
    """Sorted unique non-empty group (rack) names."""
    return sorted({(d.get("group") or "").strip() for d in devices or []}
                  - {""})


def rack_devices(devices: list[dict], group: str) -> list[dict]:
    """Devices of one rack, in list order."""
    want = (group or "").strip()
    return [d for d in devices or [] if (d.get("group") or "").strip() == want
            and d.get("host")]


def fetch_ports_data(dev: dict, months: int, skip_sfp: bool,
                     with_power: bool = False,
                     debug_log: str | None = None) -> dict:
    """Fetch and parse port data for one device (shared by both workers).

    `with_power` also runs `show power inline` for the optimization view.
    Returns physical interfaces, the unused subset, skipped SFP count,
    clearing value and (optionally) the parsed PoE snapshot.
    """
    commands = ["show interfaces", "show inventory",
                "show interfaces status"]
    if with_power:
        commands.append("show power inline")
    res = cisco_ssh.run_commands(
        dev["host"], dev["username"], dev.get("password", ""),
        dev.get("enable") or None, int(dev.get("port", 22)),
        commands=commands, debug_log=debug_log)
    out = res.get("show interfaces", "")
    if not out.strip():
        raise RuntimeError("Empty response - check privileges.")
    ifs = ports_mod.parse_show_interfaces(out)
    stocked = ports_mod.parse_inventory_transceivers(
        res.get("show inventory", ""))
    for name, typ in ports_mod.parse_status_types(
            res.get("show interfaces status", "")).items():
        if ports_mod.is_fiber_type(typ):
            stocked.add(name)
    physical = [e for e in ifs
                if ports_mod.is_physical(e.get("name", ""))]
    skipped = sum(1 for e in physical
                  if skip_sfp and (ports_mod.is_sfp(e.get("name", ""))
                                   or ports_mod.canon_name(
                                       e.get("name", "")) in stocked))
    unused = ports_mod.find_unused(physical, months, skip_sfp, stocked)
    poe = (ports_mod.parse_power_inline(res.get("show power inline", ""))
           if with_power else {})
    return {"physical": physical, "unused": unused, "skipped": skipped,
            "clearing": ports_mod.common_clearing(ifs), "poe": poe}


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

    def _ports_set_busy(self, busy: bool):
        """Disable both actions and run/hide the shared progress bar."""
        state = "disabled" if busy else "normal"
        self.btn_ports_check.configure(state=state)
        self.btn_ports_optimize.configure(state=state)
        if busy:
            self.ports_prog.pack(side="left", padx=(14, 0))
            self.ports_prog.start(12)
            return
        try:
            self.ports_prog.stop()
        except tk.TclError:
            pass
        self.ports_prog.pack_forget()

    def _ports_job_targets(self) -> tuple[str, int, list[dict]] | None:
        """Validate the form and return (rack, months, devices)."""
        if self._ports_fetching:
            return None
        if not self._require_unlocked():
            return None
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return None
        try:
            months = int(self.ports_months_var.get().strip())
            if months < 1:
                raise ValueError
        except (ValueError, AttributeError):
            messagebox.showwarning("ACL", self.T("ports_bad_months"))
            return None
        if self.ports_scope_var.get() == "rack":
            group = self.ports_group_var.get().strip()
            devs = rack_devices(self.devices, group)
            if not devs:
                messagebox.showwarning("ACL", self.T("ports_need_group"))
                return None
        else:
            dev = self._lookup_device(self.ports_dev_var.get().strip())
            if dev is None:
                messagebox.showwarning("ACL", self.T("ports_need_dev"))
                return None
            devs = [dev]
            group = ""
        return group, months, devs

    def check_ports(self):
        targets = self._ports_job_targets()
        if targets is None:
            return
        group, months, devs = targets
        self._ports_fetching = True
        self._ports_set_busy(True)
        if group:
            self.status.set(self.T("ports_fetching_rack").format(group=group,
                                                                 n=len(devs)))
        else:
            self.status.set(self.T("ports_fetching").format(host=devs[0]["host"]))
        threading.Thread(target=self._ports_rack_worker,
                         args=(group, months, self.ports_sfp_var.get(),
                               [dict(d) for d in devs], self._ssh_debug_log()),
                         daemon=True).start()

    def optimize_ports(self):
        """Run the switch-reduction analysis (ports + PoE + idle months)."""
        targets = self._ports_job_targets()
        if targets is None:
            return
        group, months, devs = targets
        self._ports_fetching = True
        self._ports_set_busy(True)
        if group:
            self.status.set(self.T("ports_optimize_fetching").format(
                group=group, n=len(devs)))
        else:
            self.status.set(self.T("ports_optimize_fetching_dev").format(
                host=devs[0]["host"]))
        threading.Thread(target=self._ports_opt_worker,
                         args=(group, months, self.ports_sfp_var.get(),
                               [dict(d) for d in devs], self._ssh_debug_log()),
                         daemon=True).start()

    def _ports_rack_worker(self, group: str, months: int, skip_sfp: bool,
                             devs: list[dict], debug_log: str | None = None):
        """Check one device or a whole rack (parallel, like search)."""
        results: dict[str, tuple] = {}

        def one(d: dict):
            host = d["host"]
            try:
                data = fetch_ports_data(d, months, skip_sfp,
                                        debug_log=debug_log)
                return (host, (data["physical"], data["unused"],
                               data["skipped"], data["clearing"], ""))
            except Exception as e:
                return (host, ([], [], 0, "", str(e)))

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(5, len(devs))) as ex:
            for host, payload in ex.map(one, devs):
                results[host] = payload
        ordered = [(d["host"], results[d["host"]]) for d in devs]
        if group:
            self.msg_queue.put(("ports_rack_list",
                                (group, months, ordered)))
        else:
            host, (physical, unused, skipped, clearing, err) = ordered[0]
            if err:
                self.msg_queue.put(("ports_error", (host, err)))
            else:
                self.msg_queue.put(("ports_list", (host, months, physical,
                                                  unused, skipped, clearing)))

    def _ports_opt_worker(self, group: str, months: int, skip_sfp: bool,
                          devs: list[dict], debug_log: str | None = None):
        """Fetch PoE + ports for the reduction analysis (parallel)."""
        results: dict[str, dict] = {}

        def one(d: dict):
            host = d["host"]
            try:
                data = fetch_ports_data(d, months, skip_sfp, with_power=True,
                                        debug_log=debug_log)
                return host, ports_mod.switch_snapshot(
                    host, data["physical"], data["unused"],
                    data["skipped"], data["poe"])
            except Exception as e:
                return host, {"host": host, "err": str(e)}

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(5, len(devs))) as ex:
            for host, snap in ex.map(one, devs):
                results[host] = snap
        ordered = [results[d["host"]] for d in devs]
        self.msg_queue.put(("ports_opt_list", (group, months, ordered)))

    def _ports_worker(self, dev: dict, months: int, skip_sfp: bool):
        # kept for compatibility: single device goes through the rack worker
        self._ports_rack_worker("", months, skip_sfp, [dev])

    def _finish_ports(self, host: str, months: int, physical: list,
                      unused: list, skipped: int, clearing: str):
        self._ports_fetching = False
        self._ports_set_busy(False)
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

    def _finish_ports_rack(self, group: str, months: int, ordered: list):
        self._ports_fetching = False
        self._ports_set_busy(False)
        self.status.set(self.T("status_ready"))
        lines = [self.T("ports_rack_hdr").format(group=group, n=len(ordered))]
        total, ok = 0, 0
        for host, (physical, unused, skipped, clearing, err) in ordered:
            lines.append("")
            lines.append(self.T("device_hdr").format(host=host))
            if err:
                lines.append(self.T("err_hdr").format(host=host, err=err))
                continue
            ok += 1
            total += len(unused)
            if clearing:
                lines.append(self.T("ports_clearing").format(v=clearing))
            lines.append(self.T("ports_summary").format(
                m=months, n=len(unused), total=len(physical) - skipped))
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
        lines.append("")
        lines.append(self.T("ports_rack_total").format(group=group, n=total,
                                                       ok=ok, d=len(ordered)))
        self._ports_report = "\n".join(lines) + "\n"
        self._set_ports_text(self._ports_report)
        self.lbl_ports_stats.configure(text=self.T("ports_rack_total").format(
            group=group, n=total, ok=ok, d=len(ordered)))

    def _ports_num(self, value) -> str:
        """One-decimal number for the report (comma in Polish)."""
        if value is None:
            return self.T("ports_opt_na")
        text = f"{float(value):.1f}"
        return text.replace(".", ",") if self.lang == "pl" else text

    def _ports_months(self, value) -> str:
        return (self.T("ports_opt_never") if value is None
                else self._ports_num(value))

    def _finish_ports_optimize(self, group: str, months: int,
                               rows: list[dict]):
        """Render the switch-reduction report (idle months + PoE + ports)."""
        self._ports_fetching = False
        self._ports_set_busy(False)
        self.status.set(self.T("status_ready"))
        S = STRINGS[self.lang]
        plan = ports_mod.plan_reduction(rows)
        ok = [r for r in rows if not r.get("err")]
        lines: list[str] = []
        if group:
            lines.append(S["ports_opt_hdr"].format(group=group, n=len(rows)))
        else:
            host = rows[0].get("host", "") if rows else ""
            lines.append(S["ports_opt_hdr_dev"].format(host=host))
        lines.append(S["ports_opt_criteria"].format(m=months))
        lines.append("")
        lines.append(
            f"{S['ports_opt_col_switch']:20} "
            f"{S['ports_opt_col_ports']:>11} "
            f"{S['ports_opt_col_free']:>5} "
            f"{S['ports_opt_col_poe']:>20} "
            f"{S['ports_opt_col_idle']:>11} "
            f"{S['ports_opt_col_idle_poe']:>16} "
            f"{S['ports_opt_col_avg']:>10}")
        lines.append("-" * 102)
        for r in rows:
            if r.get("err"):
                lines.append(S["ports_opt_err"].format(
                    host=r.get("host", ""), err=r["err"]))
                continue
            if (r.get("poe_used") is None
                    and r.get("poe_left") is None):
                poe = S["ports_opt_na"]
            else:
                poe = (f"{self._ports_num(r.get('poe_used'))}/"
                       f"{self._ports_num(r.get('poe_left'))}")
            idle_poe = (f"{self._ports_num(r.get('idle_poe_watts'))} "
                        f"({r.get('idle_poe_ports', 0)})")
            avg = ("-" if not r.get("idle_count")
                   else self._ports_months(r.get("idle_avg")))
            lines.append(
                f"{r.get('host', ''):20} "
                f"{r.get('used', 0):>4}/{r.get('total', 0):<5} "
                f"{r.get('free', 0):>5} {poe:>20} "
                f"{r.get('idle_count', 0):>11} {idle_poe:>16} "
                f"{avg:>10}")
        lines.append("")

        if ok:
            total_ports = sum(r.get("total", 0) for r in ok)
            used_ports = sum(r.get("used", 0) for r in ok)
            known_used = [r for r in ok if r.get("poe_used") is not None]
            known_left = [r for r in ok if r.get("poe_left") is not None]
            pused = (self._ports_num(sum(float(r["poe_used"])
                                         for r in known_used))
                     if known_used else S["ports_opt_na"])
            pleft = (self._ports_num(sum(float(r["poe_left"])
                                         for r in known_left))
                     if known_left else S["ports_opt_na"])
            idle_n = sum(r.get("idle_count", 0) for r in ok)
            idle_poe_n = sum(r.get("idle_poe_ports", 0) for r in ok)
            idle_poe_w = sum(r.get("idle_poe_watts", 0.0) for r in ok)
            lines.append(S["ports_opt_total"].format(
                n=len(ok), used=used_ports, total=total_ports,
                pused=pused, pleft=pleft))
            lines.append(S["ports_opt_idle_total"].format(
                m=months, n=idle_n, pw=self._ports_num(idle_poe_w),
                pp=idle_poe_n))
            if any(r.get("poe_left") is None for r in ok):
                lines.append(S["ports_opt_partial"])
        lines.append("")

        if not group:
            lines.append(S["ports_opt_no_data"] if not ok
                         else S["ports_opt_dev_note"])
        elif plan["reason"] == "no_data":
            lines.append(S["ports_opt_no_data"])
        elif plan["reason"] == "single":
            lines.append(S["ports_opt_block_single"])
        elif plan["removable"]:
            lines.append(S["ports_opt_saved"].format(
                k=len(plan["removable"]), left=plan["needed"]))
            for item in plan["removable"]:
                targets = ", ".join(
                    S["ports_opt_target"].format(
                        host=t["host"], ports=t["free"],
                        poe=t.get("poe_free", 0),
                        left=self._ports_num(t.get("left")))
                    for t in item["target_info"])
                lines.append(S["ports_opt_move"].format(
                    host=item["host"], ports=item["ports"],
                    poe_ports=item["poe_ports"],
                    watts=self._ports_num(item["watts"]),
                    targets=targets))
            lines.append(S["ports_opt_keep"].format(
                hosts=", ".join(plan["kept"])))
        else:
            lines.append(S["ports_opt_none"])
            if plan["failed"]:
                f = plan["failed"][0]
                if f["reason"] == "ports":
                    lines.append(S["ports_opt_block_ports"].format(
                        host=f["host"], need=f["ports"],
                        have=max(0, f["free_ports"])))
                elif f["reason"] == "poe_ports":
                    lines.append(S["ports_opt_block_poe_ports"].format(
                        host=f["host"], need=f["poe_ports"],
                        have=max(0, f["free_poe"])))
                elif f["reason"] == "power":
                    lines.append(S["ports_opt_block_power"].format(
                        host=f["host"], need=self._ports_num(f["watts"]),
                        have=self._ports_num(max(0.0, f["left_watts"]))))
                elif f["reason"] == "poe_unknown":
                    lines.append(S["ports_opt_block_poe_unknown"].format(
                        host=f["host"]))

        items = []
        for r in ok:
            for p in r.get("idle") or []:
                if p.get("poe_on"):
                    items.append(S["ports_opt_idle_item"].format(
                        host=r.get("host", ""), name=p.get("name", ""),
                        w=self._ports_num(p.get("watts")),
                        m=self._ports_months(p.get("months"))))
        if items:
            lines.append("")
            lines.append(S["ports_opt_idle_poe"].format(
                items=", ".join(items)))
        lines.append("")
        lines.append(S["ports_opt_note"])
        report = "\n".join(lines) + "\n"
        self._ports_report = report
        self._set_ports_text(report)

        if not group:
            if ok:
                self.lbl_ports_stats.configure(text=S[
                    "ports_opt_dev_stats"].format(
                        n=ok[0].get("idle_count", 0),
                        used=self._ports_num(ok[0].get("poe_used")),
                        left=self._ports_num(ok[0].get("poe_left"))))
            else:
                self.lbl_ports_stats.configure(text=S["ports_opt_no_data"])
        elif plan["removable"]:
            self.lbl_ports_stats.configure(text=S["ports_opt_saved"].format(
                k=len(plan["removable"]), left=plan["needed"]))
        elif plan["reason"] == "no_data":
            self.lbl_ports_stats.configure(text=S["ports_opt_no_data"])
        elif plan["reason"] == "single":
            self.lbl_ports_stats.configure(text=S["ports_opt_block_single"])
        else:
            self.lbl_ports_stats.configure(text=S["ports_opt_none"])

    def _finish_ports_error(self, host: str, err: str):
        self._ports_fetching = False
        self._ports_set_busy(False)
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
        self.btn_ports_optimize = ttk.Button(pf, text="",
                                             command=self.optimize_ports)
        self.btn_ports_optimize.grid(row=1, column=3, padx=(0, 8))
        self.ports_sfp_var = tk.BooleanVar(value=True)
        # lazy import: app.py imports this mixin, so top-level would cycle
        from app import load_ports_sfp, save_ports_sfp
        self.ports_sfp_var.set(load_ports_sfp())
        self.ports_sfp_var.trace_add(
            "write", lambda *_a: save_ports_sfp(self.ports_sfp_var.get()))
        self.chk_ports_sfp = ttk.Checkbutton(pf, text="",
                                             variable=self.ports_sfp_var)
        self.chk_ports_sfp.grid(row=2, column=0, columnspan=4, sticky="w",
                                pady=(6, 0))
        from app import load_ports_scope, save_ports_scope  # lazy: cycle
        scope, grp = load_ports_scope()
        self.ports_scope_var = tk.StringVar(value=scope)
        self.ports_group_var = tk.StringVar(value=grp)
        scope_fr = ttk.Frame(pf)
        scope_fr.grid(row=3, column=0, columnspan=4, sticky="w", pady=(6, 0))
        self.radio_ports_dev = ttk.Radiobutton(
            scope_fr, text="", value="dev", variable=self.ports_scope_var,
            command=self._sync_ports_scope)
        self.radio_ports_dev.pack(side="left")
        self.radio_ports_rack = ttk.Radiobutton(
            scope_fr, text="", value="rack", variable=self.ports_scope_var,
            command=self._sync_ports_scope)
        self.radio_ports_rack.pack(side="left", padx=(12, 0))
        self.combo_ports_group = ttk.Combobox(
            scope_fr, textvariable=self.ports_group_var, state="readonly",
            width=24, values=[])
        self.combo_ports_group.pack(side="left", padx=(8, 0))
        self.ports_scope_var.trace_add(
            "write", lambda *_a: save_ports_scope(
                self.ports_scope_var.get(), self.ports_group_var.get()))
        self.ports_group_var.trace_add(
            "write", lambda *_a: save_ports_scope(
                self.ports_scope_var.get(), self.ports_group_var.get()))
        self._sync_ports_scope()

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

    def _sync_ports_scope(self):
        """Enable only the combo matching the scope (device vs rack)."""
        try:
            rack = self.ports_scope_var.get() == "rack"
        except (tk.TclError, AttributeError):
            rack = False
        try:
            self.combo_ports_dev.configure(state="disabled" if rack
                                           else "readonly")
            self.combo_ports_group.configure(state="readonly" if rack
                                             else "disabled")
        except tk.TclError:
            pass

    def _refresh_ports_groups(self):
        """Rack combo values from device groups; keep selection if valid."""
        names = rack_names(self.devices)
        self.combo_ports_group.configure(values=names)
        if self.ports_group_var.get() not in names:
            self.ports_group_var.set(names[0] if names else "")

    def _apply_ports_language(self):
        S = STRINGS[self.lang]
        self.lbl_ports_dev.configure(text=S["ports_dev_label"])
        self.lbl_ports_months.configure(text=S["ports_months_label"])
        self.btn_ports_check.configure(text=S["ports_check_btn"])
        self.btn_ports_optimize.configure(text=S["ports_optimize_btn"])
        self.chk_ports_sfp.configure(text=S["ports_sfp_label"])
        self.btn_ports_copy.configure(text=S["copy_btn"])
        self.btn_ports_clear.configure(text=S["clear_btn"])
        self.radio_ports_dev.configure(text=S["ports_scope_dev"])
        self.radio_ports_rack.configure(text=S["ports_scope_rack"])
        self.lbl_ports_results.configure(text=S["results_label"])
