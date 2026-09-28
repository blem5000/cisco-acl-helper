"""IP tracking tab logic."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

import cisco_ssh
import track
from i18n import STRINGS


class TrackTabMixin:
    """Tab-owned App methods (mixed into App)."""

    def _set_track_text(self, content: str):
        self.txt_track.configure(state="normal")
        self.txt_track.delete("1.0", tk.END)
        self.txt_track.insert("1.0", content)
        self.txt_track.configure(state="disabled")

    def _append_track_text(self, chunk: str):
        self.txt_track.configure(state="normal")
        self.txt_track.insert(tk.END, chunk)
        self.txt_track.see(tk.END)
        self.txt_track.configure(state="disabled")

    def stop_track(self):
        self._track_stop.set()

    def clear_track(self):
        self._track_cont = None
        self.btn_track_cont.pack_forget()
        self.prog_track.configure(value=0)
        self._set_track_text("")

    @staticmethod
    def dev_label(d: dict) -> str:
        """Dropdown display: 'hostname host' when hostname set, else plain host."""
        host = d.get("host", "")
        hn = (d.get("hostname") or "").strip()
        return f"{hn} {host}".strip() if hn else host

    def _lookup_device(self, selection: str) -> dict | None:
        """Find device by dropdown label ('hostname host') or plain host."""
        s = (selection or "").strip()
        if not s:
            return None
        return next((dict(d) for d in self.devices
                     if d.get("host") == s or self.dev_label(d) == s), None)

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
        self._track_stop.clear()
        self.btn_track.configure(state="disabled")
        self.btn_track_stop.configure(state="normal")
        auto = self.track_parent_var.get()
        if auto:
            self.prog_track.configure(mode="indeterminate")
            self.prog_track.start(12)
        else:
            try:
                self.prog_track.stop()
            except tk.TclError:
                pass
            self.prog_track.configure(mode="determinate", maximum=3, value=0)
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
                      use_parent: bool, debug_log, max_hops: int = 10):
        auto = use_parent  # toggle ON = chain automatically, no button
        stop = self._track_stop
        visited: set = set()
        cur = dict(dev)
        hop = 0
        done_sent = False

        def _finish(cont_payload):
            # the UI unfreezes only on track_done - guarantee exactly one
            nonlocal done_sent
            if not done_sent:
                done_sent = True
                self.msg_queue.put(("track_done", cont_payload))

        def _stopped_chunk():
            self.msg_queue.put(("track_chunk", (None, self.T("track_stopped") + "\n")))

        while True:
            if stop.is_set():
                _stopped_chunk()
                break
            host = cur.get("host", "?")
            if host in visited:
                self.msg_queue.put(("track_chunk",
                                    (host, self.T("track_loop").format(host=host) + "\n")))
                break
            if hop >= max_hops:
                self.msg_queue.put(("track_chunk",
                                    (host, self.T("track_max_hops").format(n=max_hops) + "\n")))
                break
            visited.add(host)
            hop += 1
            lines = [f"=== {host} : {ip} ==="]
            cont: dict | None = None
            partner_hop = False
            partner = track.find_partner(devices, cur)
            partner_visited = (partner is None
                               or partner.get("host", "?") in visited)

            def _hop_to_partner():
                """Jump to the HA partner (own stored credentials).

                Returns True when the hop was taken.
                """
                nonlocal cont, partner_hop
                if partner is None or partner_visited:
                    return False
                lines.append(self.T("track_partner_hop").format(
                    host=partner.get("host", "?")))
                cont = dict(partner)
                carry = mac or cur.get("mac", "")
                if carry:
                    cont["mac"] = carry
                partner_hop = True
                return True

            try:
                arp_out = self._track_run(cur, f"show ip arp {ip}", debug_log)
                self.msg_queue.put(("track_prog", 1))
                if stop.is_set():
                    lines.append(self.T("track_stopped"))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                arp = track.parse_arp(arp_out, ip)
                mac, origin = track.resolve_mac(arp, cur.get("mac", ""))
                if mac is None:
                    if _hop_to_partner():
                        self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                        cur = cont
                        continue
                    if arp and arp.get("incomplete"):
                        lines.append(self.T("track_arp_incomplete").format(ip=ip))
                    elif partner is not None:
                        lines.append(self.T("track_arp_none_both").format(
                            ip=ip, host=host,
                            partner=partner.get("host", "?")))
                    else:
                        lines.append(self.T("track_arp_none").format(ip=ip, host=host))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                if origin == "fresh":
                    lines.append(f"ARP: {ip} -> {mac} ({arp.get('interface', '')})".rstrip())
                else:
                    lines.append(self.T("track_mac_parent").format(host=host, mac=mac))

                mac_out = self._track_run(cur, f"show mac address-table address {mac}",
                                          debug_log)
                self.msg_queue.put(("track_prog", 2))
                if stop.is_set():
                    lines.append(self.T("track_stopped"))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                entries = track.parse_mac_table(mac_out, mac)
                if not entries:
                    if _hop_to_partner():
                        self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                        cur = cont
                        continue
                    if partner is not None:
                        lines.append(self.T("track_mac_none_both").format(
                            mac=mac, host=host,
                            partner=partner.get("host", "?")))
                    else:
                        lines.append(self.T("track_mac_none").format(mac=mac, host=host))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                port = entries[0]["port"]
                for e in entries:
                    vlan = f"VLAN {e['vlan']}, " if e.get("vlan") else ""
                    lines.append(f"MAC: {mac} -> {e['port']} ({vlan}{e.get('type', '')})".rstrip())

                cdp_out = self._track_run(cur, "show cdp neighbors detail", debug_log)
                self.msg_queue.put(("track_prog", 3))
                if stop.is_set():
                    lines.append(self.T("track_stopped"))
                    self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                    break
                nb = track.find_cdp_on_port(track.parse_cdp_detail(cdp_out), port)
                if not nb:
                    lines.append(self.T("track_cdp_none").format(port=port, host=host))
                    if track.is_portchannel(port):
                        # Port-channel with no CDP info usually leads to the
                        # HA partner - follow it with the partner's own creds.
                        _hop_to_partner()
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
                                cont[k] = cur.get(k, cont.get(k))
                    elif use_parent and nb.get("ip"):
                        # neighbor not in the list: reach it with parent creds
                        cont = {"hostname": nb.get("device", ""), "host": nb["ip"],
                                "username": cur.get("username", ""),
                                "password": cur.get("password", ""),
                                "enable": cur.get("enable", ""),
                                "port": cur.get("port", 22)}
                    if cont is not None:
                        cont["mac"] = mac  # carry over for the next hop
            except Exception as e:
                lines.append(f"*** ERROR on {host}: {e} ***")
                self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                break
            else:
                self.msg_queue.put(("track_chunk", (host, "\n".join(lines) + "\n")))
                proceed = auto or partner_hop
                if cont is None or not proceed:
                    _finish(cont if not auto else None)
                    break
                cur = cont
        _finish(None)

    # ---------- search tab ----------

    def _build_track_tab(self):
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
        self.track_all_var = tk.BooleanVar(value=False)
        self.chk_track_all = ttk.Checkbutton(tf, text="",
                                             variable=self.track_all_var,
                                             command=self._refresh_gen_devices)
        self.chk_track_all.grid(row=1, column=2, sticky="w", padx=(16, 0), pady=4)

        tbtns = ttk.Frame(self.tab_track)
        tbtns.pack(fill="x", padx=10, pady=(0, 8))
        self.btn_track = ttk.Button(tbtns, text="", command=self.trace_ip)
        self.btn_track.pack(side="left", padx=(0, 6))
        self.btn_track_stop = ttk.Button(tbtns, text="", command=self.stop_track,
                                         state="disabled")
        self.btn_track_stop.pack(side="left", padx=6)
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

    def _apply_track_language(self):
        S = STRINGS[self.lang]
        self.lbl_track_ip.configure(text=S["track_ip_label"])
        self.lbl_track_dev.configure(text=S["track_dev_label"])
        self.btn_track.configure(text=S["track_btn"])
        self.btn_track_stop.configure(text=S["stop_btn"])
        self.btn_track_clear.configure(text=S["clear_btn"])
        self.chk_track_all.configure(text=S["track_all"])
        self.chk_track_parent.configure(text=S["track_parent_creds"])
        self.lbl_track_results.configure(text=S["results_label"])
