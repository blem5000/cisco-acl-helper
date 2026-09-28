"""ACL search tab logic."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import acl_parser
import cisco_ssh
from i18n import STRINGS


class SearchTabMixin:
    """Tab-owned App methods (mixed into App)."""

    def _set_text(self, content: str):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", tk.END)
        self.txt.insert("1.0", content)
        self.txt.configure(state="disabled")

    def _append_text(self, chunk: str):
        self.txt.configure(state="normal")
        self.txt.insert(tk.END, chunk)
        self.txt.see(tk.END)
        self.txt.configure(state="disabled")

    def clear_results(self):
        self.last_results = []
        self.copy_host_var.set("")
        self.copy_combo.configure(values=[])
        self.prog.configure(value=0)
        self._set_text("")

    def _refresh_copy_combo(self):
        """List only devices with actual hits; keep selection if still valid."""
        hosts = [h for h, f, e in self.last_results if f and not e]
        labels = [self._copy_label(h) for h in hosts]
        self.copy_combo.configure(values=labels)
        if self.copy_host_var.get() not in labels:
            self.copy_host_var.set(labels[0] if labels else "")

    def _copy_label(self, host: str) -> str:
        dev = self._lookup_device(host)
        return self.dev_label(dev) if dev else host

    def copy_results(self):
        # Copy ONLY the selected device's paste-safe CLI lines
        # (device context as "!" comments, ACL headers, ACE lines),
        # ending with Enter so the last line runs.
        sel = self.copy_host_var.get().strip()
        dev = self._lookup_device(sel)
        host = dev["host"] if dev else sel
        picked = [(h, f, e) for h, f, e in self.last_results if h == host and f and not e]
        if not picked:
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        script = acl_parser.format_cli_script(picked, self.negate_var.get())
        if not script.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(script)
        self._toast(self.T("copied"))

    def export_results(self):
        content = self.txt.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        path = filedialog.asksaveasfilename(
            title=self.T("export_title"),
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            messagebox.showinfo("ACL", self.T("saved").format(path=path))

    def _valid_ip(self, s: str) -> bool:
        try:
            ipaddress.ip_address(s.strip())
            return True
        except ValueError:
            return False

    def start_search(self):
        if self.searching:
            return
        if not self._require_unlocked():
            return
        ip = self.ent_ip.get().strip()
        if not ip:
            messagebox.showwarning("ACL", self.T("status_bad_query"))
            return
        by_ip = self._valid_ip(ip)
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        self.last_ip = ip
        self.last_results = []
        self.copy_host_var.set("")
        self.copy_combo.configure(values=[])
        self._set_text("")
        self.searching = True
        self.stop_event.clear()
        self.btn_search.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.prog.configure(maximum=len(self.devices), value=0)
        self.status.set(self.T("status_searching").format(n=len(self.devices)))
        threading.Thread(target=self._search_worker, args=(ip, by_ip),
                         daemon=True).start()

    def stop_search(self):
        self.stop_event.set()

    def _search_worker(self, ip: str, by_ip: bool = True):
        negate = self.negate_var.get()
        total_hits = 0
        done_devs = 0

        def one_device(d: dict):
            host = d["host"]
            try:
                cfg = cisco_ssh.fetch_config(host, d["username"], d.get("password", ""),
                                             d.get("enable") or None, int(d.get("port", 22)),
                                             debug_log=self._ssh_debug_log())
                acls = acl_parser.parse_running_config(cfg)
                if by_ip:
                    found = acl_parser.find_ip(acls, ip)
                else:
                    found = acl_parser.find_text(acls, ip)
                return (host, found, None)
            except Exception as e:
                return (host, {}, str(e))

        # keep original order: submit in order, collect in order
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(self.devices))) as ex:
            futs = [ex.submit(one_device, d) for d in self.devices]
            for fut in futs:
                if self.stop_event.is_set():
                    for f in futs:
                        f.cancel()
                    break
                try:
                    host, found, err = fut.result()
                except Exception as e:
                    host, found, err = ("?", {}, str(e))
                self.msg_queue.put(("chunk", (host, found, err)))

        self.msg_queue.put(("done", None))

    def rerender_results(self):
        """Re-render cached results when negation checkbox toggles (no reconnect)."""
        if not self.last_results:
            return
        negate = self.negate_var.get()
        parts: list[str] = []
        for host, found, err in self.last_results:
            parts.append(self.T("device_hdr").format(host=host))
            if err:
                parts.append(self.T("err_hdr").format(host=host, err=err))
            elif not found:
                parts.append(self.T("no_results").format(ip=self.last_ip))
            else:
                parts.append(acl_parser.format_results(found, negate=negate))
            parts.append("")
        self._set_text("\n".join(parts).rstrip() + "\n")

    # ---------- background msg pump ----------

    def _build_search_tab(self):
        # --- Tab 1: search ---
        self.tab_search = ttk.Frame(self.nb)
        self.nb.add(self.tab_search, text="search")
        sf = ttk.Frame(self.tab_search)
        sf.pack(fill="x", padx=10, pady=10)
        self.lbl_ip = ttk.Label(sf, text="")
        self.lbl_ip.grid(row=0, column=0, sticky="w")
        self.ent_ip = ttk.Entry(sf, width=24, font=("Consolas", 11))
        self.ent_ip.grid(row=1, column=0, sticky="w", pady=4)
        self.ent_ip.insert(0, "")
        self.btn_search = ttk.Button(sf, text="", command=self.start_search)
        self.btn_search.grid(row=1, column=1, padx=8)
        self.btn_stop = ttk.Button(sf, text="", command=self.stop_search, state="disabled")
        self.btn_stop.grid(row=1, column=2, padx=4)
        self.negate_var = tk.BooleanVar(value=False)
        self.chk_neg = ttk.Checkbutton(sf, text="", variable=self.negate_var,
                                       command=self.rerender_results)
        self.chk_neg.grid(row=2, column=0, columnspan=2, sticky="w", pady=4)

        btns = ttk.Frame(self.tab_search)
        btns.pack(fill="x", padx=10)
        self.btn_copy = ttk.Button(btns, text="", command=self.copy_results)
        self.btn_copy.pack(side="left", padx=(0, 6))
        self.btn_export = ttk.Button(btns, text="", command=self.export_results)
        self.btn_export.pack(side="left", padx=6)
        self.btn_clear = ttk.Button(btns, text="", command=self.clear_results)
        self.btn_clear.pack(side="left", padx=6)
        self.lbl_copy_from = ttk.Label(btns, text="")
        self.lbl_copy_from.pack(side="left", padx=(18, 4))
        self.copy_host_var = tk.StringVar(value="")
        self.copy_combo = ttk.Combobox(btns, textvariable=self.copy_host_var,
                                       state="readonly", width=20, values=[])
        self.copy_combo.pack(side="left")

        self.prog = ttk.Progressbar(self.tab_search, mode="determinate")
        self.prog.pack(fill="x", padx=10, pady=(6, 0))

        self.lbl_results = ttk.Label(self.tab_search, text="")
        self.lbl_results.pack(anchor="w", padx=10, pady=(8, 2))
        txt_fr = ttk.Frame(self.tab_search)
        txt_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt = tk.Text(txt_fr, wrap="none", font=("Consolas", 10), state="disabled")
        ys = ttk.Scrollbar(txt_fr, orient="vertical", command=self.txt.yview)
        xs = ttk.Scrollbar(txt_fr, orient="horizontal", command=self.txt.xview)
        self.txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.txt.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        txt_fr.grid_rowconfigure(0, weight=1)
        txt_fr.grid_columnconfigure(0, weight=1)

    def _apply_search_language(self):
        S = STRINGS[self.lang]
        self.lbl_ip.configure(text=S["search_ip_label"])
        self.btn_search.configure(text=S["search_btn"])
        self.btn_stop.configure(text=S["stop_btn"])
        self.chk_neg.configure(text=S["negate_label"])
        self.btn_copy.configure(text=S["copy_btn"])
        self.lbl_copy_from.configure(text=S["copy_from_label"])
        self.btn_export.configure(text=S["export_btn"])
        self.btn_clear.configure(text=S["clear_btn"])
        self.lbl_results.configure(text=S["results_label"])
