"""Vulnerabilities tab logic (all providers, shared workers)."""

from __future__ import annotations

import concurrent.futures
import re
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import cisco_ssh
import vuln_ssh
import vuln_telnet
import vuln_tls
from i18n import STRINGS



class VulnTabMixin:
    """Tab-owned App methods (mixed into App)."""

    def _vuln_registry(self) -> list[tuple[str, str, str]]:
        """Available checks: [(id, display name, description)].

        "Check all" stays first so it is the default selection.
        """
        S = STRINGS[self.lang]
        return [(VULN_ALL_ID, S["vuln_all_name"],
                 S["vuln_all_desc"]),
                (vuln_telnet.VULN_ID, S["vuln_telnet_name"],
                 S["vuln_telnet_desc"]),
                (vuln_ssh.VULN_ID, S["vuln_ssh_name"],
                 S["vuln_ssh_desc"]),
                (vuln_tls.VULN_ID, S["vuln_tls_name"],
                 S["vuln_tls_desc"])]

    @staticmethod
    def _vuln_mod(vuln_id: str):
        return VULN_MODS.get(vuln_id, vuln_telnet)

    @staticmethod
    def _vuln_mods(vuln_id: str) -> list:
        """Provider modules for a registry id (all of them for "all")."""
        if vuln_id == VULN_ALL_ID:
            return [VULN_MODS[vid] for vid in ("telnet", "ssh", "tls")
                    if vid in VULN_MODS]
        return [VULN_MODS.get(vuln_id, vuln_telnet)]

    def _refresh_vuln_combo(self):
        reg = self._vuln_registry()
        names = [name for _vid, name, _desc in reg]
        self.combo_vuln.configure(values=names)
        if self.vuln_id_var.get() not in names:
            self.vuln_id_var.set(names[0] if names else "")
        self._sync_vuln_desc()

    def _sync_vuln_desc(self):
        reg = self._vuln_registry()
        sel = self.vuln_id_var.get()
        for _vid, name, desc in reg:
            if name == sel:
                self.lbl_vuln_desc.configure(text=desc)
                return
        self.lbl_vuln_desc.configure(text="")

    def _selected_vuln_id(self) -> str:
        reg = self._vuln_registry()
        sel = self.vuln_id_var.get()
        for vid, name, _desc in reg:
            if name == sel:
                return vid
        return reg[0][0] if reg else ""

    def _refresh_vuln_devices(self):
        labels = [self.dev_label(d) for d in self.devices if d.get("host")]
        try:
            sel = {self.vuln_listbox.get(i)
                   for i in self.vuln_listbox.curselection()}
        except (tk.TclError, AttributeError):
            sel = set()
        try:
            self.vuln_listbox.delete(0, tk.END)
            for lb in labels:
                self.vuln_listbox.insert(tk.END, lb)
            for i, lb in enumerate(labels):
                if lb in sel:
                    self.vuln_listbox.select_set(i)
        except (tk.TclError, AttributeError):
            pass
        self._refresh_vuln_combo()

    def vuln_select_marked(self):
        """Select rows of devices marked ✓ on the Devices tab."""
        try:
            self.vuln_listbox.select_clear(0, tk.END)
            for i in range(self.vuln_listbox.size()):
                try:
                    label = self.vuln_listbox.get(i)
                except tk.TclError:
                    continue
                dev = self._lookup_device(label.strip())
                if dev is not None and dev.get("audit", True):
                    self.vuln_listbox.select_set(i)
        except tk.TclError:
            pass

    def _selected_vuln_devices(self) -> list[dict]:
        try:
            idxs = list(self.vuln_listbox.curselection())
        except tk.TclError:
            return []
        out = []
        for i in idxs:
            try:
                label = self.vuln_listbox.get(i)
            except tk.TclError:
                continue
            dev = self._lookup_device(label.strip())
            if dev is not None:
                out.append(dev)
        return out

    def _set_vuln_text(self, content: str):
        self.txt_vuln.configure(state="normal")
        self.txt_vuln.delete("1.0", tk.END)
        self.txt_vuln.insert("1.0", content)
        self.txt_vuln.configure(state="disabled")

    def _append_vuln_text(self, chunk: str):
        self.txt_vuln.configure(state="normal")
        self.txt_vuln.insert(tk.END, chunk)
        self.txt_vuln.see(tk.END)
        self.txt_vuln.configure(state="disabled")

    def _insert_vuln_segments(self, segs: list[tuple[str, str | None]],
                              clear: bool = False):
        """Insert pre-tagged lines; tags: vuln_ok (green), vuln_fail (red),
        vuln_warn (orange), None = default color."""
        self.txt_vuln.configure(state="normal")
        if clear:
            self.txt_vuln.delete("1.0", tk.END)
        for text, tag in segs:
            if tag:
                self.txt_vuln.insert(tk.END, text, tag)
            else:
                self.txt_vuln.insert(tk.END, text)
        self.txt_vuln.see(tk.END)
        self.txt_vuln.configure(state="disabled")

    def _set_vuln_prop(self, content: str):
        self.txt_vuln_prop.configure(state="normal")
        self.txt_vuln_prop.delete("1.0", tk.END)
        self.txt_vuln_prop.insert("1.0", content)
        self.txt_vuln_prop.configure(state="disabled")

    def start_vuln_check(self):
        if self._vuln_fetching or self._vuln_applying:
            return
        if not self._require_unlocked():
            return
        devs = self._selected_vuln_devices()
        if not devs:
            # empty list -> fall back to devices marked on the Devices tab
            self.vuln_select_marked()
            devs = self._selected_vuln_devices()
        if not devs:
            messagebox.showwarning("ACL", self.T("vuln_need_dev"))
            return
        if not self.devices:
            messagebox.showwarning("ACL", self.T("status_no_devices"))
            return
        vuln_id = self._selected_vuln_id()
        mods = self._vuln_mods(vuln_id)
        self.vuln_results = []
        self.vuln_proposal = ""
        self._set_vuln_text("")
        self._set_vuln_prop("")
        self._vuln_fetching = True
        self._vuln_stop.clear()
        self.btn_vuln_check.configure(state="disabled")
        self.btn_vuln_apply.configure(state="disabled")
        self.btn_vuln_stop.configure(state="normal")
        self.vuln_prog.configure(maximum=len(devs) * len(mods), value=0,
                                   mode="indeterminate",
                                   style="VulnWork.Horizontal.TProgressbar")
        self.vuln_prog.start(12)
        self.status.set(self.T("status_searching").format(n=len(devs)))
        snapshot = [dict(d) for d in devs]
        threading.Thread(target=self._vuln_worker, args=(snapshot, mods),
                         daemon=True).start()

    def stop_vuln_check(self):
        self._vuln_stop.set()
        # instant feedback: the worker may still wait out SSH timeouts
        self.status.set(self.T("vuln_stopping"))
        try:
            self.btn_vuln_stop.configure(state="disabled")
        except tk.TclError:
            pass

    def _vuln_worker(self, devs: list[dict], mods: list):
        """Check selected switches (up to 5 SSH sessions); one result chunk
        per (device, provider), device-major submission order.

        Results are collected as they finish (FIRST_COMPLETED), so progress
        and Stop stay responsive even with one straggler holding the line.
        On stop, pending tasks are cancelled and running sessions are
        abandoned, not waited out - the UI resets immediately.
        """
        def one_check(args):
            d, mod = args
            host = d.get("host", "?")
            try:
                res = mod.fetch_check_run(
                    host, d["username"], d.get("password", ""),
                    d.get("enable") or None, int(d.get("port", 22)),
                    debug_log=self._ssh_debug_log())
                return (host, res, None)
            except Exception as e:
                return (host, None, str(e))

        def _silence(fut):
            try:
                fut.exception()
            except Exception:
                pass

        tasks = [(d, mod) for d in devs for mod in mods]
        ex = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(5, len(tasks) or 1))
        try:
            futs = {ex.submit(one_check, t) for t in tasks}
            while futs:
                if self._vuln_stop.is_set():
                    break
                finished, _pending = concurrent.futures.wait(
                    futs, timeout=0.5,
                    return_when=concurrent.futures.FIRST_COMPLETED)
                for fut in finished:
                    futs.discard(fut)
                    try:
                        payload = fut.result()
                    except Exception as e:
                        payload = ("?", None, str(e))
                    self.msg_queue.put(("vuln_chunk", payload))
            for fut in futs:
                fut.cancel()
                fut.add_done_callback(_silence)
            ex.shutdown(wait=False, cancel_futures=True)
        except Exception:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        self.msg_queue.put(("vuln_done", None))

    def _finish_vuln_chunk(self, host: str, res: dict | None, err: str | None):
        self.vuln_results.append((host, res, err))
        if err:
            segs = [(self.T("device_hdr").format(host=host) + "\n", None),
                    (self.T("vuln_fetch_fail").format(host=host, err=err)
                     + "\n", "vuln_fail")]
        else:
            mod = self._vuln_mod((res or {}).get("vuln", "telnet"))
            segs = mod.format_result(host, res or {}, self.T)
        empty = not self.txt_vuln.get("1.0", tk.END).strip()
        self._insert_vuln_segments(segs, clear=empty)
        try:
            total = int(self.vuln_prog.cget("maximum") or 0)
            if total:
                self.status.set(self.T("status_progress").format(
                    done=len(self.vuln_results), total=total))
        except tk.TclError:
            pass
        self._rebuild_vuln_proposal()

    def _rebuild_vuln_proposal(self):
        """Combined paste-ready fix, per-device sections as '! ' comments."""
        parts: list[str] = []
        for host, res, err in self.vuln_results:
            if err or not res:
                continue
            prop = (res.get("proposal") or "").strip()
            if res.get("compliant") or not prop:
                continue
            parts.append(f"! ==== {host} ====")
            if res.get("ssh_enabled") is False:
                parts.append(f"! {self.T('vuln_warn_ssh')}")
            parts.append(prop)
        self.vuln_proposal = ("\n".join(parts) + "\n") if parts else ""
        if self.vuln_proposal:
            self._set_vuln_prop(self.vuln_proposal)
            return
        good = [(h, r, e) for h, r, e in self.vuln_results if not e and r]
        if good and all(r.get("compliant") for _h, r, _e in good):
            self._set_vuln_prop(self.T("vuln_no_proposal") + "\n")
        elif any(not r.get("compliant") and not (r.get("proposal") or "").strip()
                 for _h, r, _e in good):
            self._set_vuln_prop(self.T("vuln_manual_inspect") + "\n")
        else:
            self._set_vuln_prop("")

    def _finish_vuln_done(self):
        self._vuln_fetching = False
        try:
            self.btn_vuln_check.configure(state="normal")
            self.btn_vuln_apply.configure(state="normal")
            self.btn_vuln_stop.configure(state="disabled")
            self.vuln_prog.stop()
            total = int(self.vuln_prog.cget("maximum") or 0)
            if total and len(self.vuln_results) >= total:
                # everything reported -> solid green bar
                self.vuln_prog.configure(mode="determinate",
                                         style="VulnDone.Horizontal.TProgressbar",
                                         maximum=total, value=total)
            else:
                # stopped early -> back to neutral determinate bar
                self.vuln_prog.configure(mode="determinate",
                                         style="Horizontal.TProgressbar",
                                         value=len(self.vuln_results))
        except tk.TclError:
            pass
        ok = sum(1 for _h, r, e in self.vuln_results
                 if not e and r and r.get("compliant"))
        bad = sum(1 for _h, r, e in self.vuln_results
                  if not e and r and not r.get("compliant"))
        errs = sum(1 for _h, _r, e in self.vuln_results if e)
        hosts = {h for h, _r, _e in self.vuln_results}
        stopped = self._vuln_stop.is_set()
        base = self.T("vuln_summary").format(n=len(hosts),
                                             ok=ok, bad=bad, err=errs)
        self.status.set(base + (" " + self.T("vuln_stopped") if stopped else ""))

    def copy_vuln(self):
        if not self.vuln_proposal.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        self.clipboard_clear()
        self.clipboard_append(self.vuln_proposal)
        self._toast(self.T("copied"))

    def clear_vuln(self):
        self.vuln_results = []
        self.vuln_proposal = ""
        self._set_vuln_text("")
        self._set_vuln_prop("")
        try:
            self.vuln_prog.stop()
            self.vuln_prog.configure(mode="determinate",
                                     style="Horizontal.TProgressbar", value=0)
        except tk.TclError:
            pass

    def _collect_vuln_notes(self) -> str:
        """Paste-ready OpenProject reasons for unfixable findings."""
        parts = []
        for host, res, err in self.vuln_results:
            if err or not res:
                continue
            mod = self._vuln_mod(res.get("vuln", "telnet"))
            note = mod.openproject_note(host, res, self.T)
            if note:
                parts.append(note)
        return "\n\n".join(parts)

    def show_vuln_notes(self):
        text = self._collect_vuln_notes()
        if not text.strip():
            messagebox.showinfo("ACL", self.T("nothing_to_copy"))
            return
        dlg = tk.Toplevel(self)
        dlg.title(self.T("vuln_note_title"))
        dlg.geometry("640x440")
        dlg.minsize(480, 320)
        dlg.transient(self)
        txt_fr = ttk.Frame(dlg)
        txt_fr.pack(fill="both", expand=True, padx=10, pady=(10, 6))
        txt = tk.Text(txt_fr, wrap="word", font=("Consolas", 10),
                      height=12, width=70)
        ys = ttk.Scrollbar(txt_fr, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=ys.set)
        txt.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        txt.insert("1.0", text)
        txt.configure(state="disabled")
        fr = ttk.Frame(dlg)
        fr.pack(fill="x", padx=10, pady=(0, 10))

        def _copy():
            self.clipboard_clear()
            self.clipboard_append(text)
            self._toast(self.T("copied"))

        ttk.Button(fr, text=self.T("vuln_note_copy"), command=_copy).pack(
            side="left", padx=(0, 6))
        ttk.Button(fr, text=self.T("vuln_note_close"),
                   command=dlg.destroy).pack(side="left", padx=6)

    # ---------- vulnerabilities: apply the fix (one open session per device)

    def start_vuln_apply(self):
        """Apply proposals with a safe protocol per device: fresh re-check
        -> configure -> verify in running-config -> operator confirmation
        (session held open) -> write memory, else rollback."""
        if self._vuln_fetching or self._vuln_applying:
            return
        if not self._require_unlocked():
            return
        cands = [(h, r) for h, r, e in self.vuln_results
                 if not e and r]
        mods = self._vuln_mods(self._selected_vuln_id())
        by_mod = {mod.VULN_ID: mod for mod in mods}
        cands = [(h, r) for h, r in cands
                 if by_mod.get((r or {}).get("vuln", ""),
                               vuln_telnet).needs_apply(r)]
        if not cands:
            messagebox.showinfo("ACL", self.T("vuln_apply_none"))
            return
        hosts = [h for h, _r in cands]
        shown = ", ".join(hosts[:10]) + (", ..." if len(hosts) > 10 else "")
        if not messagebox.askyesno(
                "ACL", self.T("vuln_apply_overview").format(n=len(hosts),
                                                            hosts=shown)):
            return
        devs = []
        for h in hosts:
            d = self._lookup_device(h)
            if d is not None:
                devs.append(d)
        if not devs:
            return
        groups: list[tuple[list, object]] = []
        for mod in mods:
            gdevs = [d for d in devs
                     if any(h == d.get("host") and
                            (r or {}).get("vuln", "") == mod.VULN_ID
                            and mod.needs_apply(r)
                            for h, r in cands)]
            if gdevs:
                groups.append((gdevs, mod))
        if not groups:
            return
        self._vuln_applying = True
        self._vuln_stop.clear()
        self.btn_vuln_check.configure(state="disabled")
        self.btn_vuln_apply.configure(state="disabled")
        self.btn_vuln_stop.configure(state="normal")
        self.vuln_prog.configure(mode="indeterminate",
                                 style="VulnWork.Horizontal.TProgressbar")
        self.vuln_prog.start(12)
        self.status.set(self.T("vuln_apply_status").format(n=len(devs)))
        threading.Thread(target=self._apply_all_worker, args=(groups,),
                         daemon=True).start()

    def _try_rollback(self, sess, mod, targets: list
                      ) -> tuple[bool, dict | None]:
        """Restore pre-fix state; (verified?, fresh result or None)."""
        if not targets or not sess.alive():
            return False, None
        try:
            sess.configure(mod.build_rollback_commands(targets))
            fresh = mod.fetch_check_session(sess)
        except Exception:
            return False, None
        try:
            return bool(mod.rollback_verified(targets, fresh)), fresh
        except Exception:
            return False, None

    def _put_apply(self, lines: list[tuple[str, str | None]]):
        self.msg_queue.put(("vuln_apply_chunk", lines))

    def _refresh_and_residual(self, host: str, mod, fresh: dict | None):
        """Push the final per-device verdict: fresh residual line for the
        log plus a data refresh (proposal box follows the new state)."""
        if fresh is None:
            return
        summary = mod.residual_summary(fresh, self.T)
        if summary is not None:
            text, tag = summary
            self._put_apply([(text + "\n", tag)])
        self.msg_queue.put(("vuln_apply_refresh", (host, fresh)))

    def _apply_worker(self, devs: list[dict], mod):
        ok = rb = fail = skip = 0
        for d in devs:
            if self._vuln_stop.is_set():
                self._put_apply([(self.T("vuln_apply_stopped") + "\n",
                                  "vuln_warn")])
                break
            host = d.get("host", "?")
            hdr = [(self.T("device_hdr").format(host=host) + "\n", None)]
            sess = cisco_ssh.ConfigSession(
                host, d["username"], d.get("password", ""),
                d.get("enable") or None, int(d.get("port", 22)),
                debug_log=self._ssh_debug_log())
            changed: list[dict] = []
            try:
                self._put_apply(
                    hdr + [(self.T("vuln_st_recheck").format(host=host)
                            + "\n", None)])
                sess.open()
                sess.ensure_privileged()
                res = mod.fetch_check_session(sess)
                if res.get("compliant"):
                    self._put_apply([(self.T("vuln_apply_already") + "\n",
                                      "vuln_ok")])
                    skip += 1
                    continue
                if res.get("ssh_enabled") is False:
                    self._put_apply([(self.T("vuln_apply_nossh") + "\n",
                                      "vuln_warn")])
                    skip += 1
                    continue
                targets = mod.apply_targets(res)
                if not targets:
                    self._put_apply([(self.T("vuln_apply_manual") + "\n",
                                      "vuln_warn")])
                    skip += 1
                    continue
                changed = [dict(e) for e in targets]
                # Pre-flight: a FRESH login must work before we touch
                # anything (the main session alone does not prove that a
                # new login with these credentials succeeds right now).
                self._put_apply(
                    [(self.T("vuln_st_preflight").format(host=host) + "\n",
                      None)])
                try:
                    cisco_ssh.run_commands(
                        host, d["username"], d.get("password", ""),
                        d.get("enable") or None, int(d.get("port", 22)),
                        timeout=15, commands=["show clock"],
                        debug_log=self._ssh_debug_log())
                except Exception as e:
                    self._put_apply(
                        [(self.T("vuln_preflight_fail").format(err=e) + "\n",
                          "vuln_fail")])
                    skip += 1
                    continue
                self._put_apply([(self.T("vuln_preflight_ok") + "\n",
                                  "vuln_ok")])
                # Apply group by group: a rejected keyword (e.g. no `kex`
                # on older IOS) fails alone while the rest still applies.
                # Rollback later covers only groups that went in.
                self._put_apply(
                    [(self.T("vuln_st_applying").format(host=host) + "\n",
                      None)])
                applied: list[dict] = []
                for gname, gtargets in mod.split_fix_groups(targets, res):
                    try:
                        sess.configure(mod.build_fix_commands(gtargets, res))
                        applied.extend(dict(e) for e in gtargets)
                    except cisco_ssh.ConfigFailed as e:
                        if _rejected_unsupported(e):
                            self._put_apply([(
                                self.T("vuln_group_unsupported").format(
                                    group=gname,
                                    detail=_first_reject_line(e)) + "\n",
                                "vuln_warn")])
                        else:
                            raise
                if not applied:
                    skip += 1
                    continue
                changed = applied
                res2 = mod.fetch_check_session(sess)
                if not mod.fix_verified(res2, applied):
                    rb_ok, fresh = self._try_rollback(sess, mod, changed)
                    detail = (self.T("vuln_rb_ok") if rb_ok
                              else self.T("vuln_rb_bad"))
                    self._put_apply(
                        [(self.T("vuln_apply_postfail").format(detail=detail)
                          + "\n", "vuln_fail")])
                    self._refresh_and_residual(host, mod, fresh)
                    fail += 1
                    continue
                # Fix is in running-config (NOT saved). First OUR OWN test:
                # a brand-new SSH login must work, or the change is rolled
                # back immediately without bothering the operator.
                self._put_apply(
                    [(self.T("vuln_st_posttest").format(host=host) + "\n",
                      None)])
                try:
                    cisco_ssh.run_commands(
                        host, d["username"], d.get("password", ""),
                        d.get("enable") or None, int(d.get("port", 22)),
                        timeout=15, commands=["show clock"],
                        debug_log=self._ssh_debug_log())
                except Exception as e:
                    rb_ok, fresh = self._try_rollback(sess, mod, changed)
                    detail = (self.T("vuln_rb_ok") if rb_ok
                              else self.T("vuln_rb_bad"))
                    self._put_apply(
                        [(self.T("vuln_posttest_fail").format(
                            err=e, detail=detail) + "\n", "vuln_fail")])
                    self._refresh_and_residual(host, mod, fresh)
                    fail += 1
                    continue
                self._put_apply([(self.T("vuln_posttest_ok") + "\n",
                                  "vuln_ok")])
                # New logins proven working. Ask the operator to verify from
                # a NEW session; hold this one open meanwhile.
                box: dict = {}
                ev = threading.Event()
                title, text = mod.verify_prompt(host, self.T)
                try:
                    creds = {"host": d.get("host", ""),
                             "port": int(d.get("port", 22) or 22),
                             "username": d.get("username", ""),
                             "password": d.get("password", "")}
                except (TypeError, ValueError):
                    creds = {"host": d.get("host", ""), "port": 22,
                             "username": d.get("username", ""),
                             "password": d.get("password", "")}
                self.msg_queue.put((
                    "vuln_apply_confirm", (title, text, box, ev, creds)))
                alive = True
                while not ev.is_set():
                    if self._vuln_stop.is_set():
                        box["ok"] = False
                        ev.set()
                        break
                    if not sess.alive():
                        alive = False
                        break
                    try:
                        sess.exec("", 1.0)
                    except Exception:
                        alive = False
                        break
                    ev.wait(30)
                if not alive:
                    self._put_apply(
                        [(self.T("vuln_apply_sesslost").format(host=host)
                          + "\n", "vuln_fail")])
                    fail += 1
                    continue
                if box.get("ok"):
                    wout = sess.exec("write memory", 8.0)
                    if re.search(r"^%|command rejected", wout,
                                 re.M | re.IGNORECASE):
                        raise RuntimeError(f"write memory failed: {wout}")
                    last = [ln for ln in wout.splitlines() if ln.strip()]
                    self._put_apply(
                        [(self.T("vuln_apply_saved").format(
                            line=last[-1] if last else "OK") + "\n",
                          "vuln_ok")])
                    # Final truth: re-read AFTER the save, then verdict.
                    try:
                        final = mod.fetch_check_session(sess)
                    except Exception:
                        final = None
                    self._refresh_and_residual(host, mod, final)
                    ok += 1
                else:
                    rb_ok, fresh = self._try_rollback(sess, mod, changed)
                    detail = (self.T("vuln_rb_ok") if rb_ok
                              else self.T("vuln_rb_bad"))
                    tag = ("vuln_warn" if detail == self.T("vuln_rb_ok")
                           else "vuln_fail")
                    self._put_apply(
                        [(self.T("vuln_apply_rb_user").format(detail=detail)
                          + "\n", tag)])
                    self._refresh_and_residual(host, mod, fresh)
                    rb += 1
            except cisco_ssh.ConfigFailed as e:
                rb_ok, fresh = self._try_rollback(sess, mod, changed)
                detail = (self.T("vuln_rb_ok") if rb_ok
                          else self.T("vuln_rb_bad"))
                self._put_apply(
                    [(self.T("vuln_apply_error").format(err=e) + "\n",
                      "vuln_fail"),
                     (self.T("vuln_apply_postfail").format(detail=detail)
                      + "\n", "vuln_fail")])
                self._refresh_and_residual(host, mod, fresh)
                fail += 1
            except Exception as e:
                if changed:
                    self._try_rollback(sess, mod, changed)
                self._put_apply([(self.T("vuln_apply_error").format(err=e)
                                  + "\n", "vuln_fail")])
                fail += 1
            finally:
                sess.close()
        return {"ok": ok, "rb": rb, "fail": fail, "skip": skip}

    def _apply_all_worker(self, groups: list[tuple[list, object]]):
        """Run apply per provider group, sequentially; a single done."""
        total = {"ok": 0, "rb": 0, "fail": 0, "skip": 0}
        for devs, mod in groups:
            if self._vuln_stop.is_set():
                break
            stats = self._apply_worker(devs, mod)
            for key in total:
                total[key] += stats.get(key, 0)
        self.msg_queue.put(("vuln_apply_done", total))

    def _finish_apply_done(self, stats: dict):
        self._vuln_applying = False
        try:
            self.btn_vuln_check.configure(state="normal")
            self.btn_vuln_apply.configure(state="normal")
            self.btn_vuln_stop.configure(state="disabled")
            self.vuln_prog.stop()
            self.vuln_prog.configure(mode="determinate",
                                     style="VulnDone.Horizontal.TProgressbar",
                                     value=self.vuln_prog.cget("maximum"))
        except tk.TclError:
            pass
        self.status.set(self.T("vuln_apply_done").format(
            ok=stats.get("ok", 0), rb=stats.get("rb", 0),
            fail=stats.get("fail", 0), skip=stats.get("skip", 0)))

    def _build_vuln_tab(self):
        # --- Tab: vulnerabilities (check config, propose fix, apply later) ---
        self.tab_vuln = ttk.Frame(self.nb)
        self.nb.add(self.tab_vuln, text="vuln")
        vf = ttk.Frame(self.tab_vuln)
        vf.pack(fill="x", padx=10, pady=10)
        self.lbl_vuln_dev = ttk.Label(vf, text="")
        self.lbl_vuln_dev.grid(row=0, column=0, sticky="w")
        self.lbl_vuln_name = ttk.Label(vf, text="")
        self.lbl_vuln_name.grid(row=0, column=1, sticky="w", padx=(16, 0))
        dev_list_fr = ttk.Frame(vf)
        dev_list_fr.grid(row=1, column=0, sticky="w", pady=4)
        self.vuln_listbox = tk.Listbox(dev_list_fr, selectmode="extended",
                                       width=38, height=8,
                                       font=("Consolas", 10),
                                       exportselection=False)
        vuln_dev_ys = ttk.Scrollbar(dev_list_fr, orient="vertical",
                                    command=self.vuln_listbox.yview)
        self.vuln_listbox.configure(yscrollcommand=vuln_dev_ys.set)
        self.vuln_listbox.pack(side="left", fill="y")
        vuln_dev_ys.pack(side="left", fill="y")
        right_fr = ttk.Frame(vf)
        right_fr.grid(row=1, column=1, sticky="nw", padx=(16, 0), pady=4)
        self.vuln_id_var = tk.StringVar(value="")
        self.combo_vuln = ttk.Combobox(right_fr, textvariable=self.vuln_id_var,
                                       state="readonly", width=34, values=[])
        self.combo_vuln.pack(anchor="w")
        self.combo_vuln.bind("<<ComboboxSelected>>",
                             lambda _e: self._sync_vuln_desc())
        self.lbl_vuln_desc = ttk.Label(right_fr, text="", wraplength=420,
                                       justify="left", foreground="gray")
        self.lbl_vuln_desc.pack(anchor="w", pady=(6, 0))

        vbtns = ttk.Frame(self.tab_vuln)
        vbtns.pack(fill="x", padx=10, pady=(0, 8))
        self.btn_vuln_check = ttk.Button(vbtns, text="",
                                         command=self.start_vuln_check)
        self.btn_vuln_check.pack(side="left", padx=(0, 6))
        self.btn_vuln_stop = ttk.Button(vbtns, text="", command=self.stop_vuln_check,
                                        state="disabled")
        self.btn_vuln_stop.pack(side="left", padx=6)
        self.btn_vuln_copy = ttk.Button(vbtns, text="", command=self.copy_vuln)
        self.btn_vuln_copy.pack(side="left", padx=6)
        self.btn_vuln_clear = ttk.Button(vbtns, text="", command=self.clear_vuln)
        self.btn_vuln_clear.pack(side="left", padx=6)
        self.btn_vuln_apply = ttk.Button(vbtns, text="",
                                          command=self.start_vuln_apply)
        self.btn_vuln_apply.pack(side="left", padx=6)
        self.btn_vuln_all = ttk.Button(vbtns, text="",
                                       command=lambda: self.vuln_listbox.select_set(0, tk.END))
        self.btn_vuln_all.pack(side="left", padx=(18, 2))
        self.btn_vuln_none = ttk.Button(vbtns, text="",
                                        command=lambda: self.vuln_listbox.select_clear(0, tk.END))
        self.btn_vuln_none.pack(side="left", padx=2)
        self.btn_vuln_marked = ttk.Button(vbtns, text="",
                                          command=self.vuln_select_marked)
        self.btn_vuln_marked.pack(side="left", padx=2)
        self.btn_vuln_note = ttk.Button(vbtns, text="",
                                        command=self.show_vuln_notes)
        self.btn_vuln_note.pack(side="left", padx=2)
        self.vuln_style = ttk.Style(self)
        self.vuln_style.configure("VulnWork.Horizontal.TProgressbar",
                                  background="gold", thickness=18)
        self.vuln_style.configure("VulnDone.Horizontal.TProgressbar",
                                  background="green", thickness=18)
        self.vuln_prog = ttk.Progressbar(vbtns, mode="determinate", length=220)
        self.vuln_prog.pack(side="left", padx=(14, 0))

        self.lbl_vuln_results = ttk.Label(self.tab_vuln, text="")
        self.lbl_vuln_results.pack(anchor="w", padx=10, pady=(2, 2))
        vuln_fr = ttk.Frame(self.tab_vuln)
        vuln_fr.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.txt_vuln = tk.Text(vuln_fr, wrap="none", font=("Consolas", 10),
                                height=8, state="disabled")
        vuln_ys = ttk.Scrollbar(vuln_fr, orient="vertical",
                                command=self.txt_vuln.yview)
        vuln_xs = ttk.Scrollbar(vuln_fr, orient="horizontal",
                                command=self.txt_vuln.xview)
        self.txt_vuln.configure(yscrollcommand=vuln_ys.set,
                                xscrollcommand=vuln_xs.set)
        self.txt_vuln.tag_configure("vuln_ok", foreground="green")
        self.txt_vuln.tag_configure("vuln_fail", foreground="red")
        self.txt_vuln.tag_configure("vuln_warn", foreground="dark orange")
        self.txt_vuln.grid(row=0, column=0, sticky="nsew")
        vuln_ys.grid(row=0, column=1, sticky="ns")
        vuln_xs.grid(row=1, column=0, sticky="ew")
        vuln_fr.grid_rowconfigure(0, weight=1)
        vuln_fr.grid_columnconfigure(0, weight=1)

        self.lbl_vuln_prop = ttk.Label(self.tab_vuln, text="")
        self.lbl_vuln_prop.pack(anchor="w", padx=10, pady=(2, 2))
        vprop_fr = ttk.Frame(self.tab_vuln)
        vprop_fr.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.txt_vuln_prop = tk.Text(vprop_fr, wrap="none", font=("Consolas", 10),
                                     height=8, state="disabled")
        vprop_ys = ttk.Scrollbar(vprop_fr, orient="vertical",
                                 command=self.txt_vuln_prop.yview)
        vprop_xs = ttk.Scrollbar(vprop_fr, orient="horizontal",
                                 command=self.txt_vuln_prop.xview)
        self.txt_vuln_prop.configure(yscrollcommand=vprop_ys.set,
                                     xscrollcommand=vprop_xs.set)
        self.txt_vuln_prop.grid(row=0, column=0, sticky="nsew")
        vprop_ys.grid(row=0, column=1, sticky="ns")
        vprop_xs.grid(row=1, column=0, sticky="ew")
        vprop_fr.grid_rowconfigure(0, weight=1)
        vprop_fr.grid_columnconfigure(0, weight=1)

    def _apply_vuln_language(self):
        S = STRINGS[self.lang]
        self.lbl_vuln_dev.configure(text=S["vuln_devices_label"])
        self.lbl_vuln_name.configure(text=S["vuln_name_label"])
        self.btn_vuln_check.configure(text=S["vuln_check_btn"])
        self.btn_vuln_stop.configure(text=S["stop_btn"])
        self.btn_vuln_copy.configure(text=S["copy_btn"])
        self.btn_vuln_clear.configure(text=S["clear_btn"])
        self.btn_vuln_apply.configure(text=S["vuln_apply_btn"])
        self.btn_vuln_all.configure(text=S["vuln_select_all"])
        self.btn_vuln_none.configure(text=S["vuln_select_none"])
        self.btn_vuln_marked.configure(text=S["vuln_marked_btn"])
        self.btn_vuln_note.configure(text=S["vuln_note_btn"])
        self.lbl_vuln_results.configure(text=S["vuln_results_label"])
        self.lbl_vuln_prop.configure(text=S["vuln_proposal_label"])
        self._refresh_vuln_combo()

VULN_MODS = {"telnet": vuln_telnet, "ssh": vuln_ssh, "tls": vuln_tls}
VULN_ALL_ID = "all"
def _first_reject_line(err) -> str:
    """First IOS rejection line of a ConfigFailed error (for the report)."""
    try:
        cmd, out = err.failures[0]
        first = out.splitlines()[0] if out.splitlines() else "?"
        return f"{cmd}: {first}"
    except Exception:
        return str(err)
def _rejected_unsupported(err) -> bool:
    """True when EVERY rejected command looks like an unknown keyword
    (older IOS without that sub-command) rather than a real failure."""
    try:
        failures = err.failures
    except AttributeError:
        return False
    if not failures:
        return False
    return all(re.search(r"invalid|unknown command|incomplete|ambiguous",
                         out, re.IGNORECASE)
               for _cmd, out in failures)
