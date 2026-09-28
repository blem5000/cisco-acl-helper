"""Unsecured HTTP(S) management server (TLS 1.0 exposure).

Site policy: on switches the HTTP(S) server must be OFF entirely
(WLC controllers are excluded from this policy):
  no ip http server
  no ip ssh server -> (unrelated, see vuln_telnet)
  no ip http secure-server

A switch offering HTTPS on old IOS accepts TLS 1.0 (scanner finding
"TLS Version 1.0 Protocol Detection"), which has cryptographic design
flaws. Since the fix is disabling the service (not tuning versions),
it works on every IOS generation - no capability matrix needed.

Check sources: `show running-config | include ^ip http` (ignoring
`no ...` lines, last occurrence wins) plus `show version` output used
only to detect WLC controllers, which are skipped with an OpenProject
note instead of a fix.
"""

from __future__ import annotations

import re

__all__ = [
    "VULN_ID",
    "CHECK_COMMANDS",
    "TITLE",
    "analyze_tls",
    "apply_targets",
    "needs_apply",
    "build_fix_commands",
    "build_rollback_commands",
    "fix_verified",
    "rollback_verified",
    "split_fix_groups",
    "fetch_check_run",
    "fetch_check_session",
    "format_result",
    "verify_prompt",
    "residual_summary",
    "openproject_note",
]

VULN_ID = "tls"

#: Exact scanner finding title (identical in both UI languages).
TITLE = "TLS Version 1.0 Protocol Detection"

CHECK_COMMANDS = [
    "show running-config | include ^ip http",
    "show version | include Cisco|Version|Model|AIR|9800",
]

SERVICES = ("http", "secure")

_WLC_MARKERS = ("9800", "c9800", "air-ct", "wireless controller")


def _service_line(service: str) -> str:
    return "ip http server" if service == "http" else "ip http secure-server"


def _is_wlc(version_out: str) -> bool:
    low = (version_out or "").lower()
    return any(m in low for m in _WLC_MARKERS)


def _parse_http(include_out: str) -> dict:
    """Effective on/off state per service; last occurrence wins, so
    `no ip http server` after `ip http server` means OFF."""
    state = {"http": False, "secure": False}
    for line in (include_out or "").splitlines():
        s = line.strip()
        negated = s.startswith("no ")
        body = s[3:].strip() if negated else s
        if body == "ip http server":
            state["http"] = not negated
        elif body == "ip http secure-server":
            state["secure"] = not negated
    return state


def analyze_tls(include_out: str = "", version_out: str = "") -> dict:
    """Build the structured result from check outputs."""
    state = _parse_http(include_out)
    wlc = _is_wlc(version_out)
    enabled = [s for s in SERVICES if state[s]]
    if wlc:
        subs = {s: {"status": "fail" if state[s] else "ok",
                    "enabled": state[s], "appliable": False}
                for s in SERVICES}
    else:
        subs = {s: {"status": "fail" if state[s] else "ok",
                    "enabled": state[s], "appliable": state[s]}
                for s in SERVICES}
    issues = []
    if wlc and enabled:
        issues.append("wlc_excluded")
    target_subs = [s for s in SERVICES
                   if subs[s]["status"] == "fail" and subs[s]["appliable"]]
    lines = [f"no {_service_line(s)}" for s in target_subs]
    proposal_cmds = (["conf t"] + lines + ["end", "wr"]) if lines else []
    return {
        "vuln": "tls",
        "compliant": not enabled,
        "subs": subs,
        "enabled": enabled,
        "wlc": wlc,
        "orig": {s: state[s] for s in SERVICES},
        "issues": issues,
        "proposal": "\n".join(proposal_cmds) + ("\n" if proposal_cmds else ""),
        "proposal_cmds": proposal_cmds,
    }


def apply_targets(result: dict) -> list[dict]:
    """Snapshot of enabled services to switch off."""
    if (result or {}).get("vuln", "tls") != "tls":
        return []
    return [{"service": s}
            for s in SERVICES
            if result.get("subs", {}).get(s, {}).get("status") == "fail"
            and result.get("subs", {}).get(s, {}).get("appliable")]


def needs_apply(result: dict | None) -> bool:
    if ((result or {}).get("vuln", "tls") != "tls"
            or not result or result.get("compliant")):
        return False
    return bool(apply_targets(result))


def build_fix_commands(targets: list[dict], result: dict | None = None
                       ) -> list[str]:
    """Raw sub-commands for a config session (no conf t / end / wr)."""
    cmds: list[str] = []
    seen: set[str] = set()
    for t in targets or []:
        sub = t.get("service", "")
        if sub in SERVICES and sub not in seen:
            seen.add(sub)
            cmds.append(f"no {_service_line(sub)}")
    return cmds


def build_rollback_commands(targets: list[dict], result: dict | None = None
                            ) -> list[str]:
    """Re-enable exactly the services that were on before the fix."""
    cmds: list[str] = []
    seen: set[str] = set()
    for t in targets or []:
        sub = t.get("service", "")
        if sub in SERVICES and sub not in seen:
            seen.add(sub)
            cmds.append(_service_line(sub))
    return cmds


def split_fix_groups(targets: list[dict], result: dict | None = None
                     ) -> list[tuple[str, list[dict]]]:
    """HTTP(S) fix is a single group (both lines go in one configure pass)."""
    return [("http", list(targets or []))] if targets else []


def fix_verified(result: dict, targets: list[dict]) -> bool:
    """True when the fresh result shows the HTTP(S) server gone."""
    return (bool(result) and result.get("vuln", "tls") == "tls"
            and bool(result.get("compliant")))


def rollback_verified(targets: list[dict], after: dict) -> bool:
    """True when the previously enabled services are back on."""
    if not targets or not after or after.get("vuln", "tls") != "tls":
        return False
    subs = after.get("subs", {})
    return all(subs.get(t.get("service", ""), {}).get("enabled", False)
               for t in targets)


def fetch_check_run(host: str, username: str, password: str,
                    enable: str | None = None, port: int = 22,
                    debug_log: str | None = None) -> dict:
    """Fetch HTTP lines + version over a throwaway session, analyzed."""
    import cisco_ssh

    out = cisco_ssh.run_commands(
        host, username, password, enable, port,
        timeout=15, commands=CHECK_COMMANDS, debug_log=debug_log)
    return analyze_tls(out.get(CHECK_COMMANDS[0], ""),
                       out.get(CHECK_COMMANDS[1], ""))


def fetch_check_session(sess) -> dict:
    """Same, reusing an open ConfigSession."""
    out = {cmd: sess.exec(cmd, 2.5) for cmd in CHECK_COMMANDS}
    return analyze_tls(out[CHECK_COMMANDS[0]], out[CHECK_COMMANDS[1]])


def format_result(host: str, result: dict, T) -> list[tuple[str, str | None]]:
    """Per-device findings as (line, tag) segments for colored display."""
    segs = [(T("device_hdr").format(host=host) + "\n", None)]
    subs = result.get("subs", {})
    for service in SERVICES:
        s = subs.get(service, {})
        line = _service_line(service)
        if s.get("status") == "fail":
            if s.get("appliable"):
                segs.append((f"[FAIL] {TITLE}: {line} enabled\n",
                             "vuln_fail"))
            else:
                segs.append((f"[FAIL] {TITLE}: {line} enabled "
                             f"({T('tls_manual_note')})\n", "vuln_fail"))
                segs.append((f"       {T('ssh_openproject_note')}\n",
                             "vuln_warn"))
        else:
            segs.append((f"[OK] {TITLE}: {line} off\n", "vuln_ok"))
    if result.get("wlc"):
        segs.append((T("tls_wlc_skip") + "\n", "vuln_warn"))
    if result.get("compliant"):
        segs.append((T("vuln_tls_ok") + "\n", "vuln_ok"))
    else:
        segs.append((T("vuln_tls_bad") + "\n", "vuln_fail"))
    return segs


def verify_prompt(host: str, T) -> tuple[str, str]:
    return (T("tls_verify_title").format(host=host),
            T("tls_verify_msg").format(host=host))


def residual_summary(result: dict, T) -> tuple[str, str] | None:
    """Final per-device verdict after apply/rollback (log line + tag)."""
    if not result or result.get("vuln", "tls") != "tls":
        return None
    bad = [_service_line(s) for s in SERVICES
           if result.get("subs", {}).get(s, {}).get("status") == "fail"]
    if not bad:
        return T("vuln_tls_ok"), "vuln_ok"
    return (T("vuln_apply_residual").format(items=", ".join(bad)),
            "vuln_fail")


def openproject_note(host: str, result: dict, T) -> str:
    """Paste-ready justification for findings that cannot be auto-fixed."""
    if not result or result.get("vuln", "tls") != "tls":
        return ""
    subs = result.get("subs", {})
    manual = [s for s in SERVICES
              if subs.get(s, {}).get("status") == "fail"
              and not subs.get(s, {}).get("appliable")]
    if not manual:
        return ""
    lines = [T("vuln_note_header").format(host=host)]
    if result.get("wlc"):
        lines.append(T("tls_note_wlc").format(
            services=", ".join(_service_line(s) for s in manual)))
    else:
        for service in manual:
            lines.append(T("tls_note_item").format(
                service=_service_line(service)))
    lines.append(T("tls_note_footer"))
    return "\n".join(lines)
