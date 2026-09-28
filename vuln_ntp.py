"""Unsecured NTP control queries: "Network Time Protocol (NTP) Mode 6 Scanner".

Site policy: mode 6 (control) queries must not be answerable. The fix is
a restrictive query-only group, which every IOS generation accepts:
  ip access-list standard NTP-QUERY-BLOCK
   remark Block unauthenticated NTP mode 6 control queries
   deny   any log
  !
  ntp access-group query-only NTP-QUERY-BLOCK
Time synchronization itself is untouched (governed by the serve/peer
groups, not query-only). If monitoring polls NTP via control queries,
re-permit the NMS hosts in the ACL instead of opening it up.

Check sources: a no-auth UDP mode 6 probe (ntp_probe - exactly what the
server answers, like the scanner) plus `show running-config | include
^ntp` for the current posture, originals (rollback) and reporting.
A silent probe means restricted; a down host is never reported
compliant (TCP liveness check on the SSH port first).
"""

from __future__ import annotations

import re

__all__ = [
    "VULN_ID",
    "CHECK_COMMANDS",
    "TITLE",
    "ACL_NAME",
    "analyze_ntp",
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

VULN_ID = "ntp"

#: Exact scanner finding title (identical in both UI languages).
TITLE = "Network Time Protocol (NTP) Mode 6 Scanner"

ACL_NAME = "NTP-QUERY-BLOCK"

CHECK_COMMANDS = [
    "show running-config | include ^ntp",
]


def _parse_query_only(include_out: str) -> str | None:
    """Configured `ntp access-group query-only <ACL>` (None when absent)."""
    for line in (include_out or "").splitlines():
        m = re.match(r"ntp\s+access-group\s+query-only\s+(\S+)\s*$",
                     line.strip(), re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def analyze_ntp(probe_responded: bool, probe_detail: str = "",
                include_out: str = "") -> dict:
    """Build the structured result from check outputs."""
    query_acl = _parse_query_only(include_out)
    vulnerable = bool(probe_responded)
    lines = [
        f"ip access-list standard {ACL_NAME}",
        " remark Block unauthenticated NTP mode 6 control queries",
        " deny   any log",
        f"ntp access-group query-only {ACL_NAME}",
    ]
    proposal_cmds = (["conf t"] + lines + ["end", "wr"]) if vulnerable else []
    return {
        "vuln": "ntp",
        "compliant": not vulnerable,
        "probe": probe_responded,
        "probe_detail": probe_detail,
        "query_acl": query_acl,
        "issues": [],
        "proposal": "\n".join(proposal_cmds) + ("\n" if proposal_cmds else ""),
        "proposal_cmds": proposal_cmds,
    }


def apply_targets(result: dict) -> list[dict]:
    """Snapshot marker (the fix is one indivisible group).

    Carries the pre-existing query-only ACL name so the rollback can
    restore it instead of just removing our lines.
    """
    if (result or {}).get("vuln", "ntp") != "ntp":
        return []
    if not result or result.get("compliant"):
        return []
    return [{"sub": "ntp", "orig_query_acl": result.get("query_acl")}]


def needs_apply(result: dict | None) -> bool:
    if ((result or {}).get("vuln", "ntp") != "ntp"
            or not result or result.get("compliant")):
        return False
    return bool(apply_targets(result))


def build_fix_commands(targets: list[dict], result: dict | None = None
                       ) -> list[str]:
    if not targets:
        return []
    return [
        f"ip access-list standard {ACL_NAME}",
        " remark Block unauthenticated NTP mode 6 control queries",
        " deny   any log",
        " exit",
        f"ntp access-group query-only {ACL_NAME}",
    ]


def build_rollback_commands(targets: list[dict], result: dict | None = None
                            ) -> list[str]:
    """Remove our lines; restore a pre-existing query-only group, if any."""
    if not targets:
        return []
    orig = None
    for t in targets:
        if t.get("orig_query_acl"):
            orig = t["orig_query_acl"]
            break
    if orig is None and result:
        orig = result.get("query_acl")
    cmds = [f"no ip access-list standard {ACL_NAME}"]
    if orig:
        cmds.append(f"ntp access-group query-only {orig}")
    else:
        cmds.append(f"no ntp access-group query-only {ACL_NAME}")
    return cmds


def split_fix_groups(targets: list[dict], result: dict | None = None
                     ) -> list[tuple[str, list[dict]]]:
    """NTP fix is a single group (ACL + access-group in one configure pass)."""
    return [("ntp", list(targets or []))] if targets else []


def fix_verified(result: dict, targets: list[dict]) -> bool:
    """True when a fresh probe hears nothing back."""
    return (bool(result) and result.get("vuln", "ntp") == "ntp"
            and bool(result.get("compliant")))


def rollback_verified(targets: list[dict], after: dict) -> bool:
    """True when mode 6 answers again after the rollback."""
    if not targets or not after or after.get("vuln", "ntp") != "ntp":
        return False
    return bool(after.get("probe"))


def _fetch_config(host: str, username: str, password: str,
                  enable: str | None, port: int,
                  debug_log: str | None) -> str:
    import cisco_ssh

    out = cisco_ssh.run_commands(
        host, username, password, enable, port,
        timeout=15, commands=CHECK_COMMANDS, debug_log=debug_log)
    return out.get(CHECK_COMMANDS[0], "")


def fetch_check_run(host: str, username: str, password: str,
                    enable: str | None = None, port: int = 22,
                    debug_log: str | None = None) -> dict:
    """UDP probe first (no creds needed); SSH fetch only when it answers.

    A silent probe short-circuits to compliant - but only after a TCP
    liveness check proves the host is actually up.
    """
    import ntp_probe

    responded, detail = ntp_probe.probe(host)
    if not responded:
        if not ntp_probe.tcp_reachable(host, port):
            raise RuntimeError(f"{host}: host unreachable (SSH port closed).")
        return analyze_ntp(False, detail, "")
    include_out = _fetch_config(host, username, password, enable, port,
                                debug_log)
    return analyze_ntp(True, detail, include_out)


def fetch_check_session(sess) -> dict:
    """Same, reusing an open ConfigSession (+ fresh UDP probe)."""
    import ntp_probe

    try:
        responded, detail = ntp_probe.probe(sess.host)
    except Exception as e:
        raise RuntimeError(f"{sess.host}: NTP probe failed: {e}") from e
    if not responded:
        return analyze_ntp(False, detail, "")
    out = {cmd: sess.exec(cmd, 2.5) for cmd in CHECK_COMMANDS}
    return analyze_ntp(True, detail, out[CHECK_COMMANDS[0]])


def format_result(host: str, result: dict, T) -> list[tuple[str, str | None]]:
    """Per-device findings as (line, tag) segments for colored display."""
    segs = [(T("device_hdr").format(host=host) + "\n", None)]
    detail = (result.get("probe_detail") or "").strip()
    if result.get("probe"):
        segs.append((f"[FAIL] {TITLE}" + (f": {detail}" if detail else "")
                     + "\n", "vuln_fail"))
        if result.get("query_acl"):
            segs.append((T("ntp_has_group").format(acl=result["query_acl"])
                         + "\n", "vuln_warn"))
    else:
        segs.append((f"[OK] {TITLE}" + (f": {detail}" if detail else "")
                     + "\n", "vuln_ok"))
    if result.get("compliant"):
        segs.append((T("vuln_ntp_ok") + "\n", "vuln_ok"))
    else:
        segs.append((T("vuln_ntp_bad") + "\n", "vuln_fail"))
    return segs


def verify_prompt(host: str, T) -> tuple[str, str]:
    return (T("ntp_verify_title").format(host=host),
            T("ntp_verify_msg").format(host=host))


def residual_summary(result: dict, T) -> tuple[str, str] | None:
    """Final per-device verdict after apply/rollback (log line + tag)."""
    if not result or result.get("vuln", "ntp") != "ntp":
        return None
    if result.get("compliant"):
        return T("vuln_ntp_ok"), "vuln_ok"
    return (T("vuln_apply_residual").format(items=TITLE), "vuln_fail")


def openproject_note(host: str, result: dict, T) -> str:
    """NTP findings are always auto-fixable - no note is ever needed."""
    return ""
