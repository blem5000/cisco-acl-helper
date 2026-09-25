"""Checks for the "Unencrypted Telnet Server" vulnerability.

Pure logic (no SSH here): given running-config fragments fetched over SSH,
decide whether Telnet is really disabled and propose the minimal CLI fix.

Compliance rule (strict, per the scanner recommendation "Disable Telnet,
use SSH instead"):
  * every ``line vty`` block must contain exactly ``transport input ssh``
    (ssh-only). Anything else -- ``all``, ``telnet``, ``ssh telnet``,
    ``telnet ssh``, ``none``, or a missing ``transport input`` line
    (IOS default allows Telnet) -- is VULNERABLE, except ``none`` which
    blocks Telnet too but also blocks SSH (reported as a separate warning).
  * ``line con`` / ``line aux`` are physical lines, not the network Telnet
    server; they are shown for information and flagged only when they
    explicitly allow Telnet (``all`` / ``telnet``).
  * ``show ip ssh`` is used only to warn when SSH itself looks disabled:
    applying ``transport input ssh`` with no SSH server would lock you out.

Typical compliant config::

    line vty 0 4
     login local
     transport input ssh
    line vty 5 15
     login local
     transport input ssh

Proposed fix (paste-ready, same style as the ACL generator)::

    conf t
    line vty 0 4
     transport input ssh
    line vty 5 15
     transport input ssh
    end
    wr
"""

from __future__ import annotations

import re

__all__ = [
    "VULN_ID",
    "TELNET_COMMANDS",
    "CHECK_COMMANDS",
    "analyze_telnet",
    "build_proposal_script",
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
]

VULN_ID = "telnet"

#: Show commands fetched for this check (via cisco_ssh.run_commands).
TELNET_COMMANDS = [
    "show running-config | section ^line",
    "show running-config | include transport input|ip ssh|telnet",
    "show ip ssh",
]

#: Provider alias used by the generic check/apply workers in app.py.
CHECK_COMMANDS = TELNET_COMMANDS

_LINE_HDR = re.compile(r"^line\s+(vty|con|aux)\s+(.+?)\s*$", re.IGNORECASE)
_TRANSPORT = re.compile(r"^transport\s+input\s+(.+?)\s*$", re.IGNORECASE)


def _parse_line_blocks(section: str) -> list[dict]:
    """Split a ``| section ^line`` output into per-line blocks."""
    blocks: list[dict] = []
    current: dict | None = None
    for raw in (section or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("Building ", "Current configuration", "!")):
            continue
        # skip echoed command / trailing prompt leftovers
        if line.startswith("show running-config"):
            continue
        if re.match(r"^[A-Za-z0-9_.()-]+[>#]\s*$", line):
            continue
        m = _LINE_HDR.match(line)
        if m:
            kind = m.group(1).lower()
            rng = re.sub(r"\s+", " ", m.group(2).strip())
            current = {"kind": kind, "range": rng,
                       "header": f"line {kind} {rng}",
                       "transport": None, "raw": [line]}
            blocks.append(current)
            continue
        if current is not None:
            current["raw"].append(line)
            tm = _TRANSPORT.match(line)
            if tm:
                # last occurrence wins (IOS keeps a single line anyway)
                current["transport"] = re.sub(r"\s+", " ",
                                              tm.group(1).strip().lower())
    return blocks


def _transport_status(transport: str | None) -> str:
    """Map a transport value to: ok | vulnerable | blocked | missing."""
    if transport is None:
        return "missing"  # IOS default permits Telnet -> vulnerable
    tokens = set(transport.split())
    if tokens == {"ssh"}:
        return "ok"
    if tokens == {"none"} or tokens == set():
        return "blocked"  # nothing allowed: no Telnet, but no SSH either
    return "vulnerable"  # all / telnet / ssh+telnet / telnet+ssh / ...


def _ssh_enabled(show_ip_ssh: str | None) -> bool | None:
    """Tri-state SSH-server detection from ``show ip ssh``."""
    if not (show_ip_ssh or "").strip():
        return None
    low = show_ip_ssh.lower()
    if "ssh enabled" in low:
        return True
    if ("ssh disabled" in low or "not enabled" in low
            or "no ssh" in low or "%ssh" in low and "disabled" in low):
        return False
    # Heuristic: version banner without "disabled" means enabled.
    if "ssh version" in low or "ssh server version" in low:
        return True
    return None


def analyze_telnet(line_section: str = "",
                   show_ip_ssh: str = "",
                   include_out: str = "") -> dict:
    """Analyse fetched outputs, return a structured result dict.

    Keys: compliant(bool), ssh_enabled(bool|None), vty(list), con_aux(list),
    issues(list[str]), vulnerable_ranges(list[str]), proposal(str),
    proposal_cmds(list[str]).
    """
    blocks = _parse_line_blocks(line_section)

    # Fallback: some devices return nothing for "| section ^line" (old IOS
    # without section filter). Try to rebuild blocks from the include output.
    if not blocks and (include_out or "").strip():
        rebuilt = ""
        for ln in include_out.splitlines():
            s = ln.strip()
            if _LINE_HDR.match(s):
                rebuilt += s + "\n"
            elif _TRANSPORT.match(s):
                rebuilt += " " + s + "\n"
        blocks = _parse_line_blocks(rebuilt)

    vty: list[dict] = []
    con_aux: list[dict] = []
    for b in blocks:
        st = _transport_status(b["transport"])
        entry = {**b, "status": st}
        if b["kind"] == "vty":
            entry["compliant"] = st == "ok"
            vty.append(entry)
        else:
            # con/aux: only explicit telnet is a finding
            entry["compliant"] = st in ("ok", "blocked", "missing")
            con_aux.append(entry)

    ssh = _ssh_enabled(show_ip_ssh)
    issues: list[str] = []
    vuln_ranges: list[str] = []

    if not vty:
        issues.append("no_vty_found")
    for e in vty:
        if e["status"] == "ok":
            continue
        vuln_ranges.append(e["range"])
        if e["status"] == "missing":
            issues.append(f"vty_missing:{e['range']}")
        elif e["status"] == "blocked":
            issues.append(f"vty_blocked:{e['range']}")
        else:
            issues.append(f"vty_telnet:{e['range']}:{e['transport']}")
    for e in con_aux:
        if e["status"] == "vulnerable":
            issues.append(f"{e['kind']}_telnet:{e['range']}:{e['transport']}")
    if ssh is False:
        issues.append("ssh_disabled")

    compliant = bool(vty) and all(e["compliant"] for e in vty)
    proposal_cmds = build_proposal_script(vuln_vty=[e for e in vty
                                                   if not e["compliant"]
                                                   and e["status"] != "blocked"],
                                          include_blocked=False)
    # "blocked" (transport input none) already stops Telnet; do not propose
    # ssh-only there silently -- operator must decide to re-enable SSH.
    # Still, if ONLY blocked lines exist, compliant stays False so the
    # operator gets a warning instead of a silent pass.
    if any(e["status"] == "blocked" for e in vty):
        compliant = False

    return {
        "vuln": "telnet",
        "compliant": compliant,
        "ssh_enabled": ssh,
        "vty": vty,
        "con_aux": con_aux,
        "issues": issues,
        "vulnerable_ranges": vuln_ranges,
        "proposal": "\n".join(proposal_cmds) + ("\n" if proposal_cmds else ""),
        "proposal_cmds": proposal_cmds,
    }


def build_proposal_script(vuln_vty: list[dict],
                          include_blocked: bool = False) -> list[str]:
    """Build a paste-ready CLI fix for non-compliant vty ranges."""
    ranges = _unique_ranges(vuln_vty, include_blocked)
    if not ranges:
        return []
    cmds = ["conf t"]
    for rng in ranges:
        cmds.append(f"line vty {rng}")
        cmds.append(" transport input ssh")
    cmds.append("end")
    cmds.append("wr")
    return cmds


def _unique_ranges(vuln_vty: list[dict], include_blocked: bool) -> list[str]:
    ranges: list[str] = []
    for e in vuln_vty or []:
        if e.get("status") == "blocked" and not include_blocked:
            continue
        rng = (e.get("range") or "").strip()
        if rng and rng not in ranges:
            ranges.append(rng)
    return ranges


def apply_targets(result: dict) -> list[dict]:
    """Vty entries the automatic fix will touch (non-compliant, not blocked)."""
    return [e for e in (result or {}).get("vty", [])
            if not e.get("compliant") and e.get("status") != "blocked"]


def needs_apply(result: dict | None) -> bool:
    """True when a device has an auto-appliable Telnet fix.

    Refuses when SSH itself looks disabled (applying ssh-only transport
    then would lock out remote access).
    """
    if not result or result.get("compliant"):
        return False
    if result.get("ssh_enabled") is False:
        return False
    return bool(apply_targets(result))


def apply_targets(result: dict) -> list[dict]:
    """Vty entries the automatic fix will touch (non-compliant, not blocked)."""
    if (result or {}).get("vuln", "telnet") != "telnet":
        return []
    return [e for e in (result or {}).get("vty", [])
            if not e.get("compliant") and e.get("status") != "blocked"]


def needs_apply(result: dict | None) -> bool:
    """True when a device has an auto-appliable Telnet fix.

    Refuses when SSH itself looks disabled (applying ssh-only transport
    then would lock out remote access).
    """
    if ((result or {}).get("vuln", "telnet") != "telnet"
            or not result or result.get("compliant")):
        return False
    if result.get("ssh_enabled") is False:
        return False
    return bool(apply_targets(result))


def build_fix_commands(targets: list[dict], result: dict | None = None
                       ) -> list[str]:
    """Raw sub-commands for a config session (no conf t / end / wr)."""
    cmds: list[str] = []
    for rng in _unique_ranges(targets, include_blocked=False):
        cmds.append(f"line vty {rng}")
        cmds.append("transport input ssh")
    return cmds


def build_rollback_commands(targets: list[dict], result: dict | None = None
                            ) -> list[str]:
    """Restore the ORIGINAL transport inputs captured before the fix."""
    cmds: list[str] = []
    seen: set[str] = set()
    for e in targets or []:
        rng = (e.get("range") or "").strip()
        if not rng or rng in seen:
            continue
        seen.add(rng)
        cmds.append(f"line vty {rng}")
        orig = (e.get("transport") or "").strip()
        cmds.append(f"transport input {orig}" if orig else "no transport input")
    return cmds


def fix_verified(result: dict, targets: list[dict]) -> bool:
    """True when the fresh result shows the Telnet issue gone."""
    return (bool(result) and result.get("vuln", "telnet") == "telnet"
            and bool(result.get("compliant")))


def rollback_verified(targets: list[dict], after: dict) -> bool:
    """True when vty transports match the pre-fix snapshot again."""
    if not targets or not after or after.get("vuln", "telnet") != "telnet":
        return False
    want = {(e.get("range") or ""): (e.get("transport") or "")
            for e in targets}
    got = {(e.get("range") or ""): (e.get("transport") or "")
           for e in after.get("vty", [])}
    return bool(want) and all(got.get(r) == t for r, t in want.items())


def split_fix_groups(targets: list[dict], result: dict | None = None
                     ) -> list[tuple[str, list[dict]]]:
    """Telnet fix is a single group (all vty ranges in one configure pass)."""
    return [("vty", list(targets or []))] if targets else []


def fetch_check_run(host: str, username: str, password: str,
                    enable: str | None = None, port: int = 22,
                    debug_log: str | None = None) -> dict:
    """Fetch ACL-section config over a throwaway session, analyzed."""
    import cisco_ssh

    out = cisco_ssh.run_commands(
        host, username, password, enable, port,
        timeout=15, commands=CHECK_COMMANDS, debug_log=debug_log)
    return analyze_telnet(out.get(CHECK_COMMANDS[0], ""),
                          out.get(CHECK_COMMANDS[2], ""),
                          out.get(CHECK_COMMANDS[1], ""))


def fetch_check_session(sess) -> dict:
    """Same, reusing an open ConfigSession."""
    out = {cmd: sess.exec(cmd, 2.5) for cmd in CHECK_COMMANDS}
    return analyze_telnet(out[CHECK_COMMANDS[0]],
                          out[CHECK_COMMANDS[2]],
                          out[CHECK_COMMANDS[1]])


def format_result(host: str, result: dict, T) -> list[tuple[str, str | None]]:
    """Per-device Telnet findings as (line, tag) segments, colored display."""
    segs = [(T("device_hdr").format(host=host) + "\n", None)]
    vty = result.get("vty", [])
    if not vty:
        segs.append((T("vuln_no_vty") + "\n", "vuln_warn"))
    else:
        for e in vty:
            val = e.get("transport") or "(missing)"
            if e.get("compliant"):
                mark, tag = "OK ", "vuln_ok"
            else:
                mark, tag = "FAIL", "vuln_fail"
            segs.append((f"[{mark}] {e.get('header')}: "
                         f"transport input {val}\n", tag))
        for e in result.get("con_aux", []):
            if e.get("status") == "vulnerable":
                segs.append((f"[WARN] {e.get('header')}: "
                             f"transport input {e.get('transport')}\n",
                             "vuln_warn"))
    if result.get("compliant"):
        segs.append((T("vuln_ok") + "\n", "vuln_ok"))
    else:
        segs.append((T("vuln_bad") + "\n", "vuln_fail"))
    if result.get("ssh_enabled") is False:
        segs.append((T("vuln_warn_ssh") + "\n", "vuln_warn"))
    for e in vty:
        if e.get("status") == "blocked":
            segs.append((T("vuln_warn_blocked").format(
                header=e.get("header")) + "\n", "vuln_warn"))
    return segs


def verify_prompt(host: str, T) -> tuple[str, str]:
    return (T("vuln_verify_title").format(host=host),
            T("vuln_verify_msg").format(host=host))


def residual_summary(result: dict, T) -> tuple[str, str] | None:
    """Final per-device verdict after apply/rollback (log line + tag)."""
    if not result or result.get("vuln", "telnet") != "telnet":
        return None
    bad = [e.get("header", "?") for e in result.get("vty", [])
           if not e.get("compliant")]
    if not bad:
        return T("vuln_ok"), "vuln_ok"
    return (T("vuln_apply_residual").format(items=", ".join(bad)),
            "vuln_fail")
