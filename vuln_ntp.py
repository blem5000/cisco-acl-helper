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

NOTE on other access groups: per Cisco semantics the `peer` and `serve`
groups ALSO grant control-query rights - a permissive `ntp access-group
serve` answers mode 6 no matter what query-only says. All four groups
are parsed and surfaced; the automatic fix stays scoped to query-only
(touching peer/serve could break time sync - operator decision).

Fallback for stubborn boxes (e.g. 2960S on 15.2(1)E1, cf. CSCum44673):
when our query-only block is already configured but the probe still
hears an answer, the provider proposes an inbound extended ACL on the
management interface instead - NTP/123 permitted only from the
configured `ntp server`/`peer` addresses, everything else denied. The
fallback is offered only when it is fully scoppable: the checked host
must be a literal interface address (found via `show ip interface
brief`) and every server/peer value a plain IPv4 literal. Otherwise
the finding gets an OpenProject note instead of a futile re-apply.
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

#: Primary fix also permits the configured servers explicitly (peer
#: group). Reason: on some trains (e.g. 2960S 15.2(1)E1) a lone
#: query-only group starves time sync as well - the switch stops
#: hearing its servers. The peer group keeps sync working while
#: query-only blocks control queries from everyone else.
PEER_ACL_NAME = "NTP-SERVERS"

#: Fallback: inbound guard on the management interface.
IF_ACL_NAME = "NTP-CTRL-IN"

#: All NTP access-group kinds. `peer` and `serve` also grant control
#: (mode 6) query rights; `serve-only` does not.
GROUP_KINDS = ("peer", "serve-only", "serve", "query-only")
QUERY_GRANTING = ("peer", "serve")

CHECK_COMMANDS = [
    "show running-config | include ^ntp",
    "show ip interface brief",
]


def _parse_groups(include_out: str) -> dict:
    """All configured `ntp access-group <kind> <ACL>` (None when absent)."""
    groups: dict = {k: None for k in GROUP_KINDS}
    for line in (include_out or "").splitlines():
        m = re.match(r"ntp\s+access-group\s+"
                     r"(peer|serve-only|serve|query-only)\s+(\S+)\s*$",
                     line.strip(), re.IGNORECASE)
        if m:
            groups[m.group(1).lower()] = m.group(2)
    return groups


def _parse_query_only(include_out: str) -> str | None:
    """Configured `ntp access-group query-only <ACL>` (None when absent)."""
    return _parse_groups(include_out)["query-only"]


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse_servers(include_out: str) -> tuple[list[str], bool]:
    """Configured `ntp server|peer` addresses + whether the fallback can
    use them (every value must be a plain IPv4 literal - a hostname or
    `vrf` keyword would leave a hole in the permit list)."""
    servers: list[str] = []
    usable = True
    found = False
    for line in (include_out or "").splitlines():
        m = re.match(r"ntp\s+(server|peer)\s+(\S+)",
                     line.strip(), re.IGNORECASE)
        if not m:
            continue
        found = True
        val = m.group(2)
        if _IPV4.match(val):
            if val not in servers:
                servers.append(val)
        else:
            usable = False
    if not found:
        usable = False
    return servers, (usable and bool(servers))


def _find_mgmt_interface(brief_out: str, host: str) -> str | None:
    """Interface whose address equals the checked host.

    None when the host is not a literal interface address (checked via
    hostname, NAT or an HSRP/VIP address owned by a peer).
    """
    host = (host or "").strip()
    if not _IPV4.match(host):
        return None
    for line in (brief_out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == host:
            return parts[0]
    return None


def analyze_ntp(probe_responded: bool, probe_detail: str = "",
                include_out: str = "", brief_out: str = "",
                host: str = "") -> dict:
    """Build the structured result from check outputs."""
    groups = _parse_groups(include_out)
    query_acl = groups["query-only"]
    vulnerable = bool(probe_responded)
    servers, servers_ok = _parse_servers(include_out)
    mgmt_if = _find_mgmt_interface(brief_out, host) if vulnerable else None
    # Secondary mode: our primary block is in place but the box still
    # answers - offer the interface fallback instead of re-applying the
    # same lines. Anything else vulnerable gets the primary fix.
    secondary = vulnerable and query_acl == ACL_NAME
    fallback_ok = bool(secondary and mgmt_if and servers_ok)
    peer_ok = bool(vulnerable and not secondary and servers_ok)
    if peer_ok:
        lines = ([f"ip access-list standard {PEER_ACL_NAME}"]
                 + [f" permit host {s}" for s in servers]
                 + [" deny   any",
                    f"ntp access-group peer {PEER_ACL_NAME}"])
    else:
        lines = []
    if secondary and fallback_ok:
        lines = ([f"ip access-list extended {IF_ACL_NAME}"]
                 + [f"permit udp host {s} eq ntp any" for s in servers]
                 + ["deny udp any any eq ntp log",
                    "permit ip any any",
                    "exit",
                    f"interface {mgmt_if}",
                    f"ip access-group {IF_ACL_NAME} in",
                    "exit"])
    elif vulnerable and not secondary:
        lines += [
            f"ip access-list standard {ACL_NAME}",
            " remark Block unauthenticated NTP mode 6 control queries",
            " deny   any log",
            f"ntp access-group query-only {ACL_NAME}",
        ]
    else:
        lines = []
    proposal_cmds = (["conf t"] + lines + ["end", "wr"]) if lines else []
    return {
        "vuln": "ntp",
        "compliant": not vulnerable,
        "probe": probe_responded,
        "probe_detail": probe_detail,
        "query_acl": query_acl,
        "groups": groups,
        "servers": servers,
        "servers_ok": servers_ok,
        "mgmt_if": mgmt_if,
        "secondary": secondary,
        "fallback_ok": fallback_ok,
        "issues": [],
        "proposal": "\n".join(proposal_cmds) + ("\n" if proposal_cmds else ""),
        "proposal_cmds": proposal_cmds,
    }


def apply_targets(result: dict) -> list[dict]:
    """Snapshot marker(s).

    Primary mode: one indivisible group (query-only block). Secondary
    mode (our block already in place, still answering): the interface
    fallback - but only when fully scoppable; otherwise no targets, so
    the worker reports "manual" instead of re-applying futile lines.
    Both carry the snapshots the rollback needs (worker calls it
    without result).
    """
    if (result or {}).get("vuln", "ntp") != "ntp":
        return []
    if not result or result.get("compliant"):
        return []
    if result.get("secondary"):
        if not result.get("fallback_ok"):
            return []
        return [{"sub": "ntp-if", "iface": result.get("mgmt_if"),
                 "servers": list(result.get("servers") or [])}]
    return [{"sub": "ntp", "orig_query_acl": result.get("query_acl"),
             "orig_peer": (result.get("groups") or {}).get("peer"),
             "servers": list(result.get("servers") or []),
             "peer_added": bool(result.get("servers_ok"))}]


def needs_apply(result: dict | None) -> bool:
    if ((result or {}).get("vuln", "ntp") != "ntp"
            or not result or result.get("compliant")):
        return False
    return bool(apply_targets(result))


def build_fix_commands(targets: list[dict], result: dict | None = None
                        ) -> list[str]:
    if not targets:
        return []
    t = targets[0]
    if t.get("sub") == "ntp-if":
        servers = list(t.get("servers") or [])
        if not servers and result:
            servers = list(result.get("servers") or [])
        iface = t.get("iface") or (result or {}).get("mgmt_if")
        if not iface or not servers:
            return []
        return ([f"ip access-list extended {IF_ACL_NAME}"]
                + [f"permit udp host {s} eq ntp any" for s in servers]
                + ["deny udp any any eq ntp log",
                   "permit ip any any",
                   "exit",
                   f"interface {iface}",
                   f"ip access-group {IF_ACL_NAME} in",
                   "exit"])
    cmds: list[str] = []
    if t.get("peer_added"):
        servers = list(t.get("servers") or [])
        if not servers and result:
            servers = list(result.get("servers") or [])
        if servers:
            cmds += ([f"ip access-list standard {PEER_ACL_NAME}"]
                     + [f" permit host {s}" for s in servers]
                     + [" deny   any", " exit",
                        f"ntp access-group peer {PEER_ACL_NAME}"])
    return cmds + [
        f"ip access-list standard {ACL_NAME}",
        " remark Block unauthenticated NTP mode 6 control queries",
        " deny   any log",
        " exit",
        f"ntp access-group query-only {ACL_NAME}",
    ]


def build_rollback_commands(targets: list[dict], result: dict | None = None
                            ) -> list[str]:
    """Remove our lines; restore a pre-existing query-only group, if any.

    The interface fallback is rolled back by unbinding it from the
    snapshotted interface first, then deleting the extended ACL.
    """
    if not targets:
        return []
    if any(t.get("sub") == "ntp-if" for t in targets):
        cmds: list[str] = []
        for t in targets:
            if t.get("sub") != "ntp-if":
                continue
            iface = t.get("iface") or (result or {}).get("mgmt_if")
            if iface:
                cmds += [f"interface {iface}",
                         f"no ip access-group {IF_ACL_NAME} in",
                         "exit"]
        cmds.append(f"no ip access-list extended {IF_ACL_NAME}")
        return cmds
    orig = None
    orig_peer = None
    peer_added = False
    for t in targets:
        if t.get("orig_query_acl"):
            orig = t["orig_query_acl"]
        if t.get("orig_peer"):
            orig_peer = t["orig_peer"]
        if t.get("peer_added"):
            peer_added = True
    if orig is None and result:
        orig = result.get("query_acl")
    if orig_peer is None and result:
        orig_peer = (result.get("groups") or {}).get("peer")
    cmds = []
    if peer_added:
        cmds += [f"no ntp access-group peer {PEER_ACL_NAME}",
                 f"no ip access-list standard {PEER_ACL_NAME}"]
    if orig_peer and orig_peer != PEER_ACL_NAME:
        cmds.append(f"ntp access-group peer {orig_peer}")
    cmds += [f"no ip access-list standard {ACL_NAME}"]
    if orig:
        cmds.append(f"ntp access-group query-only {orig}")
    else:
        cmds.append(f"no ntp access-group query-only {ACL_NAME}")
    return cmds


def split_fix_groups(targets: list[dict], result: dict | None = None
                     ) -> list[tuple[str, list[dict]]]:
    """Each NTP fix is a single group (primary query-only block, or the
    interface fallback) applied in one configure pass."""
    if not targets:
        return []
    return [(targets[0].get("sub", "ntp"), list(targets))]


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
                   debug_log: str | None) -> dict:
    import cisco_ssh

    out = cisco_ssh.run_commands(
        host, username, password, enable, port,
        timeout=15, commands=CHECK_COMMANDS, debug_log=debug_log)
    return {cmd: out.get(cmd, "") for cmd in CHECK_COMMANDS}


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
        return analyze_ntp(False, detail, "", "", host)
    cfg = _fetch_config(host, username, password, enable, port, debug_log)
    return analyze_ntp(True, detail, cfg[CHECK_COMMANDS[0]],
                       cfg[CHECK_COMMANDS[1]], host)


def fetch_check_session(sess) -> dict:
    """Same, reusing an open ConfigSession (+ fresh UDP probe)."""
    import ntp_probe

    try:
        responded, detail = ntp_probe.probe(sess.host)
    except Exception as e:
        raise RuntimeError(f"{sess.host}: NTP probe failed: {e}") from e
    if not responded:
        return analyze_ntp(False, detail, "", "", sess.host)
    out = {cmd: sess.exec(cmd, 2.5) for cmd in CHECK_COMMANDS}
    return analyze_ntp(True, detail, out[CHECK_COMMANDS[0]],
                       out[CHECK_COMMANDS[1]], sess.host)


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
        others = _query_granting_others(result)
        if result.get("probe") and others:
            segs.append((T("ntp_other_groups").format(
                groups=", ".join(others)) + "\n", "vuln_warn"))
        if result.get("secondary") and result.get("probe"):
            if result.get("fallback_ok"):
                segs.append((T("ntp_fallback_info").format(
                    acl=IF_ACL_NAME, iface=result.get("mgmt_if"),
                    servers=", ".join(result.get("servers") or []))
                    + "\n", "vuln_warn"))
            elif not result.get("mgmt_if"):
                segs.append((T("ntp_fallback_no_if").format(host=host)
                             + "\n", "vuln_warn"))
            else:
                segs.append((T("ntp_fallback_no_servers") + "\n",
                             "vuln_warn"))
    else:
        segs.append((f"[OK] {TITLE}" + (f": {detail}" if detail else "")
                     + "\n", "vuln_ok"))
    if result.get("compliant"):
        segs.append((T("vuln_ntp_ok") + "\n", "vuln_ok"))
    else:
        segs.append((T("vuln_ntp_bad") + "\n", "vuln_fail"))
    return segs


def _query_granting_others(result: dict) -> list[str]:
    """Configured peer/serve groups ("<kind> <ACL>") - they grant control
    queries too, so a permissive one keeps answering despite query-only.
    Our own NTP-SERVERS peer group is excluded (it only permits the
    configured time sources)."""
    groups = (result or {}).get("groups") or {}
    return [f"{k} {groups[k]}" for k in QUERY_GRANTING
            if groups.get(k) and groups[k] != PEER_ACL_NAME]


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
    """Notes only where no automatic path exists.

    Primary findings are auto-fixable (no note); secondary findings with
    a scoppable fallback are too. What remains: secondary findings the
    fallback cannot cover (unscoppable interface, unusable servers, or
    peer/serve groups needing an operator decision).
    """
    if not result or result.get("vuln", "ntp") != "ntp":
        return ""
    if result.get("compliant"):
        return ""
    if not result.get("secondary") or result.get("fallback_ok"):
        return ""
    others = _query_granting_others(result)
    if others:
        return T("ntp_note_other").format(host=host,
                                          groups=", ".join(others))
    query_acl = (result.get("groups") or {}).get("query-only")
    if not result.get("mgmt_if"):
        return T("ntp_note_no_if").format(host=host, acl=query_acl)
    return T("ntp_note_no_servers").format(host=host, acl=query_acl)
