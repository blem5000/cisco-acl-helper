"""SSH hardening bundle: five scanner-style sub-findings in one vulnerability.

Covered (mirrors Nessus plugin logic on the server's OFFERED algorithms):
  mac      - SSH Weak MAC Algorithms Enabled (MD5 / *-96 / umac-64*)
  kex      - SSH Weak Key Exchange Algorithms Enabled (gex-sha1, group1-sha1,
             gss-*, rsa1024-sha1)
  cbc      - SSH Server CBC Mode Ciphers Enabled (*-cbc)
  terrapin - Terrapin prefix truncation (CVE-2023-48795): ChaCha20-Poly1305
             or CBC-with-EtM offered WITHOUT the strict-kex countermeasure
  sshv1    - SSH Protocol Version 1 offered (banner 1.x / version 1.99)

Check sources: a no-auth handshake scan (ssh_scan, exactly what the
server offers) plus `show ip ssh` / running-config / `show version`.

Fix policy is MINIMAL: the proposal keeps everything offered except the
flagged names (Cisco CLI takes full replacement lists, so kept =
offered - flagged). ChaCha20 is dropped only when Terrapin requires it
(no strict-kex and ChaCha offered). A sub-fix is marked impossible when
nothing would remain, or when the switch cannot accept algorithm
commands at all (classic IOS without `ip ssh server algorithm`):
those go to the OpenProject note instead of the proposal.
"""

from __future__ import annotations

import re

__all__ = [
    "VULN_ID",
    "CHECK_COMMANDS",
    "SUBS",
    "analyze_ssh",
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

VULN_ID = "ssh"

CHECK_COMMANDS = [
    "show ip ssh",
    "show running-config | include ^ip ssh",
    "show version | include Cisco IOS|Version",
    # Capability probe: asking the CLI itself which `algorithm` keywords
    # exist. Entering config mode for `?` changes nothing (help text only).
    "configure terminal",
    "ip ssh server algorithm ?",
    "end",
]

ALGO_KEYWORDS = ("encryption", "mac", "kex", "hostkey")

SUBS = ("mac", "kex", "cbc", "terrapin", "sshv1")

CHACHA = "chacha20-poly1305@openssh.com"
_WEAK_KEX_EXACT = {
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
    "rsa1024-sha1",
}


def _is_weak_mac(name: str) -> bool:
    n = name.lower()
    return ("md5" in n) or n.endswith("-96") or n.startswith("umac-64")


def _is_weak_kex(name: str) -> bool:
    n = name.lower()
    return n in _WEAK_KEX_EXACT or n.startswith("gss-")


def _is_cbc(name: str) -> bool:
    return name.lower().endswith("-cbc")


def _is_etm(name: str) -> bool:
    return "etm" in name.lower()


def _ios_short(version_out: str) -> str:
    """One-line IOS identification for reports ('' when unknown)."""
    m = re.search(r"Cisco IOS (?:XE )?Software[^,\n]*,\s*Version\s+[^,\n]+",
                  version_out or "", re.IGNORECASE)
    return re.sub(r"\s+", " ", m.group(0).strip()) if m else ""


def _parse_model(version_out: str) -> str:
    """Switch model token for reports (e.g. 'WS-C2960X-48FPD-L', else '')."""
    m = re.search(r"(WS-C2960X\S*|C2960X\S*)", version_out or "",
                  re.IGNORECASE)
    return m.group(1).upper() if m else ""


def _parse_algo_help(help_out: str) -> set[str]:
    """Keywords from `ip ssh server algorithm ?` (empty when unsupported)."""
    found: set[str] = set()
    for line in (help_out or "").splitlines():
        m = re.match(r"\s*(encryption|mac|kex|hostkey)\b", line,
                     re.IGNORECASE)
        if m:
            found.add(m.group(1).lower())
    return found


def _parse_algo_config(include_out: str) -> dict:
    """Original `ip ssh server algorithm ...` lines (for rollback)."""
    orig: dict[str, str] = {}
    for line in (include_out or "").splitlines():
        m = re.match(r"ip ssh server algorithm\s+(mac|kex|encryption)\s+(.+?)\s*$",
                     line.strip(), re.IGNORECASE)
        if m:
            orig[m.group(1).lower()] = re.sub(r"\s+", " ",
                                              m.group(2).strip())
    ver = None
    for line in (include_out or "").splitlines():
        m = re.match(r"ip ssh version\s+(\d+)\s*$", line.strip())
        if m:
            ver = m.group(1)
    return {"algo": orig, "version": ver}


def _parse_version(version_out: str) -> dict:
    """{flavor: xe|classic|unknown, major, minor} from `show version`."""
    text = version_out or ""
    m = re.search(r"Cisco IOS XE Software.*?Version\s+(\d+)\.(\d+)",
                  text, re.IGNORECASE | re.DOTALL)
    if m:
        return {"flavor": "xe", "major": int(m.group(1)),
                "minor": int(m.group(2))}
    if re.search(r"Cisco IOS Software", text, re.IGNORECASE):
        m2 = re.search(r"Version\s+(\d+)\.(\d+)", text, re.IGNORECASE)
        if m2:
            return {"flavor": "classic",
                    "major": int(m2.group(1)), "minor": int(m2.group(2))}
        m2 = re.search(r"Version\s+(\d+)", text, re.IGNORECASE)
        return {"flavor": "classic",
                "major": int(m2.group(1)) if m2 else 0, "minor": 0}
    return {"flavor": "unknown", "major": 0, "minor": 0}


def _matrix_ok(kind: str, ver: dict):
    """Version-matrix fallback when the `?` probe gave nothing.

    Tri-state: True (assumed supported), False (assumed absent),
    None (unknown - the apply attempt will reveal it, gracefully).
    Sources: `ip ssh server algorithm kex` born in XE 16.3 (Cisco
    Command Reference, classic IOS never listed); encryption/mac on
    classic since 15.2(2); late E-train backports (e.g. 15.2(7)E)
    carry kex, so classic kex stays unknown rather than False.
    """
    flavor, major, minor = ver["flavor"], ver["major"], ver["minor"]
    if flavor == "xe":
        if (major, minor) >= (16, 5):
            return True
        if kind == "kex":
            return (major, minor) >= (16, 3)
        if (major, minor) >= (3, 5):
            return True
        return None
    if flavor == "classic":
        if kind == "kex":
            return None
        if (major, minor) >= (15, 2):
            return True
        return False
    return None


def _capability(show_algos: dict, orig_algo: dict, ver: dict,
                keywords: set[str]) -> dict:
    """Can this switch take `ip ssh server algorithm ...` lines, per kind?

    The `algorithm ?` help probe is the primary source (strict per-keyword);
    show/config evidence and the IOS version matrix are fallbacks.
    """
    cap: dict = {"keywords": sorted(keywords)}
    if keywords:
        if keywords & {"mac", "kex", "encryption"}:
            cap.update(level="supported", reason="algo-help")
        else:
            cap.update(level="unsupported", reason="algo-help")
        return cap
    if show_algos["encryption"] or show_algos["mac"] or orig_algo:
        cap.update(level="supported", reason="algo-evidence")
        return cap
    verdicts = {k: _matrix_ok(k, ver)
                for k in ("mac", "kex", "encryption")}
    if any(v is True for v in verdicts.values()):
        reason = ("xe-version" if ver["flavor"] == "xe"
                  and (ver["major"], ver["minor"]) >= (16, 5)
                  else "ios-matrix")
        cap.update(level="supported", reason=reason)
    elif all(v is False for v in verdicts.values()):
        cap.update(level="unsupported", reason="classic-ios")
    else:
        cap.update(level="unknown", reason="unknown")
    return cap


def _kind_ok(kind: str, cap: dict, ver: dict) -> bool:
    """May an algorithm line of this kind be attempted?"""
    keywords = set(cap.get("keywords", []))
    if keywords:
        return kind in keywords  # strict: the CLI itself listed them
    res = _matrix_ok(kind, ver)
    return res is not False  # None (unknown) -> the attempt will reveal it


def analyze_ssh(scan: dict, show_ip_ssh: str = "",
                ssh_include: str = "", version_out: str = "",
                algo_help: str = "") -> dict:
    """Build the structured SSH-bundle result from check outputs."""
    from ssh_scan import parse_show_ip_ssh_algos

    macs = list(dict.fromkeys(scan.get("macs", [])))
    kex = list(scan.get("kex", []))
    ciphers = list(dict.fromkeys(scan.get("ciphers", [])))
    strict = bool(scan.get("strict_kex"))

    weak_mac = [m for m in macs if _is_weak_mac(m)]
    weak_kex = [k for k in kex if _is_weak_kex(k)]
    cbc = [c for c in ciphers if _is_cbc(c)]
    chacha = CHACHA in ciphers
    cbc_etm = bool(cbc) and any(_is_etm(m) for m in macs)
    terrapin = (chacha or cbc_etm) and not strict

    show = show_ip_ssh or ""
    v1_scan = bool(scan.get("sshv1"))
    v1_show = bool(re.search(r"[Vv]ersion\s+1\.99\b", show))
    v1_cfg = bool(re.search(r"^ip ssh version\s+1\s*$", ssh_include or "",
                            re.MULTILINE))
    sshv1 = v1_scan or v1_show or v1_cfg

    show_algos = parse_show_ip_ssh_algos(show)
    cfg = _parse_algo_config(ssh_include)
    ver = _parse_version(version_out)
    keywords = _parse_algo_help(algo_help)
    cap = _capability(show_algos, cfg["algo"], ver, keywords)
    mac_ok = _kind_ok("mac", cap, ver)
    kex_ok = _kind_ok("kex", cap, ver)
    enc_ok = _kind_ok("encryption", cap, ver)

    kept_mac = [m for m in macs if not _is_weak_mac(m)]
    kept_kex = [k for k in kex if not _is_weak_kex(k)]
    kept_ciphers = [c for c in ciphers
                    if not _is_cbc(c) and not (c == CHACHA and not strict)]

    subs: dict[str, dict] = {
        "mac": {"status": "fail" if weak_mac else "ok", "found": weak_mac,
                "kept": kept_mac,
                "appliable": bool(weak_mac) and mac_ok and bool(kept_mac)},
        "kex": {"status": "fail" if weak_kex else "ok", "found": weak_kex,
                "kept": kept_kex,
                "appliable": bool(weak_kex) and kex_ok and bool(kept_kex)},
        "cbc": {"status": "fail" if cbc else "ok", "found": cbc,
                "kept": kept_ciphers,
                "appliable": bool(cbc) and enc_ok and bool(kept_ciphers)},
        "terrapin": {
            "status": "fail" if terrapin else "ok",
            "found": ([CHACHA] if chacha and not strict else [])
                     + (["cbc+etm"] if cbc_etm and not strict else []),
            "kept": kept_ciphers,
            "appliable": bool(terrapin) and enc_ok
                         and bool(kept_ciphers)
                         and not any(_is_cbc(c) for c in kept_ciphers)
                         and (strict or CHACHA not in kept_ciphers)},
        "sshv1": {"status": "fail" if sshv1 else "ok",
                  "found": (["banner:" + scan.get("banner", "")] if v1_scan
                            else ["version 1.99" if v1_show else "version 1"]),
                  "kept": ["2"],
                  "appliable": bool(sshv1)},  # `ip ssh version 2` is universal
    }
    issues = []
    for sub in SUBS:
        s = subs[sub]
        if s["status"] == "fail" and not s["appliable"]:
            issues.append(f"{sub}_manual")

    target_subs = [s for s in SUBS if subs[s]["status"] == "fail"
                   and subs[s]["appliable"]]
    lines = build_proposal_lines(target_subs, subs, cfg)
    proposal_cmds = _wrap_proposal(lines)
    return {
        "vuln": "ssh",
        "compliant": not any(subs[s]["status"] == "fail" for s in SUBS),
        "subs": subs,
        "scan": {"banner": scan.get("banner", ""),
                 "kex": kex, "ciphers": ciphers, "macs": macs,
                 "strict_kex": strict},
        "capability": cap,
        "ios": _ios_short(version_out),
        "model": _parse_model(version_out),
        "orig_algo": cfg["algo"],
        "orig_version": cfg["version"],
        "show_algos": show_algos,
        "issues": issues,
        "proposal": "\n".join(proposal_cmds) + ("\n" if proposal_cmds else ""),
        "proposal_cmds": proposal_cmds,
    }


def build_proposal_lines(target_subs: list[str], subs: dict,
                         cfg: dict) -> list[str]:
    """Config lines (no conf t / end / wr) for the targeted sub-findings."""
    lines: list[str] = []
    if "mac" in target_subs:
        lines.append("ip ssh server algorithm mac "
                     + " ".join(subs["mac"]["kept"]))
    if "kex" in target_subs:
        lines.append("ip ssh server algorithm kex "
                     + " ".join(subs["kex"]["kept"]))
    if "cbc" in target_subs or "terrapin" in target_subs:
        kept = (subs["cbc"]["kept"] if "cbc" in target_subs
                else subs["terrapin"]["kept"])
        lines.append("ip ssh server algorithm encryption " + " ".join(kept))
    if "sshv1" in target_subs:
        lines.append("ip ssh version 2")
    return lines


def _wrap_proposal(lines: list[str]) -> list[str]:
    if not lines:
        return []
    return ["conf t"] + lines + ["end", "wr"]


def apply_targets(result: dict) -> list[dict]:
    """Snapshot list of appliable failed sub-findings (with originals)."""
    if not result or result.get("vuln") != "ssh":
        return []
    out = []
    for sub in SUBS:
        s = result["subs"][sub]
        if s["status"] == "fail" and s["appliable"]:
            out.append({"sub": sub, "found": list(s["found"]),
                        "kept": list(s["kept"]),
                        "before_scan": dict(result["scan"])})
    return out


def needs_apply(result: dict | None) -> bool:
    if not result or result.get("vuln") != "ssh" or result.get("compliant"):
        return False
    return bool(apply_targets(result))


def _target_lines(targets: list[dict], result: dict) -> list[str]:
    subs = {t["sub"]: {"kept": t["kept"]} for t in targets or []}
    return build_proposal_lines([t["sub"] for t in targets or []], subs,
                                {"algo": result.get("orig_algo", {}),
                                 "version": result.get("orig_version")})


def build_fix_commands(targets: list[dict], result: dict | None = None
                       ) -> list[str]:
    return _target_lines(targets, result or {})


def build_rollback_commands(targets: list[dict], result: dict | None = None
                            ) -> list[str]:
    """Restore pre-fix state: original algorithm lines (or their no-form)
    and the original `ip ssh version` (or its no-form when we added it)."""
    res = result or {}
    orig_algo = res.get("orig_algo", {})
    orig_version = res.get("orig_version")
    kinds: list[str] = []
    for t in targets or []:
        sub = t["sub"]
        kind = {"mac": "mac", "kex": "kex", "cbc": "encryption",
                "terrapin": "encryption"}.get(sub)
        if kind and kind not in kinds:
            kinds.append(kind)
    cmds: list[str] = []
    for kind in kinds:
        if kind in orig_algo:
            cmds.append(f"ip ssh server algorithm {kind} {orig_algo[kind]}")
        else:
            cmds.append(f"no ip ssh server algorithm {kind}")
    if any(t["sub"] == "sshv1" for t in targets or []):
        if orig_version:
            cmds.append(f"ip ssh version {orig_version}")
        else:
            cmds.append("no ip ssh version 2")
    return cmds


def fix_verified(result: dict, targets: list[dict]) -> bool:
    """True when every targeted sub-finding is clean in the fresh result."""
    if not result or result.get("vuln") != "ssh":
        return False
    subs = result.get("subs", {})
    return all(subs.get(t["sub"], {}).get("status") == "ok"
               for t in targets or [])


def rollback_verified(targets: list[dict], after: dict) -> bool:
    """True when the offered algorithms match the pre-fix snapshot again."""
    if not targets or not after or after.get("vuln") != "ssh":
        return False
    scan = after.get("scan", {})
    for t in targets or []:
        before = t.get("before_scan", {})
        for key in ("kex", "ciphers", "macs"):
            if sorted(scan.get(key, [])) != sorted(before.get(key, [])):
                return False
    return True


def split_fix_groups(targets: list[dict], result: dict | None = None
                     ) -> list[tuple[str, list[dict]]]:
    """Group targets for sequential apply: mac, kex, encryption, version.

    One group per config line, so a rejected keyword (e.g. no `kex` on
    older IOS) fails alone while the rest still applies.
    """
    groups: list[tuple[str, list[dict]]] = []
    bucket: dict[str, list[dict]] = {}
    for t in targets or []:
        name = {"mac": "mac", "kex": "kex", "cbc": "encryption",
                "terrapin": "encryption", "sshv1": "version"}[t["sub"]]
        bucket.setdefault(name, []).append(t)
    for name in ("mac", "kex", "encryption", "version"):
        if bucket.get(name):
            groups.append((name, bucket[name]))
    return groups


def fetch_check_run(host: str, username: str, password: str,
                    enable: str | None = None, port: int = 22,
                    debug_log: str | None = None) -> dict:
    """No-auth handshake scan + authenticated config fetch, analyzed."""
    import cisco_ssh
    import ssh_scan

    try:
        scan = ssh_scan.scan(host, port)
    except ssh_scan.SSHScanError as e:
        raise RuntimeError(f"{host}: SSH scan failed: {e}") from e
    out = cisco_ssh.run_commands(
        host, username, password, enable, port,
        timeout=15, commands=CHECK_COMMANDS, debug_log=debug_log)
    return analyze_ssh(scan, out.get(CHECK_COMMANDS[0], ""),
                       out.get(CHECK_COMMANDS[1], ""),
                       out.get(CHECK_COMMANDS[2], ""),
                       out.get(CHECK_COMMANDS[4], ""))


def fetch_check_session(sess) -> dict:
    """Same, but reusing an open ConfigSession (+ fresh handshake scan)."""
    import ssh_scan

    try:
        scan = ssh_scan.scan(sess.host, sess.port)
    except ssh_scan.SSHScanError as e:
        raise RuntimeError(f"{sess.host}: SSH scan failed: {e}") from e
    out = {cmd: sess.exec(cmd, 2.5) for cmd in CHECK_COMMANDS}
    return analyze_ssh(scan, out[CHECK_COMMANDS[0]],
                       out[CHECK_COMMANDS[1]], out[CHECK_COMMANDS[2]],
                       out[CHECK_COMMANDS[4]])


def format_result(host: str, result: dict, T) -> list[tuple[str, str | None]]:
    """Per-device SSH findings as (line, tag) segments for colored display."""
    segs = [(T("device_hdr").format(host=host) + "\n", None)]
    banner = (result.get("scan", {}).get("banner") or "").strip()
    if banner:
        segs.append((f"SSH: {banner}\n", None))
    subs = result.get("subs", {})
    for sub in SUBS:
        s = subs.get(sub, {})
        status = s.get("status")
        if status == "ok":
            segs.append((f"[OK] {T('ssh_sub_' + sub)}\n", "vuln_ok"))
        elif status == "fail":
            found = ", ".join(s.get("found", [])) or "?"
            if s.get("appliable"):
                segs.append((f"[FAIL] {T('ssh_sub_' + sub)}: {found}\n",
                             "vuln_fail"))
            else:
                segs.append((f"[FAIL] {T('ssh_sub_' + sub)}: {found} "
                             f"({T('ssh_manual_note')})\n", "vuln_fail"))
                segs.append((f"       {T('ssh_openproject_note')}\n",
                             "vuln_warn"))
        else:
            segs.append((f"[--] {T('ssh_sub_' + sub)}\n", None))
    cap = result.get("capability", {})
    level = cap.get("level", "unknown")
    segs.append((T("ssh_cap_" + level).format(
        reason=T("ssh_capreason_" + cap.get("reason", "unknown"))) + "\n",
        "vuln_ok" if level == "supported"
        else ("vuln_warn" if level == "unknown" else "vuln_fail")))
    if cap.get("keywords"):
        segs.append((T("ssh_cap_keywords").format(
            kw=", ".join(cap["keywords"])) + "\n", None))
    if result.get("compliant"):
        segs.append((T("vuln_ssh_ok") + "\n", "vuln_ok"))
    else:
        segs.append((T("vuln_ssh_bad") + "\n", "vuln_fail"))
    return segs


def verify_prompt(host: str, T) -> tuple[str, str]:
    return (T("ssh_verify_title").format(host=host),
            T("ssh_verify_msg").format(host=host))


def residual_summary(result: dict, T) -> tuple[str, str] | None:
    """Final per-device verdict after apply/rollback (log line + tag)."""
    if not result or result.get("vuln") != "ssh":
        return None
    bad = []
    for sub in SUBS:
        s = result.get("subs", {}).get(sub, {})
        if s.get("status") == "fail":
            found = ", ".join(s.get("found", []))
            bad.append(f"{T('ssh_sub_' + sub)}"
                       + (f" ({found})" if found else ""))
    if not bad:
        return T("vuln_ssh_ok"), "vuln_ok"
    return (T("vuln_apply_residual").format(items="; ".join(bad)),
            "vuln_fail")


def openproject_note(host: str, result: dict, T) -> str:
    """Paste-ready justification for findings that cannot be auto-fixed."""
    if not result or result.get("vuln") != "ssh":
        return ""
    subs = result.get("subs", {})
    manual = [s for s in SUBS
              if subs.get(s, {}).get("status") == "fail"
              and not subs.get(s, {}).get("appliable")]
    if not manual:
        return ""
    cap = result.get("capability", {})
    keywords = cap.get("keywords", [])
    lines = [T("vuln_note_header").format(host=host)]
    if result.get("ios"):
        lines.append(T("ssh_note_version").format(ios=result["ios"]))
    if keywords:
        lines.append(T("ssh_note_keywords").format(
            kw=", ".join(keywords)))
    kind_of = {"mac": "mac", "kex": "kex", "cbc": "encryption",
               "terrapin": "encryption"}
    for sub in manual:
        s = subs[sub]
        algos = ", ".join(s.get("found", [])) or "?"
        if not s.get("kept"):
            why = T("ssh_note_emptykept")
        elif keywords:
            why = T("ssh_note_nokeyword").format(kind=kind_of[sub])
        else:
            why = T("ssh_note_unsupported")
        lines.append(T("ssh_note_item").format(sub=T("ssh_sub_" + sub),
                                               algos=algos, why=why))
    if "2960X" in result.get("model", ""):
        lines.append(T("ssh_note_2960x").format(model=result["model"]))
    lines.append(T("ssh_note_footer"))
    return "\n".join(lines)
