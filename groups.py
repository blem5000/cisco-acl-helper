"""Automatic device grouping by hostname/label (rack/site).

Splits the source text on separator characters and joins the first
`parts` segments with "_", e.g. "MA1_2F_3_5_96105_O.lgema.local" with
separators "._" and 2 parts -> "MA1_2F". Pure functions (dialog calls
them for the live preview, tests cover them headless).
"""

from __future__ import annotations

import re


def suggest_group(source: str, seps: str = "._-", parts: int = 2) -> str:
    """Propose a group name from a hostname/label, "" when impossible."""
    try:
        n = int(parts)
    except (TypeError, ValueError):
        return ""
    if n < 1:
        return ""
    delims = set(seps or "._-")
    cur, out = "", []
    for ch in (source or "").strip():
        if ch in delims:
            if cur:
                out.append(cur)
                cur = ""
            if len(out) >= n:
                break
        else:
            cur += ch
    if cur and len(out) < n:
        out.append(cur)
    return "_".join(out[:n])


def auto_assign(devices: list[dict], source: str = "hostname",
                seps: str = "._-", parts: int = 2,
                only_empty: bool = True) -> dict[str, str]:
    """{host: proposed group} for devices (skips empty suggestions).

    `source` is "hostname" (label) or "host". With `only_empty`, devices
    that already have a group are left out (manual assignments win).
    """
    key = "host" if source == "host" else "hostname"
    out: dict[str, str] = {}
    for d in devices or []:
        host = str(d.get("host", "") or "").strip()
        if not host:
            continue
        if only_empty and (d.get("group") or "").strip():
            continue
        g = suggest_group(str(d.get(key, "") or ""), seps, parts)
        if g:
            out[host] = g
    return out
