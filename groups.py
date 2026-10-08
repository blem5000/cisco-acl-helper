"""Automatic device grouping by hostname/label via editable regex.

The group is capture group 1, or the whole match when the pattern has
no groups, e.g. "^([A-Za-z0-9]+_[A-Za-z0-9]+_[A-Za-z0-9]+)" maps
"MA1_2F_3_5_96105_O.lgema.local" -> "MA1_2F_3". Pure functions (dialog
calls them for the live preview, tests cover them headless).
"""

from __future__ import annotations

import re

#: Default: 2-3 leading segments with original separators, e.g.
#: "MA1_2F_3_5_96105_O.lgema.local" -> "MA1_2F_3",
#: "LGEMA_GMES2.0_HB_B" -> "LGEMA_GMES2.0".
DEFAULT_PATTERN = r"^([^._]+[._][^._]+(?:[._][^._]+)?)"

#: Earlier defaults, replaced by DEFAULT_PATTERN on load (the dialog
#: persists whatever was shown, so without this the old default would
#: stick forever once saved).
LEGACY_PATTERNS = (r"^([A-Za-z0-9]+_[A-Za-z0-9]+_[A-Za-z0-9]+)",)


def suggest_group_regex(source: str, pattern: str) -> str:
    """Propose a group name, "" on no match. Raises re.error if bad."""
    m = re.search(pattern or "", source or "")
    if not m:
        return ""
    try:
        g = m.group(1)
    except IndexError:
        g = m.group(0)
    return (g or "").strip()


def auto_assign_regex(devices: list[dict], source: str = "hostname",
                      pattern: str = DEFAULT_PATTERN,
                      only_empty: bool = True) -> dict[str, str]:
    """{host: proposed group} for devices (skips empty suggestions).

    `source` is "hostname" (label) or "host". With `only_empty`, devices
    that already have a group are left out (manual assignments win).
    Raises re.error on an invalid pattern (dialog shows it live).
    """
    rx = re.compile(pattern or "")
    key = "host" if source == "host" else "hostname"
    out: dict[str, str] = {}
    for d in devices or []:
        host = str(d.get("host", "") or "").strip()
        if not host:
            continue
        if only_empty and (d.get("group") or "").strip():
            continue
        m = rx.search(str(d.get(key, "") or ""))
        if not m:
            continue
        try:
            g = m.group(1)
        except IndexError:
            g = m.group(0)
        if (g or "").strip():
            out[host] = g.strip()
    return out
