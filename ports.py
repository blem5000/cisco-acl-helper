"""Find switchports unused for X months (IOS / IOS-XE).

Reads `show interfaces` over SSH and reports physical ports with no
traffic in either direction since the threshold. A port counts as used
when the last input OR the last output is newer than the threshold.
"""

from __future__ import annotations

import re

#: One "month" for the threshold (documented in the UI).
MONTH_DAYS = 30

#: Physical ethernet interface name forms (lowercase, spaces stripped).
_PHYSICAL = (
    "gigabitethernet", "gigabit", "gig", "gi",
    "fastethernet", "fast", "fa",
    "tengigabitethernet", "tengig", "ten", "te",
    "twogigabitethernet", "tw",
    "twentyfivegige", "twentyfivegigabitethernet", "twentyfivegig", "twe",
    "fivegigabitethernet", "fivegig", "fivegige", "fi",
    "fortygigabitethernet", "fortygig", "fortygige", "fo",
    "hundredgige", "hundredgig", "hu",
    "ethernet", "eth",
)

_LAST_IO = re.compile(
    r"Last input\s+(.+?),\s*output\s+(.+?),\s*output hang", re.IGNORECASE)
_LAST_CLEAR = re.compile(
    r'Last clearing of "show interface" counters\s+(.+?)\s*$',
    re.IGNORECASE | re.MULTILINE)


def is_physical(name: str) -> bool:
    """Physical ethernet port (excludes Vlan/Port-channel/Loopback/...)."""
    s = (name or "").strip().lower().replace(" ", "")
    m = re.match(r"^([a-z\-]+)", s)
    return bool(m) and m.group(1) in _PHYSICAL


def parse_age(text: str) -> float | None:
    """Relative age ("3w4d", "1d05h", "00:00:05") -> seconds.

    "never" (or unparseable) -> None. "00:00:00" means just now (0 s).
    """
    t = (text or "").strip().lower()
    if not t or t == "never":
        return None
    m = re.match(r"^(\d+):(\d\d?):(\d\d?)$", t)
    if m:
        return (int(m.group(1)) * 3600 + int(m.group(2)) * 60
                + int(m.group(3)))
    total = 0.0
    for mult, unit in ((7 * 86400, "w"), (86400, "d"), (3600, "h"),
                       (60, "m"), (1, "s")):
        # no \b: IOS glues units ("1d05h"), so only forbid a letter after
        mm = re.search(r"(\d+)\s*" + unit + r"(?![a-z])", t)
        if mm:
            total += int(mm.group(1)) * mult
    return total if total else None


def parse_show_interfaces(output: str) -> list[dict]:
    """Parse `show interfaces` into per-interface dicts.

    Each: {"name", "status" (up|down|admin down), "protocol",
    "description", "last_input", "last_output", "last_clearing"}
    (last_* are raw strings as shown by the device).
    """
    found: list[dict] = []
    cur: dict | None = None

    def _flush():
        if cur is not None:
            found.append(cur)

    for raw in (output or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = re.match(r"^(\S+)\s+is\s+(.+?),\s*line protocol is\s+(\S+)",
                     line.strip(), re.IGNORECASE)
        if m:
            _flush()
            state = m.group(2).strip().lower()
            if "administratively down" in state:
                status = "admin down"
            elif state == "up":
                status = "up"
            else:
                status = "down"
            cur = {"name": m.group(1), "status": status,
                   "protocol": m.group(3).strip().lower(),
                   "description": "", "last_input": "",
                   "last_output": "", "last_clearing": ""}
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.lower().startswith("description:"):
            cur["description"] = s.split(":", 1)[1].strip()
            continue
        mio = _LAST_IO.search(s)
        if mio:
            cur["last_input"] = mio.group(1).strip()
            cur["last_output"] = mio.group(2).strip()
            continue
        mc = re.search(
            r'Last clearing of "show interface" counters\s+(.+?)\s*$', s,
            re.IGNORECASE)
        if mc:
            cur["last_clearing"] = mc.group(1).strip()
    _flush()
    return found


def find_unused(interfaces: list[dict], months: float) -> list[dict]:
    """Physical ports with no input AND no output within `months`.

    "never" (None age) always counts as older than the threshold.
    Keeps device order.
    """
    threshold = months * MONTH_DAYS * 86400
    out: list[dict] = []
    for e in interfaces or []:
        if not is_physical(e.get("name", "")):
            continue
        age_in = parse_age(e.get("last_input", ""))
        age_out = parse_age(e.get("last_output", ""))
        used = ((age_in is not None and age_in <= threshold)
                or (age_out is not None and age_out <= threshold))
        if not used:
            out.append(e)
    return out


def common_clearing(interfaces: list[dict]) -> str:
    """Most frequent Last-clearing value (counters caveat for the report)."""
    counts: dict[str, int] = {}
    for e in interfaces or []:
        v = (e.get("last_clearing") or "").strip()
        if v:
            counts[v] = counts.get(v, 0) + 1
    if not counts:
        return ""
    return max(counts, key=lambda k: counts[k])
