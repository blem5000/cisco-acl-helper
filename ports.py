"""Find switchports unused for X months (IOS / IOS-XE).

Reads `show interfaces` over SSH and reports physical ports with no
traffic in either direction since the threshold. A port counts as used
when the last input OR the last output is newer than the threshold.
"""

from __future__ import annotations

import re

import track

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


#: SFP/transceiver uplink families (skipped by default in the report).
_SFP = (
    "tengigabitethernet", "tengig", "ten", "te",
    "twentyfivegige", "twentyfivegigabitethernet", "twentyfivegig", "twe",
    "fortygigabitethernet", "fortygig", "fortygige", "fo",
    "hundredgige", "hundredgig", "hu",
)


def is_management(name: str) -> bool:
    """Out-of-band management port (never a switching port).

    Covers Fa0 (classic IOS), GigabitEthernet0/0 (IOS-XE),
    mgmt0 (NX-OS), Management0/x (ASA), bare GigabitEthernet0 (ISR).
    Three-part 0/0/0 is deliberately kept - on ISRs those carry data.
    Numbered member-0 switching ports (Fa0/1 on old platforms) stay.
    """
    s = (name or "").strip().lower().replace(" ", "")
    m = re.match(r"^([a-z\-]+)(.*)$", s)
    if not m:
        return False
    alpha, rest = m.group(1), m.group(2)
    if alpha == "management" or alpha.startswith("mgmt"):
        return True
    return rest in ("0", "0/0")


def is_physical(name: str) -> bool:
    """Switching ethernet port.

    Excludes Vlan/Port-channel/Loopback/... and any out-of-band
    management port (see is_management).
    """
    s = (name or "").strip().lower().replace(" ", "")
    m = re.match(r"^([a-z\-]+)", s)
    if not m or m.group(1) not in _PHYSICAL:
        return False
    return not is_management(name)


def is_sfp(name: str) -> bool:
    """Transceiver (uplink) port: Te/Twe/Fo/Hu families."""
    s = (name or "").strip().lower().replace(" ", "")
    m = re.match(r"^([a-z\-]+)", s)
    return bool(m) and m.group(1) in _SFP


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


def find_unused(interfaces: list[dict], months: float,
                skip_sfp: bool = True,
                sfp_ports: set[str] | None = None) -> list[dict]:
    """Physical ports with no input AND no output within `months`.

    "never" (None age) always counts as older than the threshold.
    SFP/uplink ports are skipped by default: Te/Twe/Hu/Fo families by
    name, plus any port with an inserted transceiver (from
    `show inventory` - covers SFP cages named GigabitEthernet, e.g.
    Gi1/0/50 on 2960), matched name-form agnostically. Empty SFP cages
    cannot be detected and are still listed. Keeps device order.
    """
    threshold = months * MONTH_DAYS * 86400
    stocked = {canon_name(p) for p in sfp_ports or set()}
    out: list[dict] = []
    for e in interfaces or []:
        name = e.get("name", "")
        if not is_physical(name):
            continue
        if skip_sfp and (is_sfp(name) or canon_name(name) in stocked):
            continue
        age_in = parse_age(e.get("last_input", ""))
        age_out = parse_age(e.get("last_output", ""))
        used = ((age_in is not None and age_in <= threshold)
                or (age_out is not None and age_out <= threshold))
        if not used:
            out.append(e)
    return out


def canon_name(name: str) -> str:
    """Interface name for cross-command matching (Gi1/0/50 == full form)."""
    try:
        return track.normalize_port(name or "")
    except Exception:
        return (name or "").strip().lower().replace(" ", "")


_DUPLEX = {"a-full", "full", "a-half", "half", "auto"}

#: Media types meaning "SFP/fiber or empty cage" (skip with SFP ports).
#: Empty cages report "Not Present" (2960X) or "unknown" (9200L).
_FIBER_TYPE = re.compile(
    r"sfp|not present|unknown|no xcvr|1000base(?!tx)|10gbase|25gbase|"
    r"40gbase|100gbase",
    re.IGNORECASE)


def parse_status_types(output: str) -> dict[str, str]:
    """`show interfaces status` -> {canon_name: media Type}.

    Takes the leftmost Duplex token (descriptions containing "auto"
    err to the safe side: the port is kept, never wrongly skipped),
    Speed is the next token, Type is everything after it - so
    descriptions with spaces and multi-word types ("1000BaseSX SFP",
    "Not Present") cannot shift the columns. Lines without Duplex
    (headers) are skipped.
    """
    types: dict[str, str] = {}
    for raw in (output or "").splitlines():
        parts = raw.split()
        if len(parts) < 5 or parts[0].lower() == "port":
            continue
        dup = next((k for k in range(1, len(parts))
                    if parts[k].lower() in _DUPLEX and k + 1 < len(parts)),
                   None)
        if dup is None:
            continue
        typ = " ".join(parts[dup + 2:])
        types[canon_name(parts[0])] = typ
    return types


def is_fiber_type(typ: str) -> bool:
    """Media Type of an SFP/fiber port or an empty cage."""
    return bool(typ) and bool(_FIBER_TYPE.search(typ))


def parse_inventory_transceivers(output: str) -> set[str]:
    """Physical interface names holding a transceiver (`show inventory`).

    Only NAME fields that look like a physical port are returned
    (switch/power/fan entries ignored).
    """
    found: set[str] = set()
    for m in re.finditer(r'NAME:\s*"([^"]+)"', output or ""):
        name = m.group(1).strip()
        if is_physical(name):
            found.add(name)
    return found


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


# ---------------------------------------------------------------- PoE ----

#: `show power inline` budget header (classic IOS / IOS-XE).
_POE_AVAILABLE = re.compile(r"Available:\s*([\d.]+)\s*\(?w", re.IGNORECASE)
_POE_USED = re.compile(r"Used:\s*([\d.]+)\s*\(?w", re.IGNORECASE)
_POE_LEFT = re.compile(r"Remaining:\s*([\d.]+)\s*\(?w", re.IGNORECASE)

#: Some IOS-XE stacks print a module table instead of the inline header.
_POE_MODULE_HDR = re.compile(
    r"^Module\b.*\bAvailable\b.*\bUsed\b.*\bRemaining\b", re.IGNORECASE)
_POE_MODULE_ROW = re.compile(
    r"^\d+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$")

#: Per-port table columns (`Admin` and `Oper` state words).
_POE_ADMIN = {"auto", "never", "static", "off"}
_POE_OPER = {"on", "off", "faulty", "deny", "err-disable", "n/a",
             "power-deny", "unknown"}


def _poe_header(regex: re.Pattern, text: str) -> float | None:
    """Sum every match of one budget header field (stack members)."""
    values: list[float] = []
    for m in regex.finditer(text):
        try:
            values.append(float(m.group(1)))
        except ValueError:
            pass
    return sum(values) if values else None


def _poe_module_totals(text: str) -> tuple[float, float, float] | None:
    """Sum `Module Available Used Remaining` rows, if that layout is used."""
    totals = [0.0, 0.0, 0.0]
    found = False
    in_table = False
    for raw in text.splitlines():
        s = raw.strip()
        if _POE_MODULE_HDR.match(s):
            in_table = True
            continue
        if not in_table:
            continue
        if not s:
            in_table = False
            continue
        m = _POE_MODULE_ROW.match(s)
        if m:
            found = True
            for i in range(3):
                totals[i] += float(m.group(i + 1))
    return tuple(totals) if found else None


def parse_power_inline(output: str) -> dict:
    """Parse `show power inline` -> PoE budget and per-port state.

    Handles both layouts seen on Cisco access switches:

        Available:740.0(w)  Used:131.4(w)  Remaining:608.6(w)
        Interface Admin  Oper       Power   Device              Class Max
        Gi1/0/1   auto   on         6.3     IP Phone 7960       2     15.4

    and the `Module Available Used Remaining` table used by some
    IOS-XE stacks. Returns {"available", "used", "remaining", "ports"}
    where `ports` maps canon_name -> {"admin", "oper", "watts"}.
    Budget values are None when the device did not report them.
    """
    text = output or ""
    available = _poe_header(_POE_AVAILABLE, text)
    used = _poe_header(_POE_USED, text)
    remaining = _poe_header(_POE_LEFT, text)
    if available is None and used is None and remaining is None:
        table = _poe_module_totals(text)
        if table:
            available, used, remaining = table
    if remaining is None and available is not None and used is not None:
        remaining = max(0.0, available - used)

    ports: dict[str, dict] = {}
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 4:
            continue
        name, admin, oper = parts[0], parts[1].lower(), parts[2].lower()
        if admin not in _POE_ADMIN or oper not in _POE_OPER:
            continue
        try:
            watts = float(parts[3])
        except ValueError:
            continue
        if not is_physical(name):
            continue
        ports[canon_name(name)] = {"admin": admin, "oper": oper,
                                   "watts": watts}
    return {"available": available, "used": used, "remaining": remaining,
            "ports": ports}


def port_idle_months(entry: dict) -> float | None:
    """How many months a port has been idle (None = never active).

    Uses the newer of the two directions, the same rule as find_unused:
    traffic in either direction means the port was in use.
    """
    ages = [parse_age(entry.get("last_input", "")),
            parse_age(entry.get("last_output", ""))]
    ages = [a for a in ages if a is not None]
    if not ages:
        return None
    return min(ages) / (MONTH_DAYS * 86400)


def switch_snapshot(host: str, physical: list[dict], unused: list[dict],
                    skipped: int, poe: dict | None = None) -> dict:
    """Collect one switch's data for the reduction planner.

    `physical`/`unused`/`skipped` come from parse_show_interfaces,
    find_unused and the SFP filter. `poe` comes from parse_power_inline.
    The result separates:
      * used access ports and their live PoE load (what must move),
      * free access ports and free PoE-capable ports (where it can move),
      * idle ports and how long they have been idle (and any PoE they
        still draw even though they carry no traffic).
    """
    poe = poe or {}
    poe_ports = poe.get("ports") or {}
    unused = unused or []
    physical = physical or []
    idle_names = {canon_name(e.get("name", "")) for e in unused}

    idle: list[dict] = []
    for e in unused:
        name = e.get("name", "")
        p = poe_ports.get(canon_name(name)) or {}
        idle.append({
            "name": name,
            "status": e.get("status", ""),
            "description": e.get("description", ""),
            "last_input": e.get("last_input", ""),
            "last_output": e.get("last_output", ""),
            "months": port_idle_months(e),
            "watts": float(p.get("watts") or 0.0),
            "poe_on": p.get("oper") == "on",
        })

    active_poe = 0
    active_watts = 0.0
    poe_free = 0
    for e in physical:
        name = canon_name(e.get("name", ""))
        p = poe_ports.get(name)
        if p is None:
            continue
        idle_here = name in idle_names
        if p.get("oper") == "on":
            # Idle powered ports are not "live load" - only the ones that
            # stay connected have to fit on the surviving switches.
            if not idle_here:
                active_poe += 1
                active_watts += float(p.get("watts") or 0.0)
        # An idle PoE port is free for a moved PD whether or not an idle
        # device is still powered there (that device is part of the cleanup).
        if (idle_here and p.get("oper") in ("on", "off")
              and p.get("admin") in ("auto", "static")):
            poe_free += 1

    total = max(0, len(physical) - skipped)
    months = [p["months"] for p in idle if p["months"] is not None]
    return {
        "host": host,
        "total": total,
        "used": max(0, total - len(unused)),
        "free": len(unused),
        "skipped": skipped,
        "idle": idle,
        "idle_count": len(idle),
        "idle_never": sum(1 for p in idle if p["months"] is None),
        "idle_avg": (sum(months) / len(months)) if months else None,
        "idle_poe_ports": sum(1 for p in idle if p["poe_on"]),
        "idle_poe_watts": sum(p["watts"] for p in idle if p["poe_on"]),
        "active_poe": active_poe,
        "active_watts": active_watts,
        "poe_free": poe_free,
        "poe_available": poe.get("available"),
        "poe_used": poe.get("used"),
        "poe_left": poe.get("remaining"),
        "err": "",
    }


def _reduction_key(switch: dict) -> tuple:
    """Prefer the emptiest switches, then the longest-idle ports."""
    total = switch.get("total") or 0
    util = (switch.get("used") or 0) / total if total else 0.0
    avg = switch.get("idle_avg")
    return (util, -(avg if avg is not None else 999.0))


def plan_reduction(switches: list[dict]) -> dict:
    """Estimate how many switches a rack can lose (greedy).

    An underused switch is a removal candidate when its live ports,
    live PoE ports and live PoE watts fit into the combined free ports,
    free PoE ports and remaining PoE budget of the other switches.
    Candidates are tried emptiest-first; a candidate that does not fit
    stays and its free capacity remains available for later moves.

    This is an aggregate estimate - per-port PoE limits, VLANs and
    uplinks are not modelled. Returns:
      removable: [{host, ports, poe_ports, watts, targets, ...}]
      kept:      host names that must stay
      failed:    rejected candidates with a `reason` (ports, poe_ports,
                 power, poe_unknown)
    """
    live = [s for s in switches or [] if not s.get("err")]
    if not live:
        return {"removable": [], "kept": [], "total": 0, "needed": 0,
                "failed": [], "reason": "no_data"}
    if len(live) == 1:
        return {"removable": [], "kept": [live[0]["host"]], "total": 1,
                "needed": 1, "failed": [], "reason": "single"}

    kept = list(live)
    removable: list[dict] = []
    failed: list[dict] = []
    moved_ports = 0
    moved_poe = 0
    moved_watts = 0.0

    for s in sorted(live, key=_reduction_key):
        if len(kept) <= 1:
            break
        others = [o for o in kept if o is not s]
        free_ports = sum(o.get("free", 0) for o in others) - moved_ports
        free_poe = sum(o.get("poe_free", 0) for o in others) - moved_poe
        known = [o for o in others if o.get("poe_left") is not None]
        # Idle PoE ports are treated as free: their current draw comes back
        # to the budget when the idle devices are disconnected.
        left_watts = (sum(float(o["poe_left"])
                          + float(o.get("idle_poe_watts") or 0.0)
                          for o in known) - moved_watts if known else None)
        need_ports = s.get("used", 0)
        need_poe = s.get("active_poe", 0)
        need_watts = float(s.get("active_watts") or 0.0)

        reason = ""
        if need_ports > free_ports:
            reason = "ports"
        elif need_poe > free_poe:
            reason = "poe_ports"
        elif need_watts > 0 and left_watts is None:
            reason = "poe_unknown"
        elif need_watts > (left_watts or 0.0) + 1e-9:
            reason = "power"

        entry = {
            "host": s.get("host", ""),
            "ports": need_ports,
            "poe_ports": need_poe,
            "watts": need_watts,
            "targets": [o.get("host", "") for o in others],
            "target_info": [
                {"host": o.get("host", ""), "free": o.get("free", 0),
                 "poe_free": o.get("poe_free", 0),
                 "left": (None if o.get("poe_left") is None else
                          float(o["poe_left"])
                          + float(o.get("idle_poe_watts") or 0.0))}
                for o in others
            ],
            "free_ports": free_ports,
            "free_poe": free_poe,
            "left_watts": left_watts,
        }
        if reason:
            entry["reason"] = reason
            failed.append(entry)
            continue

        removable.append(entry)
        kept.remove(s)
        moved_ports += need_ports
        moved_poe += need_poe
        moved_watts += need_watts

    return {"removable": removable,
            "kept": [s.get("host", "") for s in kept],
            "total": len(live), "needed": len(kept),
            "failed": failed, "reason": ""}
