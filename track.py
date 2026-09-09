"""IP -> MAC -> switchport -> CDP neighbor tracing parsers (IOS / IOS-XE)."""

from __future__ import annotations

import re

_MAC_DOTTED = re.compile(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}")
_MAC_COLON = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")

_IFACE_EXPAND = {
    "gigabitethernet": "gigabitethernet",
    "gigabit": "gigabitethernet",
    "gig": "gigabitethernet",
    "gi": "gigabitethernet",
    "tengigabitethernet": "tengigabitethernet",
    "tengig": "tengigabitethernet",
    "ten": "tengigabitethernet",
    "te": "tengigabitethernet",
    "fastethernet": "fastethernet",
    "fast": "fastethernet",
    "fa": "fastethernet",
    "port-channel": "port-channel",
    "portchannel": "port-channel",
    "po": "port-channel",
    "twogigabitethernet": "twogigabitethernet",
    "tw": "twogigabitethernet",
    "hundredgige": "hundredgige",
    "hu": "hundredgige",
    "ethernet": "ethernet",
    "eth": "ethernet",
}


def canon_mac(mac: str) -> str:
    """MAC to 12 lowercase hex digits for comparison."""
    return re.sub(r"[^0-9a-fA-F]", "", mac).lower()


def normalize_port(name: str) -> str:
    """Gi1/0/5, GigabitEthernet 1/0/5 -> gigabitethernet1/0/5 (for matching)."""
    s = name.strip().lower().replace(" ", "")
    m = re.match(r"^([a-z\-]+)(.+)$", s)
    if not m:
        return s
    alpha, rest = m.group(1), m.group(2)
    if alpha in _IFACE_EXPAND:
        return _IFACE_EXPAND[alpha] + rest
    for key in sorted(_IFACE_EXPAND, key=len, reverse=True):
        if alpha.startswith(key):
            return _IFACE_EXPAND[key] + alpha[len(key):] + rest
    return s


def parse_arp(output: str, ip: str) -> dict | None:
    """Parse `show ip arp <ip>`.

    Returns {"mac", "interface", "age"} | {"incomplete": True} | None.
    """
    for line in output.splitlines():
        if ip not in line:
            continue
        if "incomplete" in line.lower():
            return {"incomplete": True}
        m = _MAC_DOTTED.search(line) or _MAC_COLON.search(line)
        if not m:
            continue
        parts = line.split()
        age = parts[2] if len(parts) > 3 else ""
        return {"mac": m.group(0).lower(), "interface": parts[-1] if parts else "",
                "age": age}
    return None


def parse_mac_table(output: str, mac: str) -> list[dict]:
    """Parse `show mac address-table address <mac>`.

    Returns [{"vlan", "type", "port"}] (usually one entry).
    """
    want = canon_mac(mac)
    found: list[dict] = []
    for line in output.splitlines():
        cands = _MAC_DOTTED.findall(line) + _MAC_COLON.findall(line)
        if not cands or not any(canon_mac(c) == want for c in cands):
            continue
        parts = line.split()
        if not parts:
            continue
        vlan, typ, port = parts[0], "", ""
        up = [p.upper() for p in parts]
        for i, p in enumerate(up):
            if p in ("DYNAMIC", "STATIC", "MULTICAST", "SYSTEM", "IGMP"):
                typ = parts[i]
                port = " ".join(parts[i + 1:])
                break
        if not port and len(parts) >= 4:
            typ, port = parts[2], " ".join(parts[3:])
        found.append({"vlan": vlan, "type": typ, "port": port.strip()})
    return found


def parse_cdp_detail(output: str) -> list[dict]:
    """Parse `show cdp neighbors detail`.

    Returns [{"device", "ip", "local", "remote", "platform"}].
    """
    entries: list[dict] = []
    for block in re.split(r"-{10,}", output):
        mdev = re.search(r"Device ID:\s*(\S+)", block)
        if not mdev:
            continue
        e: dict[str, str] = {"device": mdev.group(1), "ip": "",
                             "local": "", "remote": "", "platform": ""}
        mip = re.search(r"IP address:\s*(\d{1,3}(?:\.\d{1,3}){3})", block)
        if mip:
            e["ip"] = mip.group(1)
        mif = re.search(r"Interface:\s*([^,]+),\s*Port ID[^:]*:\s*(\S+)", block)
        if mif:
            e["local"], e["remote"] = mif.group(1).strip(), mif.group(2).strip()
        else:
            ml = re.search(r"Interface:\s*(\S+)", block)
            mr = re.search(r"Port ID[^:]*:\s*(\S+)", block)
            if ml:
                e["local"] = ml.group(1)
            if mr:
                e["remote"] = mr.group(1)
        mp = re.search(r"Platform:\s*([^,\n]+)", block)
        if mp:
            e["platform"] = mp.group(1).strip()
        entries.append(e)
    return entries


def find_cdp_on_port(entries: list[dict], port: str) -> dict | None:
    """CDP entry whose local interface matches `port` (name-form agnostic)."""
    want = normalize_port(port)
    for e in entries:
        if e.get("local") and normalize_port(e["local"]) == want:
            return e
    return None
