"""Best-effort DHCP reservation check for Windows DHCP servers.

Runs on the user's PC (no credentials needed beyond the user's own rights):
  1. PowerShell DHCP cmdlets (needs RSAT DHCP tools + rights on the server).
  2. Fallback: netsh dhcp (parses scopes + reservedip).

Returns (status, detail):
  ("ok", mac)      - reservation found
  ("none", "")     - server reachable, no reservation for this IP
  ("unknown", why) - could not verify (no tools / no access / timeout / ...)

Never raises - all errors map to ("unknown", reason).
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import unicodedata

PS_TIMEOUT = 25
NETSH_TIMEOUT = 25

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}")


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run a console helper with NO visible window (GUI app)."""
    info = None
    flags = 0
    if hasattr(subprocess, "STARTUPINFO"):  # Windows
        try:
            info = subprocess.STARTUPINFO()
            info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = 0  # SW_HIDE
        except Exception:
            info = None
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          startupinfo=info, creationflags=flags)


def check_reservation(server: str, ip: str) -> tuple[str, str]:
    """Check DHCP reservation. Never raises."""
    server = (server or "").strip()
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return ("unknown", "bad IP")
    if not server:
        return ("unknown", "no server")
    last_why = "no method"
    for method in (_via_powershell, _via_netsh):
        try:
            status, detail = method(server, ip.strip())
        except Exception:  # noqa: BLE001 - best effort by design
            continue
        if status in ("ok", "none"):
            return (status, detail)
        # "unknown" -> try next method, remember reason
        last_why = detail or last_why
    return ("unknown", last_why)


def _via_powershell(server: str, ip: str) -> tuple[str, str]:
    ps = (
        "$ErrorActionPreference='Stop';"
        f"$scopes=Get-DhcpServerv4Scope -ComputerName '{server}';"
        "$out=@();"
        "foreach($s in $scopes){"
        f"$r=Get-DhcpServerv4Reservation -ComputerName '{server}' "
        "-ScopeId $s.ScopeId.IPAddressToString -ErrorAction SilentlyContinue;"
        "foreach($x in $r){$out+=[pscustomobject]@{"
        "IP=$x.IPAddress.IPAddressToString;MAC=[string]$x.ClientId;"
        "Scope=$s.ScopeId.IPAddressToString}}};"
        "$out|ConvertTo-Json -Compress -Depth 3"
    )
    p = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
             PS_TIMEOUT)
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip().splitlines()
        return ("unknown", err[-1][:120] if err else "powershell failed")
    try:
        data = json.loads(p.stdout or "null")
    except json.JSONDecodeError:
        return ("unknown", "powershell parse error")
    if not data:
        return ("none", "")
    rows = data if isinstance(data, list) else [data]
    for row in rows:
        if str(row.get("IP", "")).strip() == ip:
            return ("ok", str(row.get("MAC", "")).strip())
    return ("none", "")


def _scope_for_ip(server: str, ip: str) -> str | None:
    p = _run(["netsh", "dhcp", "server", server, "show", "scope"], NETSH_TIMEOUT)
    if p.returncode != 0:
        return None
    addr = ipaddress.ip_address(ip)
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})", p.stdout):
        try:
            net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
        except ValueError:
            continue
        if addr in net:
            return m.group(1)
    return None


def _via_netsh(server: str, ip: str) -> tuple[str, str]:
    scope = _scope_for_ip(server, ip)
    if scope is None:
        return ("unknown", "netsh: no scope / no access")
    p = _run(["netsh", "dhcp", "server", server, "scope", scope,
              "show", "reservedip"], NETSH_TIMEOUT)
    if p.returncode != 0:
        return ("unknown", "netsh reservedip failed")
    out = p.stdout
    if ip not in out:
        return ("none", "")
    # MAC from the same blank-line-separated block as the IP, if present
    for block in re.split(r"\n\s*\n", out):
        if ip in block:
            m = _MAC_RE.search(block)
            return ("ok", m.group(0) if m else "")
    return ("ok", "")


def _run_utf8(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Like _run, but decodes stdout as UTF-8 (for Name/Description text).

    Windows PowerShell writes ConvertTo-Json output in the console code
    page by default, which mangles national characters - forcing
    [Console]::OutputEncoding to UTF-8 on the PS side keeps "ąęłńó"
    intact in reservation descriptions.
    """
    info = None
    flags = 0
    if hasattr(subprocess, "STARTUPINFO"):  # Windows
        try:
            info = subprocess.STARTUPINFO()
            info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = 0  # SW_HIDE
        except Exception:
            info = None
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                       startupinfo=info, creationflags=flags)
    try:
        text = (p.stdout or b"").decode("utf-8-sig")
    except (UnicodeDecodeError, ValueError):
        text = (p.stdout or b"").decode("cp1250", errors="replace")
    try:
        err = (p.stderr or b"").decode("utf-8-sig")
    except (UnicodeDecodeError, ValueError):
        err = (p.stderr or b"").decode("cp1250", errors="replace")
    p.stdout = text
    p.stderr = err
    return p


def fetch_all_reservations(server: str) -> tuple[dict[str, dict], str]:
    """Dump every DHCPv4 reservation from `server` in one PowerShell call.

    Returns ({ip: {"mac", "name", "description"}}, err). `err` is "" on
    success. PowerShell-only (netsh cannot show Name/Description);
    per-scope failures are skipped, an empty dump means "no reservations".
    Never raises.
    """
    server = (server or "").strip()
    if not server:
        return ({}, "no server")
    ps = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        "$ErrorActionPreference='Stop';"
        f"$scopes=Get-DhcpServerv4Scope -ComputerName '{server}';"
        "$out=@();"
        "foreach($s in $scopes){"
        f"$r=Get-DhcpServerv4Reservation -ComputerName '{server}' "
        "-ScopeId $s.ScopeId.IPAddressToString -ErrorAction SilentlyContinue;"
        "foreach($x in $r){$out+=[pscustomobject]@{"
        "IP=$x.IPAddress.IPAddressToString;MAC=[string]$x.ClientId;"
        "Name=[string]$x.Name;Description=[string]$x.Description}}};"
        "$out|ConvertTo-Json -Compress -Depth 3"
    )
    try:
        p = _run_utf8(["powershell", "-NoProfile", "-NonInteractive",
                       "-Command", ps], 60)
    except Exception as e:  # noqa: BLE001 - best effort by design
        return ({}, str(e)[:120])
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip().splitlines()
        return ({}, err[-1][:160] if err else "powershell failed")
    try:
        data = json.loads(p.stdout or "null")
    except json.JSONDecodeError:
        return ({}, "powershell parse error")
    if not data:
        return ({}, "")
    rows = data if isinstance(data, list) else [data]
    out: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("IP", "")).strip()
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        out[ip] = {"mac": str(row.get("MAC", "") or "").strip(),
                   "name": str(row.get("Name", "") or "").strip(),
                   "description": str(row.get("Description", "") or "").strip()}
    return (out, "")


# ł/Ł have no NFKD decomposition, so they need an explicit map; the
# NFKD fallback below strips any other accented letters.
_PL_ASCII = str.maketrans({
    "ą": "a", "ć": "c", "ę": "e", "ł": "l", "ń": "n",
    "ó": "o", "ś": "s", "ź": "z", "ż": "z",
    "Ą": "A", "Ć": "C", "Ę": "E", "Ł": "L", "Ń": "N",
    "Ó": "O", "Ś": "S", "Ź": "Z", "Ż": "Z",
})


def _to_ascii(text: str) -> str:
    """Polish (and other) diacritics -> plain ASCII for IOS remarks."""
    text = text.translate(_PL_ASCII)
    return unicodedata.normalize("NFKD", text).encode(
        "ascii", "ignore").decode("ascii")


def owner_from_description(desc: str) -> str:
    """Extract "Imie Nazwisko" from a DHCP reservation description.

    Real-world formats (BCS marker anywhere, dash/dot separators,
    any case): "BCS - Jan Kowalski", "BCS Jan Kowalski",
    "BCS - JAN.KOWALSKI", "Jan Kowalski BCS", "jan.kowalski BCS".
    Result is Title Case ASCII (no Polish characters - IOS remarks):
    "Łukasz Żółć" -> "Lukasz Zolc".
    Returns "" when nothing usable remains (e.g. bare "BCS").
    """
    if not desc:
        return ""
    text = re.sub(r"(?i)\bbcs\b", " ", desc)
    text = text.replace(".", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text).strip(" ,;")
    if not text:
        return ""
    return _to_ascii(text).title()[:100]
