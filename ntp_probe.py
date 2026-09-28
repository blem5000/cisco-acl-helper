"""No-auth NTP mode 6 (control query) probe (UDP/123).

Sends a control READVAR request and reports whether the server answers.
No response (timeout) is the DESIRED state here - it means control
queries are restricted. Raises only on local socket setup errors, never
on timeout, so callers must check host reachability separately when a
negative answer would otherwise look like compliance.
"""

from __future__ import annotations

import socket
import struct

__all__ = ["NTP_PORT", "probe", "tcp_reachable", "build_mode6_request",
           "is_mode6_response"]

NTP_PORT = 123

MODE_CONTROL = 6
OP_READVAR_REQ = 1


def build_mode6_request() -> bytes:
    """Minimal control READVAR request: LI=0, VN=3, Mode=6, opcode 1."""
    first = (0 << 6) | (3 << 3) | MODE_CONTROL
    second = OP_READVAR_REQ
    return struct.pack(">BBHH", first, second, 0, 0)


def is_mode6_response(data: bytes) -> bool:
    """Any NTP control reply packet counts (content is irrelevant)."""
    return len(data) >= 4 and (data[0] & 0x07) == MODE_CONTROL


def probe(host: str, port: int = NTP_PORT, timeout: float = 2.0,
          tries: int = 3) -> tuple[bool, str]:
    """Return (responded, detail). Timeout on all tries means no response.

    UDP delivery is best-effort: several tries guard against a single
    lost datagram before concluding the server stays silent.
    """
    req = build_mode6_request()
    last_err = ""
    for _ in range(max(1, tries)):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as e:
            raise RuntimeError(f"{host}: UDP socket failed: {e}") from e
        try:
            sock.settimeout(timeout)
            try:
                sock.sendto(req, (host, port))
            except OSError as e:
                last_err = str(e)
                continue
            try:
                data, _addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError as e:
                last_err = str(e)
                continue
            if is_mode6_response(data):
                return True, f"{len(data)}-byte mode 6 reply"
        finally:
            try:
                sock.close()
            except OSError:
                pass
    if last_err:
        return False, f"no mode 6 reply ({last_err})"
    return False, "no mode 6 reply (timeout)"


def tcp_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """Quick liveness check so a down host is never reported compliant."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    try:
        sock.close()
    except OSError:
        pass
    return True
