"""No-auth NTP mode 6 (control query) probe (UDP/123).

Sends well-formed control READVAR requests (ntpq-style, like the
scanners) and reports whether the server answers. No response (timeout)
is the DESIRED state here - it means control queries are restricted.
Raises only on local socket setup errors, never on timeout, so callers
must check host reachability separately when a negative answer would
otherwise look like compliance.
"""

from __future__ import annotations

import socket
import struct

__all__ = ["NTP_PORT", "probe", "tcp_reachable", "build_mode6_request",
           "is_mode6_response", "REQUEST_VARIANTS"]

NTP_PORT = 123

MODE_CONTROL = 6
OP_READSTAT_REQ = 1
OP_READVAR_REQ = 2

#: (label, version, opcode) tried in order, each in its own send/receive
#: window. Scanners send ntpq-style READVAR; different NTP stacks answer
#: different versions - ANY mode 6 reply means the server is exposed.
REQUEST_VARIANTS = (
    ("vn4/readvar", 4, OP_READVAR_REQ),
    ("vn3/readvar", 3, OP_READVAR_REQ),
    ("vn2/readvar", 2, OP_READVAR_REQ),
    ("vn3/readstat", 3, OP_READSTAT_REQ),
)


def build_mode6_request(version: int = 4,
                        opcode: int = OP_READVAR_REQ) -> bytes:
    """Well-formed 12-octet control header (LI=0, given VN, Mode=6).

    Truncated (e.g. 4-byte) control packets are silently dropped by
    strict stacks, which is indistinguishable from a restricted server
    and produces false negatives - hence the full header.
    """
    first = (0 << 6) | ((version & 0x07) << 3) | MODE_CONTROL
    second = opcode & 0x1F
    return struct.pack(">BBHHHHH", first, second, 0, 0, 0, 0, 0)


def is_mode6_response(data: bytes) -> bool:
    """Any NTP control reply packet counts (content is irrelevant)."""
    return len(data) >= 4 and (data[0] & 0x07) == MODE_CONTROL


def probe(host: str, port: int = NTP_PORT, timeout: float = 1.5,
          tries: int = 2) -> tuple[bool, str]:
    """Return (responded, detail). Timeout on all tries means no response.

    Every REQUEST_VARIANTS entry gets its own send/receive window so the
    detail names the variant the server answered; UDP delivery is
    best-effort, so variants are retried across rounds before concluding
    the server stays silent.
    """
    last_err = ""
    for _ in range(max(1, tries)):
        for label, version, opcode in REQUEST_VARIANTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except OSError as e:
                raise RuntimeError(f"{host}: UDP socket failed: {e}") from e
            try:
                sock.settimeout(timeout)
                try:
                    sock.sendto(build_mode6_request(version, opcode),
                                (host, port))
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
                    return True, f"{len(data)}-byte mode 6 reply ({label})"
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
