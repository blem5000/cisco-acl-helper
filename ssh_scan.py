"""No-authentication SSH handshake scanner (Nessus-style algorithm audit).

Opens TCP to the SSH port, reads the server banner and its KEXINIT packet,
and reports exactly what the server offers: protocol version hint, key
exchange / cipher (both directions) / MAC (both directions) name-lists and
whether the Terrapin strict-kex countermeasure is present. No login, no
auth - safe to run against any host, mirroring what network scanners check.

Pure logic + tiny socket framing; raises RuntimeError with a friendly
message when the handshake cannot be completed.
"""

from __future__ import annotations

import os
import socket
import struct

__all__ = ["SSHScanError", "scan", "parse_kexinit", "build_kexinit"]

SSH_MSG_KEXINIT = 20
STRICT_KEX = ("kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com")

CLIENT_VERSION = "SSH-2.0-CiscoACLHelper-SSHscan"

#: Full client offer (never negotiated - we close after KEXINIT). A broad,
#: sane offer matters: picky servers (e.g. Cisco IOS) may drop clients
#: that send no version string or an empty algorithm list.
_OFFER_KEX = [
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
]
_OFFER_HOSTKEY = [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
]
_OFFER_CIPHER = [
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr",
    "aes256-gcm", "aes128-gcm",
    "aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc",
]
_OFFER_MAC = [
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512",
    "hmac-sha1-etm@openssh.com", "hmac-sha1",
    "hmac-sha1-96", "hmac-md5-etm@openssh.com", "hmac-md5", "hmac-md5-96",
    "umac-128-etm@openssh.com", "umac-128@openssh.com",
    "umac-64-etm@openssh.com", "umac-64@openssh.com",
]


class SSHScanError(RuntimeError):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SSHScanError("connection closed during handshake")
        buf += chunk
    return buf


def _read_banner(sock: socket.socket) -> str:
    """Server version string; tolerates a few non-SSH preamble lines."""
    data = b""
    skipped = 0
    while True:
        while not data.endswith(b"\n"):
            if len(data) > 255:
                raise SSHScanError("banner line too long (not an SSH server?)")
            chunk = sock.recv(64)
            if not chunk:
                raise SSHScanError("connection closed before banner")
            data += chunk
        try:
            line = data.decode("ascii", errors="replace").strip()
        except Exception as e:
            raise SSHScanError(f"bad banner: {e}") from e
        data = b""
        if line.startswith("SSH-"):
            return line
        skipped += 1
        if skipped > 5:
            raise SSHScanError(f"not an SSH banner: {line[:60]!r}")


def _offer_blob(names: list[str]) -> bytes:
    raw = ",".join(names).encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def build_kexinit() -> bytes:
    """Client KEXINIT with a broad offer (never negotiated afterwards)."""
    payload = struct.pack("B", SSH_MSG_KEXINIT) + os.urandom(16)
    for names in (_OFFER_KEX, _OFFER_HOSTKEY, _OFFER_CIPHER, _OFFER_CIPHER,
                  _OFFER_MAC, _OFFER_MAC, ["none"], ["none"], [], []):
        payload += _offer_blob(names)
    payload += struct.pack("B", 0) + struct.pack(">I", 0)
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    return (struct.pack(">I", len(payload) + 1 + pad_len)
            + struct.pack("B", pad_len) + payload + os.urandom(pad_len))


def _read_packet(sock: socket.socket, timeout: float) -> tuple[int, bytes]:
    sock.settimeout(timeout)
    packet_len = struct.unpack(">I", _recv_exact(sock, 4))[0]
    if packet_len > 35000 or packet_len < 12:
        raise SSHScanError("bad SSH packet length")
    body = _recv_exact(sock, packet_len)
    padding_len = body[0]
    payload = body[1:len(body) - padding_len]
    if not payload:
        raise SSHScanError("empty SSH payload")
    return payload[0], payload[1:]


def parse_kexinit(payload: bytes) -> dict:
    """Parse a KEXINIT payload (without the message byte) into name-lists."""
    if len(payload) < 16:
        raise SSHScanError("truncated KEXINIT")
    off = 16
    lists: list[list[str]] = []
    for _ in range(10):
        if off + 4 > len(payload):
            raise SSHScanError("truncated KEXINIT name-list")
        (ln,) = struct.unpack(">I", payload[off:off + 4])
        off += 4
        if off + ln > len(payload):
            raise SSHScanError("truncated KEXINIT name-list data")
        raw = payload[off:off + ln].decode("ascii", errors="replace")
        off += ln
        lists.append([n for n in raw.split(",") if n] if raw else [])
    keys = ("kex", "hostkey", "c2s_cipher", "s2c_cipher", "c2s_mac",
            "s2c_mac", "c2s_comp", "s2c_comp", "c2s_lang", "s2c_lang")
    return dict(zip(keys, lists))


def _split_names(text: str) -> list[str]:
    return [n.strip() for n in text.replace(",", " ").split() if n.strip()]


def scan(host: str, port: int = 22, timeout: float = 10.0) -> dict:
    """Run the handshake scan, return the capability/finding dictionary."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise SSHScanError(
            f"cannot reach SSH on {host}:{port} ({e}). Check IP/port/VPN."
        ) from e
    try:
        sock.settimeout(timeout)
        # Protocol order matters: our version string first (strict servers
        # wait for it and drop clients that skip straight to KEXINIT).
        try:
            sock.sendall(CLIENT_VERSION.encode("ascii") + b"\r\n")
        except OSError as e:
            raise SSHScanError(f"cannot send client banner: {e}") from e
        banner = _read_banner(sock)
        try:
            sock.sendall(build_kexinit())
        except OSError:
            pass  # some servers answer before reading ours; keep going
        kex = None
        for _ in range(8):  # skip any pre-KEXINIT noise, then parse
            msg, payload = _read_packet(sock, timeout)
            if msg == SSH_MSG_KEXINIT:
                kex = parse_kexinit(payload)
                break
        if kex is None:
            raise SSHScanError("server sent no KEXINIT")
    except SSHScanError:
        raise
    except Exception as e:
        raise SSHScanError(f"SSH handshake with {host} failed: {e}") from e
    finally:
        try:
            sock.close()
        except OSError:
            pass
    sshv1 = banner.startswith("SSH-1.")
    kex_list = kex["kex"]
    return {
        "banner": banner,
        "sshv1": sshv1,
        "kex": kex_list,
        "hostkey": kex["hostkey"],
        "c2s_cipher": kex["c2s_cipher"],
        "s2c_cipher": kex["s2c_cipher"],
        "c2s_mac": kex["c2s_mac"],
        "s2c_mac": kex["s2c_mac"],
        "strict_kex": any(n in STRICT_KEX for n in kex_list),
        "ciphers": sorted(set(kex["c2s_cipher"]) | set(kex["s2c_cipher"])),
        "macs": sorted(set(kex["c2s_mac"]) | set(kex["s2c_mac"])),
    }


def parse_show_ip_ssh_algos(text: str) -> dict:
    """Effective algorithm lists from `show ip ssh` (newer IOS-XE)."""
    out = {"encryption": [], "mac": [], "kex": [], "hostkey": []}
    for line in (text or "").splitlines():
        low = line.strip().lower()
        for key, markers in (
                ("encryption", ("encryption algorithms:",)),
                ("mac", ("mac algorithms:",)),
                ("kex", ("kex algorithms:", "key exchange algorithms:")),
                ("hostkey", ("hostkey algorithms:", "host key algorithms:"))):
            for marker in markers:
                if marker in low:
                    out[key] = _split_names(line.split(":", 1)[1])
                    break
    return out
