"""Tests for the no-auth SSH handshake scanner (ssh_scan)."""

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ssh_scan


def build_server_kexinit(kex, ciphers, macs) -> bytes:
    payload = struct.pack("B", ssh_scan.SSH_MSG_KEXINIT) + b"C" * 16
    for names in (kex, ["ssh-rsa"], ciphers, ciphers, macs, macs,
                  ["none"], ["none"], [], []):
        raw = ",".join(names).encode("ascii")
        payload += struct.pack(">I", len(raw)) + raw
    payload += struct.pack("B", 0) + struct.pack(">I", 0)
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    return (struct.pack(">I", len(payload) + 1 + pad_len)
            + struct.pack("B", pad_len) + payload + b"P" * pad_len)


def _read_line(conn) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(64)
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


def _read_packet_framed(conn) -> bytes:
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise OSError("closed")
        raw_len += chunk
    (plen,) = struct.unpack(">I", raw_len)
    body = b""
    while len(body) < plen:
        chunk = conn.recv(plen - len(body))
        if not chunk:
            raise OSError("closed")
        body += chunk
    return body


def _drain(conn):
    try:
        conn.settimeout(0.5)
        while conn.recv(4096):
            pass
    except OSError:
        pass


class FakeSSHServer(threading.Thread):
    def __init__(self, banner, packet):
        super().__init__(daemon=True)
        self.banner = banner
        self.packet = packet
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def run(self):
        try:
            conn, _addr = self.sock.accept()
            with conn:
                conn.sendall(self.banner + b"\r\n")
                _read_line(conn)  # client version
                _read_packet_framed(conn)  # client KEXINIT (drained)
                conn.sendall(self.packet)
                _drain(conn)
        except OSError:
            pass
        finally:
            try:
                self.sock.close()
            except OSError:
                pass


class ScanTest(unittest.TestCase):
    def _scan(self, banner, kex, ciphers, macs):
        srv = FakeSSHServer(banner, build_server_kexinit(kex, ciphers, macs))
        srv.start()
        try:
            return ssh_scan.scan("127.0.0.1", srv.port, timeout=5.0)
        finally:
            srv.join(timeout=10)

    def test_weak_cisco_like_offer(self):
        res = self._scan(
            b"SSH-1.99-Cisco-1.25",
            ["diffie-hellman-group-exchange-sha1",
             "diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256"],
            ["aes128-ctr", "aes128-cbc", "3des-cbc"],
            ["hmac-sha1", "hmac-sha1-96"])
        self.assertTrue(res["sshv1"])
        self.assertFalse(res["strict_kex"])
        self.assertIn("diffie-hellman-group-exchange-sha1", res["kex"])
        self.assertIn("3des-cbc", res["ciphers"])
        self.assertIn("hmac-sha1-96", res["macs"])

    def test_modern_offer(self):
        res = self._scan(
            b"SSH-2.0-OpenSSH_9.6",
            ["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
            ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
            ["hmac-sha2-256-etm@openssh.com"])
        self.assertFalse(res["sshv1"])
        self.assertTrue(res["strict_kex"])

class StrictServerTest(unittest.TestCase):
    """Emulates a picky server (like Cisco): drops clients that skip the
    version string or send an empty KEXINIT offer."""

    def _serve(self, port_holder, banner, packet):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port_holder.append(srv.getsockname()[1])
        try:
            conn, _addr = srv.accept()
            with conn:
                conn.settimeout(5.0)
                # banner FIRST (like real servers), then validate the client
                version = _read_line(conn)
                if not version.startswith(b"SSH-"):
                    return  # garbage version -> drop
                conn.sendall(banner + b"\r\n")
                body = _read_packet_framed(conn)
                pad = body[0]
                payload = body[1:len(body) - pad]
                if not payload or payload[0] != ssh_scan.SSH_MSG_KEXINIT:
                    return
                (kex_len,) = struct.unpack(">I", payload[1 + 16:1 + 16 + 4])
                if kex_len == 0:
                    return  # empty offer -> drop
                conn.sendall(packet)
                _drain(conn)
        except OSError:
            pass
        finally:
            try:
                srv.close()
            except OSError:
                pass

    def test_strict_server_accepts_us(self):
        kex = ["diffie-hellman-group14-sha1"]
        ciphers = ["aes128-ctr"]
        macs = ["hmac-sha1"]
        ports: list = []
        t = threading.Thread(
            target=self._serve,
            args=(ports, b"SSH-1.99-Cisco-1.25",
                  build_server_kexinit(kex, ciphers, macs)),
            daemon=True)
        t.start()
        while not ports:
            threading.Event().wait(0.01)
        res = ssh_scan.scan("127.0.0.1", ports[0], timeout=5.0)
        t.join(timeout=10)
        self.assertTrue(res["sshv1"])
        self.assertEqual(res["kex"], kex)

    def test_closed_port_fails_friendly(self):
        with self.assertRaises(ssh_scan.SSHScanError):
            ssh_scan.scan("127.0.0.1", 1, timeout=2.0)

    def test_show_ip_ssh_algo_parsing(self):
        out = ssh_scan.parse_show_ip_ssh_algos(
            "SSH Enabled - version 2.0\n"
            "Encryption Algorithms: aes128-ctr, aes192-ctr, aes256-ctr, "
            "aes128-cbc, 3des-cbc\n"
            "MAC Algorithms: hmac-sha1 hmac-sha1-96\n")
        self.assertIn("aes128-cbc", out["encryption"])
        self.assertIn("hmac-sha1-96", out["mac"])
        self.assertEqual(out["kex"], [])


if __name__ == "__main__":
    unittest.main()
