"""Tests for vendored legacy SSH algorithms (ssh_legacy). Headless-safe."""

import hashlib
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko

import ssh_legacy
from paramiko.transport import Transport

# sha256 of the %X rendering of KexGroup1SHA1.P - guards the 1024-bit
# Oakley Group 2 constant against typos (byte-compared once against
# paramiko-2.12.0 KexGroup1.P during development).
GROUP1_P_SHA256 = (
    "693daceaf10c4200894cbd5696b120faebc30f7c4a242a8cd915ca3e83e141db")


class Group1ConstTest(unittest.TestCase):
    def test_prime_shape(self):
        p = ssh_legacy.KexGroup1SHA1.P
        self.assertEqual(p.bit_length(), 1024)
        self.assertEqual(ssh_legacy.KexGroup1SHA1.G, 2)
        self.assertEqual(ssh_legacy.KexGroup1SHA1.name,
                         "diffie-hellman-group1-sha1")

    def test_prime_checksum(self):
        h = hashlib.sha256(
            ("%X" % ssh_legacy.KexGroup1SHA1.P).encode()).hexdigest()
        self.assertEqual(h, GROUP1_P_SHA256)


class OfferOrderTest(unittest.TestCase):
    def test_group1_offered_last(self):
        ssh_legacy.enable_legacy_cisco_algos()
        ssh_legacy.enable_legacy_cisco_algos()  # idempotent
        kex = list(Transport._preferred_kex)
        self.assertIn("diffie-hellman-group1-sha1", kex)
        self.assertIn("diffie-hellman-group14-sha1", kex)
        self.assertLess(kex.index("diffie-hellman-group14-sha1"),
                        kex.index("diffie-hellman-group1-sha1"))
        self.assertEqual(kex[-1], "diffie-hellman-group1-sha1")
        self.assertIn("ssh-rsa", Transport._preferred_keys)


class _AllowAll(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        return True


class Group1HandshakeTest(unittest.TestCase):
    """Full session against a group1-only server (old-IOS profile).

    Encrypted shell data flowing both ways proves the DH mechanics end
    to end (a wrong prime or hash would fail exchange-hash verification
    before NEWKEYS). The prime constant itself is pinned by
    Group1ConstTest against paramiko-2.12.0.
    """

    def test_group1_only_server_session(self):
        ssh_legacy.enable_legacy_cisco_algos()
        hostkey = paramiko.RSAKey.generate(1024)
        # Real loopback TCP, not socketpair(): Windows emulates socketpair
        # over TCP with small buffers and no accept(), which made the
        # handshake time out as soon as the machine was busy (a full test
        # run adds ~35s of load). A listening socket behaves like a real
        # server and keeps the exchange mechanics under test.
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        addr = listener.getsockname()
        srv_sock = cli_sock = None
        server_exc = []
        client_done = threading.Event()

        def run_server():
            nonlocal srv_sock
            t = None
            try:
                listener.settimeout(30)
                srv_sock, _ = listener.accept()
                t = Transport(srv_sock)
                t.add_server_key(hostkey)
                t._preferred_kex = ("diffie-hellman-group1-sha1",)
                t._preferred_keys = ("ssh-rsa",)
                t.start_server(server=_AllowAll())
                chan = t.accept(30)
                self.assertIsNotNone(chan)
                chan.settimeout(30)
                self.assertEqual(chan.recv(8), b"ping")
                chan.send(b"group1-ok")
                self.assertTrue(client_done.wait(30))
            except Exception as e:  # noqa: BLE001
                server_exc.append(e)
            finally:
                # teardown races prove nothing - exchange already asserted
                if t is not None:
                    try:
                        t.close()
                    except Exception:  # noqa: BLE001, S110
                        pass

        th = threading.Thread(target=run_server, daemon=True)
        th.start()
        cli_sock = socket.create_connection(addr, timeout=30)
        client = Transport(cli_sock)
        try:
            client.start_client(timeout=30)
            self.assertTrue(client.is_active())
            client.auth_password("user", "pass")
            chan = client.open_session(timeout=30)
            chan.settimeout(30)
            chan.send(b"ping")
            got = chan.recv(16)
            self.assertEqual(got, b"group1-ok")
            client_done.set()
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001, S110
                pass
            try:
                listener.close()
            except Exception:  # noqa: BLE001, S110
                pass
        th.join(timeout=40)
        self.assertFalse(th.is_alive())
        self.assertEqual(server_exc, [])


if __name__ == "__main__":
    unittest.main()
