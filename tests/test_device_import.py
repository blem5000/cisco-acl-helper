"""Tests for XML device import (device_import). Headless-safe."""

import base64
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import device_import as di
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os as _os


def gcm_blob(plain: str, password: str = "mR3m") -> str:
    """mRemoteNG >= 1.75 layout: salt(16) + nonce(16) + ct + tag(16)."""
    salt, nonce = _os.urandom(16), _os.urandom(16)
    key = PBKDF2HMAC(algorithm=SHA1(), length=32, salt=salt,
                     iterations=1000).derive(password.encode())
    ct = AESGCM(key).encrypt(nonce, plain.encode(), salt)
    return base64.b64encode(salt + nonce + ct).decode()


def cbc_blob(plain: str, password: str = "mR3m") -> str:
    """mRemoteNG legacy layout: IV(16) + ciphertext, key = MD5(password)."""
    iv = _os.urandom(16)
    pad = padding.PKCS7(128).padder()
    padded = pad.update(plain.encode()) + pad.finalize()
    enc = Cipher(AES(hashlib.md5(password.encode()).digest()),
                 CBC(iv)).encryptor()
    return base64.b64encode(iv + enc.update(padded) + enc.finalize()).decode()


MRNG = """<Connections Name="C" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="False" ConfVersion="2.6">
<Node Name="sw-core" Type="Connection" Hostname="10.0.0.1" Protocol="SSH2" Port="22" Username="admin" Password="{pw}"/>
<Node Name="sw-dup" Type="Connection" Hostname="10.0.0.1" Protocol="SSH2" Port="22" Username="admin" Password=""/>
<Node Name="srv-rdp" Type="Connection" Hostname="10.0.0.9" Protocol="RDP" Port="3389" Username="u" Password=""/>
<Node Name="folder" Type="Container" Hostname="" Protocol="" Port="0" Username="" Password=""/>
<Node Name="nohost" Type="Connection" Hostname="" Protocol="SSH2" Port="22" Username="" Password=""/>
</Connections>"""

GENERIC = """<devices>
<device host="10.0.2.1" hostname="cam-sw" username="admin" password="p1" port="22" enable="en1"/>
<device><host>10.0.2.2</host><username>op</username></device>
<host>10.0.2.3</host>
<device><hostname>nohost</hostname></device>
</devices>"""


class MremotengTest(unittest.TestCase):
    def test_detect_and_gcm_roundtrip(self):
        xml = MRNG.format(pw=gcm_blob("s3cret!"))
        self.assertEqual(di.detect_format(xml), "mremoteng")
        entries, info = di.parse_mremoteng(xml)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["password"], "s3cret!")
        self.assertTrue(entries[0]["_pw_decrypted"])
        self.assertEqual(info["decrypted"], 1)
        self.assertEqual(info["skipped_non_ssh"], 1)
        self.assertEqual(info["skipped_no_host"], 1)
        self.assertEqual(info["mode"], "GCM")

    def test_legacy_cbc(self):
        xml = ('<Connections Name="C"><Node Name="old" Type="Connection" '
               f'Hostname="10.0.1.1" Protocol="SSH1" Port="2222" '
               f'Username="root" Password="{cbc_blob("oldpass")}"/>'
               "</Connections>")
        self.assertEqual(di.detect_format(xml), "mremoteng")
        entries, info = di.parse_mremoteng(xml)
        self.assertEqual(entries[0]["password"], "oldpass")
        self.assertEqual(entries[0]["port"], 2222)
        self.assertEqual(info["mode"], "CBC")

    def test_wrong_master_password_falls_back(self):
        xml = MRNG.format(pw=gcm_blob("s3cret!"))
        entries, info = di.parse_mremoteng(xml, master_password="wrong")
        self.assertEqual(entries[0]["password"], "")
        self.assertEqual(info["decrypted"], 0)

    def test_full_file_with_inner_password(self):
        inner = (f'<Connections Name="C"><Node Name="f" Type="Connection" '
                 f'Hostname="10.9.9.9" Protocol="SSH2" Port="22" '
                 f'Username="a" Password="{gcm_blob("innerpw")}"/>'
                 "</Connections>")
        salt, nonce = _os.urandom(16), _os.urandom(16)
        key = PBKDF2HMAC(algorithm=SHA1(), length=32, salt=salt,
                         iterations=1000).derive(b"mR3m")
        blob = base64.b64encode(
            salt + nonce + AESGCM(key).encrypt(nonce, inner.encode(), salt)
        ).decode()
        xml = (f'<Connections Name="C" EncryptionEngine="AES" '
               f'BlockCipherMode="GCM" KdfIterations="1000" '
               f'FullFileEncryption="True">{blob}</Connections>')
        entries, info = di.parse_mremoteng(xml)
        self.assertEqual(entries[0]["password"], "innerpw")
        self.assertTrue(info["full_file"])
        self.assertEqual(info["mode"], "GCM")


class GenericTest(unittest.TestCase):
    def test_mixed_device_and_host(self):
        self.assertEqual(di.detect_format(GENERIC), "generic")
        entries, info = di.parse_generic(GENERIC)
        self.assertEqual(len(entries), 3)
        self.assertEqual(info["invalid"], 1)
        self.assertEqual(entries[0]["password"], "p1")
        self.assertEqual(entries[2]["host"], "10.0.2.3")


class MergeTest(unittest.TestCase):
    def test_dedupe_case_insensitive(self):
        existing = [{"hostname": "", "host": "10.0.0.1", "port": 22,
                     "username": "a", "password": "x", "enable": ""}]
        imported = [{"hostname": "", "host": " 10.0.0.1 ", "port": 22,
                     "username": "", "password": "", "enable": ""}]
        res = di.merge_devices(existing, imported)
        self.assertEqual(res["added"], 0)
        self.assertEqual(res["duplicates"], 1)

    def test_fill_missing_vs_overwrite(self):
        existing = []
        imp = [{"hostname": "n", "host": "10.0.0.6", "port": 22,
                "username": "file_u", "password": "file_p", "enable": ""}]
        r1 = di.merge_devices(existing, imp, username="D", password="DP")
        self.assertEqual(r1["devices"][0]["username"], "file_u")
        self.assertEqual(r1["devices"][0]["password"], "file_p")
        r2 = di.merge_devices(existing, imp, username="D", password="DP",
                              overwrite=True)
        self.assertEqual(r2["devices"][0]["username"], "D")
        self.assertEqual(r2["devices"][0]["password"], "DP")

    def test_bad_xml_raises(self):
        for bad in ("", "<devices><device>", "plain text"):
            with self.assertRaises(ValueError, msg=repr(bad)[:30]):
                di.detect_format(bad)


if __name__ == "__main__":
    unittest.main()
