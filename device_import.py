"""Import device lists from XML files.

Two formats, auto-detected:

1. mRemoteNG (confCons.xml) -- ``<Connections>`` root with ``<Node>``
   entries (``Name`` / ``Hostname`` / ``Username`` / ``Password`` /
   ``Port`` / ``Protocol`` attributes). Only SSH1/SSH2 connections are
   imported. Passwords are decrypted when possible:
     * >= 1.75 (BlockCipherMode="GCM"): AES-GCM, key = PBKDF2-HMAC-SHA1
       (master password, salt, KdfIterations, 32 bytes), blob layout
       salt(16) + nonce(16) + ciphertext + tag(16), AAD = salt.
     * older files (no BlockCipherMode): AES-CBC, key = MD5(master
       password), blob layout IV(16) + ciphertext (PKCS7).
   Default master password is ``mR3m``; a custom one can be supplied.
   Entries whose password cannot be decrypted fall back to the
   import-wide credentials from the UI dialog. A fully encrypted file
   (FullFileEncryption="True") is decrypted as a whole first.
2. Generic XML -- a simple structure, attribute or element style::

     <devices>
       <device host="10.0.0.1" hostname="sw1" username="admin"
               password="secret" port="22" enable="en-secret"/>
       <device><host>10.0.0.2</host><username>admin</username></device>
       <host>10.0.0.3</host>
     </devices>

   (tag/attribute names are case-insensitive; passwords are plaintext.)

Pure logic, no GUI here. Merging de-duplicates by host: an entry whose
host (case-insensitive, stripped) is already on the device list is
skipped and reported, never added twice.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import xml.etree.ElementTree as ET

__all__ = [
    "MREMOTENG_DEFAULT_PASSWORD",
    "detect_format",
    "count_entries",
    "parse_mremoteng",
    "parse_generic",
    "merge_devices",
]

MREMOTENG_DEFAULT_PASSWORD = "mR3m"

_SSH_PROTOCOLS = {"ssh1", "ssh2"}

_GENERIC_FIELDS = ("host", "hostname", "username", "password", "port",
                   "enable")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _parse_xml(text: str) -> ET.Element:
    try:
        return ET.fromstring((text or "").lstrip("\ufeff"))
    except ET.ParseError as e:
        raise ValueError(f"invalid XML: {e}") from e


def _looks_mremoteng(root: ET.Element) -> bool:
    if _local(root.tag).lower() == "connections":
        return True
    for el in root.iter():
        if _local(el.tag) == "Node" and (el.get("Hostname") or "").strip():
            return True
    return False


def detect_format(text: str) -> str:
    """Return 'mremoteng' or 'generic'. Raises ValueError on bad XML."""
    return "mremoteng" if _looks_mremoteng(_parse_xml(text)) else "generic"


# ---------- mRemoteNG password decryption (cryptography lib) ----------

def _decrypt_gcm(blob: bytes, password: str, iterations: int) -> bytes | None:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA1
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        return None
    try:
        if len(blob) < 48:
            return None
        salt, nonce, ct_tag = blob[:16], blob[16:32], blob[32:]
        kdf = PBKDF2HMAC(algorithm=SHA1(), length=32, salt=salt,
                         iterations=iterations)
        key = kdf.derive(password.encode("utf-8"))
        return AESGCM(key).decrypt(nonce, ct_tag, salt)
    except Exception:
        return None


def _decrypt_cbc(blob: bytes, password: str) -> bytes | None:
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.ciphers.algorithms import AES
        from cryptography.hazmat.primitives.ciphers.modes import CBC
    except ImportError:
        return None
    try:
        if len(blob) < 32 or len(blob) % 16:
            return None
        key = hashlib.md5(password.encode("utf-8")).digest()
        dec = Cipher(AES(key), CBC(blob[:16])).decryptor()
        raw = dec.update(blob[16:]) + dec.finalize()
        unpad = padding.PKCS7(128).unpadder()
        return unpad.update(raw) + unpad.finalize()
    except Exception:
        return None


def _decrypt_password(b64: str, mode: str, password: str,
                      iterations: int) -> str | None:
    """Decrypt one base64 mRemoteNG password blob; None when impossible."""
    b64 = (b64 or "").strip()
    if not b64:
        return None
    try:
        blob = base64.b64decode(b64)
    except (binascii.Error, ValueError):
        return None
    if mode == "GCM":
        raw = _decrypt_gcm(blob, password, iterations)
    elif mode == "CBC":
        raw = _decrypt_cbc(blob, password)
    else:  # Serpent/Twofish/EAX/CCM... -- not supported here
        return None
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _mremoteng_params(root: ET.Element) -> tuple[str, int]:
    """(cipher mode, kdf iterations) from the Connections root node."""
    if "BlockCipherMode" not in root.attrib:
        return "CBC", 1000  # pre-1.75 legacy files
    engine = (root.get("EncryptionEngine") or "AES").strip().upper()
    block_mode = (root.get("BlockCipherMode") or "GCM").strip().upper()
    if engine != "AES" or block_mode != "GCM":
        return "UNSUPPORTED", 1000
    try:
        iters = int(root.get("KdfIterations") or 1000)
    except ValueError:
        iters = 1000
    return "GCM", max(iters, 1)


def parse_mremoteng(text: str, master_password: str = "") -> tuple[list, dict]:
    """Parse a confCons.xml file.

    Returns (entries, info). Each entry: {hostname, host, port, username,
    password (decrypted or ""), _pw_decrypted (bool)}. info holds counters:
    decrypted, pw_fallback, skipped_non_ssh, skipped_no_host, full_file.
    """
    master = master_password or MREMOTENG_DEFAULT_PASSWORD
    root = _parse_xml(text)
    full = (root.get("FullFileEncryption") or "").strip().lower() == "true"
    outer_mode, outer_iters = _mremoteng_params(root)
    if full:
        mode0, iters0 = _mremoteng_params(root)
        inner_b64 = "".join(root.itertext()).strip()
        try:
            inner_blob = base64.b64decode(inner_b64)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"full-file blob is not base64: {e}") from e
        raw = (_decrypt_gcm(inner_blob, master, iters0) if mode0 == "GCM"
               else _decrypt_cbc(inner_blob, master) if mode0 == "CBC"
               else None)
        if raw is None:
            raise ValueError("cannot decrypt fully-encrypted file "
                             "(wrong master password?)")
        try:
            root = ET.fromstring(raw.decode("utf-8").lstrip("\ufeff"))
        except ET.ParseError as e:
            raise ValueError(f"decrypted inner XML is invalid: {e}") from e
    # NOTE: the inner XML of a fully-encrypted file carries no crypto
    # attributes, but its password blobs use the OUTER file's cipher --
    # keep the outer mode/iterations for them.
    mode, iters = (outer_mode, outer_iters) if full else _mremoteng_params(root)

    entries: list[dict] = []
    info = {"decrypted": 0, "pw_fallback": 0, "skipped_non_ssh": 0,
            "skipped_no_host": 0, "full_file": full, "mode": mode}
    for el in root.iter():
        if _local(el.tag) != "Node":
            continue
        ntype = (el.get("Type") or "").strip().lower()
        if ntype and ntype != "connection":
            continue
        host = (el.get("Hostname") or "").strip()
        if not host:
            info["skipped_no_host"] += 1
            continue
        proto = (el.get("Protocol") or "").strip().lower()
        if proto not in _SSH_PROTOCOLS:
            info["skipped_non_ssh"] += 1
            continue
        try:
            port = int((el.get("Port") or "22").strip() or "22")
        except ValueError:
            port = 22
        pw = _decrypt_password(el.get("Password") or "", mode, master,
                               iters)
        if pw is not None:
            info["decrypted"] += 1
        else:
            info["pw_fallback"] += 1
            pw = ""
        entries.append({"hostname": (el.get("Name") or "").strip(),
                        "host": host, "port": port,
                        "username": (el.get("Username") or "").strip(),
                        "password": pw, "enable": "",
                        "_pw_decrypted": bool(pw)})
    return entries, info


# ---------- generic XML ----------

def _generic_device(el: ET.Element) -> dict | None:
    """Build an entry from a <device>-like element (attrs + children)."""
    vals: dict[str, str] = {}
    for k, v in el.attrib.items():
        kl = k.strip().lower()
        if kl in _GENERIC_FIELDS:
            vals[kl] = (v or "").strip()
    for child in el:
        cl = _local(child.tag).strip().lower()
        if cl in _GENERIC_FIELDS and cl not in vals:
            vals[cl] = "".join(child.itertext()).strip()
    if not vals.get("host"):
        return None
    try:
        port = int(vals.get("port", "") or 22)
    except ValueError:
        port = 22
    return {"hostname": vals.get("hostname", ""),
            "host": vals["host"], "port": port,
            "username": vals.get("username", ""),
            "password": vals.get("password", ""),
            "enable": vals.get("enable", ""),
            "_pw_decrypted": bool(vals.get("password"))}


def parse_generic(text: str) -> tuple[list, dict]:
    """Parse the simple <devices>/<device> (or bare <host>) structure."""
    root = _parse_xml(text)
    entries: list[dict] = []
    invalid = 0
    for el in root.iter():
        if _local(el.tag).lower() != "device":
            continue
        dev = _generic_device(el)
        if dev is None:
            invalid += 1
        else:
            entries.append(dev)

    def _walk(el: ET.Element, in_device: bool):
        nonlocal invalid
        is_dev = _local(el.tag).lower() == "device"
        if _local(el.tag).lower() == "host" and not in_device and not list(el):
            host = "".join(el.itertext()).strip()
            if not host:
                invalid += 1
            else:
                entries.append({"hostname": "", "host": host, "port": 22,
                                "username": "", "password": "", "enable": "",
                                "_pw_decrypted": False})
        for child in el:
            _walk(child, in_device or is_dev)

    # bare <host> values outside any <device> (whole-list or mixed files)
    _walk(root, False)
    return entries, {"invalid": invalid, "decrypted": len(
        [e for e in entries if e["_pw_decrypted"]]), "pw_fallback": len(
        [e for e in entries if not e["_pw_decrypted"]])}


def count_entries(text: str, fmt: str) -> int:
    """Lightweight pre-import count (no password decryption)."""
    if fmt == "mremoteng":
        entries, _info = parse_mremoteng(text)
        return len(entries)
    entries, _info = parse_generic(text)
    return len(entries)


# ---------- merge with de-duplication ----------

def _norm_host(host: str) -> str:
    return (host or "").strip().lower()


def merge_devices(existing: list[dict], imported: list[dict],
                  username: str = "", password: str = "",
                  enable: str = "", overwrite: bool = False) -> dict:
    """Merge imports into the device list, skipping duplicate hosts.

    Import-wide credentials fill entries lacking them (or replace all
    when overwrite=True). Returns {devices, added, duplicates, invalid,
    dup_hosts, from_form} where devices is the new full list.
    """
    seen = {_norm_host(d.get("host", "")) for d in existing
            if _norm_host(d.get("host", ""))}
    devices = [dict(d) for d in existing]
    added, invalid, from_form = 0, 0, 0
    dup_hosts: list[str] = []
    for cand in imported:
        host = (cand.get("host") or "").strip()
        if not host:
            invalid += 1
            continue
        if _norm_host(host) in seen:
            dup_hosts.append(host)
            continue
        try:
            port = int(cand.get("port", 22) or 22)
        except (ValueError, TypeError):
            port = 22
        entry = {"hostname": (cand.get("hostname") or "").strip(),
                 "host": host, "port": port,
                 "username": (cand.get("username") or "").strip(),
                 "password": cand.get("password", "") or "",
                 "enable": (cand.get("enable") or "").strip()}
        for key, val in (("username", username), ("password", password),
                         ("enable", enable)):
            if overwrite:
                if val:
                    entry[key] = val
            elif not entry[key] and val:
                entry[key] = val
        if password and (overwrite or not cand.get("password")):
            from_form += 1
        devices.append(entry)
        seen.add(_norm_host(host))
        added += 1
    return {"devices": devices, "added": added,
            "duplicates": len(dup_hosts), "dup_hosts": dup_hosts,
            "invalid": invalid, "from_form": from_form}
