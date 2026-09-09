"""Legacy SSH algorithms for old Cisco devices (Paramiko >= 3 removed them).

Old IOS boxes (e.g. `SSH-2.0-Cisco-1.25`) may offer ONLY:
  kex:      diffie-hellman-group14-sha1 (sometimes + group-exchange-sha1)
  hostkey:  ssh-rsa (1024/2048-bit RSA, SHA1 signatures)
  ciphers:  aes128-ctr / aes128-cbc / 3des-cbc ...
  macs:     hmac-sha1 ...

Modern Paramiko still implements the CBC ciphers and hmac-sha1, but the
SHA1 kex / ssh-rsa hostkey *implementations* are gone. Merely appending the
names to the offer lists (as tried before) makes Paramiko *agree* on them
and then crash with `KeyError: 'diffie-hellman-group14-sha1'` - exactly the
reported log. So this module vendors the missing pieces:

  - KexGroup14SHA1: same RFC3526 2048-bit group as the bundled
    KexGroup14SHA256, only the exchange hash is SHA1. Subclassed, not copied.
  - ssh-rsa host key: RSAKey class + SHA1 in its signature-hash map.

Both are appended at the END of the offer lists, so any modern algorithm
the server supports is always preferred; legacy is used only when the peer
supports nothing better. Only algorithms with a working implementation are
ever offered (group1-sha1 / group-exchange-sha1 stay disabled - no impl).
"""

from __future__ import annotations

from hashlib import sha1

try:
    from cryptography.hazmat.primitives import hashes

    from paramiko.kex_group14 import KexGroup14SHA256
    from paramiko.rsakey import RSAKey
    from paramiko.transport import Transport

    class KexGroup14SHA1(KexGroup14SHA256):
        """diffie-hellman-group14-sha1 - same group, SHA1 exchange hash."""

        name = "diffie-hellman-group14-sha1"
        hash_algo = sha1

    _HAVE_BASES = True
except Exception:  # pragma: no cover - very old paramiko layouts
    _HAVE_BASES = False

LEGACY_KEX = ("diffie-hellman-group14-sha1",)
LEGACY_KEYS = ("ssh-rsa",)

_enabled = False


def enable_legacy_cisco_algos() -> None:
    """Register + offer legacy algorithms (idempotent, never raises)."""
    global _enabled
    try:
        if _HAVE_BASES:
            if "diffie-hellman-group14-sha1" not in Transport._kex_info:
                Transport._kex_info["diffie-hellman-group14-sha1"] = KexGroup14SHA1
            if "ssh-rsa" not in Transport._key_info:
                Transport._key_info["ssh-rsa"] = RSAKey
            if "ssh-rsa" not in RSAKey.HASHES:
                RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
        # offer only what has an implementation, modern algos stay first
        kex = [k for k in Transport._preferred_kex
               if k in Transport._kex_info]
        for algo in LEGACY_KEX:
            if algo in Transport._kex_info and algo not in kex:
                kex.append(algo)
        Transport._preferred_kex = tuple(kex)
        keys = [k for k in Transport._preferred_keys
                if k in Transport._key_info]
        for algo in LEGACY_KEYS:
            if algo in Transport._key_info and algo not in keys:
                keys.append(algo)
        Transport._preferred_keys = tuple(keys)
    except Exception:
        pass
    _enabled = True
