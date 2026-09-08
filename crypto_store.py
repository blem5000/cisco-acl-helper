"""Encrypted storage for devices + subnets using a master password.

File format (JSON):
    {"salt": "<base64>", "token": "<fernet token>"}
where token = Fernet(PBKDF2(master, salt)).encrypt(json(store).encode())
and store = {"devices": [...], "subnets": [...]} (v1 files held a bare list).

The master password is asked at startup and kept in memory only.
"""

from __future__ import annotations

import base64
import json
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS = 200_000


def _derive_key(master: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master.encode("utf-8")))


def load_devices(path: str, master: str) -> list[dict]:
    """Legacy wrapper: load device list only."""
    return load_store(path, master)["devices"]


def save_devices(path: str, devices: list[dict], master: str) -> None:
    """Legacy wrapper: save device list, keep existing subnets."""
    try:
        store = load_store(path, master)
    except ValueError:
        store = {"devices": [], "subnets": []}
    store["devices"] = devices
    save_store(path, store, master)


def load_store(path: str, master: str) -> dict:
    """Load and decrypt the whole store: {"devices": [...], "subnets": [...]}.

    Migrates the old format (bare device list) automatically.
    Raises ValueError on wrong password.
    """
    raw = _load_raw(path, master)
    if isinstance(raw, list):  # format v1: devices only
        return {"devices": raw, "subnets": []}
    if isinstance(raw, dict):
        devs = raw.get("devices", [])
        subs = raw.get("subnets", [])
        return {"devices": devs if isinstance(devs, list) else [],
                "subnets": subs if isinstance(subs, list) else []}
    return {"devices": [], "subnets": []}


def save_store(path: str, store: dict, master: str) -> None:
    """Encrypt and save the whole store."""
    _save_raw(path, {"devices": store.get("devices", []),
                     "subnets": store.get("subnets", [])}, master)


def _load_raw(path: str, master: str):
    """Load and decrypt raw store payload (list=v1, dict=v2)."""
    if not os.path.exists(path):
        return {"devices": [], "subnets": []}
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    try:
        salt = base64.b64decode(blob["salt"])
        token = blob["token"].encode("utf-8")
        fnet = Fernet(_derive_key(master, salt))
        plain = fnet.decrypt(token)
        return json.loads(plain.decode("utf-8"))
    except (InvalidToken, KeyError, ValueError, json.JSONDecodeError) as e:
        raise ValueError("wrong master password or corrupted file") from e


def _save_raw(path: str, data, master: str) -> None:
    """Encrypt and save raw payload. Reuses existing salt if present."""
    salt: bytes | None = None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            salt = base64.b64decode(blob.get("salt", ""))
        except Exception:
            salt = None
    if not salt:
        salt = secrets.token_bytes(16)
    fnet = Fernet(_derive_key(master, salt))
    token = fnet.encrypt(json.dumps(data).encode("utf-8")).decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"salt": base64.b64encode(salt).decode("ascii"), "token": token}, f)
