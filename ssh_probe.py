"""SSH negotiation probe - no login, only handshake (safe to share output).

Usage:
    python ssh_probe.py <host> [port]

Opens TCP, runs the SSHv2 handshake WITHOUT authenticating, prints:
  - server version string
  - algorithms agreed upon (kex / hostkey / cipher / mac)
  - our offer lists
On handshake failure it prints the error + relevant lines from the debug log
(server proposal). Nothing secret is printed (no credentials exchanged).
"""
import os
import socket
import sys

import paramiko

import cisco_ssh  # noqa: F401  (applies legacy-algo patch)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
    log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_probe.log")
    if os.path.exists(log):
        os.remove(log)
    paramiko.util.log_to_file(log, level="DEBUG")

    from paramiko.transport import Transport
    print(f"Our KEX offer:     {list(Transport._preferred_kex)}")
    print(f"Our hostkey offer: {list(Transport._preferred_keys)}")
    print(f"Our cipher offer:  {list(Transport._preferred_ciphers)}")
    print(f"Our MAC offer:     {list(Transport._preferred_macs)}")
    print(f"Connecting to {host}:{port} ...")
    try:
        sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        print(f"TCP FAILED: {e}")
        return 1
    try:
        t = Transport(sock)
        t.start_client(timeout=10)
    except Exception as e:
        print(f"\nHANDSHAKE FAILED: {e}\n")
        print(f"--- relevant lines from {log} ---")
        _dump_interesting(log)
        return 1

    print(f"\nserver version: {t.remote_version}")
    ke = getattr(t, "kex_engine", None)
    print(f"agreed kex:     {getattr(ke, 'name', ke)}")
    print(f"agreed cipher:  client->server {t.local_cipher} / server->client {t.remote_cipher}")
    print(f"agreed mac:     client->server {t.local_mac} / server->client {t.remote_mac}")
    sk = getattr(t, "server_key", None)
    print(f"server hostkey: {sk.get_name() if sk is not None else None}")
    print(f"\nFull negotiation log: {log}")
    print("--- relevant lines ---")
    _dump_interesting(log)
    t.close()
    return 0


def _dump_interesting(log: str) -> None:
    keys = ("kex", "cipher", "mac", "host key", "agreed", "incompatible",
            "no matching", "ssh-rsa", "rsa-sha2", "gcm", "ctr", "group",
            "ecdh", "curve", "hmac", "aes", "proposal")
    try:
        with open(log, encoding="utf-8", errors="replace") as f:
            for line in f:
                ll = line.lower()
                if any(k in ll for k in keys):
                    print(line.rstrip())
    except FileNotFoundError:
        print("(no log file)")


if __name__ == "__main__":
    raise SystemExit(main())
