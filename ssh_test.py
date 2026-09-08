"""Standalone SSH diagnostic for Cisco ACL Helper (bypasses the GUI).

Usage:
    python ssh_test.py <host> <username> [port]

Prompts for password (and enable secret), enables Paramiko DEBUG logging,
and tries the same fetch_config() the GUI uses. Prints the negotiation
result and first bytes of config, or the friendly error.
"""
import getpass
import os
import sys

import cisco_ssh


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    host = sys.argv[1]
    username = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 22
    password = getpass.getpass(f"SSH password for {username}@{host}: ")
    enable = getpass.getpass("Enable secret (Enter to skip): ") or None

    debug_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_debug.log")
    print(f"Connecting (SSHv2, Paramiko {__import__('paramiko').__version__}) "
          f"to {username}@{host}:{port} ...")
    print(f"Debug log: {debug_log}")
    try:
        cfg = cisco_ssh.fetch_config(host, username, password, enable, port,
                                     timeout=15, debug_log=debug_log)
    except Exception as e:
        print(f"\nFAILED:\n{e}\n")
        print("Next steps:")
        print(f"  1. Check {debug_log} tail for 'kex', 'host key', 'Authentication'.")
        print(f"  2. Compare with: ssh -vvv {username}@{host}")
        print(f"  3. On the device: show ip ssh   (look at version, timeouts, ACL)")
        return 1

    import acl_parser
    acls = acl_parser.parse_running_config(cfg)
    print(f"\nOK. ACL blocks: {len(acls)}")
    for name, aces in list(acls.items())[:5]:
        print(f"  {name}: {len(aces)} lines")
    print("\n--- config head ---")
    print(cfg[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
