"""SSH fetching of IOS / IOS-XE ACL config via Paramiko (SSHv2 only).

Paramiko implements SSHv2 exclusively - it never uses SSHv1. So this module
is always SSHv2.

Why "Authentication failed: transport shut down or saw EOF" happens on Cisco:
  1. Wrong username/password (most common).
  2. Device requires keyboard-interactive auth (TACACS/AAA) instead of plain
     password auth -> handled here with a fallback.
  3. Old IOS offers only legacy kex/hostkey (diffie-hellman-group14-sha1,
     ssh-rsa SHA1) which Paramiko >= 3 neither offers nor implements ->
     vendored in ssh_legacy (offered last, used only as last resort).
"""

from __future__ import annotations

import re
import socket
import time

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    BadHostKeyException,
    NoValidConnectionsError,
    SSHException,
)

from ssh_legacy import enable_legacy_cisco_algos as _enable_legacy_cisco_algos


_enable_legacy_cisco_algos()

ACL_COMMANDS = [
    "show running-config | section ^ip access-list",
    "show running-config | include ^ip access-list|^ permit|^ deny|^[0-9]+ ",
    "show ip access-lists",
]


def _ki_handler_factory(password: str):
    def handler(title, instructions, prompt_list):
        return [password for _ in prompt_list]

    return handler


def _friendly_error(host: str, e: BaseException, debug_log: str | None) -> RuntimeError:
    where = f" (see {debug_log})" if debug_log else ""
    msg = str(e) or repr(e)
    low = msg.lower()
    if isinstance(e, OSError):
        return RuntimeError(
            f"Cannot reach {host} (TCP error){where}: {msg}. "
            f"Check IP/port, VPN, and firewall."
        )
    if isinstance(e, NoValidConnectionsError):
        return RuntimeError(
            f"Cannot reach {host} (TCP/SSH port closed or filtered){where}: {msg}"
        )
    if isinstance(e, BadHostKeyException):
        return RuntimeError(f"Host key mismatch for {host}{where}: {msg}")
    if isinstance(e, AuthenticationException) or "authentication failed" in low:
        # transport shutdown / EOF during auth == handshake or creds problem
        return RuntimeError(
            f"Authentication failed for {host}{where}. "
            f"App tries keyboard-interactive first, then password (your device "
            f"allows keyboard-interactive only - correct order). So this now "
            f"means: wrong username/password, or account locked/AAA down. "
            f"Verify with: ssh -vvv <user>@{host} ; on the device: show ip ssh. "
            f"Detail: {msg}"
        )
    if "eof" in low or "transport shut down" in low or isinstance(e, (SSHException, EOFError)):
        return RuntimeError(
            f"SSH negotiation with {host} failed{where} (server closed connection). "
            f"Tried full cipher set + fallback without GCM (forcing aes256-ctr). "
            f"Usually: wrong credentials, AAA/keyboard-interactive required, "
            f"or no common kex/hostkey/cipher/MAC. Your device allows "
            f"enc aes256-gcm,aes256-ctr / mac hmac-sha2-512 (both offered here) - "
            f"so please also send KEX + hostkey lines from 'show ip ssh'. "
            f"Verify with: ssh -vvv <user>@{host}. "
            f"Detail: {msg}"
        )
    return RuntimeError(f"{host}: {msg}{where}")


_GCM_CIPHERS = ("aes128-gcm@openssh.com", "aes256-gcm@openssh.com")


def _looks_like_negotiation_failure(e: BaseException) -> bool:
    low = (str(e) or repr(e)).lower()
    return (
        isinstance(e, (SSHException, EOFError))
        or "eof" in low
        or "transport shut down" in low
        or "negotiat" in low
        or "no matching" in low
        or "incompatible" in low
    )


def _connect_once(host: str, username: str, password: str, port: int,
                  timeout: int, disabled_algorithms: dict | None) -> paramiko.Transport:
    """One SSHv2 connect attempt, returns an authenticated Transport.

    Uses a raw Transport (not SSHClient) so we fully control the auth order:
    keyboard-interactive FIRST, plain "password" ONLY as fallback when the
    server explicitly offers it. Hardened Cisco boxes configured with
    "Authentication methods:keyboard-interactive" drop the transport when
    they receive a "password" auth request - so "password" must never be
    sent first. (Paramiko's SSHClient would do exactly the wrong order, and
    its correct method is Transport.auth_interactive, not a similarly-named
    method that does not exist.)
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    t = paramiko.Transport(sock, disabled_algorithms=disabled_algorithms)
    try:
        t.banner_timeout = 20
        t.auth_timeout = 30
        t.start_client(timeout=timeout)
    except Exception:
        t.close()
        raise
    try:
        t.auth_interactive(username, _ki_handler_factory(password))
    except BadAuthenticationType as e:
        # Server offers no keyboard-interactive - use password if offered.
        if "password" in (e.allowed_types or []):
            t.auth_password(username, password)
        else:
            t.close()
            raise
    except Exception:
        t.close()
        raise
    return t


def _shell_read(chan, timeout: float = 1.0) -> str:
    time.sleep(timeout)
    out = ""
    while chan.recv_ready():
        out += chan.recv(65535).decode("utf-8", errors="replace")
    return out


def _shell_exec(chan, command: str, wait: float = 1.5) -> str:
    chan.send(command + "\n")
    time.sleep(wait)
    out = ""
    for _ in range(30):
        while chan.recv_ready():
            chunk = chan.recv(65535).decode("utf-8", errors="replace")
            out += chunk
        if re.search(r"--More--| --More-- ", out[-200:]):
            chan.send(" ")
            time.sleep(0.6)
            continue
        time.sleep(0.4)
        if not chan.recv_ready():
            break
    out = out.replace("--More--", "").replace(" --More-- ", "")
    return out


def fetch_config(host: str, username: str, password: str,
                 enable: str | None = None, port: int = 22,
                 timeout: int = 15, debug_log: str | None = None) -> str:
    """Connect via SSHv2 and return running-config ACL section text.

    Keyboard-interactive auth is used first (required by hardened devices
    allowing only that method), plain password only as fallback.
    Raises RuntimeError with a user-friendly message on failure.
    """
    if debug_log:
        try:
            paramiko.util.log_to_file(debug_log, level="DEBUG")
        except Exception:
            pass

    _enable_legacy_cisco_algos()  # ensure patch active (also for frozen exe)

    client = _connect_with_retry(host, username, password, port, timeout,
                                 debug_log)

    try:
        chan = _open_shell(client, enable)

        best = ""
        for cmd in ACL_COMMANDS:
            out = _shell_exec(chan, cmd, 2.0)
            lines = out.splitlines()
            if lines and cmd.split("|")[0].strip()[:10] in lines[0]:
                lines = lines[1:]
            if lines and re.search(r"[#>]\s*$", lines[-1]):
                lines = lines[:-1]
            text = "\n".join(lines)
            if "ip access-list" in text.lower() or re.search(r"^\s*\d+\s+(permit|deny)", text, re.M):
                if len(text) > len(best):
                    best = text
            if best and "ip access-list extended" in best.lower():
                break
        chan.close()
        if not best.strip():
            raise RuntimeError("Empty response - check privileges / enable password.")
        return best
    finally:
        client.close()


def _connect_with_retry(host: str, username: str, password: str, port: int,
                        timeout: int, debug_log: str | None) -> paramiko.Transport:
    """Connect with GCM->CTR fallback. Raises friendly RuntimeError on failure."""
    # Attempt 1: full algorithm set. Attempt 2 (only if negotiation died):
    # disable GCM ciphers to force aes256-ctr - some devices list aes256-gcm
    # first and Paramiko<->Cisco GCM interop is a known trouble spot.
    attempts: list[dict | None] = [
        None,
        {"ciphers": list(_GCM_CIPHERS)},
    ]
    last_err: BaseException | None = None
    for disabled in attempts:
        try:
            return _connect_once(host, username, password, port, timeout, disabled)
        except AuthenticationException as e:
            # Pure credential rejection - retrying with other ciphers won't help.
            raise _friendly_error(host, e, debug_log) from e
        except OSError as e:
            # TCP-level failure - not a cipher problem, don't retry.
            raise _friendly_error(host, e, debug_log) from e
        except Exception as e:
            last_err = e
            if disabled is None and _looks_like_negotiation_failure(e):
                continue  # try again without GCM
            break
    raise _friendly_error(host, last_err or RuntimeError("SSH connect failed"),
                          debug_log)


def _open_shell(t: paramiko.Transport, enable: str | None = None):
    """Open shell channel, handle enable, disable paging/wrapping."""
    chan = t.open_session()
    chan.get_pty(term="vt100", width=500, height=100)
    chan.invoke_shell()
    _shell_read(chan, 1.0)
    if enable:
        chan.send("enable\n")
        time.sleep(0.8)
        prompt = ""
        while chan.recv_ready():
            prompt += chan.recv(65535).decode("utf-8", errors="replace")
        if re.search(r"[Pp]assword", prompt):
            chan.send(enable + "\n")
            time.sleep(1.0)
            _shell_read(chan, 0.5)
    _shell_exec(chan, "terminal length 0", 1.0)
    _shell_exec(chan, "terminal width 512", 1.0)  # avoid wrapped lines
    return chan


def _clean_output(out: str, cmd: str) -> str:
    """Strip echoed command (first line) and trailing prompt line."""
    lines = out.splitlines()
    if lines and cmd.split("|")[0].strip()[:10] in lines[0]:
        lines = lines[1:]
    if lines and re.search(r"[#>]\s*$", lines[-1]):
        lines = lines[:-1]
    return "\n".join(lines)


def run_commands(host: str, username: str, password: str,
                 enable: str | None = None, port: int = 22,
                 timeout: int = 15, commands: tuple | list = (),
                 debug_log: str | None = None) -> dict:
    """Run arbitrary show commands over one SSHv2 shell session.

    Returns {command: cleaned output}. Raises friendly RuntimeError on failure.
    """
    if debug_log:
        try:
            paramiko.util.log_to_file(debug_log, level="DEBUG")
        except Exception:
            pass

    _enable_legacy_cisco_algos()
    client = _connect_with_retry(host, username, password, port, timeout, debug_log)
    try:
        chan = _open_shell(client, enable)
        res = {}
        for cmd in commands:
            res[cmd] = _clean_output(_shell_exec(chan, cmd, 2.5), cmd)
        chan.close()
        return res
    finally:
        client.close()


_CONFIG_ERROR = re.compile(r"^%|command rejected", re.M | re.IGNORECASE)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class ConfigFailed(RuntimeError):
    """Some `configure terminal` sub-commands were rejected by IOS."""

    def __init__(self, failures: list[tuple[str, str]]):
        self.failures = failures
        detail = "; ".join(f"{c!r}: {o.splitlines()[0] if o.splitlines() else '?'}"
                           for c, o in failures)
        super().__init__(f"IOS rejected {len(failures)} command(s): {detail}")


class ConfigSession:
    """One persistent privileged shell for check -> fix -> verify -> wr/rollback.

    The session stays open across the whole operation (including while the
    operator verifies the device in a separate window), so a bad change can
    always be rolled back. Use as a context manager or open()/close().
    """

    def __init__(self, host: str, username: str, password: str,
                 enable: str | None = None, port: int = 22,
                 timeout: int = 15, debug_log: str | None = None):
        self.host = host
        self.username = username
        self.password = password
        self.enable = enable
        self.port = port
        self.timeout = timeout
        self.debug_log = debug_log
        self._t = None
        self._chan = None

    def __enter__(self) -> "ConfigSession":
        self.open()
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    def open(self) -> None:
        if self.debug_log:
            try:
                paramiko.util.log_to_file(self.debug_log, level="DEBUG")
            except Exception:
                pass
        _enable_legacy_cisco_algos()
        self._t = _connect_with_retry(self.host, self.username, self.password,
                                      self.port, self.timeout, self.debug_log)
        try:
            self._chan = _open_shell(self._t, self.enable)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self._chan is not None:
                self._chan.close()
        except Exception:
            pass
        finally:
            self._chan = None
        try:
            if self._t is not None:
                self._t.close()
        except Exception:
            pass
        finally:
            self._t = None

    def alive(self) -> bool:
        try:
            return (self._t is not None and self._chan is not None
                    and self._t.is_active() and not self._chan.closed)
        except Exception:
            return False

    def exec(self, command: str, wait: float = 2.5) -> str:
        """Run one command, return output without echo/prompt lines."""
        if self._chan is None:
            raise RuntimeError(f"{self.host}: session is not open")
        return _clean_output(_shell_exec(self._chan, command, wait), command)

    def _prompt_tail(self, command: str = "", wait: float = 1.2) -> str:
        """Last non-empty line from RAW shell output (no echo stripping).

        Prompt detection must use raw output: _clean_output() removes the
        trailing prompt line, so a cleaned read can never see '#' or '>'.
        """
        if self._chan is None:
            raise RuntimeError(f"{self.host}: session is not open")
        raw = _ANSI.sub("", _shell_exec(self._chan, command, wait))
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        return lines[-1] if lines else ""

    def ensure_privileged(self) -> None:
        """Reach a '#' prompt, trying a bare `enable` when needed.

        Devices without an enable secret land at '>' and accept a plain
        `enable`; devices with one get the configured secret answered.
        Raises showing the last prompt seen when elevation fails.
        """
        if re.search(r"#\s*$", self._prompt_tail()):
            return
        out = _ANSI.sub("", _shell_exec(self._chan, "enable", 1.5))
        if re.search(r"[Pp]assword", out):
            self._chan.send((self.enable or "") + "\n")
            time.sleep(1.0)
            _shell_read(self._chan, 0.5)
        last = self._prompt_tail()
        if not re.search(r"#\s*$", last):
            raise RuntimeError(
                f"{self.host}: privileged (enable) mode not reached "
                f"(prompt: {last!r}). The account needs privilege 15 or a "
                f"working `enable` (enable secret, if the device has one).")

    def configure(self, commands: list | tuple) -> None:
        """Push config sub-commands via `configure terminal` ... `end`.

        Raises ConfigFailed listing every rejected command (the session is
        always brought back to privileged exec first).
        """
        out = self.exec("configure terminal", 2.0)
        if _CONFIG_ERROR.search(out):
            raise ConfigFailed([("configure terminal", out.strip())])
        failures: list[tuple[str, str]] = []
        try:
            for cmd in commands:
                o = self.exec(cmd, 2.0)
                if _CONFIG_ERROR.search(o):
                    failures.append((cmd, o.strip()))
        finally:
            try:
                self.exec("end", 1.5)
            except Exception:
                pass
        if failures:
            raise ConfigFailed(failures)
