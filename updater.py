"""Self-update from GitHub Releases (stdlib only, Windows-focused).

Flow (onedir build):
  1. fetch_latest_release() -> {"tag", "name", "body", "zip_url", "zip_size"}
  2. is_newer(latest_tag, current_version) compares "v1.4.0"-style tags.
  3. download_asset() streams the CiscoACLHelper-windows.zip to temp with progress.
  4. write_apply_script() creates a .bat that waits for our PID to exit,
     extracts the zip and robocopies it over the app dir (preserving user
     files), then restarts the exe. App launches the bat detached and quits.

User files that are NEVER overwritten (robocopy /XF + not present in zip):
  devices.enc, config.json, ssh_debug.log, ssh_probe.log
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.request

from version import __version__ as CURRENT_VERSION

GITHUB_REPO = "blem5000/cisco-acl-helper"
ASSET_NAME = "CiscoACLHelper-windows.zip"
API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

PRESERVED_FILES = ("devices.enc", "config.json", "ssh_debug.log", "ssh_probe.log")


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def app_dir() -> str:
    if is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def exe_path() -> str:
    if is_frozen():
        return sys.executable
    return os.path.abspath(__file__)


def current_version() -> str:
    return CURRENT_VERSION


def parse_version(s: str) -> tuple[int, ...]:
    s = (s or "").strip()
    if s.lower().startswith("v"):
        s = s[1:]
    parts: list[int] = []
    for chunk in s.split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def is_newer(latest_tag: str, current: str | None = None) -> bool:
    return parse_version(latest_tag) > parse_version(current or CURRENT_VERSION)


def fetch_latest_release(timeout: int = 15) -> dict:
    """Return {"tag","name","body","zip_url","zip_size"} or raise RuntimeError."""
    req = urllib.request.Request(
        API_LATEST,
        headers={
            "User-Agent": "CiscoACLHelper-updater",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        raise RuntimeError(f"GitHub API error: {e}") from e
    tag = str(data.get("tag_name", "") or "").strip()
    if not tag:
        raise RuntimeError("GitHub API: empty tag_name")
    assets = data.get("assets") or []
    chosen = None
    for a in assets:
        if a.get("name") == ASSET_NAME:
            chosen = a
            break
    if chosen is None:
        for a in assets:
            name = str(a.get("name", ""))
            if name.endswith(".zip"):
                chosen = a
                break
    if chosen is None:
        raise RuntimeError("No .zip asset found in latest release")
    url = chosen.get("browser_download_url", "")
    if not url:
        raise RuntimeError("Release asset has no download URL")
    return {
        "tag": tag,
        "name": str(data.get("name") or tag),
        "body": str(data.get("body") or ""),
        "zip_url": url,
        "zip_size": int(chosen.get("size") or 0),
    }


def download_asset(url: str, dest_path: str, progress_cb=None,
                   cancel_event=None, timeout: int = 30) -> str:
    """Stream-download url -> dest_path. progress_cb(downloaded, total)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "CiscoACLHelper-updater",
                      "Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = 0
        try:
            total = int(resp.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            total = 0
        downloaded = 0
        last_report = 0
        with open(dest_path, "wb") as f:
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError("cancelled")
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if progress_cb and (downloaded - last_report >= 512 * 1024
                                    or downloaded == total):
                    last_report = downloaded
                    progress_cb(downloaded, total)
    if progress_cb:
        progress_cb(downloaded, total or downloaded)
    return dest_path


def temp_download_path(tag: str) -> str:
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in tag)
    fd, path = tempfile.mkstemp(prefix=f"acl_update_{safe}_", suffix=".zip")
    os.close(fd)
    return path


def _own_start_unix() -> int:
    """Unix timestamp (seconds) of current process start, Windows only.

    Used to guard against PID reuse: the apply script proceeds immediately
    if the process currently holding our PID started at a different time.
    Returns 0 when unavailable (check is then skipped).
    """
    try:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.GetProcessTimes.restype = wintypes.BOOL
        # PROCESS_QUERY_LIMITED_INFORMATION is enough and never fails for self
        h = k32.OpenProcess(0x1000, False, k32.GetCurrentProcessId())
        if not h:
            return 0
        try:
            creation = wintypes.FILETIME()
            dummy1 = wintypes.FILETIME()
            dummy2 = wintypes.FILETIME()
            dummy3 = wintypes.FILETIME()
            if not k32.GetProcessTimes(h, ctypes.byref(creation),
                                       ctypes.byref(dummy1),
                                       ctypes.byref(dummy2),
                                       ctypes.byref(dummy3)):
                return 0
        finally:
            k32.CloseHandle(h)
        ft = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return int(ft // 10000000 - 11644473600)
    except Exception:
        return 0


def write_apply_script(zip_path: str, target_dir: str, pid_to_wait: int) -> str:
    """Write update_apply_<pid>.bat next to temp; return its path.

    The script waits for our PID to vanish (single powershell Wait-Process,
    no tasklist/find loop), extracts the zip to a staging dir, copies
    (robocopy) the inner folder over target_dir excluding user files,
    restarts the exe, then cleans up temp files. Progress goes to
    %TEMP%\\acl_update_<pid>.log. Runs fully hidden (see
    launch_apply_and_exit); a visible window appears only on failure.
    """
    exe_name = os.path.basename(exe_path())
    if not exe_name.lower().endswith(".exe"):
        exe_name = "CiscoACLHelper.exe"
    staging = os.path.join(tempfile.gettempdir(),
                           f"acl_update_stage_{pid_to_wait}")
    bat_path = os.path.join(tempfile.gettempdir(),
                            f"acl_apply_{pid_to_wait}.bat")
    xf = " ".join(PRESERVED_FILES)
    pid_start = _own_start_unix()
    # Wait snippet: if the PID holder started at a different second than us,
    # the PID was reused after our exit -> do NOT wait (install immediately).
    # $t = 0 means start time unknown -> plain wait (old behaviour, still hidden).
    wait_ps = (
        '"$t = %PIDSTART%; '
        'try { $p = Get-Process -Id %PIDW% -ErrorAction Stop; '
        'if ($t -ne 0) { $e = [datetime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc); '
        '$s = [int][double]($p.StartTime.ToUniversalTime().Subtract($e).TotalSeconds); '
        'if ($s -ne $t) { exit 0 } }; $p.WaitForExit() } catch { }"'
    )
    # robocopy exit codes 0-7 mean success -> always exit 0 afterwards.
    bat = (
        "@echo off\r\n"
        "setlocal\r\n"
        f'set "ZIP={zip_path}"\r\n'
        f'set "DST={target_dir}"\r\n'
        f'set "STAGE={staging}"\r\n'
        f'set "PIDW={pid_to_wait}"\r\n'
        f'set "PIDSTART={pid_start}"\r\n'
        f'set "EXE={exe_name}"\r\n'
        f'set "LOG=%TEMP%\\acl_update_{pid_to_wait}.log"\r\n'
        'echo [%date% %time%] waiting for PID %PIDW% (start %PIDSTART%) > "%LOG%"\r\n'
        'powershell -NoProfile -ExecutionPolicy Bypass -Command '
        f'{wait_ps} >> "%LOG%" 2>&1\r\n'
        'echo [%date% %time%] process gone, extracting >> "%LOG%"\r\n'
        'if exist "%STAGE%" rmdir /s /q "%STAGE%"\r\n'
        'mkdir "%STAGE%"\r\n'
        'powershell -NoProfile -ExecutionPolicy Bypass -Command '
        '"Expand-Archive -LiteralPath \'"%ZIP%"\' -DestinationPath \'"%STAGE%"\' -Force" '
        '>> "%LOG%" 2>&1\r\n'
        "if errorlevel 1 (\r\n"
        '  echo Update failed: cannot extract zip. See "%LOG%". >> "%LOG%"\r\n'
        '  start "" /wait cmd /c "echo Update failed while extracting. See "%LOG%" & pause"\r\n'
        "  exit /b 1\r\n"
        ")\r\n"
        'set "SRC=%STAGE%"\r\n'
        'if exist "%STAGE%\\CiscoACLHelper\\%EXE%" set "SRC=%STAGE%\\CiscoACLHelper"\r\n'
        f'robocopy "%SRC%" "%DST%" /E /IS /IT /R:2 /W:1 /NFL /NDL /NJH /NJS /XF {xf} >> "%LOG%" 2>&1\r\n'
        "ver>nul\r\n"
        'echo [%date% %time%] copy done, restarting >> "%LOG%"\r\n'
        'start "" "%DST%\\%EXE%"\r\n'
        'del "%ZIP%" >nul 2>&1\r\n'
        'rmdir /s /q "%STAGE%" >nul 2>&1\r\n'
        "(goto) 2>nul & del \"%~f0\" >nul 2>&1\r\n"
    )
    with open(bat_path, "w", encoding="utf-8", newline="") as f:
        f.write(bat)
    return bat_path


def launch_apply_and_exit(bat_path: str) -> None:
    """Launch the apply script fully hidden and detached.

    CREATE_NO_WINDOW is essential: without a console, every console-mode
    child (previously tasklist/find/timeout in a loop) would pop its own
    visible window. Caller must quit the app right after.
    """
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    subprocess.Popen(
        ["cmd", "/c", bat_path],
        startupinfo=si,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
    )
