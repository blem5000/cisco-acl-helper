"""Self-update from GitHub Releases (stdlib only, Windows-focused).

Flow (onedir build):
  1. fetch_latest_release() -> {"tag", "name", "body", "zip_url", "zip_size"}
  2. is_newer(latest_tag, current_version) compares "v1.4.0"-style tags.
  3. download_asset() streams the CiscoACLHelper-windows.zip to temp with progress.
  4. Preferred: stage_gui_updater() + launch_gui_updater() run the separate
     CiscoACLHelperUpdater.exe (own Tk window with progress, no cmd /
     powershell windows at all). It waits for our PID, extracts the zip
     (zipfile), copies files over the app dir (shutil, preserving user
     files), restarts the exe and cleans up.
  5. Fallback (updater exe missing, e.g. updating from an old version):
     write_apply_script() creates a hidden .bat doing the same steps.

User files that are NEVER overwritten (excluded from copy):
  devices.enc, config.json, ssh_debug.log, ssh_probe.log
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

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


_PROCESS_QUERY_LIMITED = 0x1000
_SYNCHRONIZE = 0x100000
_WAIT_OBJECT_0 = 0x00000000


def _k32():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.GetProcessTimes.restype = wintypes.BOOL
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    return k32


def _handle_start_unix(k32, h) -> int:
    import ctypes
    from ctypes import wintypes
    creation = wintypes.FILETIME()
    dummy1 = wintypes.FILETIME()
    dummy2 = wintypes.FILETIME()
    dummy3 = wintypes.FILETIME()
    if not k32.GetProcessTimes(h, ctypes.byref(creation),
                               ctypes.byref(dummy1),
                               ctypes.byref(dummy2),
                               ctypes.byref(dummy3)):
        return 0
    ft = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
    return int(ft // 10000000 - 11644473600)


def proc_start_unix(pid: int) -> int:
    """Unix timestamp (seconds) of process `pid` start, Windows only.

    Returns 0 when the process does not exist or the time is unavailable.
    Used to guard against PID reuse: a PID holder with a different start
    time is a different process.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return 0
    if pid <= 0:
        return 0
    try:
        k32 = _k32()
        # PROCESS_QUERY_LIMITED_INFORMATION suffices for the start time
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED, False, pid)
        if not h:
            return 0
        try:
            return _handle_start_unix(k32, h)
        finally:
            k32.CloseHandle(h)
    except Exception:
        return 0


def _own_start_unix() -> int:
    """Unix timestamp (seconds) of current process start. 0 when unavailable."""
    try:
        import ctypes
        return proc_start_unix(int(ctypes.windll.kernel32.GetCurrentProcessId()))
    except Exception:
        return 0


def wait_for_exit(pid: int, expected_start: int = 0, poll: float = 0.5) -> bool:
    """Block until `pid` exited (or is held by a different process). Always True.

    Uses WaitForSingleObject on a fresh handle: unlike OpenProcess success
    (which also succeeds for already-exited processes while anyone still
    holds a handle to them), the wait handle is signaled only on real exit.
    `expected_start`: value from _own_start_unix() of the waited-on process;
    0 disables the PID-reuse check.
    """
    pid = int(pid or 0)
    if pid <= 0:
        return True
    k32 = _k32()
    wait_ms = max(50, int(poll * 1000))
    while True:
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED | _SYNCHRONIZE, False, pid)
        if not h:
            return True  # no such process
        try:
            if expected_start:
                if _handle_start_unix(k32, h) != int(expected_start):
                    return True  # PID reused by a different process
            if k32.WaitForSingleObject(h, wait_ms) == _WAIT_OBJECT_0:
                return True  # exited
        finally:
            k32.CloseHandle(h)


def extract_zip(zip_path: str, staging: str, progress_cb=None) -> str:
    """Extract zip -> staging dir. progress_cb(done_bytes, total_bytes)."""
    if os.path.isdir(staging):
        shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        total = sum(i.file_size for i in infos) or 1
        done = 0
        for info in infos:
            z.extract(info, staging)
            done += info.file_size
            if progress_cb:
                progress_cb(done, total)
    if progress_cb:
        progress_cb(total, total)
    return staging


def resolve_source(staging: str, exe_name: str) -> str:
    """Release zips contain a top-level CiscoACLHelper/ folder; return it
    when present, else the staging dir itself."""
    inner = os.path.join(staging, "CiscoACLHelper")
    if os.path.isfile(os.path.join(inner, exe_name)):
        return inner
    return staging


def copy_tree(src: str, dst: str, exclude_names=(), progress_cb=None,
              retries: int = 5) -> None:
    """Copy src -> dst, skipping `exclude_names` basenames (user files).

    progress_cb(done_bytes, total_bytes). Retries locked files (the old app
    may still be releasing handles) before giving up.
    """
    excluded = set(exclude_names or ())
    jobs: list[tuple[str, str, int]] = []
    total = 0
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if fn in excluded:
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, src)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            jobs.append((full, rel, size))
            total += size
    total = total or 1
    done = 0
    for full, rel, size in jobs:
        target = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        last_err: Exception | None = None
        for attempt in range(max(1, retries)):
            try:
                shutil.copy2(full, target)
                last_err = None
                break
            except OSError as e:
                last_err = e
                time.sleep(1)
        if last_err is not None:
            raise RuntimeError(f"Cannot replace {rel}: {last_err}")
        done += size
        if progress_cb:
            progress_cb(done, total)
    if progress_cb:
        progress_cb(total, total)


def clear_skipped_version(target_dir: str) -> None:
    """Reset update_skipped in target config.json (best effort)."""
    try:
        cfg_path = os.path.join(target_dir, "config.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("update_skipped"):
            data["update_skipped"] = ""
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(data, f)
    except Exception:
        pass


def stage_gui_updater(src_exe: str) -> str:
    """Copy the bundled updater exe to a fixed temp dir and return its path.

    The updater must NOT run from the app dir: it replaces every file there
    (including its own bundled copy, which would be locked while running).
    """
    run_dir = os.path.join(tempfile.gettempdir(), "acl_updater_run")
    os.makedirs(run_dir, exist_ok=True)
    dst = os.path.join(run_dir, "CiscoACLHelperUpdater.exe")
    try:
        shutil.copy2(src_exe, dst)
        return dst
    except OSError:
        alt = os.path.join(run_dir, f"CiscoACLHelperUpdater_{os.getpid()}.exe")
        shutil.copy2(src_exe, alt)
        return alt


def launch_gui_updater(updater_exe: str, zip_path: str, target_dir: str,
                       exe_name: str, pid: int, pid_start: int, tag: str) -> None:
    """Start the GUI updater (windowed exe: no console ever). Caller quits."""
    subprocess.Popen(
        [updater_exe, "--zip", zip_path, "--target", target_dir,
         "--exe", exe_name, "--pid", str(pid),
         "--pid-start", str(pid_start), "--tag", tag],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
    )


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
