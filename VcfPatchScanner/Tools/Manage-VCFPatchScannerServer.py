#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
#
# SOFTWARE LICENSE AGREEMENT
#
# Copyright (c) CA, Inc. All rights reserved.
#
# You are hereby granted a non-exclusive, worldwide, royalty-free license
# under CA, Inc.'s copyrights to use, copy, modify, and distribute this
# software in source code or binary form for use in connection with CA, Inc.
# products.
#
# This copyright notice shall be included in all copies or substantial
# portions of the software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# =============================================================================
#
# Manage-VCFPatchScannerServer.py
# Cross-platform background process manager for Start-VCFPatchScannerServer.py.
#
# Usage:
#   python Manage-VCFPatchScannerServer.py start [--port=8765] [--no-browser]
#   python Manage-VCFPatchScannerServer.py stop
#   python Manage-VCFPatchScannerServer.py status
#   python Manage-VCFPatchScannerServer.py restart [--port=8765] [--no-browser]
#
# The VcfPatchScannerBaseDirectory environment variable must be set (run
# Initialize-VcfPatchScanner in PowerShell once to create it).  The PID file
# is written to <base>/Logs/vcfpatch-server.pid by the server process itself
# once it is bound and ready; the manager waits up to 8 seconds for it to appear.

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

_ENV_VAR_BASE_DIR  = "VcfPatchScannerBaseDirectory"
_SERVER_SCRIPT     = Path(__file__).parent / "Start-VCFPatchScannerServer.py"
_PID_FILENAME      = "vcfpatch-server.pid"
_STOP_TIMEOUT_SECS = 10   # seconds to wait for graceful shutdown before force-kill
_START_WAIT_SECS   = 8    # seconds to wait for PID file to appear after launch


def _get_base_dir() -> Path:
    val = os.environ.get(_ENV_VAR_BASE_DIR, "").strip()
    if not val:
        print(
            f"[ERROR] {_ENV_VAR_BASE_DIR} is not set.\n"
            "  Run Initialize-VcfPatchScanner in PowerShell to create the required\n"
            "  directory structure, then try again.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    p = Path(val)
    if not p.is_dir():
        print(
            f"[ERROR] {_ENV_VAR_BASE_DIR} is set to '{val}' but that path does not exist.\n"
            "  Re-run Initialize-VcfPatchScanner to recreate the directory, then try again.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return p


def get_pid_file(base_dir: Path) -> Path:
    """Return the expected PID file path for the given base directory."""
    return base_dir / "Logs" / _PID_FILENAME


def read_pid(pid_file: Path) -> "int | None":
    """Read and return the integer PID from pid_file, or None on any error."""
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def is_running(pid: int) -> bool:
    """Return True when a process with pid exists.  Uses signal 0 (existence probe).

    PermissionError (EPERM) means the process exists but is owned by another user —
    this is still "running".  ProcessLookupError (ESRCH) means no such process.
    """
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True   # Process exists; we lack permission to signal it.
    except OSError:
        return False


def _start_background(port: int, no_browser: bool, pid_file: Path) -> subprocess.Popen:
    """Launch Start-VCFPatchScannerServer.py as a detached background process.

    stdout and stderr are appended to <pid_file.parent>/VcfPatchScannerServer-daemon.log so
    startup messages are preserved even though there is no terminal.
    """
    log_file = pid_file.parent / "VcfPatchScannerServer-daemon.log"
    pid_file.parent.mkdir(parents=True, exist_ok=True)

    args = [
        sys.executable,
        str(_SERVER_SCRIPT),
        f"--port={port}",
        f"--pid-file={pid_file}",
        "--no-browser",
    ]
    if not no_browser:
        # Remove --no-browser so the server opens the browser in the user session.
        # When start is called non-interactively (e.g. from a login script) the
        # caller should pass --no-browser explicitly to suppress this.
        args = [a for a in args if a != "--no-browser"]

    out = open(log_file, "a", encoding="utf-8")   # noqa: WPS515  (intentional open-without-context)

    kwargs: dict = {
        "stdout": out,
        "stderr": out,
        "stdin":  subprocess.DEVNULL,
    }

    if sys.platform == "win32":
        # DETACHED_PROCESS: no console window; CREATE_NEW_PROCESS_GROUP: allows
        # os.kill(pid, CTRL_BREAK_EVENT) from this manager if needed later.
        DETACHED_PROCESS         = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        # start_new_session=True calls setsid() so the child gets its own session
        # and is not killed when this terminal closes.
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(args, **kwargs)
    out.close()
    return proc


def cmd_start(port: int, no_browser: bool) -> None:
    base_dir = _get_base_dir()
    pid_file = get_pid_file(base_dir)

    if pid_file.exists():
        existing_pid = read_pid(pid_file)
        if existing_pid and is_running(existing_pid):
            print(f"Server is already running (PID {existing_pid}).")
            print(f"URL: http://localhost:{port}")
            return
        # Stale PID file from a previous crash — remove it and start fresh.
        pid_file.unlink(missing_ok=True)

    # Orphan guard: detect a server process that is still bound to the port but
    # has no PID file (e.g. started manually or crashed without cleanup).  Without
    # this check the new server would silently fail to bind and exit, leaving the
    # old instance running and the user with no clear error message.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _probe:
        _probe.settimeout(0.5)
        if _probe.connect_ex(("127.0.0.1", port)) == 0:
            print(
                f"[WARNING] Port {port} is already in use by another process.\n"
                "  A previous server instance may be running without a PID file.\n"
                "  Run 'Stop-VCFPatchScannerServer' to stop it, or locate and kill\n"
                "  the process manually, then try again.",
                file=sys.stderr,
            )
            return

    proc = _start_background(port, no_browser, pid_file)

    # Wait for the server to write its PID file (it does so after binding the socket).
    deadline = time.monotonic() + _START_WAIT_SECS
    while time.monotonic() < deadline:
        if pid_file.exists():
            actual_pid = read_pid(pid_file)
            if actual_pid and is_running(actual_pid):
                print(f"Server started (PID {actual_pid}) at http://localhost:{port}")
                log_path = pid_file.parent / "VcfPatchScannerServer-daemon.log"
                print(f"Startup log: {log_path}")
                return
        if proc.poll() is not None:
            log_path = pid_file.parent / "VcfPatchScannerServer-daemon.log"
            print(
                f"[ERROR] Server exited immediately (exit code {proc.returncode}).\n"
                f"  Check {log_path} for details.",
                file=sys.stderr,
            )
            sys.exit(1)
        time.sleep(0.1)

    log_path = pid_file.parent / "VcfPatchScannerServer-daemon.log"
    print(
        f"[WARNING] Server launched but PID file did not appear within {_START_WAIT_SECS}s.\n"
        f"  The server may still be starting. Check http://localhost:{port}\n"
        f"  and {log_path} for details.",
        file=sys.stderr,
    )


def cmd_stop() -> None:
    base_dir = _get_base_dir()
    pid_file = get_pid_file(base_dir)

    pid = read_pid(pid_file)
    if pid is None:
        print("Server is not running (no PID file found).")
        return

    if not is_running(pid):
        print(f"Server process {pid} is not running. Removing stale PID file.")
        pid_file.unlink(missing_ok=True)
        return

    print(f"Stopping server (PID {pid})...")
    try:
        if sys.platform == "win32":
            # SIGTERM on Windows calls TerminateProcess — immediate hard stop.
            os.kill(pid, signal.SIGTERM)
        else:
            # SIGTERM on POSIX: the server's signal handler calls server.shutdown()
            # for a clean exit.
            os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"[ERROR] Could not send stop signal to PID {pid}: {exc}", file=sys.stderr)
        sys.exit(1)

    deadline = time.monotonic() + _STOP_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if not is_running(pid):
            pid_file.unlink(missing_ok=True)
            print("Server stopped.")
            return
        time.sleep(0.2)

    print(f"[WARNING] Server did not exit within {_STOP_TIMEOUT_SECS}s. Forcing termination...")
    try:
        if sys.platform == "win32":
            os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    time.sleep(1.0)
    pid_file.unlink(missing_ok=True)
    print("Server force-stopped.")


def cmd_status() -> None:
    base_dir = _get_base_dir()
    pid_file = get_pid_file(base_dir)

    pid = read_pid(pid_file)
    if pid is None:
        print("Server is not running.")
        return

    if is_running(pid):
        print(f"Server is running (PID {pid}).")
    else:
        print(f"Server is not running (stale PID file for PID {pid}). Cleaning up.")
        pid_file.unlink(missing_ok=True)


def _usage() -> None:
    print(
        "Usage: python Manage-VCFPatchScannerServer.py <command> [options]\n"
        "\n"
        "Commands:\n"
        "  start   [--port=8765] [--no-browser]   Start the server as a background process\n"
        "  stop                                    Stop the running server gracefully\n"
        "  status                                  Report whether the server is running\n"
        "  restart [--port=8765] [--no-browser]    Stop then start the server\n"
        "\n"
        "Options:\n"
        "  --port=N       Port number (default: 8765)\n"
        "  --no-browser   Do not open a browser tab on start\n"
        "\n"
        "The VcfPatchScannerBaseDirectory environment variable must be set.\n"
        "Run Initialize-VcfPatchScanner in PowerShell to configure it.\n"
    )


def main() -> None:
    args = sys.argv[1:]
    if not args:
        _usage()
        sys.exit(1)

    cmd  = args[0].lower()
    port = 8765
    no_browser = False

    for arg in args[1:]:
        if arg.startswith("--port="):
            raw = arg.split("=", 1)[1]
            try:
                port = int(raw)
            except ValueError:
                print(f"[ERROR] Invalid port value: '{raw}'", file=sys.stderr)
                sys.exit(1)
            if not (1 <= port <= 65535):
                print(f"[ERROR] Port {port} out of range (1–65535).", file=sys.stderr)
                sys.exit(1)
        elif arg == "--no-browser":
            no_browser = True
        else:
            print(f"[ERROR] Unknown option: '{arg}'", file=sys.stderr)
            _usage()
            sys.exit(1)

    if cmd == "start":
        cmd_start(port, no_browser)
    elif cmd == "stop":
        cmd_stop()
    elif cmd == "status":
        cmd_status()
    elif cmd == "restart":
        cmd_stop()
        time.sleep(0.5)
        cmd_start(port, no_browser)
    else:
        print(f"[ERROR] Unknown command: '{cmd}'", file=sys.stderr)
        _usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
