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
# Start-VCFPatchScannerServer.py
# Web UI for Invoke-VCFPatchScanner.ps1. Supports VCF 5.x, VCF 9.x,
# vSphere (standalone vCenter + optional NSX), and VVF 9.x environments.

import csv
import errno
import hashlib
import io
import json
import logging
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# SSL context for upstream advisory and PSGallery requests.
# certifi supplies a bundled CA store that works on macOS without running the Python
# cert-install helper.  It is optional — Linux and Windows use system certs via the
# default context; macOS users with the cert helper (python.org installer) also work.
try:
    import certifi as _certifi
    _UPSTREAM_SSL_CTX = ssl.create_default_context(cafile=_certifi.where())
except ImportError:
    _UPSTREAM_SSL_CTX = ssl.create_default_context()

_SERVER_VERSION             = "1.0.0.1001"
_DEFAULT_ADVISORY_FILE      = "securityAdvisory.json"
_VCENTER_BUILD_MAP_FILE     = "vcenterBuildMap.json"
_DEFAULT_FINDINGS_DIR       = "Findings"
_FINDINGS_GLOB              = "vcf-findings-*.json"
_DEFAULT_PORT               = 8765
_HTTP_HANDLER_TIMEOUT       = 30   # seconds; applied to each accepted socket by StreamRequestHandler
# Client-disconnect error types that are safe to suppress silently on all platforms.
# ConnectionResetError = WinError 10054 / ECONNRESET (client hard-closed the socket)
# BrokenPipeError      = EPIPE (Unix write to a closed socket)
# ConnectionAbortedError = WinError 10053 (Windows "software caused connection abort",
#   raised when the local TCP stack aborts a send after the remote peer disappears)
_CLIENT_DISCONNECT_ERRORS   = (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)
_VALIDATE_TIMEOUT_SECONDS   = 120  # max time to wait for a validate-credentials subprocess
# Discovery subprocess ceiling = user timeout + 15 s fixed startup overhead.
# The user's configured timeout is the primary control; the buffer covers PowerShell
# startup, module load, and any single internal retry without doubling the wait.
_TCP_PROBE_TIMEOUT_SECONDS  = 5    # timeout for the UI's reachability TCP probe
_SCAN_TIMEOUT_SECONDS       = 3600 # max time for a single scan subprocess (1 hour)

# Environment variable name that Initialize-VcfPatchScanner sets to the user's base directory.
_ENV_VAR_BASE_DIR           = "VcfPatchScannerBaseDirectory"

# Sub-directory names under the user base directory (must match VcfPatchScanner.psm1 constants).
_BASE_CONFIG_SUBDIR         = "Config"
_BASE_DATA_SUBDIR           = "Data"
_BASE_FINDINGS_SUBDIR       = "Findings"
_BASE_LOGS_SUBDIR           = "Logs"

# Allowlist of environment variable names forwarded to PowerShell subprocesses.
# Using an allowlist (not a denylist) ensures unknown credential vars (AWS keys,
# GitHub tokens, etc.) are never forwarded, regardless of what the user has set.
# All entries are stored in uppercase; _base_subprocess_env() compares k.upper()
# so the filter is case-insensitive on all platforms (important for Windows, where
# env var names are case-insensitive, and for PSModulePath which can appear in
# mixed-case form set by PowerShell itself on macOS/Linux).
_SUBPROCESS_ENV_ALLOWLIST = frozenset({
    # Universal
    "PATH", "HOME", "USER", "LOGNAME", "SHELL",
    # Temp dirs (cross-platform)
    "TEMP", "TMP", "TMPDIR",
    # PowerShell module resolution (matches PSModulePath, PSMODULEPATH, etc.)
    "PSMODULEPATH",
    # VCF Patch Scanner paths (PowerShell reads these env vars)
    "VCFPATCHSCANNERBASEDIRECTORY",
    # Module manifest path injected by Start-VCFPatchScannerServer (PowerShell) via ModuleBase
    # so child PowerShell processes can locate VcfPatchScanner.psd1 in deployed layouts where
    # Tools/ lives outside the module tree.  Must be in the allowlist to survive the filter.
    "VCFPATCHSCANNER_MODULE_PSD1",
    # Linux/macOS XDG dirs (PowerShell Core reads these for config)
    "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
    # Windows essentials — no-ops on macOS/Linux
    "USERNAME", "USERPROFILE", "USERDOMAIN", "COMPUTERNAME",
    "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "WINDIR", "SYSTEMDRIVE",
    "OS", "PROCESSOR_ARCHITECTURE",
})

SCAN_SCRIPT   = Path(__file__).parent / "Invoke-VCFPatchScanner.ps1"


def _locate_module_psd1() -> Path:
    """Return the path to VcfPatchScanner.psd1 using the following priority:

    1. ``VCFPATCHSCANNER_MODULE_PSD1`` already set in the parent environment — lets
       operators point the server at an installed or deployed module without
       changing any code.
    2. Resolved sibling of Tools/ (follows symlinks) — correct for the git-repo
       layout and for deployments that keep the module alongside the Tools directory.
    3. Unresolved sibling of Tools/ — retained as a last-resort fallback.

    In all cases the returned path is logged at startup; if it does not exist as a
    file a prominent warning is printed so the operator can act immediately.
    """
    env_override = os.environ.get("VCFPATCHSCANNER_MODULE_PSD1", "").strip()
    if env_override:
        p = Path(env_override)
        if p.is_file():
            return p

    # Use .resolve() to canonicalise the script path before going up two levels so
    # that symlinks in the Tools/ path are dereferenced correctly.
    resolved = Path(__file__).resolve().parent.parent / "VcfPatchScanner.psd1"
    if resolved.is_file():
        return resolved

    # Final fallback: unresolved path (matches the original behaviour).
    return Path(__file__).parent.parent / "VcfPatchScanner.psd1"


_MODULE_PSD1 = _locate_module_psd1()

# Upstream advisory database — raw GitHub content URL for the published securityAdvisory.json.
_UPSTREAM_ADVISORY_URL = (
    "https://raw.githubusercontent.com/vmware/powershell-module-for-vcf-patch-scanner"
    "/main/data/securityAdvisory.json"
)
_UPSTREAM_CHECK_TIMEOUT_SECONDS  = 10   # HEAD requests and small companion file fetches (sha256sum)
_UPSTREAM_DOWNLOAD_TIMEOUT_SECONDS = 60  # full advisory JSON download (~156 KB)

# PowerShell Gallery module version check.
# Uses the NuGet v2 OData API — returns XML, parsed with xml.etree.ElementTree (stdlib).
_PSGALLERY_API_URL = (
    "https://www.powershellgallery.com/api/v2/FindPackagesById()"
    "?id='VcfPatchScanner'&$orderby=Version%20desc&$top=1"
)
_MODULE_GALLERY_PAGE_URL      = "https://www.powershellgallery.com/packages/VcfPatchScanner/"
_MODULE_UPDATE_CACHE_TTL_SECS = 3600  # re-fetch PSGallery at most once per hour


def _require_base_dir() -> Path:
    """Return the validated user base directory or abort with a clear setup error.

    Exits the process (exit code 1) when VcfPatchScannerBaseDirectory is not set or
    does not point to an existing directory.  This is an explicit design constraint:
    the server must not silently write settings, findings, or logs to an unintended
    location.  Run Initialize-VcfPatchScanner once to create the directory and persist
    the environment variable before starting the server.
    """
    val = os.environ.get(_ENV_VAR_BASE_DIR, "").strip()
    if not val:
        print(
            f"\n[ERROR] {_ENV_VAR_BASE_DIR} is not set.\n"
            "  Run Initialize-VcfPatchScanner in PowerShell to create the required\n"
            "  directory structure and persist the environment variable, then\n"
            "  start the server again.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    p = Path(val)
    if not p.is_dir():
        print(
            f"\n[ERROR] {_ENV_VAR_BASE_DIR} is set to '{val}' but that path does not exist.\n"
            "  Re-run Initialize-VcfPatchScanner to recreate the directory, then\n"
            "  start the server again.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return p


_USER_BASE_DIR: Path = _require_base_dir()

SETTINGS_FILE = _USER_BASE_DIR / _BASE_CONFIG_SUBDIR / "scan-settings.json"

# Security: Bind exclusively to localhost (127.0.0.1), never public interfaces
BIND_HOST = "127.0.0.1"

# Logger initialized here with a NullHandler so every call site can log unconditionally.
# _initialize_logging() replaces NullHandler with a FileHandler once the log directory
# is confirmed.  Keeping logger non-None avoids silent audit-trail gaps if startup fails
# before _initialize_logging() completes.
logger = logging.getLogger("VcfPatchScanner-Server")
logger.addHandler(logging.NullHandler())
log_dir = None

def _build_allowed_origin_hosts() -> frozenset:
    """Builds the set of hostnames accepted in HTTP Origin header.

    Always includes loopback aliases (127.0.0.1, localhost, ::1).
    Also includes the machine's short hostname (case-insensitive) so that
    browsers opening http://<COMPUTERNAME>:<port> are not rejected.
    Safe because server is bound exclusively to 127.0.0.1; any Origin with
    the machine name must have originated from the server's own browser.
    """
    hosts = {"127.0.0.1", "localhost", "::1"}
    try:
        short = socket.gethostname().lower().split(".")[0]
        if short:
            hosts.add(short)
    except Exception:
        pass
    return frozenset(hosts)

ALLOWED_ORIGIN_HOSTS = _build_allowed_origin_hosts()


def _resolve_logs_dir(_settings: dict) -> Path:
    """Return <base>/Logs/ — the directory for diagnostic log files."""
    return _USER_BASE_DIR / _BASE_LOGS_SUBDIR


def _resolve_findings_dir(_settings: dict) -> Path:
    """Return <base>/Findings/ — the root directory for scan output JSON files."""
    return _USER_BASE_DIR / _BASE_FINDINGS_SUBDIR


_ENV_DIRNAME_UNSAFE_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def _sanitize_env_dirname(name: str) -> str:
    """Convert a user-supplied environment name to a safe filesystem directory name."""
    safe = _ENV_DIRNAME_UNSAFE_RE.sub('_', name.strip())
    safe = re.sub(r'_+', '_', safe).strip('_').lstrip('.')
    return safe or "default"


def _resolve_env_findings_dir(settings: dict, env_name: str) -> Path:
    """Return <base>/Findings/<env_name>/ — the per-environment subdirectory for scan output files."""
    return _resolve_findings_dir(settings) / _sanitize_env_dirname(env_name)


def _ensure_user_dir(d: Path) -> None:
    """Create d (and any missing parents) if absent, then restrict to the current user.

    Permission errors from chmod are silently ignored on platforms that do not
    enforce POSIX permissions (e.g. Windows without WSL).  OSError from mkdir
    propagates to the caller.
    """
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass  # best-effort on Windows or restricted filesystems.


def _ensure_env_findings_dir(env_dir: Path) -> None:
    """Create env_dir if absent; raises RuntimeError when creation fails.

    Also ensures the Findings root (env_dir.parent) exists and is restricted to
    the current user, so the root directory is not world-listable even though the
    env-specific subdirectory already carries its own 0o700 permission.
    """
    # Protect the Findings/ root before creating the env-specific subdirectory.
    # Wrap any OSError so callers always see RuntimeError on any creation failure.
    try:
        _ensure_user_dir(env_dir.parent)
    except OSError as exc:
        raise RuntimeError(
            f"Cannot create findings directory '{env_dir}': {exc}"
        ) from exc

    if env_dir.is_dir():
        return
    try:
        env_dir.mkdir(parents=False, exist_ok=False)
    except FileExistsError:
        return  # created concurrently between the is_dir check and mkdir — acceptable.
    except OSError as exc:
        raise RuntimeError(
            f"Cannot create findings directory '{env_dir}': {exc}"
        ) from exc
    try:
        env_dir.chmod(0o700)
    except OSError:
        pass  # best-effort: chmod is not supported on all platforms.


def _resolve_advisory_path(settings: dict) -> Path:
    """Return the security advisory file path.

    Resolution rules (in order):
    1. Empty / absent setting → <base>/Data/securityAdvisory.json (default).
    2. Bare filename with no directory component (e.g. "securityAdvisory.json") →
       <base>/Data/<filename>.  This preserves backward-compatibility with existing
       settings files written by earlier versions that stored only the filename.
    3. Relative path containing a separator (e.g. "Data/custom.json") →
       <base>/<path>.
    4. Absolute path → used as-is, provided it remains within the home directory.
    Paths outside the home directory fall back to the default.
    """
    default = _USER_BASE_DIR / _BASE_DATA_SUBDIR / _DEFAULT_ADVISORY_FILE
    raw = settings.get("securityAdvisoryFile", "").strip()
    if not raw:
        return default
    p = Path(raw)
    if p.parent == Path("."):
        # Bare filename — always locate in the Data subdirectory.
        candidate = _USER_BASE_DIR / _BASE_DATA_SUBDIR / p
    elif p.is_absolute():
        candidate = p
    else:
        candidate = _USER_BASE_DIR / p
    resolved = candidate.resolve()
    home = Path.home().resolve()
    if not str(resolved).startswith(str(home)):
        logger.warning("securityAdvisoryFile '%s' is outside the home directory; using default.", raw)
        return default
    return resolved

def _resolve_build_map_path() -> Path:
    """Return <base>/Data/vcenterBuildMap.json — generated by Convert-BroadcomAdvisoriesToSchema.ps1."""
    return _USER_BASE_DIR / _BASE_DATA_SUBDIR / _VCENTER_BUILD_MAP_FILE

def _load_html_template() -> bytes:
    """Load vcp-patch-ui.html (consolidated HTML with inline CSS and JS).

    The HTML file (vcp-patch-ui.html) is a self-contained file with all
    CSS and JavaScript inlined for easy distribution and deployment.
    """
    ui_path = Path(__file__).parent / "vcp-patch-ui.html"
    try:
        return ui_path.read_bytes()
    except FileNotFoundError:
        return b"<html><body>vcp-patch-ui.html not found</body></html>"

_lock       = threading.Lock()
_scan_state = {
    "status":           "idle",   # idle | running | complete | failed
    "process":          None,
    "exit_code":        None,
    "error":            None,     # populated on failure; None otherwise
    "envType":          "",       # type of current environment being scanned
    "envConfig":        {},       # shallow copy of env dict — hostnames only; MUST NOT be added to /scan/status response (would leak server names)
    "currentEnvName":   "",       # display name shown in status badge
    "queuePosition":    0,        # 1-indexed position in the current session queue
    "queueTotal":       0,        # total environments queued this session
    "sessionStartTime":    0.0,   # time.time() snapshot when the session began
    "sessionEndTime":      0.0,   # time.time() snapshot when the session ended
    "totalDurationSeconds": 0,    # rounded integer seconds for the full session
    "envTimings":          [],    # [{name, durationSeconds}] per completed environment
    "envStartTime":        0.0,   # time.time() snapshot when current env started
    "fileEnvMap":          {},    # findings filename → environment display name
    "failedEndpoints":     {},    # env_name → [failedEndpoint dicts] for retry-failed mode
    "vcfMinorVersions":    {},    # env_name → "9.0" or "9.1" detected during Fleet inventory
    "versionCatalog":      {},    # env_name → [catalog entry dicts] from Fleet LCM release-versions
}

_validate_lock            = threading.Lock()
_validate_state           = {"items": [], "done": True}

# Timestamp (time.time()) set at the start of each discovery call so /discovery/log
# can return only the log lines written during that call.
_discovery_start_time: float = 0.0
_validate_proc: "subprocess.Popen | None" = None  # current validation subprocess; None when idle
_validate_stop_requested  = False                  # set by /scan/validate-stop to abort the run

# Advisory update check state — populated once at startup, re-populated by manual checks.
# Keys match the _check_upstream_advisory return dict plus a "checked" sentinel.
_advisory_check_lock  = threading.Lock()
_advisory_check_state: "dict | None" = None   # None = check not yet run

# Module version update check state (PSGallery).
# _module_update_cache holds the last fetch result; None = not yet fetched.
# _module_install_state tracks a background Update-Module subprocess.
_module_update_lock:   threading.Lock    = threading.Lock()
_module_update_cache:  "dict | None"     = None
_module_install_lock:  threading.Lock    = threading.Lock()
_module_install_state: dict              = {"status": "idle"}   # idle / running / success / failed


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def _default_settings() -> dict:
    return {
        "environments": [],
        "findingsOutputDirectory": _DEFAULT_FINDINGS_DIR,
        "logDirectory": _BASE_LOGS_SUBDIR,
        "logLevel": "INFO",
        "securityAdvisoryFile": _DEFAULT_ADVISORY_FILE,
        "ignoreCertificate": True,
        "connectionTimeoutSeconds": 30,
        "lightMode": False,
        # hiddenCols is intentionally absent here: the UI applies column defaults from _COL_DEFS
        # when no colSchemaVersion is present in settings (i.e. a fresh install). A server-side
        # default would be silently ignored because the UI requires colSchemaVersion to match
        # before trusting the saved list. Column visibility is fully managed by the UI.
        # Advisory update check settings.
        # checkUpdateDisabled: true = never contact GitHub (offline/dark-site installs).
        # updateCheckPromptShown: true = the offline prompt was already shown once; never repeat it.
        "checkUpdateDisabled": False,
        "updateCheckPromptShown": False,
        # Module (PSGallery) update check settings.
        # disableModuleUpdateReminders: true = never contact PSGallery for module version checks.
        "disableModuleUpdateReminders": False,
    }

# Export for tests
DEFAULT_SETTINGS = _default_settings()

_settings_cache: "dict | None" = None
_settings_lock = threading.Lock()


def _load_settings() -> dict:
    """Load settings, returning a cached copy when available.

    The cache is invalidated by _save_settings so disk reads only happen once
    per settings change, not once per HTTP request.
    """
    global _settings_cache
    with _settings_lock:
        if _settings_cache is not None:
            return _settings_cache
        result: dict
        try:
            if SETTINGS_FILE.exists():
                data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
                result = _default_settings()
                result.update(data)
            else:
                result = _default_settings()
        except Exception:
            result = _default_settings()
        _settings_cache = result
        return result


def _validate_settings(data: dict) -> "str | None":
    """Validate incoming settings payload. Return an error string or None."""
    valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR"}

    if not isinstance(data, dict):
        return "Settings must be a JSON object."

    log_level = data.get("logLevel")
    if log_level is not None and log_level not in valid_log_levels:
        return f"logLevel must be one of {sorted(valid_log_levels)}."

    conn_timeout = data.get("connectionTimeoutSeconds")
    if conn_timeout is not None:
        if not isinstance(conn_timeout, int) or not (1 <= conn_timeout <= 900):
            return "connectionTimeoutSeconds must be an integer between 1 and 900."

    for bool_field in ("ignoreCertificate", "lightMode", "checkUpdateDisabled", "updateCheckPromptShown",
                       "disableModuleUpdateReminders"):
        val = data.get(bool_field)
        if val is not None and not isinstance(val, bool):
            return f"{bool_field} must be a boolean."

    envs = data.get("environments")
    if envs is not None:
        if not isinstance(envs, list):
            return "environments must be a list."
        if len(envs) > 100:
            return "environments must contain at most 100 items."

    hidden_cols = data.get("hiddenCols")
    if hidden_cols is not None and not isinstance(hidden_cols, list):
        return "hiddenCols must be a list."

    return None


def _save_settings(data: dict) -> None:
    """Persist settings to disk atomically and invalidate the in-memory cache.

    Writes to a timestamped temporary file then replaces the target with it.
    Path.replace() (os.replace) is used rather than Path.rename() (os.rename)
    because on Windows, os.rename raises FileExistsError when the destination
    already exists; os.replace overwrites it atomically on both Windows and POSIX.
    """
    global _settings_cache
    content = json.dumps(data, indent=2, ensure_ascii=False)
    _ensure_user_dir(SETTINGS_FILE.parent)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    tmp = SETTINGS_FILE.with_name(f"{SETTINGS_FILE.name}.{timestamp}.tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(SETTINGS_FILE)
        try:
            SETTINGS_FILE.chmod(0o600)
        except OSError:
            pass  # best-effort on Windows or restricted filesystems.
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    with _settings_lock:
        _settings_cache = None  # Invalidate cache so next load re-reads from disk.


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _extract_json_from_output(output: str) -> "dict | list | None":
    """Scan stdout for the first line that parses as JSON.

    The discovery subprocess may emit log lines before the JSON result
    if $InformationPreference suppression is incomplete. This helper finds
    the JSON result line regardless of what precedes it.
    """
    for line in output.splitlines():
        line = line.strip()
        if line and line[0] in ('{', '['):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


_VSPHERE_FIELDS: list = [
    ("vcenterServer",    "-VcenterServer"),
    ("vcenterUser",      "-VcenterUser"),
    ("nsxManagerServer", "-NsxManagerServer"),
    ("nsxManagerUser",   "-NsxManagerUser"),
]

# Maps environment type to the list of (env-dict-key, PowerShell-flag) pairs.
_ENV_TYPE_FIELDS: dict = {
    "vcf9": [
        ("sddcManagerInstanceName", "-SddcManagerInstanceName"),
        ("sddcManagerServer",       "-SddcManagerServer"),
        ("sddcManagerUser",         "-SddcManagerUser"),
        ("vcfOpsServer",            "-VcfOpsServer"),
        ("vcfOpsUser",              "-VcfOpsUser"),
        ("vcfFMServer",             "-VcfFMServer"),
        ("vcfFMUser",               "-VcfFMUser"),
    ],
    "vcf5": [
        ("sddcManagerServer", "-SddcManagerServer"),
        ("sddcManagerUser",   "-SddcManagerUser"),
        ("vrslcmServer",      "-VrslcmServer"),
        ("vrslcmUser",        "-VrslcmUser"),
    ],
    "vsphere8": _VSPHERE_FIELDS,
    "vvf9": [
        ("vcfOpsServer", "-VcfOpsServer"),
        ("vcfOpsUser",   "-VcfOpsUser"),
        ("vcfFMServer",  "-VcfFMServer"),
        ("vcfFMUser",    "-VcfFMUser"),
        ("vcenterUser",  "-VcenterUser"),
    ],
}


def _is_vcf91(env: dict) -> bool:
    """Return True when env is a VCF 9.1+ environment (VSP Fleet-LCM path).

    VCF 9.1 uses Fleet Controller as the authoritative source for VCF Operations
    inventory; the native VCF Operations API is not called and its credential is
    not required.
    """
    return env.get("type") == "vcf9" and env.get("vcfMinorVersion", "") == "9.1"


def _is_vvf91(env: dict) -> bool:
    """Return True when env is a VVF 9.1+ environment (VSP Fleet-LCM path).

    Like VCF 9.1, VVF 9.1 routes through Fleet Controller for VCF Operations
    inventory; the native VCF Operations API is not called and its credential is
    not required at scan time.  Standalone vCenter FQDNs are stored in the
    environment config during wizard authentication and passed via VCENTER_FQDNS.
    """
    return env.get("type") == "vvf9" and env.get("vcfMinorVersion", "") == "9.1"


def _env_type_args(env: dict) -> list:
    """Return the environment-type-specific CLI args for Invoke-VCFPatchScanner.ps1.

    Maps Python env dict keys to PowerShell parameter names. VcfMajorVersion
    is the validated PowerShell value (vcf5/vcf9/vsphere8/vvf9), not a bare
    major-version number.

    For VCF 9.1 and VVF 9.1 environments the VCF Operations server/user args are
    omitted so PowerShell treats VCF Operations as NOT_CONFIGURED (Skipped).
    Fleet Manager is authoritative for VCF Operations on both 9.1 paths.
    """
    t = env.get("type", "")
    fields = _ENV_TYPE_FIELDS.get(t)
    if fields is None:
        return []
    args = ["-VcfMajorVersion", t]
    ops_keys = {"vcfOpsServer", "vcfOpsUser"}
    # Both VCF 9.1 and VVF 9.1 route through Fleet Controller for VCF Operations;
    # the native Ops API is not called so its server/user args are not forwarded.
    skip_ops = _is_vcf91(env) or _is_vvf91(env)
    for key, flag in fields:
        if skip_ops and key in ops_keys:
            continue
        v = env.get(key, "").strip()
        if v:
            args += [flag, v]
    vcf_minor = env.get("vcfMinorVersion", "").strip()
    if vcf_minor:
        args += ["-VcfMinorVersion", vcf_minor]
    return args


# ---------------------------------------------------------------------------
# Credential validation via PowerShell
# ---------------------------------------------------------------------------

def _run_validation_in_powershell(env: dict, passwords: dict, timeout_seconds: int = 30) -> "tuple[list, str | None]":
    """Run credential validation via PowerShell -ValidateCredentialsOnly.

    Returns (endpoint_tests, None) on success or (endpoint_tests, error_string) on failure.
    endpoint_tests is a list of per-endpoint dicts: Endpoint, Server, Status, Connected, Message.
    When per-endpoint JSON is available the list is always returned; the caller uses the
    individual Status values to determine which endpoints passed or failed.
    Returns ([], "stopped") when the user requested cancellation via /scan/validate-stop.
    """
    global _validate_proc
    args = [
        "pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCAN_SCRIPT),
        "-ValidateCredentialsOnly",
        "-LogLevel", "WARNING",
        "-LogDirectory", str(_resolve_logs_dir({})),
        "-ConnectionTimeoutSeconds", str(timeout_seconds),
    ]
    if env.get("name", "").strip():
        args += ["-EnvironmentDisplayName", env["name"].strip()]
    args += _env_type_args(env)

    env_vars = _build_env_vars(env, passwords)

    try:
        proc = subprocess.Popen(
            args,
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(SCAN_SCRIPT.parent),
            text=True
        )
        with _validate_lock:
            _validate_proc = proc
        try:
            stdout, stderr = proc.communicate(timeout=_VALIDATE_TIMEOUT_SECONDS)
        finally:
            with _validate_lock:
                _validate_proc = None

        if _validate_stop_requested:
            return [], "stopped"

        json_data = _extract_json_from_output(stdout)
        endpoint_tests: list = []
        if json_data and isinstance(json_data, dict):
            endpoint_tests = json_data.get("EndpointTests", [])

        if proc.returncode != 0:
            if endpoint_tests:
                # Per-endpoint data available — each test carries its own Status.
                return endpoint_tests, None
            raw = stderr.strip() or stdout.strip()
            meaningful = next(
                (l.strip() for l in reversed(raw.split('\n')) if l.strip()), raw
            )
            meaningful = re.sub(r'^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\]\s+\[\w+\]\s+', '', meaningful)
            return [], f"Credential validation failed: {meaningful[:200]}"

        return endpoint_tests, None
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        with _validate_lock:
            _validate_proc = None
        return [], f"Validation timed out (exceeded {_VALIDATE_TIMEOUT_SECONDS} seconds)"
    except Exception as exc:
        with _validate_lock:
            _validate_proc = None
        return [], f"Validation error: {str(exc)}"


def _sanitize_error_message(message: str) -> str:
    """Remove sensitive information and control sequences from error messages before logging."""
    # Strip PSStyle / VT100 ANSI CSI sequences (e.g. ESC[31;1m, ESC[0m) emitted by
    # PowerShell when $PSStyle.OutputRendering is not set to 'PlainText'.
    message = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', message)
    message = re.sub(r'Authorization:\s+[^\n]+', 'Authorization: [REDACTED]', message)
    message = re.sub(r'Basic\s+[A-Za-z0-9+/=]+', 'Basic [REDACTED]', message)
    message = re.sub(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]', message)
    message = re.sub(r'"token":\s*"[^"]*"', '"token": "[REDACTED]"', message)
    return message


def _discovery_subprocess_timeout(timeout_seconds: int) -> int:
    """Return the subprocess ceiling for a discovery call.

    Adds a fixed 15 s buffer for PowerShell startup and module load on top of
    the user's configured per-call timeout.  The user's setting is the primary
    control and is what appears in any timeout error message.
    """
    return timeout_seconds + 15


def _clean_powershell_error(raw: str) -> str:
    """Extract a human-readable message from a raw PowerShell VCF cmdlet error.

    VCF PowerCLI cmdlets embed a JSON body in their exception messages, e.g.:
      '6/18/2026 9:43:52 PM Connect-VcfOpsServer {"type":"Error","message":"The
       provided username/password or token is not valid.","httpStatusCode":401}'

    This function extracts the 'message' field and prepends context for common
    HTTP status codes.  Falls back to stripping the leading timestamp + cmdlet
    name when no embedded JSON is found.
    """
    if not raw:
        return raw
    m = re.search(r'\{.*\}', raw, re.DOTALL)
    if m:
        try:
            body = json.loads(m.group(0))
            msg    = str(body.get("message") or body.get("error") or "").strip()
            status = body.get("httpStatusCode") or body.get("statusCode")
            if msg:
                if status == 401:
                    return f"Authentication failed: {msg}"
                if status == 403:
                    return f"Access denied: {msg}"
                if status == 404:
                    return f"Endpoint not found: {msg}"
                return msg
        except Exception:
            pass
    # Strip leading "MM/DD/YYYY HH:MM:SS AM/PM CmdletName " pattern when no JSON found.
    cleaned = re.sub(r'^\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M\s+\S+\s*', '', raw).strip()
    return cleaned or raw


def _discover_sddc_from_ops_via_powershell(ops_host: str, username: str, password: str, timeout_seconds: int = 30) -> "tuple[list[dict], str | None, str, list[str]]":
    """Discover SDDC Manager instances and standalone vCenters via PowerShell.

    Invokes Invoke-VCFPatchScanner.ps1 -DiscoverSddcManagers so all parameter
    passing goes through named CLI args (no heredoc injection risk).

    Returns (instances, error_or_None, ops_version_string, vcenter_fqdns) where:
      instances       — list of dicts with keys 'fqdn', 'instanceName', 'sddcUsername'
      ops_version_string — releaseName from GET /api/versions/current (e.g. "VCF Operations 9.1.0.0")
      vcenter_fqdns   — list of standalone vCenter FQDNs registered via the VMWARE adapter
    """
    args = [
        "pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCAN_SCRIPT),
        "-DiscoverSddcManagers",
        "-VcfOpsServer", ops_host,
        "-VcfOpsUser",   username,
        "-LogLevel",     "DEBUG",
        "-LogDirectory", str(_resolve_logs_dir({})),
        "-ConnectionTimeoutSeconds", str(timeout_seconds),
    ]

    env_vars = _base_subprocess_env()
    env_vars["VCF_OPS_PASSWORD"] = password

    try:
        proc = subprocess.Popen(
            args,
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(SCAN_SCRIPT.parent),
            text=True
        )
        subprocess_timeout = _discovery_subprocess_timeout(timeout_seconds)
        stdout, _ = proc.communicate(timeout=subprocess_timeout)

        json_result = _extract_json_from_output(stdout)

        if proc.returncode != 0:
            if json_result and isinstance(json_result, dict) and json_result.get("error"):
                return [], _clean_powershell_error(json_result["error"]), "", []
            return [], _clean_powershell_error(stdout.strip()[:300]), "", []

        if json_result is None:
            return [], f"No JSON found in discovery output: {stdout.strip()[:200]}", "", []

        if isinstance(json_result, dict):
            if json_result.get("error"):
                return [], _clean_powershell_error(json_result["error"]), "", []
            instances = [
                {
                    "fqdn":          str(i.get("fqdn", "")).strip(),
                    "instanceName":  str(i.get("instanceName", "") or ""),
                    "sddcUsername":  str(i.get("sddcUsername", "") or ""),
                }
                for i in json_result.get("instances", [])
                if i.get("fqdn")
            ]
            ops_version   = str(json_result.get("opsVersion") or "").strip()
            vcenter_fqdns = [
                str(f).strip() for f in (json_result.get("vcenterFqdns") or [])
                if str(f).strip()
            ]
            return instances, None, ops_version, vcenter_fqdns

        return [], f"Unexpected response format: {type(json_result).__name__}", "", []

    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return [], f"Discovery timed out (exceeded {timeout_seconds} seconds).", "", []
    except Exception as exc:
        return [], f"Discovery error: {str(exc)[:100]}", "", []


def _discover_fleet_manager_from_ops_via_powershell(ops_host: str, username: str, password: str, timeout_seconds: int = 30, ops_version: str = "") -> "tuple[str | None, str | None, str | None]":
    """Discover the Fleet Manager FQDN from VCF Operations via PowerShell.

    Dispatches to the version-appropriate API:
      VCF 9.1+: GET /suite-api/internal/components?componentType=VSP  (fleetFqdn property)
      VCF 9.0:  GET /casa/capabilities  (ops-lcm entry)
    The PowerShell layer performs the dispatch based on -VcfOpsVersion.

    Returns (fleet_fqdn, vcf_fm_user, error_or_None).
    """
    args = [
        "pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCAN_SCRIPT),
        "-DiscoverFleetManager",
        "-VcfOpsServer", ops_host,
        "-VcfOpsUser",   username,
        "-LogLevel",     "DEBUG",
        "-LogDirectory", str(_resolve_logs_dir({})),
        "-ConnectionTimeoutSeconds", str(timeout_seconds),
    ]
    if ops_version:
        args += ["-VcfOpsVersion", ops_version]

    env_vars = _base_subprocess_env()
    env_vars["VCF_OPS_PASSWORD"] = password

    try:
        proc = subprocess.Popen(
            args,
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(SCAN_SCRIPT.parent),
            text=True
        )
        subprocess_timeout = _discovery_subprocess_timeout(timeout_seconds)
        stdout, _ = proc.communicate(timeout=subprocess_timeout)

        json_result = _extract_json_from_output(stdout)

        if proc.returncode != 0:
            if json_result and isinstance(json_result, dict) and json_result.get("error"):
                return None, None, _clean_powershell_error(json_result["error"])
            return None, None, _clean_powershell_error(stdout.strip()[:300])

        if json_result is None:
            return None, None, f"No JSON found in Fleet Manager discovery output: {stdout.strip()[:200]}"

        if isinstance(json_result, dict):
            if json_result.get("error"):
                return None, None, _clean_powershell_error(json_result["error"])
            fleet_fqdn = str(json_result.get("fleetFqdn") or "").strip()
            vcf_fm_user = str(json_result.get("vcfFMUser") or "").strip()
            if not fleet_fqdn:
                return None, None, "Fleet Manager FQDN not found in discovery response."
            return fleet_fqdn, vcf_fm_user, None

        return None, None, f"Unexpected response format: {type(json_result).__name__}"

    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None, None, f"Fleet Manager discovery timed out (exceeded {timeout_seconds} seconds)."
    except Exception as exc:
        return None, None, f"Fleet Manager discovery error: {str(exc)[:100]}"


def _discover_vrslcm_from_sddc_via_powershell(sddc_host: str, username: str, password: str, timeout_seconds: int = 30) -> "tuple[str | None, str, str | None]":
    """Discover the vRSLCM FQDN registered with SDDC Manager via GET /v1/vrslcms (VCF 5.x only).

    Returns (vrslcm_fqdn, vrslcm_version, error_or_None).
    vrslcm_fqdn is None when no vRSLCM is registered (error is also None in that case).
    """
    args = [
        "pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCAN_SCRIPT),
        "-DiscoverVrslcm",
        "-SddcManagerServer", sddc_host,
        "-SddcManagerUser",   username,
        "-LogLevel",          "DEBUG",
        "-LogDirectory",      str(_resolve_logs_dir({})),
        "-ConnectionTimeoutSeconds", str(timeout_seconds),
    ]

    env_vars = _base_subprocess_env()
    env_vars["SDDC_MANAGER_PASSWORD"] = password

    try:
        proc = subprocess.Popen(
            args,
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(SCAN_SCRIPT.parent),
            text=True
        )
        subprocess_timeout = _discovery_subprocess_timeout(timeout_seconds)
        stdout, _ = proc.communicate(timeout=subprocess_timeout)

        json_result = _extract_json_from_output(stdout)

        if proc.returncode != 0:
            if json_result and isinstance(json_result, dict) and json_result.get("error"):
                return None, "", json_result["error"]
            return None, "", f"vRSLCM discovery failed (exit {proc.returncode}): {stdout.strip()[:300]}"

        if json_result is None:
            return None, "", f"No JSON found in vRSLCM discovery output: {stdout.strip()[:200]}"

        if isinstance(json_result, dict):
            if json_result.get("error"):
                return None, "", json_result["error"]
            vrslcm_fqdn    = str(json_result.get("vrslcmFqdn") or "").strip()
            vrslcm_version = str(json_result.get("vrslcmVersion") or "").strip()
            return (vrslcm_fqdn or None), vrslcm_version, None

        return None, "", f"Unexpected response format: {type(json_result).__name__}"

    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None, "", f"vRSLCM discovery timed out (exceeded {timeout_seconds} seconds)."
    except Exception as exc:
        return None, "", f"vRSLCM discovery error: {str(exc)[:100]}"


_ENDPOINT_STATUS_MAP = {
    "Connected":      "success",
    "Failed":         "unreachable",   # TCP/network issue — user may skip
    "Unauthenticated": "auth_failed",  # Reachable but credentials rejected — must fix
}


def _run_all_validation_bg(validate_list: list, timeout_seconds: int = 30) -> None:
    """Run credential validation for one or more (env, passwords) pairs via PowerShell."""
    global _validate_state, _validate_stop_requested
    accumulated: list = []
    multi = len(validate_list) > 1

    for env, passwords in validate_list:
        if _validate_stop_requested:
            break

        env_name = env.get("name", "")
        prefix = f"[{env_name}] " if multi else ""

        endpoint_tests, err = _run_validation_in_powershell(env, passwords, timeout_seconds)

        # Stopped mid-validation — emit a cancelled item and exit cleanly.
        if err == "stopped" or _validate_stop_requested:
            accumulated.append({
                "label": "Validation cancelled by user.",
                "status": "cancelled",
            })
            break

        if err:
            # No per-endpoint data at all — fall back to a single environment-level error item.
            accumulated.append({
                "label": f"{prefix}{env_name} (validation failed)" if env_name else "Validation Error",
                "status": "failed",
                "error": _sanitize_error_message(err),
            })
            with _validate_lock:
                _validate_state = {"items": accumulated, "done": False}
        elif endpoint_tests:
            # Emit one item per tested endpoint; skip "Skipped" / NOT_CONFIGURED entries.
            for test in endpoint_tests:
                ep_name   = test.get("Endpoint", "")
                server    = test.get("Server", "")
                ep_status = test.get("Status", "")
                message   = _sanitize_error_message(test.get("Message", ""))
                if ep_status == "Skipped" or server == "NOT_CONFIGURED":
                    continue
                ui_status = _ENDPOINT_STATUS_MAP.get(ep_status, "failed")
                item: dict = {
                    "label":    f"{prefix}{ep_name} \"{server}\"",
                    "endpoint": ep_name,
                    "server":   server,
                    "envName":  env_name,
                    "status":   ui_status,
                }
                if ui_status in ("unreachable", "failed") and message:
                    item["error"] = message
                elif ui_status == "auth_failed" and message:
                    item["note"] = message
                accumulated.append(item)
            with _validate_lock:
                _validate_state = {"items": accumulated, "done": False}
        else:
            # Fallback when JSON was not emitted (older PS script or unexpected error path).
            accumulated.append({
                "label": f"{prefix}{env_name} (all endpoints validated)" if env_name else "All endpoints validated",
                "status": "success",
            })
            with _validate_lock:
                _validate_state = {"items": accumulated, "done": False}

    # Clear the stop flag and mark done atomically so a /scan/validate-stop call that
    # arrives between these two writes cannot leave the flag set for a subsequent run.
    with _validate_lock:
        _validate_stop_requested = False
        _validate_state = {"items": accumulated, "done": True}


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def _validate_env_config(env: dict) -> "str | None":
    """Return an error string or None."""
    t = env.get("type", "")
    if t in ("vcf9", "vcf5"):
        if not env.get("sddcManagerServer", "").strip():
            return "SDDC Manager Server is required."
        if not env.get("sddcManagerUser", "").strip():
            return "SDDC Manager Username is required."
        if t == "vcf9":
            if not _is_vcf91(env):
                # VCF 9.1+ uses Fleet Controller as the authoritative VCF Operations source;
                # the native VCF Operations API is not called, so its credentials are optional.
                if not env.get("vcfOpsServer", "").strip():
                    return "VCF Operations Server is required."
                if not env.get("vcfOpsUser", "").strip():
                    return "VCF Operations Username is required."
            if not env.get("vcfFMServer", "").strip():
                return "Fleet Manager Server is required for VCF 9."
            # vcfFMUser is derived from the VCF Operations version; never required from the user.
    elif t == "vvf9":
        if not env.get("vcfOpsServer", "").strip():
            return "VCF Operations Server is required for VVF 9."
        if not env.get("vcfOpsUser", "").strip():
            return "VCF Operations Username is required for VVF 9."
        if not env.get("vcfFMServer", "").strip():
            return "Fleet Manager Server is required for VVF 9."
        if not env.get("vcenterUser", "").strip():
            return "vCenter Username is required for VVF 9."
    elif t == "vsphere8":
        if not env.get("vcenterServer", "").strip():
            return "vCenter Server is required."
        if not env.get("vcenterUser", "").strip():
            return "vCenter Username is required."
        if env.get("nsxManagerServer", "").strip() and not env.get("nsxManagerUser", "").strip():
            return "NSX Manager Username is required when NSX Manager Server is configured."
    else:
        return f"Unknown environment type: '{t}'."
    return None


def _build_ps_args(env: dict, passwords: dict, settings: dict, retry_fqdns: "list[str] | None" = None) -> list:
    env_name     = env.get("name", "").strip()
    findings_dir = _resolve_env_findings_dir(settings, env_name)
    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    findings_path = str(findings_dir / f"vcf-findings-{timestamp}.json")

    advisory_path  = str(_resolve_advisory_path(settings))
    build_map_path = _resolve_build_map_path()
    logs_dir       = str(_resolve_logs_dir(settings))

    args = [
        "pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCAN_SCRIPT),
        "-LogLevel",             settings.get("logLevel", "INFO"),
        "-LogDirectory",         logs_dir,
        "-SecurityAdvisoryFile", advisory_path,
        "-FindingsOutputPath",   findings_path,
        "-ConnectionTimeoutSeconds", str(settings.get("connectionTimeoutSeconds", 30)),
    ]
    # Pass the build map when it exists; the scanner degrades gracefully when absent.
    # The file is generated by Convert-BroadcomAdvisoriesToSchema.ps1, not by this server.
    if build_map_path.exists():
        args += ["-VcenterBuildMapFile", str(build_map_path)]
    if settings.get("ignoreCertificate", True):
        args.append("-IgnoreInvalidCertificate")
    if env.get("name", "").strip():
        args += ["-EnvironmentDisplayName", env["name"].strip()]
    # Retry-failed-only: restrict inventory to the previously failed FQDNs.
    if retry_fqdns:
        args.append("-RetryFailedEndpointsOnly")
        args += ["-FailedEndpointFqdns", json.dumps(retry_fqdns)]
    args += _env_type_args(env)
    return args


def _base_subprocess_env() -> dict:
    """Return the process environment filtered to _SUBPROCESS_ENV_ALLOWLIST.

    Starting from an allowlist ensures unknown credential vars (AWS keys, GitHub
    tokens, etc.) are never forwarded to child processes regardless of what the
    user has set in their shell session. Comparison is case-insensitive so that
    mixed-case names (e.g. PSModulePath set by PowerShell on macOS/Linux) are
    forwarded regardless of how the OS stored them.

    VCFPATCHSCANNER_MODULE_PSD1 is injected unconditionally so that
    Invoke-VCFPatchScanner.ps1 can find the module manifest regardless of whether the
    Tools directory is deployed to a separate base directory or run from the git repo.
    """
    ev = {k: v for k, v in os.environ.items() if k.upper() in _SUBPROCESS_ENV_ALLOWLIST}
    if _MODULE_PSD1.exists():
        ev["VCFPATCHSCANNER_MODULE_PSD1"] = str(_MODULE_PSD1)
    return ev


def _build_env_vars(env: dict, passwords: dict) -> dict:
    """Build the subprocess environment for a scan or validation run.

    Starts from the allowlist-filtered base environment and adds only the
    credential env vars required for this specific environment type.  Credentials
    are always provided explicitly through the UI — never inherited from the
    parent shell.
    """
    ev             = _base_subprocess_env()
    t              = env.get("type", "")
    single_pass    = env.get("useSinglePassword", False)
    fallback_pass  = passwords.get("sddcPass") if single_pass else None
    if t in ("vcf9", "vcf5"):
        if passwords.get("sddcPass"):
            ev["SDDC_MANAGER_PASSWORD"] = passwords["sddcPass"]
        if t == "vcf9":
            # VCF 9.1: Fleet Controller is authoritative for VCF Operations; skip its password
            # so PowerShell never attempts the native VCF Operations API, even when
            # useSinglePassword would otherwise supply the SDDC password as a fallback.
            if not _is_vcf91(env):
                ops_pass = passwords.get("opsPass") or fallback_pass
                if ops_pass:
                    ev["VCF_OPS_PASSWORD"] = ops_pass
            fm_pass = passwords.get("fmPass") or fallback_pass
            if fm_pass:
                ev["VCF_FM_PASSWORD"] = fm_pass
        if t == "vcf5":
            # NSX_MANAGER_PASSWORD is intentionally not set for VCF 5.x. The PowerShell
            # module retrieves the NSX admin password directly from the SDDC Manager
            # credentials API (GET /v1/credentials?resourceType=NSXT_MANAGER) via
            # Get-NsxAdminPasswordFromSddc — no separate user input is required.
            vrslcm_pass = passwords.get("vrslcmPass") or fallback_pass
            if vrslcm_pass and env.get("vrslcmServer", "").strip():
                ev["VRSLCM_PASSWORD"] = vrslcm_pass
    elif t == "vvf9":
        # VVF9 9.1: Fleet Controller is authoritative for VCF Operations; skip its
        # password so PowerShell never attempts the native VCF Operations API.
        if not _is_vvf91(env):
            ops_pass = passwords.get("opsPass")
            if ops_pass:
                ev["VCF_OPS_PASSWORD"] = ops_pass
        fm_pass = passwords.get("fmPass")
        if fm_pass:
            ev["VCF_FM_PASSWORD"] = fm_pass
        if passwords.get("vcenterPass"):
            ev["VCENTER_PASSWORD"] = passwords["vcenterPass"]
    # vvf9: pass stored standalone vCenter FQDNs so PowerShell can scan them
    # without re-querying VCF Operations at scan time (required on 9.1 where the native
    # Ops API is skipped; harmless on 9.0 where Get-VcfOpsInventory already covers it).
    # vcf9 is intentionally excluded: VCF Operations returns vCenters that overlap with
    # SDDC Manager-managed workload-domain vCenters and cannot be reliably filtered at
    # discovery time; SDDC Manager scanning already covers them.
    if t == "vvf9":
        vc_fqdns = [str(f).strip() for f in (env.get("vcenterFqdns") or []) if str(f).strip()]
        if vc_fqdns:
            ev["VCENTER_FQDNS"] = json.dumps(vc_fqdns)
    elif t == "vsphere8":
        if passwords.get("vcenterPass"):
            ev["VCENTER_PASSWORD"] = passwords["vcenterPass"]
        if passwords.get("nsxPass"):
            ev["NSX_MANAGER_PASSWORD"] = passwords["nsxPass"]
    return ev


def _configured_hosts(env: dict) -> set:
    """Return the set of lowercase hostnames explicitly configured in env.

    For VCF 9.1 environments the VCF Operations server is excluded because
    Fleet Controller is authoritative there; the native VCF Operations API is
    not called, so its FQDN should never appear in the scan-progress panel.

    For VVF 9 environments an empty set is returned so the progress filter
    passes all items through — standalone vCenter FQDNs are discovered at
    scan time and cannot be known in advance.
    """
    if env.get("type") == "vvf9":
        return set()
    hosts = set()
    for field in ("sddcManagerServer", "vcfOpsServer", "vcfFMServer",
                  "vcenterServer", "nsxManagerServer", "vrslcmServer"):
        if _is_vcf91(env) and field == "vcfOpsServer":
            continue
        h = env.get(field, "").strip().lower()
        if h:
            hosts.add(h)
    return hosts


def _filter_progress_to_configured(items: list, env: dict) -> list:
    """Remove progress items whose hostname is not in the environment's configured servers."""
    configured = _configured_hosts(env)
    if not configured:
        return items
    result = []
    for item in items:
        m = re.search(r'"([^"]+)"', item.get("label", ""))
        host = m.group(1).strip().lower() if m else None
        if host is None or host in configured:
            result.append(item)
    return result


def _run_scan_queue(scan_queue: list, settings: dict, retry_fqdns_map: "dict[str, list[str]] | None" = None) -> None:
    """Run (env, passwords) pairs sequentially; update _scan_state throughout.

    retry_fqdns_map maps env name → list of FQDNs to re-inventory (retry-failed-only mode).
    When None or empty, a full scan is performed for every environment.
    """
    total = len(scan_queue)

    for pos, (env, passwords) in enumerate(scan_queue, 1):
        # Build a display name for this environment: prefer the user-configured name,
        # then fall back to the primary server FQDN so results are always attributable.
        env_name = (
            env.get("name", "")
            or env.get("vcenterServer", "")
            or env.get("sddcManagerServer", "")
            or env.get("type", "")
        )
        env_findings_dir = _resolve_env_findings_dir(settings, env_name)
        env_start  = time.time()
        with _lock:
            _scan_state["envType"]        = env.get("type", "")
            _scan_state["envConfig"]      = dict(env)  # shallow copy; prevents mutation by concurrent settings writes
            _scan_state["currentEnvName"] = env_name
            _scan_state["queuePosition"]  = pos
            _scan_state["queueTotal"]     = total
            _scan_state["envStartTime"]   = env_start

        # Snapshot existing findings files before the scan so we can identify new ones.
        existing_files: set = set()
        if env_findings_dir.is_dir():
            existing_files = {p.name for p in env_findings_dir.glob(_FINDINGS_GLOB)}

        retry_fqdns = (retry_fqdns_map or {}).get(env_name)
        env_vars = _build_env_vars(env, passwords)
        try:
            _ensure_env_findings_dir(env_findings_dir)
            args = _build_ps_args(env, passwords, settings, retry_fqdns)
            proc = subprocess.Popen(
                args,
                env=env_vars,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=str(SCAN_SCRIPT.parent),
                text=True
            )
            with _lock:
                _scan_state["process"] = proc
            try:
                _, stderr = proc.communicate(timeout=_SCAN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr = proc.communicate()
                stderr = f"Scan timed out after {_SCAN_TIMEOUT_SECONDS}s."
            exit_code = proc.returncode
        except Exception as e:
            exit_code = -1
            stderr = str(e)

        env_duration = round(time.time() - env_start)

        # Map any newly created findings files to this environment's display name.
        # env_name is always non-empty here (populated from name / primary server / type above).
        env_failed_endpoints: list = []
        if env_findings_dir.is_dir():
            new_files = {p.name for p in env_findings_dir.glob(_FINDINGS_GLOB)} - existing_files
            with _lock:
                for fname in new_files:
                    _scan_state["fileEnvMap"][fname] = env_name
            # Read failedEndpoints, versionCatalog, and vcfMinorVersion from the most recently
            # written findings file.
            env_vcf_minor: str = ""
            if new_files:
                latest_new = max(
                    (env_findings_dir / fn for fn in new_files),
                    key=lambda p: p.stat().st_mtime
                )
                try:
                    data = json.loads(latest_new.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        env_failed_endpoints = data.get("failedEndpoints") or []
                        catalog = data.get("versionCatalog") or []
                        env_vcf_minor = str(data.get("vcfMinorVersion") or "").strip()
                        if catalog and env_name:
                            with _lock:
                                _scan_state["versionCatalog"][env_name] = catalog
                except Exception:
                    pass

        with _lock:
            if env_name:
                _scan_state["envTimings"].append({
                    "name":            env_name,
                    "durationSeconds": env_duration,
                })
                if env_failed_endpoints:
                    _scan_state["failedEndpoints"][env_name] = env_failed_endpoints
                if env_vcf_minor:
                    _scan_state["vcfMinorVersions"][env_name] = env_vcf_minor
            _scan_state["process"] = None
            if exit_code != 0:
                _scan_state["status"]    = "failed"
                _scan_state["exit_code"] = exit_code
                if stderr:
                    _scan_state["error"] = _sanitize_error_message(stderr.strip())[:500]
                return  # Abort remaining queue on failure.

    session_end = time.time()
    with _lock:
        _scan_state["status"]               = "complete"
        _scan_state["exit_code"]            = 0
        _scan_state["sessionEndTime"]       = session_end
        _scan_state["totalDurationSeconds"] = round(session_end - _scan_state["sessionStartTime"])


def _start_scan(scan_queue: list, settings: dict, retry_fqdns_map: "dict[str, list[str]] | None" = None) -> "dict | None":
    """Validate and start a scan queue. scan_queue is a list of (env, passwords) tuples.

    retry_fqdns_map maps env name → list of FQDNs for retry-failed-only mode.
    """
    with _lock:
        if _scan_state["status"] == "running":
            return {"error": "A scan is already running."}

    for env, _ in scan_queue:
        err = _validate_env_config(env)
        if err:
            name = (
                env.get("name", "")
                or env.get("vcenterServer", "")
                or env.get("sddcManagerServer", "")
                or env.get("type", "?")
            )
            return {"error": f"[{name}] {err}"}

    with _lock:
        _scan_state["status"]               = "running"
        _scan_state["exit_code"]            = None
        _scan_state["error"]                = None
        _scan_state["process"]              = None
        _scan_state["queueTotal"]           = len(scan_queue)
        _scan_state["queuePosition"]        = 0
        _scan_state["sessionStartTime"]     = time.time()
        _scan_state["sessionEndTime"]       = 0.0
        _scan_state["totalDurationSeconds"] = 0
        _scan_state["envTimings"]           = []
        _scan_state["envStartTime"]         = 0.0
        _scan_state["fileEnvMap"]           = {}
        _scan_state["failedEndpoints"]      = {}
        _scan_state["vcfMinorVersions"]     = {}
        _scan_state["versionCatalog"]       = {}

    threading.Thread(target=_run_scan_queue, args=(scan_queue, settings, retry_fqdns_map), daemon=True).start()
    return None


# ---------------------------------------------------------------------------
# Log / findings helpers
# ---------------------------------------------------------------------------

def _find_latest_log(settings: dict) -> "Path | None":
    base = _resolve_logs_dir(settings)
    if not base.is_dir():
        return None
    logs = sorted(base.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return logs[0] if logs else None


def _find_session_findings(settings: dict, session_start: float) -> list:
    """Return findings files created at or after session_start (with a 5 s buffer).

    Searches all per-environment subdirectories under Findings/ so results from
    multi-environment scans are collected regardless of subdirectory layout.
    """
    base   = _resolve_findings_dir(settings)
    cutoff = session_start - 5.0  # 5 s buffer for PS script startup latency.
    if not base.is_dir():
        return []
    files = [p for p in base.rglob(_FINDINGS_GLOB) if p.stat().st_mtime >= cutoff]
    return sorted(files, key=lambda p: p.stat().st_mtime)


def _find_latest_findings(settings: dict) -> "Path | None":
    base = _resolve_findings_dir(settings)
    if not base.is_dir():
        return None
    files = sorted(
        base.rglob(_FINDINGS_GLOB),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files[0] if files else None


# CSV column order and headers — mirrors the UI table column definitions.
_CSV_COLUMNS = [
    ("EnvironmentName",    "Environment"),
    ("instanceName",       "VCF Instance"),
    ("domainName",         "VCF Domain"),
    ("clusterName",        "vSphere Cluster"),
    ("vmsaId",             "VMSA ID"),
    ("VmsaSeverity",       "VMSA Severity"),
    ("CvssRange",          "VMSA CVSS Range"),
    ("severity",           "Component Severity"),
    ("ComponentCvssRange", "Component CVSS Range"),
    ("component",          "Component"),
    ("endpointSubType",    "Sub-Component"),
    ("serverFqdn",         "Endpoint"),
    ("currentVersion",     "Current Version"),
    ("currentBuild",       "Current Build"),
    ("fixedVersions",      "Min. Fixed Version"),
    ("cves",               "CVEs"),
    ("Workaround",         "Workaround"),
    ("Description",        "Description"),
    ("AdditionalDocs",     "Additional Documentation"),
]


def _findings_to_csv(findings: list) -> bytes:
    """Serialise a findings list to UTF-8 CSV bytes with a BOM so Excel auto-detects encoding."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow([header for _, header in _CSV_COLUMNS])
    for row in findings:
        csv_row = []
        for field, _ in _CSV_COLUMNS:
            val = row.get(field, "")
            if isinstance(val, list):
                val = "; ".join(str(v) for v in val)
            csv_row.append(str(val) if val is not None else "")
        writer.writerow(csv_row)
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


# Maps v2.0 camelCase scanner field names to the PascalCase names the UI JavaScript expects.
# JavaScript property access is case-sensitive; PowerShell PSCustomObject serialises all
# field names exactly as declared, so the v2.0 scanner output is pure camelCase.
# Adding aliases here avoids touching the large HTML/JS file while keeping backward
# compatibility with old findings files that already carry PascalCase names.
_CAMEL_TO_PASCAL_ALIASES: dict = {
    "vmsaId":                    "VMSA_ID",
    "component":                 "Component",
    "endpointSubType":           "EndpointSubType",
    "severity":                  "Severity",
    "serverFqdn":                "ServerFqdn",
    "fixedVersions":             "FixedVersions",
    "currentVersion":            "CurrentVersion",
    "currentBuild":              "CurrentBuild",  # raw Fleet build number when it differs from CurrentVersion
    "cves":                      "CVEs",
    "domainName":                "DomainName",
    "clusterName":               "ClusterName",
    "instanceName":              "InstanceName",
    "advisoryUrl":               "VmsaUrl",      # UI reads f.VmsaUrl for the VMSA advisory hyperlink
    "fixedVersionUrl":           "FixedVersionUrl",
    "vulnerableMinimumVersion":  "VulnerableMinimumVersion",
}


def _add_pascal_aliases(finding: dict) -> dict:
    """Add PascalCase aliases for v2.0 camelCase scanner fields.

    The web UI JavaScript expects PascalCase field names; the v2.0 scanner generates
    camelCase.  This function adds aliases so the UI renders correctly for all findings
    files regardless of schema version.  An alias is only added when the PascalCase key
    is not already present, so legacy findings files that already carry PascalCase names
    are passed through unchanged.
    """
    result = dict(finding)
    for camel, pascal in _CAMEL_TO_PASCAL_ALIASES.items():
        if camel in result and pascal not in result:
            result[pascal] = result[camel]
    return result


def _get_advisory_check_state() -> "dict | None":
    """Return the cached advisory check result (thread-safe read)."""
    with _advisory_check_lock:
        return _advisory_check_state


def _set_advisory_check_state(result: dict) -> None:
    """Store an advisory check result into the cache (thread-safe write)."""
    global _advisory_check_state
    with _advisory_check_lock:
        _advisory_check_state = result


def _run_advisory_check_background(settings: dict) -> None:
    """Run the upstream advisory check in a background thread and cache the result.

    Called once at server startup (when checkUpdateDisabled is False).  The UI polls
    GET /advisory/status which returns the cached result immediately — no blocking wait.
    """
    adv_path = _resolve_advisory_path(settings)
    result   = _check_upstream_advisory(adv_path)
    _set_advisory_check_state(result)


# ---------------------------------------------------------------------------
# Module version update check (PSGallery)
# ---------------------------------------------------------------------------

def _get_module_version_from_psd1() -> str:
    """Extract the ModuleVersion value from the deployed VcfPatchScanner.psd1 file.

    Returns 'unknown' when the psd1 file is missing or the field cannot be parsed.
    """
    if not _MODULE_PSD1 or not _MODULE_PSD1.is_file():
        return "unknown"
    try:
        text = _MODULE_PSD1.read_text(encoding="utf-8")
        m    = re.search(r"ModuleVersion\s*=\s*['\"]([^'\"]+)['\"]", text)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def _version_is_newer(candidate: str, baseline: str) -> bool:
    """Return True when candidate version is strictly greater than baseline.

    Compares version tuples element-by-element (e.g. '1.0.0.2' > '1.0.0.1').
    Returns False on any parse error so a malformed PSGallery response never
    incorrectly triggers the update banner.
    """
    try:
        def _to_tuple(v: str) -> tuple:
            return tuple(int(x) for x in v.strip().split("."))
        return _to_tuple(candidate) > _to_tuple(baseline)
    except (ValueError, AttributeError):
        return False


def _fetch_psgallery_module_version() -> dict:
    """Fetch the latest VcfPatchScanner version from the PowerShell Gallery NuGet v2 API.

    Respects a 1-hour in-memory cache (_module_update_cache) so PSGallery is contacted
    at most once per server lifetime.  Returns one of:
      - {"version": "x.y.z", "fetchedAt": datetime}            — success
      - {"error": "...", "errorType": "network" | "parse"}      — failure
    """
    global _module_update_cache
    with _module_update_lock:
        cached = _module_update_cache
    if cached and "version" in cached:
        age = (datetime.now() - cached["fetchedAt"]).total_seconds()
        if age < _MODULE_UPDATE_CACHE_TTL_SECS:
            return cached

    try:
        req = urllib.request.Request(
            _PSGALLERY_API_URL,
            headers={"User-Agent": f"VcfPatchScannerServer/{_SERVER_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=_UPSTREAM_CHECK_TIMEOUT_SECONDS,
                                    context=_UPSTREAM_SSL_CTX) as resp:
            xml_text = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        return {"error": f"Could not reach PowerShell Gallery: {exc.reason}", "errorType": "network"}
    except Exception as exc:
        return {"error": f"PSGallery request failed: {exc}", "errorType": "network"}

    try:
        root = ET.fromstring(xml_text)
        ns   = {
            "d": "http://schemas.microsoft.com/ado/2007/08/dataservices",
            "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",
        }
        version_el = root.find(".//m:properties/d:Version", ns)
        if version_el is None or not (version_el.text or "").strip():
            return {"error": "Version element not found in PSGallery response.", "errorType": "parse"}
        result = {"version": version_el.text.strip(), "fetchedAt": datetime.now()}
    except ET.ParseError as exc:
        return {"error": f"Could not parse PSGallery response: {exc}", "errorType": "parse"}

    with _module_update_lock:
        _module_update_cache = result
    return result


def _run_module_update_check_background() -> None:
    """Fetch the PSGallery module version in a background thread.

    Called once at server startup when disableModuleUpdateReminders is False.
    The UI polls GET /module/update-status which reads _module_update_cache without
    blocking.  _fetch_psgallery_module_version updates _module_update_cache under
    the lock before returning, so no second write is needed here.
    """
    _fetch_psgallery_module_version()


def _run_module_install_background() -> None:
    """Run Update-Module -Name VcfPatchScanner -Force in a background PowerShell subprocess.

    Updates _module_install_state throughout with status 'running', then 'success' or
    'failed'.  The UI polls GET /module/install-status while the install is in progress.
    """
    global _module_install_state
    with _module_install_lock:
        _module_install_state = {"status": "running"}

    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
           "Update-Module -Name VcfPatchScanner -Force -ErrorAction Stop"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=300,   # 5-minute ceiling for a module download
        )
        if proc.returncode == 0:
            with _module_install_lock:
                _module_install_state = {"status": "success"}
        else:
            stderr = (proc.stderr or proc.stdout or "Unknown error.").strip()
            with _module_install_lock:
                _module_install_state = {"status": "failed", "error": _sanitize_error_message(stderr)}
    except subprocess.TimeoutExpired:
        with _module_install_lock:
            _module_install_state = {"status": "failed", "error": "Update timed out after 5 minutes."}
    except FileNotFoundError:
        with _module_install_lock:
            _module_install_state = {
                "status": "failed",
                "error": "PowerShell (pwsh) was not found. Install PowerShell 7+ and retry.",
            }
    except Exception as exc:
        with _module_install_lock:
            _module_install_state = {"status": "failed", "error": str(exc)}


def _etag_path(advisory_path: Path) -> Path:
    """Return the sidecar ETag cache file path for an advisory JSON file."""
    return advisory_path.with_suffix(".json.etag")


def _read_local_etag(advisory_path: Path) -> str | None:
    """Return the cached ETag for the advisory file, or None if absent."""
    p = _etag_path(advisory_path)
    try:
        return p.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _write_local_etag(advisory_path: Path, etag: str) -> None:
    """Persist the ETag alongside the advisory file."""
    _etag_path(advisory_path).write_text(etag, encoding="utf-8")


def _check_upstream_advisory(local_path: Path) -> dict:
    """Compare the local advisory database against the upstream published version.

    Issues a lightweight HEAD request to retrieve the upstream ETag.  The full file
    is never downloaded by this function — it only signals whether an update is
    available.  Returns a dict with:
      - upToDate (bool): True when the local ETag matches the upstream value.
      - updateAvailable (bool): True when the ETags differ (or no local ETag exists).
      - localFileOk (bool): True when the local advisory file was read successfully.
        False means the file is missing or unreadable — the UI will block Run Scan.
      - localEtag (str|None): ETag cached from the last successful download.
      - upstreamEtag (str|None): ETag returned by the upstream HEAD request.
      - localUpdatedAt (str|None): updatedAt from the local JSON file.
      - error (str|None): human-readable error when the check could not complete.

    All network failures are caught; the caller always receives a valid dict.
    """
    local_etag = _read_local_etag(local_path)
    local_updated_at: str | None = None
    upstream_etag: str | None = None
    error: str | None = None

    try:
        raw = json.loads(local_path.read_text(encoding="utf-8"))
        local_updated_at = raw.get("updatedAt") or raw.get("generatedAt")
    except Exception as exc:
        error = f"Could not read local advisory file: {exc}"
        return {
            "upToDate": False,
            "updateAvailable": False,
            "localFileOk": False,
            "localEtag": local_etag,
            "upstreamEtag": None,
            "localUpdatedAt": None,
            "error": error,
        }

    try:
        req = urllib.request.Request(
            _UPSTREAM_ADVISORY_URL,
            method="HEAD",
            headers={"User-Agent": f"VcfPatchScannerServer/{_SERVER_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=_UPSTREAM_CHECK_TIMEOUT_SECONDS, context=_UPSTREAM_SSL_CTX) as resp:
            upstream_etag = resp.headers.get("ETag", "").strip('" ')
    except urllib.error.URLError as exc:
        error = f"Could not reach upstream advisory source: {exc.reason}"
    except Exception as exc:
        error = f"Upstream check failed: {exc}"

    up_to_date = bool(local_etag and upstream_etag and local_etag == upstream_etag)
    update_available = bool(upstream_etag and not up_to_date)

    return {
        "upToDate": up_to_date,
        "updateAvailable": update_available,
        "localFileOk": True,
        "localEtag": local_etag,
        "upstreamEtag": upstream_etag,
        "localUpdatedAt": local_updated_at,
        "error": error,
    }


def _verify_sha256(body: bytes, local_path: Path) -> "str | None":
    """Fetch the upstream SHA-256 checksum and verify body matches it.

    Downloads <advisory_url>.sha256sum (a plain hex-digest text file published alongside
    the advisory JSON by Convert-BroadcomAdvisoriesToSchema.ps1). Returns None on success,
    or an error string if the checksum cannot be fetched or does not match.
    """
    checksum_url = _UPSTREAM_ADVISORY_URL + ".sha256sum"
    try:
        req = urllib.request.Request(
            checksum_url,
            headers={"User-Agent": f"VcfPatchScannerServer/{_SERVER_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=_UPSTREAM_CHECK_TIMEOUT_SECONDS, context=_UPSTREAM_SSL_CTX) as resp:
            raw = resp.read(256).decode("ascii", errors="replace").strip().lower()
            # Accept both bare hex (64 chars) and standard sha256sum format "<hash>  <filename>".
            m = re.search(r"[0-9a-f]{64}", raw)
            expected_hex = m.group(0) if m else ""
    except Exception as exc:
        return f"Could not fetch checksum file: {exc}"

    if not expected_hex:
        return f"Upstream checksum file did not contain a valid SHA-256 hex digest"

    actual_hex = hashlib.sha256(body).hexdigest()
    if actual_hex != expected_hex:
        return f"SHA-256 mismatch — upstream: {expected_hex}, downloaded: {actual_hex}"
    return None


def _download_advisory_if_changed(local_path: Path) -> dict:
    """Download the upstream advisory file only when the ETag has changed.

    Flow:
      1. HEAD request → read upstream ETag.
      2. Compare against cached local ETag — skip download when identical.
      3. GET the full file only when ETags differ.
      4. Parse and validate schema (major version must match, advisories non-empty).
      5. Verify SHA-256 checksum against the companion .sha256sum file on GitHub.
      6. Back up the existing file to <path>.old.
      7. Atomic write: temp file → rename → overwrite local copy.
      8. Persist the new ETag to the sidecar cache file.
      9. Mirror to VcfPatchScanner/Data/ (the module data directory).

    Returns a dict with:
      - downloaded (bool): True when the file was actually replaced.
      - skipped (bool): True when ETags matched — no download needed.
      - upstreamEtag (str|None)
      - localUpdatedAt (str|None): updatedAt from the newly-written file.
      - error (str|None): human-readable error; None on success.
    """
    local_etag = _read_local_etag(local_path)
    upstream_etag: str | None = None

    # --- Step 1: HEAD to get upstream ETag cheaply ---
    try:
        req = urllib.request.Request(
            _UPSTREAM_ADVISORY_URL,
            method="HEAD",
            headers={"User-Agent": f"VcfPatchScannerServer/{_SERVER_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=_UPSTREAM_CHECK_TIMEOUT_SECONDS, context=_UPSTREAM_SSL_CTX) as resp:
            upstream_etag = resp.headers.get("ETag", "").strip('" ')
    except urllib.error.URLError as exc:
        return {"downloaded": False, "skipped": False, "upstreamEtag": None,
                "localUpdatedAt": None, "error": f"Upstream unreachable: {exc.reason}"}
    except Exception as exc:
        return {"downloaded": False, "skipped": False, "upstreamEtag": None,
                "localUpdatedAt": None, "error": f"HEAD request failed: {exc}"}

    # --- Step 2: ETag match — nothing to do ---
    if local_etag and upstream_etag and local_etag == upstream_etag:
        local_updated_at = None
        try:
            raw = json.loads(local_path.read_text(encoding="utf-8"))
            local_updated_at = raw.get("updatedAt") or raw.get("generatedAt")
        except Exception:
            pass
        return {"downloaded": False, "skipped": True, "upstreamEtag": upstream_etag,
                "localUpdatedAt": local_updated_at, "error": None}

    # --- Step 3: GET the full file ---
    try:
        req = urllib.request.Request(
            _UPSTREAM_ADVISORY_URL,
            headers={"User-Agent": f"VcfPatchScannerServer/{_SERVER_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=_UPSTREAM_DOWNLOAD_TIMEOUT_SECONDS, context=_UPSTREAM_SSL_CTX) as resp:
            body = resp.read()
            # Re-read ETag from the GET response (may differ from HEAD under caching).
            get_etag = resp.headers.get("ETag", "").strip('" ') or upstream_etag
    except Exception as exc:
        return {"downloaded": False, "skipped": False, "upstreamEtag": upstream_etag,
                "localUpdatedAt": None, "error": f"Download failed: {exc}"}

    # --- Step 4: Parse and validate schema ---
    try:
        raw = json.loads(body.decode("utf-8"))
    except Exception as exc:
        return {"downloaded": False, "skipped": False, "upstreamEtag": upstream_etag,
                "localUpdatedAt": None, "error": f"Upstream file is not valid JSON: {exc}"}

    schema_version = raw.get("schemaVersion") or raw.get("SchemaVersion") or ""
    if not schema_version.startswith("2."):
        return {"downloaded": False, "skipped": False, "upstreamEtag": upstream_etag,
                "localUpdatedAt": None,
                "error": f"Upstream schema version '{schema_version}' is incompatible (expected 2.x)."}

    advisories = raw.get("advisories") or raw.get("Advisories")
    if not isinstance(advisories, list) or len(advisories) == 0:
        return {"downloaded": False, "skipped": False, "upstreamEtag": upstream_etag,
                "localUpdatedAt": None, "error": "Upstream file contains no advisories."}

    local_updated_at = raw.get("updatedAt") or raw.get("generatedAt")

    # --- Step 5: SHA-256 verification ---
    checksum_error = _verify_sha256(body, local_path)
    if checksum_error:
        return {"downloaded": False, "skipped": False, "upstreamEtag": upstream_etag,
                "localUpdatedAt": None, "error": f"Integrity check failed: {checksum_error}"}

    # --- Step 6: Back up the existing file ---
    if local_path.exists():
        try:
            shutil.copy2(local_path, local_path.with_suffix(".json.old"))
        except Exception:
            pass  # Backup failure is non-fatal; proceed with the update.

    # --- Step 7: Atomic write (temp → rename) ---
    tmp_path = local_path.with_name(f"{local_path.stem}.{uuid.uuid4().hex}.tmp")
    try:
        tmp_path.write_bytes(body)
        tmp_path.replace(local_path)
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        return {"downloaded": False, "skipped": False, "upstreamEtag": upstream_etag,
                "localUpdatedAt": None, "error": f"Could not write advisory file: {exc}"}

    # --- Step 8: Persist the new ETag ---
    try:
        _write_local_etag(local_path, get_etag)
    except Exception:
        pass  # ETag cache failure is non-fatal — next check will re-download once.

    # --- Step 9: Mirror to the module Data directory ---
    module_data = Path(__file__).parent.parent / "Data" / local_path.name
    if module_data != local_path:
        try:
            module_data.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(local_path, module_data)
        except Exception:
            pass  # Mirror failure is non-fatal; local copy is valid.

    return {"downloaded": True, "skipped": False, "upstreamEtag": get_etag,
            "localUpdatedAt": local_updated_at, "error": None}


def _enrich_findings(findings: list, adv_path: Path) -> list:
    """Adds Description, Workaround, CvssRange, ComponentCvssRange from the advisory database.

    Findings that have no matching VMSA_ID in the database are returned unchanged.
    Missing or unreadable advisory file is silently ignored — the table still renders without
    the enrichment columns.
    """
    try:
        raw = json.loads(adv_path.read_text(encoding="utf-8"))
        # Support both v2.0 camelCase and v1.0 PascalCase advisory array keys.
        if isinstance(raw, dict):
            advisories = raw.get("advisories") or raw.get("Advisories") or raw
        else:
            advisories = raw
    except Exception:
        return findings

    adv_map: dict = {}
    for adv in (advisories if isinstance(advisories, list) else []):
        vmsa_id = adv.get("vmsaId") or adv.get("VMSA_ID")
        if vmsa_id:
            adv_map[vmsa_id] = adv

    enriched: list = []
    for finding in findings:
        vmsa_id = finding.get("vmsaId") or finding.get("VMSA_ID")
        if not vmsa_id or vmsa_id not in adv_map:
            enriched.append(finding)
            continue
        adv = adv_map[vmsa_id]
        component_name = finding.get("component") or finding.get("Component") or finding.get("EndpointSubType") or ""
        component_cvss = ""
        workaround = ""
        additional_docs = ""
        for comp in (adv.get("impactedComponents") or adv.get("ImpactedComponents") or []):
            comp_name = comp.get("component") or comp.get("Component") or ""
            if comp_name == component_name:
                component_cvss  = comp.get("cvssRange") or comp.get("CVSSv3_Range") or ""
                raw_workaround  = comp.get("workaround") or comp.get("Workaround") or ""
                raw_docs        = comp.get("additionalDocs") or comp.get("AdditionalDocumentation") or ""
                workaround      = "" if (raw_workaround is None or str(raw_workaround).strip().lower() in ("none", "n/a")) else str(raw_workaround)
                additional_docs = "" if (raw_docs is None or str(raw_docs).strip().lower() in ("none", "n/a")) else str(raw_docs)
                break
        enriched.append({
            **finding,
            "Description":        adv.get("description") or adv.get("Description") or "",
            "Workaround":         workaround,
            "VmsaSeverity":       adv.get("severity") or adv.get("Severity") or "",
            "CvssRange":          adv.get("cvssRange") or adv.get("CVSSv3_Range") or finding.get("CvssRange") or "",
            "ComponentCvssRange": component_cvss,
            "AdditionalDocs":     additional_docs,
        })
    return enriched


def _tail_log(log_path: Path, n: int = 200) -> list:
    try:
        text  = log_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        return lines[-n:] if len(lines) > n else lines
    except Exception:
        return []


def _tail_log_by_session_time(log_path: Path, session_start: float, n: int = 200) -> list:
    """Return log lines from the current session (created at or after session_start).

    Parses timestamps from log lines in format: [yyyy-MM-dd HH:mm:ss.fff] or
    [yyyy-MM-dd HH:mm:ss] (milliseconds optional for backwards compatibility with
    older log files written before the .fff format was adopted).
    Only includes lines with timestamps >= session_start - 5s buffer for script startup.
    """
    try:
        text  = log_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        if session_start <= 0:
            # No session time available; fall back to last n lines
            return lines[-n:] if len(lines) > n else lines

        # Parse timestamps and filter by session time (5s buffer for PS startup latency).
        # Milliseconds are optional: newer logs use HH:mm:ss.fff; older logs use HH:mm:ss.
        cutoff = session_start - 5.0
        filtered = []
        timestamp_pattern = re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)\]')

        for line in lines:
            match = timestamp_pattern.match(line)
            if match:
                try:
                    ts_str = match.group(1)
                    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in ts_str else "%Y-%m-%d %H:%M:%S"
                    ts = datetime.strptime(ts_str, fmt).timestamp()
                    if ts >= cutoff:
                        filtered.append(line)
                except (ValueError, TypeError):
                    # Timestamp parse error; include the line rather than silently drop it.
                    filtered.append(line)
            # Lines without a recognised timestamp (continuation lines, stack traces) are
            # included only when there are already filtered lines — they belong to the last
            # timestamped entry within the session window.
            elif filtered:
                filtered.append(line)

        return filtered[-n:] if len(filtered) > n else filtered
    except Exception:
        return []


_PROGRESS_ELLIPSIS = r"(?:\u2026|\.\.\.)"
# Allow optional suffix between the hostname quote and the ellipsis (e.g. ' as "admin@vsp.local"')
# so that Fleet LCM log lines such as:
#   Connecting to VSP Fleet LCM "host" as "user"... succeeded.
# are correctly promoted to "done".
_RE_PROGRESS_COLLECT  = re.compile(r"Collecting inventory from\s+(\S[^\x22]*)\x22([^\x22]+)\x22")
_RE_PROGRESS_SUCCESS  = re.compile(rf"Connecting to\s+([^\x22]*)\x22([^\x22]+)\x22.*?{_PROGRESS_ELLIPSIS}\s*succeeded", re.IGNORECASE)
_RE_PROGRESS_FAILED   = re.compile(rf"Connecting to\s+([^\x22]*)\x22([^\x22]+)\x22.*?{_PROGRESS_ELLIPSIS}\s*failed",    re.IGNORECASE)
_RE_PROGRESS_CONN_RAW = re.compile(r"Connecting to\s+([^\x22]*)\x22([^\x22]+)\x22",                                     re.IGNORECASE)


def _parse_scan_progress(lines: list) -> list:
    """Parse log lines into structured endpoint-progress items."""
    items: dict = {}

    for line in lines:
        if m := _RE_PROGRESS_SUCCESS.search(line):
            key = f"{m.group(1).strip()} {m.group(2).strip()}"
            items[key] = {"label": f"{m.group(1).strip()} \"{m.group(2).strip()}\"", "status": "done"}
            continue
        if m := _RE_PROGRESS_FAILED.search(line):
            key = f"{m.group(1).strip()} {m.group(2).strip()}"
            items[key] = {"label": f"{m.group(1).strip()} \"{m.group(2).strip()}\"", "status": "failed"}
            continue
        if m := _RE_PROGRESS_COLLECT.search(line):
            key = f"{m.group(1).strip()} {m.group(2).strip()}"
            if key not in items:
                items[key] = {"label": f"{m.group(1).strip()} \"{m.group(2).strip()}\"", "status": "pending"}
            continue
        if m := _RE_PROGRESS_CONN_RAW.search(line):
            key = f"{m.group(1).strip()} {m.group(2).strip()}"
            if key not in items:
                items[key] = {"label": f"{m.group(1).strip()} \"{m.group(2).strip()}\"", "status": "pending"}

    return list(items.values())

# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    timeout = _HTTP_HANDLER_TIMEOUT

    def handle_error(self, request, client_address):
        """Suppress client-initiated disconnects; log everything else."""
        exc_type, _, _ = sys.exc_info()
        if exc_type is not None and issubclass(exc_type, _CLIENT_DISCONNECT_ERRORS):
            # Client closed the TCP connection before or during response send.
            # Normal for keep-alive connections, page refreshes, and Windows
            # TCP stack aborts (WinError 10053/10054).  Nothing actionable here.
            return
        super().handle_error(request, client_address)

    def log_message(self, fmt, *args):
        pass  # Suppress default access log.

    def log_error(self, fmt, *args) -> None:
        """Route handler errors to the server log with appropriate severity.

        BaseHTTPRequestHandler emits "Request timed out: …" when the per-socket
        idle timeout fires on a browser keep-alive connection that sent no further
        request within _HTTP_HANDLER_TIMEOUT seconds.  This is normal browser
        behaviour — demote to DEBUG so it does not appear as spurious ERROR noise.
        All other handler errors are logged at ERROR with the client address and,
        when available, the request path for context.
        """
        msg = (fmt % args) if args else fmt
        client = f"{self.client_address[0]}:{self.client_address[1]}" if self.client_address else "unknown"
        path   = getattr(self, "path", None)
        if "request timed out" in msg.lower():
            logger.debug("Keep-alive idle timeout from %s (normal browser behaviour)", client)
        elif path:
            logger.error("Handler error [%s %s] from %s: %s", getattr(self, "command", "?"), path, client, msg)
        else:
            logger.error("Handler error from %s: %s", client, msg)
    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        if not self._check_origin():
            self.send_response(403)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "3600")
        self._send_security_headers()
        self.end_headers()

    def _check_origin(self) -> bool:
        """Returns True when the request is safe to process.

        Non-browser clients (curl, PowerShell Invoke-RestMethod) send no Origin
        header and are always allowed. Browser requests include an Origin; we
        only permit origins whose hostname is in ALLOWED_ORIGIN_HOSTS.
        Origin: null is always rejected — it signals a sandboxed or file://
        origin, neither of which should reach this server.
        """
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        if origin == "null":
            return False
        try:
            host = (urlparse(origin).hostname or "").lower()
            return host in ALLOWED_ORIGIN_HOSTS
        except Exception:
            return False

    def _send_security_headers(self):
        """Sends common security headers on every response."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
        )

    def _send_forbidden(self) -> None:
        """Send a 403 JSON response with Content-Length.  Used by every origin-check failure path."""
        body = b'{"error": "Forbidden"}'
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        try:
            self.end_headers()
            self.wfile.write(body)
        except _CLIENT_DISCONNECT_ERRORS:
            pass

    def _json(self, data, code: int = 200) -> None:
        if not self._check_origin():
            self._send_forbidden()
            return
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self._send_security_headers()
        try:
            self.end_headers()
            self.wfile.write(body)
        except _CLIENT_DISCONNECT_ERRORS:
            # Client disconnected before or during the response write.  The
            # exception is swallowed here so callers do not attempt a second
            # write on an already-dead socket (which would produce a cascading
            # double traceback, as seen with WinError 10053 on Windows).
            pass

    def _html(self, body: str, code: int = 200) -> None:
        if not self._check_origin():
            self._send_forbidden()
            return
        enc = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self._send_security_headers()
        try:
            self.end_headers()
            self.wfile.write(enc)
        except _CLIENT_DISCONNECT_ERRORS:
            pass

    _MAX_BODY_BYTES = 5 * 1024 * 1024

    def _read_body(self) -> "bytes | None":
        """Read the request body.

        Returns None and sends a 413 response when the declared Content-Length
        exceeds the allowed maximum, so callers must check for None before use.

        Note: http.server does not implement chunked Transfer-Encoding.  A request
        without Content-Length (or with Content-Length: 0) produces an empty read,
        not a blocked stream.  The 30-second per-socket timeout (_HTTP_HANDLER_TIMEOUT)
        bounds any slow-drain scenario.  The 5 MB limit enforced here covers all
        well-formed Content-Length requests, which is the only request type the UI sends.
        """
        length = max(0, int(self.headers.get("Content-Length", 0)))
        if length > self._MAX_BODY_BYTES:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(b'{"error": "Request body too large."}')
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"

        if path == "/":
            # Explicit origin check required — success path writes raw HTML bytes, not via _json().
            if not self._check_origin():
                self._send_forbidden()
                return
            body = _load_html_template()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(body)

        elif path == "/settings":
            self._json(_load_settings())

        elif path == "/scan/status":
            with _lock:
                s = _scan_state.copy()
            session_start = s.get("sessionStartTime", 0.0)
            session_end   = s.get("sessionEndTime", 0.0)
            status        = s["status"]
            if status == "running" and session_start:
                elapsed = round(time.time() - session_start)
            elif status in ("complete", "failed") and session_start:
                elapsed = s.get("totalDurationSeconds") or round((session_end or time.time()) - session_start)
            else:
                elapsed = 0
            resp = {
                "status":               status,
                "exitCode":             s["exit_code"],
                "queuePosition":        s.get("queuePosition", 0),
                "queueTotal":           s.get("queueTotal", 0),
                "currentEnvName":       s.get("currentEnvName", ""),
                "elapsedSeconds":       elapsed,
                "envTimings":           s.get("envTimings", []),
                "totalDurationSeconds": s.get("totalDurationSeconds", 0),
                "failedEndpoints":      s.get("failedEndpoints", {}),
                "vcfMinorVersions":     s.get("vcfMinorVersions", {}),
                "versionCatalog":       s.get("versionCatalog", {}),
            }
            if s.get("error"):
                resp["error"] = s["error"]
            self._json(resp)

        elif path == "/scan/log":
            settings = _load_settings()
            lp = _find_latest_log(settings)
            with _lock:
                session_start = _scan_state.get("sessionStartTime", 0.0)
            lines = _tail_log_by_session_time(lp, session_start) if lp else []
            self._json({"lines": lines})

        elif path == "/discovery/log":
            settings = _load_settings()
            lp = _find_latest_log(settings)
            disc_start = _discovery_start_time
            lines = _tail_log_by_session_time(lp, disc_start) if lp else []
            self._json({"lines": lines})

        elif path == "/scan/progress":
            settings = _load_settings()
            lp = _find_latest_log(settings)
            items = _parse_scan_progress(_tail_log(lp, 500)) if lp else []
            with _lock:
                env_type   = _scan_state.get("envType", "")
                env_config = _scan_state.get("envConfig", {})
            # For vSphere/VVF, SDDC Manager is never a configured endpoint.
            if env_type in ("vsphere8", "vvf9"):
                items = [i for i in items if "sddc manager" not in i.get("label", "").lower()]
            # Filter out any dynamically-discovered hosts not present in the env config.
            if env_config:
                items = _filter_progress_to_configured(items, env_config)
            self._json({"items": items})

        elif path == "/scan/validate-progress":
            with _validate_lock:
                state = dict(_validate_state)
            self._json(state)

        elif path == "/scan/findings":
            settings = _load_settings()
            with _lock:
                scan_status   = _scan_state.get("status", "idle")
                session_start = _scan_state.get("sessionStartTime", 0.0)
                file_env_map  = dict(_scan_state.get("fileEnvMap", {}))

            # Guard: do not return stale findings from a previous server session.
            # When status is "idle" no scan has run since the server started; returning
            # an old file would show results from a completely different environment type.
            # The same applies when the current session has not produced any findings yet
            # (e.g. scan errored before writing output or credentials were rejected by the
            # server at scan time) — fall back to nothing rather than an unrelated old file.
            if scan_status == "idle":
                self._json([])
                return

            fps = (_find_session_findings(settings, session_start)
                   if session_start > 0 else [])
            if not fps:
                self._json([])
                return
            combined: list = []
            seen: set = set()
            for fp in fps:
                try:
                    data = json.loads(fp.read_text(encoding="utf-8"))
                    items = data if isinstance(data, list) else data.get("findings", [])
                    env_name = file_env_map.get(fp.name, "")
                    for item in items:
                        # Deduplicate by vmsaId + component + vulnerableMinimumVersion + serverFqdn.
                        # Support both v2.0 camelCase and legacy PascalCase field names from old findings files.
                        vmsa_id = item.get("vmsaId") or item.get("VMSA_ID") or item.get("VmsaId") or ""
                        component = item.get("component") or item.get("Component") or ""
                        min_version = item.get("vulnerableMinimumVersion") or item.get("VulnerableMinimumVersion") or ""
                        server_fqdn = (item.get("serverFqdn") or item.get("ServerFqdn") or item.get("EndpointFqdn") or item.get("Endpoint") or "").lower()
                        key = (vmsa_id, component, min_version, server_fqdn)
                        if key not in seen:
                            seen.add(key)
                            # Inject environment name when not already present in the finding.
                            if env_name and not item.get("EnvironmentName"):
                                item["EnvironmentName"] = env_name
                            combined.append(item)
                except Exception:
                    pass
            combined = _enrich_findings(combined, _resolve_advisory_path(settings))
            combined = [_add_pascal_aliases(f) for f in combined]
            self._json(combined if combined else {"error": "No findings in session."})

        elif path == "/scan/download":
            # Explicit origin check required — success path writes raw binary bytes, not via _json().
            if not self._check_origin():
                self._send_forbidden()
                return
            settings = _load_settings()
            with _lock:
                dl_scan_status   = _scan_state.get("status", "idle")
                dl_session_start = _scan_state.get("sessionStartTime", 0.0)
            if dl_scan_status == "idle":
                self._json({"error": "No findings file."}, 404)
                return
            fps_dl = (_find_session_findings(settings, dl_session_start)
                      if dl_session_start > 0 else [])
            fp = max(fps_dl, key=lambda p: p.stat().st_mtime) if fps_dl else None
            if fp is None:
                self._json({"error": "No findings for current session."}, 404)
                return
            try:
                body = fp.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                safe_name = fp.name.replace('"', '_').replace('\\', '_')
                self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
                self.send_header("Content-Length", str(len(body)))
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json({"error": str(exc)}, 500)

        elif path == "/scan/download/csv":
            # Explicit origin check required — success path writes raw CSV bytes, not via _json().
            if not self._check_origin():
                self._send_forbidden()
                return
            settings = _load_settings()
            # Mirror /scan/findings: collect all session files so multi-environment scans
            # export every environment's findings and the EnvironmentName column is populated.
            with _lock:
                scan_status   = _scan_state.get("status", "idle")
                session_start = _scan_state.get("sessionStartTime", 0.0)
                file_env_map  = dict(_scan_state.get("fileEnvMap", {}))
            if scan_status == "idle":
                self._json({"error": "No findings file."}, 404)
                return
            fps = (_find_session_findings(settings, session_start)
                   if session_start > 0 else [])
            if not fps:
                self._json({"error": "No findings for current session."}, 404)
                return
            latest_fp = max(fps, key=lambda p: p.stat().st_mtime)
            try:
                combined: list = []
                seen: set = set()
                for fp in fps:
                    data = json.loads(fp.read_text(encoding="utf-8"))
                    items = data if isinstance(data, list) else data.get("findings", [])
                    env_name = file_env_map.get(fp.name, "")
                    for item in items:
                        # Mirror /scan/findings: support v2.0 camelCase and legacy PascalCase field names.
                        vmsa_id     = item.get("vmsaId") or item.get("VMSA_ID") or item.get("VmsaId") or ""
                        component   = item.get("component") or item.get("Component") or ""
                        min_version = item.get("vulnerableMinimumVersion") or item.get("VulnerableMinimumVersion") or ""
                        server_fqdn = (item.get("serverFqdn") or item.get("ServerFqdn") or item.get("EndpointFqdn") or item.get("Endpoint") or "").lower()
                        key = (vmsa_id, component, min_version, server_fqdn)
                        if key not in seen:
                            seen.add(key)
                            if env_name and not item.get("EnvironmentName"):
                                item["EnvironmentName"] = env_name
                            combined.append(item)
                combined = _enrich_findings(combined, _resolve_advisory_path(settings))
                combined = [_add_pascal_aliases(f) for f in combined]
                body = _findings_to_csv(combined)
                csv_name = (latest_fp.stem + ".csv").replace('"', '_').replace('\\', '_')
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{csv_name}"')
                self.send_header("Content-Length", str(len(body)))
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json({"error": str(exc)}, 500)

        elif path == "/advisory/status":
            settings = _load_settings()
            if settings.get("checkUpdateDisabled", False):
                # Update checks disabled — return local advisory info only.
                adv_path = _resolve_advisory_path(settings)
                local_updated_at = None
                local_file_ok = False
                local_file_error: str | None = None
                try:
                    raw = json.loads(adv_path.read_text(encoding="utf-8"))
                    local_updated_at = raw.get("updatedAt") or raw.get("generatedAt")
                    local_file_ok = True
                except Exception as exc:
                    local_file_error = f"Could not read local advisory file: {exc}"
                self._json({
                    "upToDate": local_file_ok,
                    "updateAvailable": False,
                    "localFileOk": local_file_ok,
                    "localEtag": _read_local_etag(adv_path),
                    "upstreamEtag": None,
                    "localUpdatedAt": local_updated_at,
                    "checkDisabled": True,
                    "error": local_file_error,
                })
                return
            # Return the cached startup check result.  When the background thread has not
            # completed yet, return a lightweight "checking" sentinel so the UI can display
            # a spinner immediately rather than blocking this handler for up to 10 seconds.
            cached = _get_advisory_check_state()
            if cached is None:
                self._json({
                    "upToDate": False, "updateAvailable": False,
                    "localFileOk": None,
                    "localEtag": None, "upstreamEtag": None, "localUpdatedAt": None,
                    "checking": True, "checkDisabled": False,
                    "promptShown": settings.get("updateCheckPromptShown", False),
                    "error": None,
                })
                return
            self._json(dict(cached, checkDisabled=False, promptShown=settings.get("updateCheckPromptShown", False)))

        elif path == "/version":
            self._json({"version": _SERVER_VERSION})

        elif path == "/module/update-status":
            settings       = _load_settings()
            current_ver    = _get_module_version_from_psd1()
            if settings.get("disableModuleUpdateReminders", False):
                self._json({
                    "checkDisabled": True,
                    "currentVersion": current_ver,
                    "galleryUrl": _MODULE_GALLERY_PAGE_URL,
                })
                return
            with _module_update_lock:
                cached = _module_update_cache
            if cached is None:
                self._json({"checking": True, "currentVersion": current_ver})
                return
            if "error" in cached:
                self._json({
                    "currentVersion": current_ver,
                    "error": cached["error"],
                    "errorType": cached.get("errorType", "unknown"),
                    "galleryUrl": _MODULE_GALLERY_PAGE_URL,
                })
                return
            latest = cached["version"]
            self._json({
                "currentVersion": current_ver,
                "latestVersion":  latest,
                "updateAvailable": _version_is_newer(latest, current_ver),
                "galleryUrl": _MODULE_GALLERY_PAGE_URL,
            })

        elif path == "/module/install-status":
            with _module_install_lock:
                state = _module_install_state.copy()
            self._json(state)

        elif path == "/scan/collect-logs":
            # Explicit origin check required — success path writes a ZIP archive, not via _json().
            if not self._check_origin():
                self._send_forbidden()
                return
            settings = _load_settings()
            log_dir  = _resolve_logs_dir(settings)
            if not log_dir.is_dir():
                self._json({"error": f"Log directory not found: {log_dir}"}, 404)
                return
            log_files = sorted(log_dir.glob("*.log"), key=lambda p: p.stat().st_mtime)
            if not log_files:
                self._json({"error": "No log files found."}, 404)
                return
            try:
                stamp    = datetime.now().strftime("%Y%m%d-%H%M%S")
                zip_name = f"VcfPatchScanner-logs-{stamp}.zip"
                buf      = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for lf in log_files:
                        zf.write(lf, lf.name)
                body = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{zip_name}"')
                self.send_header("Content-Length", str(len(body)))
                self._send_security_headers()
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json({"error": str(exc)}, 500)

        elif path == "/probe/tcp":
            host = parse_qs(parsed.query).get("host", [""])[0].strip()
            if not host or not re.fullmatch(r"[a-zA-Z0-9.\-_:\[\]]+", host):
                self._json({"ok": False, "error": "Invalid or missing host parameter."}, 400)
                return
            # Parse host and port.  Three forms are accepted:
            #   - "hostname" or "1.2.3.4"     → probe port 443
            #   - "hostname:8443"              → probe the explicit port
            #   - "[::1]:8443" or "[::1]"      → IPv6 (bracketed), optional port
            # A bare IPv6 address like "::1" (multiple colons, no brackets) has no port
            # component — treat the whole string as the hostname and probe port 443.
            # Exactly one colon unambiguously means "host:port"; everything else defaults.
            if host.startswith("["):
                # Bracketed IPv6 — "[::1]" or "[::1]:8443"
                bracket_close = host.rfind("]")
                probe_host = host[1:bracket_close] if bracket_close > 0 else host.strip("[]")
                port_suffix = host[bracket_close + 1:] if bracket_close > 0 else ""
                if port_suffix.startswith(":"):
                    try:
                        probe_port = int(port_suffix[1:])
                        if not (1 <= probe_port <= 65535):
                            raise ValueError
                    except ValueError:
                        self._json({"ok": False, "error": "Invalid port in host parameter."}, 400)
                        return
                else:
                    probe_port = 443
            elif host.count(":") == 1:
                # Exactly one colon: "hostname:port" or "1.2.3.4:port"
                parts = host.split(":", 1)
                try:
                    probe_port = int(parts[1])
                    if not (1 <= probe_port <= 65535):
                        raise ValueError
                    probe_host = parts[0]
                except ValueError:
                    self._json({"ok": False, "error": "Invalid port in host parameter."}, 400)
                    return
            else:
                # No colon, or multiple colons without brackets (bare IPv6 like "::1")
                probe_host = host
                probe_port = 443
            try:
                sock = socket.create_connection((probe_host, probe_port), timeout=_TCP_PROBE_TIMEOUT_SECONDS)
                sock.close()
                self._json({"ok": True, "host": probe_host, "port": probe_port})
            except OSError:
                self._json({"ok": False, "host": probe_host, "port": probe_port,
                            "error": f"Port {probe_port} unreachable."})

        else:
            self._json({"error": "Not found."}, 404)

    def do_POST(self) -> None:
        global _discovery_start_time
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        raw    = self._read_body()
        if raw is None:
            return  # 413 already sent by _read_body

        if path == "/settings":
            try:
                data = json.loads(raw) if raw else {}
            except Exception as e:
                logger.debug(f"Bad JSON in POST /settings: {e}")
                self._json({"error": "Invalid JSON."}, 400)
                return
            validation_error = _validate_settings(data)
            if validation_error:
                self._json({"error": validation_error}, 400)
                return
            _save_settings(data)
            self._json({"ok": True})

        elif path == "/scan/validate":
            try:
                body = json.loads(raw) if raw else {}
            except Exception as e:
                logger.debug(f"Bad JSON in POST /scan/validate: {e}")
                self._json({"error": "Invalid JSON."}, 400)
                return

            # Accept queue: [{env, passwords}, ...] OR legacy single-env {env/envIndex, passwords}.
            queue_items = body.get("queue")
            if queue_items and isinstance(queue_items, list):
                validate_list = [(item["env"], item.get("passwords", {}))
                                 for item in queue_items if "env" in item]
            else:
                settings  = _load_settings()
                envs      = settings.get("environments", [])
                env_data  = body.get("env")
                idx       = body.get("envIndex", -1)
                passwords = body.get("passwords", {})
                if env_data and isinstance(env_data, dict):
                    env = env_data
                elif isinstance(idx, int) and 0 <= idx < len(envs):
                    env = envs[idx]
                else:
                    self._json({"error": "Invalid environment."}, 400)
                    return
                validate_list = [(env, passwords)]

            settings = _load_settings()
            conn_timeout = settings.get("connectionTimeoutSeconds", 30)
            global _validate_state, _validate_stop_requested
            # Guard: reject a new validation request when one is already in progress.
            # Mirrors the 409 guard on POST /scan/start to prevent concurrent threads
            # from writing _validate_state simultaneously.
            with _validate_lock:
                if not _validate_state.get("done", True):
                    self._json({"error": "A validation is already running."}, 409)
                    return
                _validate_stop_requested = False
                _validate_state = {"items": [], "done": False}
            # Record session start so /scan/log returns validation-phase log entries even when
            # the scan never starts (e.g. auth failure). _start_scan overwrites this with the
            # scan-start time when the scan proceeds; the 5 s buffer in _tail_log_by_session_time
            # keeps validation entries visible after the handoff.
            with _lock:
                _scan_state["sessionStartTime"] = time.time()
            threading.Thread(
                target=_run_all_validation_bg, args=(validate_list, conn_timeout), daemon=True
            ).start()
            self._json({"ok": True})

        elif path == "/scan/start":
            try:
                body = json.loads(raw) if raw else {}
            except Exception as e:
                logger.debug(f"Bad JSON in POST /scan/start: {e}")
                self._json({"error": "Invalid JSON."}, 400)
                return

            settings = _load_settings()
            envs     = settings.get("environments", [])

            # Accept queue: [{env, passwords}, ...] OR legacy single-env payload.
            queue_items = body.get("queue")
            if queue_items and isinstance(queue_items, list):
                scan_queue = [(item["env"], item.get("passwords", {}))
                              for item in queue_items if "env" in item]
            else:
                env_data  = body.get("env")
                idx       = body.get("envIndex", -1)
                passwords = body.get("passwords", {})
                if env_data and isinstance(env_data, dict):
                    env = env_data
                elif isinstance(idx, int) and 0 <= idx < len(envs):
                    env = envs[idx]
                else:
                    self._json({"error": "Invalid environment."}, 400)
                    return
                scan_queue = [(env, passwords)]

            # Build retry-failed-only map when requested.
            retry_fqdns_map: "dict[str, list[str]] | None" = None
            if body.get("retryFailedOnly"):
                with _lock:
                    prev_failed = dict(_scan_state.get("failedEndpoints", {}))
                if prev_failed:
                    retry_fqdns_map = {
                        env_name: [ep["Fqdn"] for ep in eps if ep.get("Fqdn")]
                        for env_name, eps in prev_failed.items()
                        if eps
                    }

            err = _start_scan(scan_queue, settings, retry_fqdns_map)
            if err:
                self._json(err, 409)
            else:
                self._json({"ok": True})

        elif path == "/advisory/update":
            settings  = _load_settings()
            adv_path  = _resolve_advisory_path(settings)
            result    = _download_advisory_if_changed(adv_path)
            # Refresh the cached advisory check state so the UI reflects the new status.
            if result.get("downloaded"):
                _set_advisory_check_state({
                    "upToDate": True, "updateAvailable": False,
                    "localEtag": result.get("upstreamEtag"),
                    "upstreamEtag": result.get("upstreamEtag"),
                    "localUpdatedAt": result.get("localUpdatedAt"),
                    "error": None,
                })
            self._json(result)

        elif path == "/advisory/check":
            # Manual re-check: force a fresh HEAD request regardless of cached state.
            settings = _load_settings()
            adv_path = _resolve_advisory_path(settings)
            result   = _check_upstream_advisory(adv_path)
            _set_advisory_check_state(result)
            self._json(dict(result, checkDisabled=settings.get("checkUpdateDisabled", False),
                            promptShown=settings.get("updateCheckPromptShown", False)))

        elif path == "/advisory/dismiss-prompt":
            # User responded to the offline modal — record that it was shown so we never ask again.
            try:
                body_data = json.loads(raw) if raw else {}
            except Exception:
                body_data = {}
            disable_checks = bool(body_data.get("disableChecks", False))
            settings = _load_settings()
            settings["updateCheckPromptShown"] = True
            if disable_checks:
                settings["checkUpdateDisabled"] = True
            _save_settings(settings)
            self._json({"ok": True, "checkUpdateDisabled": settings["checkUpdateDisabled"]})

        elif path == "/module/install-update":
            # Start an Update-Module subprocess in the background if one is not already running.
            with _module_install_lock:
                current_status = _module_install_state.get("status", "idle")
            if current_status == "running":
                self._json({"error": "An install is already in progress."}, 409)
                return
            # Reset state so the UI starts polling from a clean baseline.
            with _module_install_lock:
                _module_install_state["status"] = "idle"
            threading.Thread(
                target=_run_module_install_background, daemon=True,
                name="module-install",
            ).start()
            self._json({"ok": True})

        elif path == "/module/dismiss-prompt":
            # User elected to disable PSGallery checks permanently from the offline warning.
            settings = _load_settings()
            settings["disableModuleUpdateReminders"] = True
            _save_settings(settings)
            self._json({"ok": True})

        elif path == "/scan/stop":
            with _lock:
                proc = _scan_state.get("process")
            if proc is not None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            self._json({"ok": True})

        elif path == "/scan/validate-stop":
            # _validate_stop_requested is declared `global` in the /scan/validate branch earlier in
            # this same do_POST method; that declaration covers the entire function scope.
            _validate_stop_requested = True
            with _validate_lock:
                proc_to_kill = _validate_proc
            if proc_to_kill is not None:
                try:
                    proc_to_kill.terminate()
                except Exception:
                    pass
            self._json({"ok": True})

        elif path == "/vcf/ops/discover-sddc":
            try:
                body = json.loads(raw) if raw else {}
            except Exception as e:
                logger.debug(f"Bad JSON in POST /vcf/ops/discover-sddc: {e}")
                self._json({"error": "Invalid JSON."}, 400)
                return

            ops_host = body.get("opsHost", "").strip()
            username = body.get("username", "").strip()
            password = body.get("password", "")

            logger.info(f"Discovery request: opsHost={ops_host}, username={username}")
            _discovery_start_time = time.time()
            if not ops_host or not username or not password:
                err_msg = "opsHost, username, and password are required."
                logger.debug(err_msg)
                self._json({"error": err_msg}, 400)
                return

            try:
                disc_settings = _load_settings()
                disc_timeout  = disc_settings.get("connectionTimeoutSeconds", 30)
                instances, err, ops_version, vcenter_fqdns = _discover_sddc_from_ops_via_powershell(ops_host, username, password, disc_timeout)
                if err:
                    sanitized_err = _sanitize_error_message(err)
                    logger.error(f"Discovery error: {sanitized_err}")
                    self._json({"instances": [], "opsVersion": ops_version, "vcenterFqdns": [], "error": sanitized_err})
                else:
                    logger.info(f"Discovery succeeded: found {len(instances)} SDDC Manager(s), {len(vcenter_fqdns)} vCenter(s), opsVersion={ops_version!r}")
                    self._json({"instances": instances, "opsVersion": ops_version, "vcenterFqdns": vcenter_fqdns, "error": None})
            except Exception as e:
                error_detail = _sanitize_error_message(f"Discovery exception: {str(e)}")
                logger.error(error_detail)
                self._json({"instances": [], "opsVersion": "", "vcenterFqdns": [], "error": error_detail})

        elif path == "/vcf/ops/discover-fleet-manager":
            try:
                body = json.loads(raw) if raw else {}
            except Exception as e:
                logger.debug(f"Bad JSON in POST /vcf/ops/discover-fleet-manager: {e}")
                self._json({"error": "Invalid JSON."}, 400)
                return

            ops_host    = body.get("opsHost", "").strip()
            username    = body.get("username", "").strip()
            password    = body.get("password", "")
            ops_version = str(body.get("opsVersion") or "").strip()

            logger.info(f"Fleet Manager discovery request: opsHost={ops_host}, username={username}, opsVersion={ops_version!r}")
            _discovery_start_time = time.time()
            if not ops_host or not username or not password:
                err_msg = "opsHost, username, and password are required."
                logger.debug(err_msg)
                self._json({"error": err_msg}, 400)
                return

            try:
                disc_settings   = _load_settings()
                disc_timeout    = disc_settings.get("connectionTimeoutSeconds", 30)
                fleet_fqdn, vcf_fm_user, err = _discover_fleet_manager_from_ops_via_powershell(
                    ops_host, username, password, disc_timeout, ops_version
                )
                if err:
                    sanitized_err = _sanitize_error_message(err)
                    logger.error(f"Fleet Manager discovery error: {sanitized_err}")
                    self._json({"fleetFqdn": None, "vcfFMUser": None, "error": sanitized_err})
                else:
                    logger.info(f"Fleet Manager discovery succeeded: {fleet_fqdn}")
                    self._json({"fleetFqdn": fleet_fqdn, "vcfFMUser": vcf_fm_user, "error": None})
            except Exception as e:
                error_detail = _sanitize_error_message(f"Fleet Manager discovery exception: {str(e)}")
                logger.error(error_detail)
                self._json({"fleetFqdn": None, "vcfFMUser": None, "error": error_detail})

        elif path == "/vcf/vcf5/discover-vrslcm":
            try:
                body = json.loads(raw) if raw else {}
            except Exception as e:
                logger.debug(f"Bad JSON in POST /vcf/vcf5/discover-vrslcm: {e}")
                self._json({"error": "Invalid JSON."}, 400)
                return

            sddc_host = body.get("sddcHost", "").strip()
            username  = body.get("username", "").strip()
            password  = body.get("password", "")

            logger.info(f"vRSLCM discovery request: sddcHost={sddc_host}, username={username}")
            if not sddc_host or not username or not password:
                err_msg = "sddcHost, username, and password are required."
                logger.debug(err_msg)
                self._json({"error": err_msg}, 400)
                return

            try:
                disc_settings  = _load_settings()
                disc_timeout   = disc_settings.get("connectionTimeoutSeconds", 30)
                vrslcm_fqdn, vrslcm_version, err = _discover_vrslcm_from_sddc_via_powershell(
                    sddc_host, username, password, disc_timeout
                )
                if err:
                    sanitized_err = _sanitize_error_message(err)
                    logger.error(f"vRSLCM discovery error: {sanitized_err}")
                    self._json({"vrslcmFqdn": None, "vrslcmVersion": "", "error": sanitized_err})
                else:
                    logger.info(f"vRSLCM discovery result: {vrslcm_fqdn!r}")
                    self._json({"vrslcmFqdn": vrslcm_fqdn, "vrslcmVersion": vrslcm_version, "error": None})
            except Exception as e:
                error_detail = _sanitize_error_message(f"vRSLCM discovery exception: {str(e)}")
                logger.error(error_detail)
                self._json({"vrslcmFqdn": None, "vrslcmVersion": "", "error": error_detail})

        else:
            self._json({"error": "Not found."}, 404)


# ---------------------------------------------------------------------------
# Logging initialization
# ---------------------------------------------------------------------------
def _initialize_logging() -> None:
    """Attach a FileHandler to the module-level logger.

    The logger is pre-initialized at module load with a NullHandler so all call sites
    can log unconditionally.  This function replaces the NullHandler with a rotating
    daily FileHandler once the log directory is confirmed to exist.
    When VcfPatchScannerBaseDirectory is set (populated by Initialize-VcfPatchScanner), logs
    are written to <base>/Logs/.
    """
    global log_dir

    log_dir = _USER_BASE_DIR / _BASE_LOGS_SUBDIR

    try:
        _ensure_user_dir(log_dir)
    except Exception as exc:
        print(f"[WARNING] Could not create log directory {log_dir}: {exc}", file=sys.stderr)

    logger.setLevel(logging.DEBUG)

    if log_dir and log_dir.exists():
        log_file = log_dir / f"VcfPatchScannerServer-{datetime.now().strftime('%Y-%m-%d')}.log"
        try:
            # Pre-create the file and restrict permissions before the first append so
            # the file is never world-readable even for a brief window at session start.
            if not log_file.exists():
                log_file.touch(mode=0o600)
            else:
                try:
                    log_file.chmod(0o600)
                except OSError:
                    pass  # best-effort on Windows or restricted filesystems.
            handler = logging.FileHandler(log_file, mode='a')
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            handler.setFormatter(formatter)
            # Remove the startup NullHandler now that a real handler is in place.
            logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.NullHandler)]
            logger.addHandler(handler)
        except Exception as exc:
            print(f"[WARNING] Could not open log file {log_file}: {exc}. Security events will not be logged.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    global SETTINGS_FILE

    _initialize_logging()
    port          = _DEFAULT_PORT
    no_browser    = False
    pid_file_path: "Path | None" = None

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg.startswith("--port="):
            raw_port = arg.split("=", 1)[1]
            try:
                port = int(raw_port)
            except ValueError:
                print(f"\n[ERROR] Invalid port value in '{arg}' — must be an integer.\n", file=sys.stderr)
                sys.exit(1)
            if not (1 <= port <= 65535):
                print(f"\n[ERROR] Port {port} is out of range — must be between 1 and 65535.\n", file=sys.stderr)
                sys.exit(1)
        elif arg == "--port" and i < len(sys.argv) - 1:
            raw_port = sys.argv[i + 1]
            try:
                port = int(raw_port)
            except ValueError:
                print(f"\n[ERROR] Invalid port value '{raw_port}' — must be an integer.\n", file=sys.stderr)
                sys.exit(1)
            if not (1 <= port <= 65535):
                print(f"\n[ERROR] Port {port} is out of range — must be between 1 and 65535.\n", file=sys.stderr)
                sys.exit(1)
        elif arg.startswith("--settings="):
            candidate = Path(arg.split("=", 1)[1]).resolve()
            home_dir  = Path.home().resolve()
            if not str(candidate).startswith(str(home_dir) + os.sep):
                print(
                    f"\n[ERROR] --settings path must be within the home directory ({home_dir}).\n"
                    f"  Rejected: {candidate}\n",
                    file=sys.stderr,
                )
                sys.exit(1)
            SETTINGS_FILE = candidate
        elif arg == "--no-browser":
            no_browser = True
        elif arg.startswith("--pid-file="):
            candidate = Path(arg.split("=", 1)[1]).resolve()
            home_dir  = Path.home().resolve()
            if not str(candidate).startswith(str(home_dir) + os.sep):
                print(
                    f"\n[ERROR] --pid-file path must be within the home directory ({home_dir}).\n"
                    f"  Rejected: {candidate}\n",
                    file=sys.stderr,
                )
                sys.exit(1)
            pid_file_path = candidate

    if not SCAN_SCRIPT.exists():
        print(f"ERROR: Invoke-VCFPatchScanner.ps1 not found at {SCAN_SCRIPT}")
        sys.exit(1)

    if not SETTINGS_FILE.exists():
        _save_settings(_default_settings())
        msg = f"Created default settings file: {SETTINGS_FILE}"
        print(msg)
        logger.info(msg)
    url    = f"http://localhost:{port}"
    # ThreadingHTTPServer assigns a new thread to each accepted connection so that
    # long-running advisory downloads (up to 70 s) do not block scan/validation polling.
    # All shared state (_scan_state, _validate_state, _advisory_check_state, _settings_cache)
    # is already guarded by per-state threading.Lock instances.
    try:
        server = ThreadingHTTPServer((BIND_HOST, port), Handler)
    except OSError as e:
        if e.errno == errno.EADDRINUSE:
            print(
                f"\n[ERROR] Port {port} is already in use.\n"
                f"  The VCF Patch Scan Server may already be running.\n"
                f"  Open http://localhost:{port} in your browser, or stop the\n"
                f"  existing server first, then run Start-VCFPatchScannerServer again.\n",
                file=sys.stderr,
            )
        else:
            print(f"\n[ERROR] Could not start server on port {port}: {e}\n", file=sys.stderr)
        sys.exit(1)

    startup_msg = f"VCF Patch Scan Server running at {url}, listening on {BIND_HOST}:{port}"
    print(startup_msg)
    logger.info(startup_msg)
    print(f"Settings file: {SETTINGS_FILE}")
    print(f"Module path:   {_MODULE_PSD1}")
    if not _MODULE_PSD1.is_file():
        warn = (
            f"\nWARNING: VcfPatchScanner module not found at: {_MODULE_PSD1}\n"
            "Scans and discovery will fail until the module is available.\n"
            "To fix, set the VCFPATCHSCANNER_MODULE_PSD1 environment variable to the\n"
            "full path of VcfPatchScanner.psd1 before starting the server.  Example:\n"
            f"  export VCFPATCHSCANNER_MODULE_PSD1=/path/to/VcfPatchScanner/VcfPatchScanner.psd1\n"
        )
        print(warn)
        logger.warning(warn.strip())
    if log_dir:
        print(f"Log directory: {log_dir}")

    if pid_file_path:
        try:
            pid_file_path.parent.mkdir(parents=True, exist_ok=True)
            pid_file_path.write_text(str(os.getpid()), encoding="utf-8")
            try:
                pid_file_path.chmod(0o600)
            except OSError:
                pass
        except OSError as exc:
            print(f"[WARNING] Could not write PID file {pid_file_path}: {exc}", file=sys.stderr)
            pid_file_path = None

    if no_browser:
        print("Running in daemon mode — browser will not be opened automatically.")
        print(f"Open {url} manually to access the web UI.")
    else:
        print("Press Ctrl+C to stop.")
        threading.Thread(
            target=lambda: (time.sleep(0.8), webbrowser.open(url)),
            daemon=True,
        ).start()

    # Install a SIGTERM handler on POSIX so `kill <pid>` triggers a clean shutdown
    # identical to Ctrl+C.  Windows does not honour Python SIGTERM handlers (os.kill
    # calls TerminateProcess directly), so the handler is skipped there.
    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, lambda sig, frame: server.shutdown())

    # Run the advisory update check once in the background so the UI can show the result
    # without blocking startup.  Skipped when the user has disabled update checks.
    startup_settings = _load_settings()
    if not startup_settings.get("checkUpdateDisabled", False):
        threading.Thread(
            target=_run_advisory_check_background,
            args=(startup_settings,),
            daemon=True,
            name="advisory-update-check",
        ).start()

    # Run the PSGallery module version check in the background.  Skipped when the user
    # has disabled module update reminders (e.g. air-gapped / dark-site installs).
    if not startup_settings.get("disableModuleUpdateReminders", False):
        threading.Thread(
            target=_run_module_update_check_background,
            daemon=True,
            name="module-update-check",
        ).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_msg = "Server stopped."
        print(f"\n{stop_msg}")
        logger.info(stop_msg)
        if pid_file_path:
            try:
                pid_file_path.unlink(missing_ok=True)
            except OSError:
                pass
if __name__ == "__main__":
    main()
