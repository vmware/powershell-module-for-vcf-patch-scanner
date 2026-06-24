#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# Static regression guards for PowerShell source files.
# Parses PS1/PY source to enforce structural invariants that have caused
# regressions when violated.  No PowerShell runtime required.
#
# Run standalone:  python -m unittest discover -s . -p "test_ps1_static.py"

import os
import re
import unittest

_TOOLS_DIR = os.path.join(os.path.dirname(__file__), "..", "Tools")
_PRIVATE_DIR = os.path.join(os.path.dirname(__file__), "..", "Private")

_TOOLS_PS1     = os.path.join(_PRIVATE_DIR, "Tools.ps1")
_SERVER_PY     = os.path.join(_TOOLS_DIR, "Start-VCFPatchScannerServer.py")
_INVOKE_PS1    = os.path.join(_TOOLS_DIR, "Invoke-VCFPatchScanner.ps1")


def _load(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _extract_ps_function(src: str, name: str) -> str:
    """Return the body text of the first PowerShell function with the given name."""
    pattern = rf"(?m)^function\s+{re.escape(name)}\s*\{{"
    m = re.search(pattern, src)
    if not m:
        raise AssertionError(f"Function {name!r} not found in source")
    start = m.start()
    depth = 0
    i = src.index("{", start)
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1
    raise AssertionError(f"Could not find closing brace for {name!r}")


class TestStartServerModulePathInjection(unittest.TestCase):
    """
    Guards the module-path injection contract in Start-VCFPatchScannerServer (PS).

    The regression: Start-VCFPatchScannerServer never injected VCFPATCHSCANNER_MODULE_PSD1
    into the Python server's environment, so every discovery call failed with
    "Failed to load VcfPatchScanner module" in the deployed layout.

    These tests verify that the PowerShell function:
    1. Computes the module path using MyInvocation.MyCommand.Module.ModuleBase
       (the only expression that resolves to the correct directory regardless of
       where the module was loaded from).
    2. Sets VCFPATCHSCANNER_MODULE_PSD1 in the environment dict forwarded to the
       Python server subprocess.
    """

    def setUp(self):
        self._src = _load(_TOOLS_PS1)
        self._fn  = _extract_ps_function(self._src, "Start-VCFPatchScannerServer")

    def test_uses_module_base_for_psd1_path(self):
        self.assertRegex(
            self._fn,
            r"MyInvocation\.MyCommand\.Module\.ModuleBase",
            "Start-VCFPatchScannerServer must resolve the PSD1 path via "
            "$MyInvocation.MyCommand.Module.ModuleBase — this is the only expression "
            "that returns the correct directory regardless of where the module was loaded from. "
            "Using PSScriptRoot or a hardcoded path fails in the deployed layout.",
        )

    def test_injects_vcfpatchscan_module_psd1_env_var(self):
        self.assertRegex(
            self._fn,
            r"VCFPATCHSCANNER_MODULE_PSD1",
            "Start-VCFPatchScannerServer must inject VCFPATCHSCANNER_MODULE_PSD1 into "
            "the subprocess environment dict so Invoke-VCFPatchScanner.ps1 can locate "
            "the module manifest in the deployed layout (Tools/ outside the module tree).",
        )

    def test_guards_injection_with_test_path(self):
        src = self._fn
        test_m   = re.search(r"Test-Path\b", src)
        assign_m = re.search(r"VCFPATCHSCANNER_MODULE_PSD1", src)
        self.assertIsNotNone(test_m, "Start-VCFPatchScannerServer must guard VCFPATCHSCANNER_MODULE_PSD1 "
                             "injection with Test-Path so a bad path is never injected")
        self.assertIsNotNone(assign_m)
        self.assertLess(
            test_m.start(), assign_m.start(),
            "Test-Path guard must appear before the VCFPATCHSCANNER_MODULE_PSD1 assignment",
        )

    def test_module_psd1_written_to_session_env_before_background_branch(self):
        # The background code path inherits $env: (not processInfo.Environment), so
        # $env:VCFPATCHSCANNER_MODULE_PSD1 must be set before the if ($Background) block.
        fn = self._fn
        session_m    = re.search(r"\$env:VCFPATCHSCANNER_MODULE_PSD1\s*=", fn)
        background_m = re.search(r"if\s*\(\s*\$Background\s*\)", fn)
        self.assertIsNotNone(
            session_m,
            "Start-VCFPatchScannerServer must write $env:VCFPATCHSCANNER_MODULE_PSD1 so "
            "the background code path (& python manage.py start) inherits it via the "
            "session environment. PSGallery installs use a versioned subfolder that the "
            "Python server's PSModulePath search missed in v1001, causing Import-Module "
            "to fail with the base-directory fallback path.",
        )
        self.assertIsNotNone(background_m, "if ($Background) branch not found in function body")
        self.assertLess(
            session_m.start(), background_m.start(),
            "$env:VCFPATCHSCANNER_MODULE_PSD1 must be assigned before the if ($Background) "
            "block so both foreground and background code paths inherit the correct module path.",
        )


class TestSubprocessEnvAllowlist(unittest.TestCase):
    """
    Guards the subprocess environment allowlist in the Python server.

    The regression: VCFPATCHSCANNER_MODULE_PSD1 was injected by the PowerShell wrapper
    into the Python server's os.environ, but _SUBPROCESS_ENV_ALLOWLIST did not
    include it, so _base_subprocess_env() silently stripped it before passing the
    environment to child PowerShell processes.  Discovery failed in the deployed
    layout despite the PowerShell fix being in place.
    """

    def setUp(self):
        self._src = _load(_SERVER_PY)

    def test_allowlist_contains_module_psd1_var(self):
        m = re.search(
            r"_SUBPROCESS_ENV_ALLOWLIST\s*=\s*frozenset\s*\(\s*\{(.+?)\}\s*\)",
            self._src,
            re.DOTALL,
        )
        self.assertIsNotNone(m, "_SUBPROCESS_ENV_ALLOWLIST frozenset must be defined in server")
        block = m.group(1)
        self.assertIn(
            "VCFPATCHSCANNER_MODULE_PSD1", block,
            "_SUBPROCESS_ENV_ALLOWLIST must include 'VCFPATCHSCANNER_MODULE_PSD1' so the path "
            "injected by Start-VCFPatchScannerServer (PowerShell) survives the allowlist filter "
            "and is forwarded to child PowerShell subprocesses.  Without this entry the "
            "module-path chain is silently broken in the deployed layout.",
        )


class TestEnvVarsAppliedToProcessInfo(unittest.TestCase):
    """
    Guards the connection between $env_vars dict population and processInfo.Environment.

    The regression scenario: $env_vars['VCFPATCHSCANNER_MODULE_PSD1'] is correctly
    populated, but an early `return` or restructuring break between that assignment
    and the `foreach ($key in $env_vars.Keys)` loop that applies vars to
    processInfo.Environment — injection silently fails even though the dict is built.

    These tests verify that the foreach loop exists in the function and that it
    appears after the VCFPATCHSCANNER_MODULE_PSD1 assignment.
    """

    def setUp(self):
        self._src = _load(_TOOLS_PS1)
        self._fn  = _extract_ps_function(self._src, "Start-VCFPatchScannerServer")

    def test_foreach_loop_applies_env_vars_to_process_info(self):
        self.assertRegex(
            self._fn,
            r"foreach\s*\(\s*\$\w+\s+in\s+\$env_vars",
            "Start-VCFPatchScannerServer must iterate $env_vars.Keys and apply each to "
            "processInfo.Environment; without this loop the dict is built but never "
            "forwarded to the subprocess.",
        )

    def test_process_info_environment_assignment_present(self):
        self.assertRegex(
            self._fn,
            r"processInfo\.Environment\[",
            "Start-VCFPatchScannerServer must assign to processInfo.Environment[key] "
            "inside the foreach loop; if this line is missing the Python server "
            "receives no injected env vars at all.",
        )

    def test_env_var_injection_before_process_start(self):
        fn = self._fn
        inject_m = re.search(r"VCFPATCHSCANNER_MODULE_PSD1", fn)
        start_m  = re.search(r"Process\]::Start\s*\(", fn)
        self.assertIsNotNone(inject_m, "VCFPATCHSCANNER_MODULE_PSD1 assignment not found")
        self.assertIsNotNone(start_m,  "[System.Diagnostics.Process]::Start not found")
        self.assertLess(
            inject_m.start(), start_m.start(),
            "VCFPATCHSCANNER_MODULE_PSD1 must be assigned before Process::Start is called; "
            "any restructuring that moves the injection after the Start call means the "
            "Python server launches with an incomplete environment.",
        )


class TestInvokeScriptModulePathPriority(unittest.TestCase):
    """
    Guards the module-loading priority in Invoke-VCFPatchScanner.ps1.

    Invoke-VCFPatchScanner.ps1 must prefer VCFPATCHSCANNER_MODULE_PSD1 (injected by
    Start-VCFPatchScannerServer) over any fallback path so that the deployed layout
    (Tools/ outside the module tree) works correctly.
    """

    def setUp(self):
        self._src = _load(_INVOKE_PS1)

    def test_env_var_takes_priority_over_fallback(self):
        env_m      = re.search(r"VCFPATCHSCANNER_MODULE_PSD1", self._src)
        fallback_m = re.search(r"PSScriptRoot|Split-Path", self._src)
        self.assertIsNotNone(
            env_m,
            "Invoke-VCFPatchScanner.ps1 must read VCFPATCHSCANNER_MODULE_PSD1 to locate "
            "the module in the deployed layout.",
        )
        self.assertIsNotNone(
            fallback_m,
            "Invoke-VCFPatchScanner.ps1 must also have a fallback path for local dev "
            "where the env var is not set.",
        )
        self.assertLess(
            env_m.start(), fallback_m.start(),
            "VCFPATCHSCANNER_MODULE_PSD1 env-var check must appear BEFORE the "
            "PSScriptRoot/Split-Path fallback — the env var is the authoritative "
            "path in the deployed layout and must win when set.",
        )


if __name__ == "__main__":
    unittest.main()
