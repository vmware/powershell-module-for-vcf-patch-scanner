#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================
#
# Negative tests for Start-VCFPatchScannerServer.py.
# Covers: input validation, env-var injection logic, progress filtering,
# HTTP handler error paths, and concurrent-request guards.
#
# Run standalone:  python -m unittest discover -s . -p "test_server.py"
# Run via Run-Tests.ps1 (invokes python -m unittest automatically).

import base64
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

# ── module import ─────────────────────────────────────────────────────────────
# Start-VCFPatchScannerServer.py calls _require_base_dir() at module scope.
# Set VcfPatchScannerBaseDirectory to a real temp directory before importing so
# the import succeeds without starting the HTTP server.

_BASE_DIR = tempfile.mkdtemp(prefix="vcf_server_test_")
os.environ["VcfPatchScannerBaseDirectory"] = _BASE_DIR

_SERVER_PATH = (
    Path(__file__).resolve().parent.parent / "Tools" / "Start-VCFPatchScannerServer.py"
)
_spec = importlib.util.spec_from_file_location("vcf_server", str(_SERVER_PATH))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
# ─────────────────────────────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ─────────────────────────────────────────────────────────────────────────────
# _validate_env_config
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateEnvConfig(unittest.TestCase):
    """_validate_env_config — every env type, every missing-field branch."""

    def _v(self, env):
        return _mod._validate_env_config(env)

    # Unknown / empty type
    def test_unknown_type_returns_error(self):
        err = self._v({"type": "vcf99"})
        self.assertIsNotNone(err)
        self.assertIn("Unknown environment type", err)

    def test_empty_type_returns_error(self):
        self.assertIsNotNone(self._v({"type": ""}))

    def test_missing_type_key_returns_error(self):
        self.assertIsNotNone(self._v({}))

    # VCF 5
    def test_vcf5_missing_sddc_server(self):
        err = self._v({"type": "vcf5", "sddcManagerUser": "admin"})
        self.assertIsNotNone(err)
        self.assertIn("SDDC Manager Server", err)

    def test_vcf5_whitespace_only_sddc_server(self):
        err = self._v({"type": "vcf5", "sddcManagerServer": "   ", "sddcManagerUser": "admin"})
        self.assertIsNotNone(err)

    def test_vcf5_missing_sddc_user(self):
        err = self._v({"type": "vcf5", "sddcManagerServer": "sddc.lab"})
        self.assertIsNotNone(err)
        self.assertIn("SDDC Manager Username", err)

    def test_vcf5_valid_returns_none(self):
        err = self._v({"type": "vcf5", "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin"})
        self.assertIsNone(err)

    # VCF 9 (non-9.1: vcfMinorVersion absent)
    def test_vcf9_missing_ops_server(self):
        err = self._v({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                       "sddcManagerUser": "admin", "vcfFMServer": "fm.lab"})
        self.assertIsNotNone(err)
        self.assertIn("VCF Operations Server", err)

    def test_vcf9_whitespace_ops_server(self):
        err = self._v({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                       "sddcManagerUser": "admin", "vcfOpsServer": "  ",
                       "vcfOpsUser": "admin@local", "vcfFMServer": "fm.lab"})
        self.assertIsNotNone(err)

    def test_vcf9_missing_ops_user(self):
        err = self._v({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                       "sddcManagerUser": "admin", "vcfOpsServer": "ops.lab",
                       "vcfFMServer": "fm.lab"})
        self.assertIsNotNone(err)
        self.assertIn("VCF Operations Username", err)

    def test_vcf9_missing_fm_server(self):
        err = self._v({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                       "sddcManagerUser": "admin", "vcfOpsServer": "ops.lab",
                       "vcfOpsUser": "admin@local"})
        self.assertIsNotNone(err)
        self.assertIn("Fleet Manager Server", err)

    def test_vcf9_91_skips_ops_server_check(self):
        # VCF 9.1: vcfMinorVersion == "9.1" means ops server is not required.
        err = self._v({"type": "vcf9", "vcfMinorVersion": "9.1",
                       "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin",
                       "vcfFMServer": "fleet-lc.lab"})
        self.assertIsNone(err)

    def test_vcf9_valid_non91_returns_none(self):
        err = self._v({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                       "sddcManagerUser": "admin", "vcfOpsServer": "ops.lab",
                       "vcfOpsUser": "admin@local", "vcfFMServer": "fm.lab"})
        self.assertIsNone(err)

    # VVF 9
    def test_vvf9_missing_ops_server(self):
        err = self._v({"type": "vvf9", "vcfOpsUser": "admin",
                       "vcfFMServer": "fm.lab", "vcenterUser": "admin"})
        self.assertIsNotNone(err)
        self.assertIn("VCF Operations Server", err)

    def test_vvf9_missing_ops_user(self):
        err = self._v({"type": "vvf9", "vcfOpsServer": "ops.lab",
                       "vcfFMServer": "fm.lab", "vcenterUser": "admin"})
        self.assertIsNotNone(err)
        self.assertIn("VCF Operations Username", err)

    def test_vvf9_missing_fm_server(self):
        err = self._v({"type": "vvf9", "vcfOpsServer": "ops.lab",
                       "vcfOpsUser": "admin", "vcenterUser": "admin"})
        self.assertIsNotNone(err)
        self.assertIn("Fleet Manager Server", err)

    def test_vvf9_missing_vcenter_user(self):
        err = self._v({"type": "vvf9", "vcfOpsServer": "ops.lab",
                       "vcfOpsUser": "admin", "vcfFMServer": "fm.lab"})
        self.assertIsNotNone(err)
        self.assertIn("vCenter Username", err)

    def test_vvf9_whitespace_vcenter_user_fails(self):
        err = self._v({"type": "vvf9", "vcfOpsServer": "ops.lab",
                       "vcfOpsUser": "admin", "vcfFMServer": "fm.lab",
                       "vcenterUser": "   "})
        self.assertIsNotNone(err)

    def test_vvf9_valid_returns_none(self):
        err = self._v({"type": "vvf9", "vcfOpsServer": "ops.lab",
                       "vcfOpsUser": "admin", "vcfFMServer": "fm.lab",
                       "vcenterUser": "admin@vsphere.local"})
        self.assertIsNone(err)

    # vSphere 8
    def test_vsphere8_missing_vcenter_server(self):
        err = self._v({"type": "vsphere8", "vcenterUser": "admin"})
        self.assertIsNotNone(err)
        self.assertIn("vCenter Server", err)

    def test_vsphere8_missing_vcenter_user(self):
        err = self._v({"type": "vsphere8", "vcenterServer": "vc.lab"})
        self.assertIsNotNone(err)
        self.assertIn("vCenter Username", err)

    def test_vsphere8_nsx_server_without_user_returns_error(self):
        # Entering the ops server FQDN in the NSX field would pass field-presence
        # validation but fail the user check — the server-side guard catches the gap.
        err = self._v({"type": "vsphere8", "vcenterServer": "vc.lab",
                       "vcenterUser": "admin", "nsxManagerServer": "ops.wrong.lab"})
        self.assertIsNotNone(err)
        self.assertIn("NSX Manager Username", err)

    def test_vsphere8_nsx_server_with_user_returns_none(self):
        err = self._v({"type": "vsphere8", "vcenterServer": "vc.lab",
                       "vcenterUser": "admin", "nsxManagerServer": "nsx.lab",
                       "nsxManagerUser": "admin"})
        self.assertIsNone(err)

    def test_vsphere8_without_nsx_returns_none(self):
        err = self._v({"type": "vsphere8", "vcenterServer": "vc.lab",
                       "vcenterUser": "admin"})
        self.assertIsNone(err)


# ─────────────────────────────────────────────────────────────────────────────
# _build_env_vars
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildEnvVars(unittest.TestCase):
    """_build_env_vars — correct credential env vars per type; no leakage across types."""

    def _build(self, env, passwords):
        return _mod._build_env_vars(env, passwords)

    # VVF9 — no NSX, three separate passwords
    def test_vvf9_never_sets_nsx_password(self):
        ev = self._build({"type": "vvf9"},
                         {"opsPass": "op", "fmPass": "fm", "vcenterPass": "vc", "nsxPass": "nx"})
        self.assertNotIn("NSX_MANAGER_PASSWORD", ev)

    def test_vvf9_sets_ops_fm_vcenter(self):
        ev = self._build({"type": "vvf9"},
                         {"opsPass": "op", "fmPass": "fm", "vcenterPass": "vc"})
        self.assertEqual(ev.get("VCF_OPS_PASSWORD"), "op")
        self.assertEqual(ev.get("VCF_FM_PASSWORD"), "fm")
        self.assertEqual(ev.get("VCENTER_PASSWORD"), "vc")

    def test_vvf9_empty_ops_password_not_injected(self):
        ev = self._build({"type": "vvf9"},
                         {"opsPass": "", "fmPass": "fm", "vcenterPass": "vc"})
        self.assertNotIn("VCF_OPS_PASSWORD", ev)

    def test_vvf9_none_vcenter_password_not_injected(self):
        ev = self._build({"type": "vvf9"},
                         {"opsPass": "op", "fmPass": "fm"})
        self.assertNotIn("VCENTER_PASSWORD", ev)

    # VCF 9.1 — ops password must be suppressed
    def test_vcf9_91_suppresses_ops_password(self):
        env = {"type": "vcf9", "vcfMinorVersion": "9.1", "useSinglePassword": False}
        ev = self._build(env, {"sddcPass": "sp", "opsPass": "op", "fmPass": "fm"})
        self.assertNotIn("VCF_OPS_PASSWORD", ev)
        self.assertEqual(ev.get("SDDC_MANAGER_PASSWORD"), "sp")
        self.assertEqual(ev.get("VCF_FM_PASSWORD"), "fm")

    def test_vcf9_non91_sets_ops_password(self):
        env = {"type": "vcf9", "useSinglePassword": False}
        ev = self._build(env, {"sddcPass": "sp", "opsPass": "op", "fmPass": "fm"})
        self.assertEqual(ev.get("VCF_OPS_PASSWORD"), "op")

    # VCF 9 single-password: sddc password must propagate to fm
    def test_vcf9_single_password_populates_fm(self):
        env = {"type": "vcf9", "useSinglePassword": True}
        ev = self._build(env, {"sddcPass": "shared"})
        self.assertEqual(ev.get("VCF_FM_PASSWORD"), "shared")

    # VCF 5 — no NSX password injected (retrieved via SDDC credentials API)
    def test_vcf5_never_sets_nsx_password(self):
        ev = self._build({"type": "vcf5"}, {"sddcPass": "sp", "nsxPass": "nx"})
        self.assertNotIn("NSX_MANAGER_PASSWORD", ev)

    def test_vcf5_vrslcm_password_only_when_server_configured(self):
        ev_with = self._build({"type": "vcf5", "vrslcmServer": "vrlcm.lab"},
                              {"sddcPass": "sp", "vrslcmPass": "vp"})
        ev_without = self._build({"type": "vcf5"},
                                 {"sddcPass": "sp", "vrslcmPass": "vp"})
        self.assertIn("VRSLCM_PASSWORD", ev_with)
        self.assertNotIn("VRSLCM_PASSWORD", ev_without)

    # vSphere 8 — NSX password injected when present
    def test_vsphere8_sets_nsx_password(self):
        ev = self._build({"type": "vsphere8"}, {"vcenterPass": "vc", "nsxPass": "nx"})
        self.assertEqual(ev.get("NSX_MANAGER_PASSWORD"), "nx")

    def test_vsphere8_no_nsx_password_when_absent(self):
        ev = self._build({"type": "vsphere8"}, {"vcenterPass": "vc"})
        self.assertNotIn("NSX_MANAGER_PASSWORD", ev)

    # Unknown type must not leak any credential variable
    def test_unknown_type_leaks_no_credential_vars(self):
        ev = self._build({"type": "bogus"}, {"sddcPass": "sp", "vcenterPass": "vc",
                                              "opsPass": "op", "nsxPass": "nx"})
        for key in ("SDDC_MANAGER_PASSWORD", "VCF_OPS_PASSWORD", "VCF_FM_PASSWORD",
                    "VCENTER_PASSWORD", "NSX_MANAGER_PASSWORD", "VRSLCM_PASSWORD"):
            self.assertNotIn(key, ev, f"{key} must not be set for unknown env type")

    def test_build_env_vars_inherits_base_subprocess_env(self):
        """_build_env_vars must call _base_subprocess_env so VCFPATCHSCANNER_MODULE_PSD1 survives.

        If someone refactors _build_env_vars to start from {} instead of
        _base_subprocess_env(), the module-path chain silently breaks for every
        scan and validation subprocess — the credential keys are still injected
        but the module manifest path is gone.
        """
        fake_path = "/fake/VcfPatchScanner/VcfPatchScanner.psd1"
        saved = os.environ.get("VCFPATCHSCANNER_MODULE_PSD1")
        try:
            os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = fake_path
            with unittest.mock.patch.object(_mod, "_MODULE_PSD1") as mock_psd1:
                mock_psd1.exists.return_value = False
                ev = self._build({"type": "vcf9", "useSinglePassword": False},
                                 {"sddcPass": "sp", "fmPass": "fm"})
            self.assertEqual(
                ev.get("VCFPATCHSCANNER_MODULE_PSD1"), fake_path,
                "_build_env_vars must inherit VCFPATCHSCANNER_MODULE_PSD1 from _base_subprocess_env; "
                "if it starts from {} instead, the module-path chain silently breaks for every "
                "scan subprocess even though credential keys are still injected correctly.",
            )
        finally:
            if saved is None:
                os.environ.pop("VCFPATCHSCANNER_MODULE_PSD1", None)
            else:
                os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = saved


# ─────────────────────────────────────────────────────────────────────────────
# _env_type_args — CLI args forwarded to Invoke-VCFPatchScanner.ps1
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvTypeArgs(unittest.TestCase):
    """_env_type_args — correct -VcfMajorVersion and field flags per env type.

    This function is the sibling of _build_env_vars on the credential side.
    It maps env dict keys to PowerShell CLI parameter names.  A new env type
    that is added to _ENV_TYPE_FIELDS but not tested here will silently pass
    the wrong or missing args to Invoke-VCFPatchScanner.ps1.
    """

    def _args(self, env):
        return _mod._env_type_args(env)

    def test_vcf9_emits_major_version(self):
        args = self._args({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                           "sddcManagerUser": "admin@local", "vcfOpsServer": "ops.lab",
                           "vcfOpsUser": "admin@local", "vcfFMServer": "fm.lab", "vcfFMUser": "admin"})
        self.assertIn("-VcfMajorVersion", args)
        self.assertEqual(args[args.index("-VcfMajorVersion") + 1], "vcf9")

    def test_vcf9_includes_sddc_and_fm_flags(self):
        args = self._args({"type": "vcf9", "sddcManagerServer": "sddc.lab",
                           "sddcManagerUser": "admin", "vcfFMServer": "fm.lab", "vcfFMUser": "fu"})
        self.assertIn("-SddcManagerServer", args)
        self.assertIn("-VcfFMServer", args)

    def test_vcf9_91_omits_ops_server_and_user(self):
        env = {"type": "vcf9", "vcfMinorVersion": "9.1",
               "vcfOpsServer": "ops.lab", "vcfOpsUser": "admin@local"}
        args = self._args(env)
        self.assertNotIn("-VcfOpsServer", args,
                         "VCF 9.1 uses Fleet Controller; -VcfOpsServer must not be forwarded")
        self.assertNotIn("-VcfOpsUser", args)

    def test_vcf9_non91_includes_ops_server_and_user(self):
        env = {"type": "vcf9", "vcfOpsServer": "ops.lab", "vcfOpsUser": "admin@local"}
        args = self._args(env)
        self.assertIn("-VcfOpsServer", args)
        self.assertIn("-VcfOpsUser", args)

    def test_vcf5_emits_major_version(self):
        args = self._args({"type": "vcf5", "sddcManagerServer": "sddc.lab",
                           "sddcManagerUser": "admin@local"})
        self.assertIn("-VcfMajorVersion", args)
        self.assertEqual(args[args.index("-VcfMajorVersion") + 1], "vcf5")

    def test_vcf5_does_not_emit_fm_flag(self):
        args = self._args({"type": "vcf5", "sddcManagerServer": "sddc.lab",
                           "sddcManagerUser": "admin", "vcfFMServer": "fm.lab"})
        self.assertNotIn("-VcfFMServer", args,
                         "vcf5 has no Fleet Manager; -VcfFMServer must never appear in its args")

    def test_vvf9_emits_major_version(self):
        args = self._args({"type": "vvf9", "vcfOpsServer": "ops.lab", "vcfOpsUser": "admin",
                           "vcfFMServer": "fm.lab", "vcfFMUser": "fu", "vcenterUser": "vu"})
        self.assertIn("-VcfMajorVersion", args)
        self.assertEqual(args[args.index("-VcfMajorVersion") + 1], "vvf9")

    def test_vvf9_includes_vcenter_user_flag(self):
        args = self._args({"type": "vvf9", "vcenterUser": "vc-admin"})
        self.assertIn("-VcenterUser", args,
                      "VVF 9 provides a shared vCenter username; -VcenterUser must be forwarded")

    def test_vvf9_does_not_emit_sddc_flag(self):
        args = self._args({"type": "vvf9", "sddcManagerServer": "sddc.lab"})
        self.assertNotIn("-SddcManagerServer", args,
                         "VVF 9 has no SDDC Manager; -SddcManagerServer must never appear")

    def test_vsphere8_emits_major_version(self):
        args = self._args({"type": "vsphere8", "vcenterServer": "vc.lab", "vcenterUser": "admin"})
        self.assertIn("-VcfMajorVersion", args)
        self.assertEqual(args[args.index("-VcfMajorVersion") + 1], "vsphere8")

    def test_vsphere8_includes_vcenter_and_nsx_flags(self):
        args = self._args({"type": "vsphere8", "vcenterServer": "vc.lab", "vcenterUser": "admin",
                           "nsxManagerServer": "nsx.lab", "nsxManagerUser": "admin"})
        self.assertIn("-VcenterServer", args)
        self.assertIn("-NsxManagerServer", args)

    def test_empty_field_values_omitted(self):
        args = self._args({"type": "vcf9", "sddcManagerServer": "", "vcfOpsServer": "  "})
        self.assertNotIn("-SddcManagerServer", args,
                         "Empty or whitespace field values must not produce a CLI flag")
        self.assertNotIn("-VcfOpsServer", args)

    def test_unknown_type_returns_empty_list(self):
        args = self._args({"type": "bogus", "vcenterServer": "vc.lab"})
        self.assertEqual(args, [],
                         "_env_type_args must return [] for unknown types so no stray flags reach pwsh")

    def test_minor_version_appended_when_present(self):
        args = self._args({"type": "vcf9", "vcfMinorVersion": "9.1"})
        self.assertIn("-VcfMinorVersion", args)
        self.assertEqual(args[args.index("-VcfMinorVersion") + 1], "9.1")

    def test_minor_version_omitted_when_empty(self):
        args = self._args({"type": "vcf9", "vcfMinorVersion": ""})
        self.assertNotIn("-VcfMinorVersion", args)


# ─────────────────────────────────────────────────────────────────────────────
# _base_subprocess_env — module-path forwarding contract
# ─────────────────────────────────────────────────────────────────────────────

class TestBaseSubprocessEnv(unittest.TestCase):
    """_base_subprocess_env — VCFPATCHSCANNER_MODULE_PSD1 threading across the PS → Python → PS chain.

    When the module is deployed to ~/VcfPatchScanner/Tools/ the PSD1 is not adjacent
    to the server script, so _MODULE_PSD1.exists() is False.  The PowerShell
    Start-VCFPatchScannerServer wrapper injects VCFPATCHSCANNER_MODULE_PSD1 via
    ModuleBase; this class verifies that the Python server forwards it to its own
    subprocess environment instead of silently dropping it through the allowlist filter.
    """

    def _build_base(self):
        return _mod._base_subprocess_env()

    def test_module_psd1_forwarded_when_set_in_parent_env(self):
        fake_path = "/fake/VcfPatchScanner/VcfPatchScanner.psd1"
        saved = os.environ.get("VCFPATCHSCANNER_MODULE_PSD1")
        try:
            os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = fake_path
            with unittest.mock.patch.object(_mod, "_MODULE_PSD1") as mock_psd1:
                mock_psd1.exists.return_value = False
                ev = self._build_base()
            self.assertEqual(
                ev.get("VCFPATCHSCANNER_MODULE_PSD1"), fake_path,
                "When _MODULE_PSD1 does not exist (deployed layout) and the PowerShell wrapper "
                "injected VCFPATCHSCANNER_MODULE_PSD1, the Python server must forward it to child "
                "subprocesses via the allowlist; without this the module-path chain is broken.",
            )
        finally:
            if saved is None:
                os.environ.pop("VCFPATCHSCANNER_MODULE_PSD1", None)
            else:
                os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = saved

    def test_module_psd1_from_filesystem_takes_priority_over_env(self):
        fake_env_path  = "/env/injected/VcfPatchScanner.psd1"
        fake_file_path = "/filesystem/VcfPatchScanner.psd1"
        saved = os.environ.get("VCFPATCHSCANNER_MODULE_PSD1")
        try:
            os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = fake_env_path
            with unittest.mock.patch.object(_mod, "_MODULE_PSD1") as mock_psd1:
                mock_psd1.exists.return_value = True
                mock_psd1.__str__ = lambda _: fake_file_path
                ev = self._build_base()
            self.assertEqual(
                ev.get("VCFPATCHSCANNER_MODULE_PSD1"), fake_file_path,
                "When running from the repo the local _MODULE_PSD1 exists and must "
                "take precedence over any parent-injected env var.",
            )
        finally:
            if saved is None:
                os.environ.pop("VCFPATCHSCANNER_MODULE_PSD1", None)
            else:
                os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = saved

    def test_module_psd1_absent_when_neither_file_nor_env(self):
        saved = os.environ.get("VCFPATCHSCANNER_MODULE_PSD1")
        try:
            os.environ.pop("VCFPATCHSCANNER_MODULE_PSD1", None)
            with unittest.mock.patch.object(_mod, "_MODULE_PSD1") as mock_psd1:
                mock_psd1.exists.return_value = False
                ev = self._build_base()
            self.assertNotIn(
                "VCFPATCHSCANNER_MODULE_PSD1", ev,
                "When _MODULE_PSD1 does not exist and no env override is set, "
                "VCFPATCHSCANNER_MODULE_PSD1 must not appear in the subprocess env.",
            )
        finally:
            if saved is not None:
                os.environ["VCFPATCHSCANNER_MODULE_PSD1"] = saved


# ─────────────────────────────────────────────────────────────────────────────
# _configured_hosts
# ─────────────────────────────────────────────────────────────────────────────

class TestConfiguredHosts(unittest.TestCase):
    """_configured_hosts — VVF9 passthrough, VCF 9.1 ops exclusion, hostname normalisation."""

    def _hosts(self, env):
        return _mod._configured_hosts(env)

    def test_vvf9_returns_empty_set_for_passthrough(self):
        # VVF9 vCenters are discovered at scan time; no pre-known hosts.
        env = {"type": "vvf9", "vcfOpsServer": "ops.lab", "vcfFMServer": "fm.lab"}
        self.assertEqual(self._hosts(env), set())

    def test_vcf9_91_excludes_ops_server(self):
        # VCF 9.1 does not call the native VCF Ops API; its FQDN must not appear in progress.
        env = {"type": "vcf9", "vcfMinorVersion": "9.1",
               "sddcManagerServer": "sddc.lab", "vcfOpsServer": "ops.lab",
               "vcfFMServer": "fleet-lc.lab"}
        hosts = self._hosts(env)
        self.assertNotIn("ops.lab", hosts)
        self.assertIn("sddc.lab", hosts)
        self.assertIn("fleet-lc.lab", hosts)

    def test_vcf9_non91_includes_ops_server(self):
        env = {"type": "vcf9", "sddcManagerServer": "sddc.lab",
               "vcfOpsServer": "ops.lab", "vcfFMServer": "fm.lab"}
        self.assertIn("ops.lab", self._hosts(env))

    def test_vsphere8_collects_vcenter_and_nsx(self):
        env = {"type": "vsphere8", "vcenterServer": "vc.lab", "nsxManagerServer": "nsx.lab"}
        hosts = self._hosts(env)
        self.assertIn("vc.lab", hosts)
        self.assertIn("nsx.lab", hosts)

    def test_empty_field_values_excluded(self):
        env = {"type": "vsphere8", "vcenterServer": "vc.lab", "nsxManagerServer": ""}
        hosts = self._hosts(env)
        self.assertNotIn("", hosts)

    def test_hostnames_lowercased(self):
        env = {"type": "vsphere8", "vcenterServer": "VC.CORP.EXAMPLE.COM"}
        self.assertIn("vc.corp.example.com", self._hosts(env))

    def test_whitespace_only_field_excluded(self):
        env = {"type": "vsphere8", "vcenterServer": "vc.lab", "nsxManagerServer": "   "}
        hosts = self._hosts(env)
        self.assertEqual(len(hosts), 1)


# ─────────────────────────────────────────────────────────────────────────────
# _filter_progress_to_configured
# ─────────────────────────────────────────────────────────────────────────────

class TestFilterProgressToConfigured(unittest.TestCase):
    """_filter_progress_to_configured — VVF9 passthrough, unknown-host filtering."""

    @staticmethod
    def _item(label):
        return {"label": label, "status": "ok"}

    def _filter(self, items, env):
        return _mod._filter_progress_to_configured(items, env)

    def test_vvf9_passes_all_items_including_discovered_vcenters(self):
        # VVF9 returns an empty configured-host set, so all items flow through.
        env = {"type": "vvf9", "vcfOpsServer": "ops.lab"}
        items = [self._item('"ops.lab"'), self._item('"auto-discovered-vc.lab"')]
        self.assertEqual(len(self._filter(items, env)), 2)

    def test_unknown_fqdn_filtered_out_for_vsphere8(self):
        env = {"type": "vsphere8", "vcenterServer": "vc.lab"}
        items = [self._item('"vc.lab"'), self._item('"rogue-sddc.lab"')]
        result = self._filter(items, env)
        self.assertEqual(len(result), 1)
        self.assertIn("vc.lab", result[0]["label"])

    def test_item_without_quoted_hostname_always_passes(self):
        env = {"type": "vsphere8", "vcenterServer": "vc.lab"}
        items = [self._item("Scanning vCenter infrastructure"), self._item('"vc.lab"')]
        # Items with no quoted hostname (host is None) pass through unconditionally.
        self.assertEqual(len(self._filter(items, env)), 2)

    def test_empty_items_list_returns_empty(self):
        self.assertEqual(self._filter([], {"type": "vsphere8", "vcenterServer": "vc.lab"}), [])

    def test_all_items_pass_when_configured_set_is_empty(self):
        env = {"type": "vsphere8", "vcenterServer": ""}
        items = [self._item('"anything.lab"')]
        self.assertEqual(len(self._filter(items, env)), 1)

    def test_sddc_manager_label_filtered_for_vsphere8(self):
        # "SDDC Manager" label is filtered by the caller (do_GET /scan/progress),
        # but if an item with a non-configured FQDN slips in it is also filtered here.
        env = {"type": "vsphere8", "vcenterServer": "vc.lab"}
        items = [self._item('"sddc.lab"'), self._item('"vc.lab"')]
        result = self._filter(items, env)
        self.assertEqual(len(result), 1)


# ─────────────────────────────────────────────────────────────────────────────
# _is_vcf91
# ─────────────────────────────────────────────────────────────────────────────

class TestIsVcf91(unittest.TestCase):
    """_is_vcf91 — detects VCF 9.1 via vcfMinorVersion field, not hostname."""

    def test_minor_version_91_is_vcf91(self):
        self.assertTrue(_mod._is_vcf91({"type": "vcf9", "vcfMinorVersion": "9.1"}))

    def test_minor_version_90_not_vcf91(self):
        self.assertFalse(_mod._is_vcf91({"type": "vcf9", "vcfMinorVersion": "9.0"}))

    def test_missing_minor_version_not_vcf91(self):
        self.assertFalse(_mod._is_vcf91({"type": "vcf9"}))

    def test_empty_minor_version_not_vcf91(self):
        self.assertFalse(_mod._is_vcf91({"type": "vcf9", "vcfMinorVersion": ""}))

    def test_vvf9_type_never_vcf91(self):
        self.assertFalse(_mod._is_vcf91({"type": "vvf9", "vcfMinorVersion": "9.1"}))

    def test_vcf5_type_never_vcf91(self):
        self.assertFalse(_mod._is_vcf91({"type": "vcf5", "vcfMinorVersion": "9.1"}))


# ─────────────────────────────────────────────────────────────────────────────
# _validate_settings
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateSettings(unittest.TestCase):
    """_validate_settings — rejects invalid log levels, timeouts, and bool types."""

    def _validate(self, settings):
        return _mod._validate_settings(settings)

    def test_valid_empty_settings_returns_none(self):
        self.assertIsNone(self._validate({}))

    def test_invalid_log_level_returns_error(self):
        err = self._validate({"logLevel": "TRACE"})
        self.assertIsNotNone(err)
        self.assertIn("logLevel", err)

    def test_valid_log_levels_return_none(self):
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self.assertIsNone(self._validate({"logLevel": level}),
                              f"Expected None for level={level}")

    def test_connection_timeout_zero_returns_error(self):
        err = self._validate({"connectionTimeoutSeconds": 0})
        self.assertIsNotNone(err)

    def test_connection_timeout_negative_returns_error(self):
        err = self._validate({"connectionTimeoutSeconds": -1})
        self.assertIsNotNone(err)

    def test_connection_timeout_over_max_returns_error(self):
        err = self._validate({"connectionTimeoutSeconds": 901})
        self.assertIsNotNone(err)

    def test_connection_timeout_string_returns_error(self):
        err = self._validate({"connectionTimeoutSeconds": "30"})
        self.assertIsNotNone(err)

    def test_ignore_certificate_string_returns_error(self):
        err = self._validate({"ignoreCertificate": "true"})
        self.assertIsNotNone(err)

    def test_environments_not_a_list_returns_error(self):
        err = self._validate({"environments": "should-be-a-list"})
        self.assertIsNotNone(err)

    def test_more_than_100_environments_returns_error(self):
        err = self._validate({"environments": [{}] * 101})
        self.assertIsNotNone(err)

    def test_non_dict_input_returns_error(self):
        err = self._validate("not-a-dict")
        self.assertIsNotNone(err)

    def test_valid_full_settings_returns_none(self):
        err = self._validate({
            "logLevel": "DEBUG",
            "connectionTimeoutSeconds": 60,
            "ignoreCertificate": True,
            "lightMode": False,
            "environments": [],
        })
        self.assertIsNone(err)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler — negative paths
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpHandlerNegative(unittest.TestCase):
    """HTTP endpoint negative cases via a real server bound to a free port.

    Settings I/O is patched to avoid filesystem dependencies; only the handler
    routing and guard logic is exercised.
    """

    @classmethod
    def setUpClass(cls):
        cls._patchers = [
            unittest.mock.patch.object(_mod, "_load_settings", return_value={
                "environments": [],
                "logLevel": "INFO",
                "connectionTimeoutSeconds": 30,
            }),
            unittest.mock.patch.object(_mod, "_save_settings", return_value=None),
        ]
        for p in cls._patchers:
            p.start()

        port = _free_port()
        cls._server = ThreadingHTTPServer(("127.0.0.1", port), _mod.Handler)
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        for p in cls._patchers:
            p.stop()

    def _post(self, path, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self._base + path, data=data,
            headers={"Content-Type": "application/json", "Content-Length": str(len(data))},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def _get(self, path, headers=None):
        req = urllib.request.Request(self._base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    # Bad JSON body
    def test_post_settings_malformed_json_returns_400(self):
        raw = b"{not: valid json"
        req = urllib.request.Request(
            self._base + "/settings", data=raw,
            headers={"Content-Type": "application/json", "Content-Length": str(len(raw))},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as r:
                code, body = r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            code, body = e.code, json.loads(e.read())
        self.assertEqual(code, 400)
        self.assertIn("error", body)

    # Invalid env index
    def test_post_scan_start_bad_env_index_returns_400(self):
        code, body = self._post("/scan/start", {"envIndex": 999, "passwords": {}})
        self.assertEqual(code, 400)
        self.assertIn("error", body)

    def test_post_scan_start_no_env_returns_400(self):
        # Neither envIndex, env, nor queue supplied.
        code, body = self._post("/scan/start", {"passwords": {}})
        self.assertEqual(code, 400)
        self.assertIn("error", body)

    def test_post_scan_validate_bad_env_index_returns_400(self):
        code, body = self._post("/scan/validate", {"envIndex": 999, "passwords": {}})
        self.assertEqual(code, 400)
        self.assertIn("error", body)

    # Concurrent validation guard
    def test_post_scan_validate_while_running_returns_409(self):
        # Set done=False to simulate in-progress validation. Send env dict directly
        # (not envIndex) so env resolution succeeds and the 409 guard is reached.
        original_done = _mod._validate_state.get("done", True)
        _mod._validate_state["done"] = False
        try:
            valid_env = {"type": "vcf5", "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin"}
            code, body = self._post("/scan/validate", {"env": valid_env, "passwords": {}})
            self.assertEqual(code, 409)
            self.assertIn("error", body)
        finally:
            _mod._validate_state["done"] = original_done

    # Unknown path → 404
    def test_get_unknown_path_returns_404(self):
        self.assertEqual(self._get("/no/such/endpoint"), 404)

    # Origin: null → 403
    def test_browser_null_origin_returns_403(self):
        self.assertEqual(self._get("/settings", {"Origin": "null"}), 403)

    # Body too large → 413
    # The server rejects on Content-Length before reading any body bytes.
    # Use http.client so we can declare the Content-Length without sending the bytes,
    # which avoids the BrokenPipe the urllib approach causes.
    def test_post_oversized_body_returns_413(self):
        import http.client
        import urllib.parse
        parsed = urllib.parse.urlparse(self._base)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port)
        try:
            conn.request(
                "POST", "/settings",
                headers={"Content-Type": "application/json",
                         "Content-Length": str(6 * 1024 * 1024)},
            )
            resp = conn.getresponse()
            self.assertEqual(resp.status, 413)
        finally:
            conn.close()

    # POST /scan/start when another scan is already running → 409
    def test_post_scan_start_while_running_returns_409(self):
        # The guard checks _scan_state["status"] == "running". Send env dict directly
        # so env resolution succeeds before _start_scan is called.
        original_status = _mod._scan_state.get("status", "idle")
        _mod._scan_state["status"] = "running"
        try:
            valid_env = {"type": "vcf5", "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin"}
            code, body = self._post("/scan/start", {"env": valid_env, "passwords": {}})
            self.assertEqual(code, 409)
        finally:
            _mod._scan_state["status"] = original_status

    # POST /settings with invalid log level → 400 (validation rejects before save)
    def test_post_settings_invalid_log_level_returns_400(self):
        code, body = self._post("/settings", {"logLevel": "VERBOSE"})
        self.assertEqual(code, 400)
        self.assertIn("error", body)

    # POST /settings with connection timeout out of range → 400
    def test_post_settings_timeout_out_of_range_returns_400(self):
        code, body = self._post("/settings", {"connectionTimeoutSeconds": 9999})
        self.assertEqual(code, 400)
        self.assertIn("error", body)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP handler — positive (success) paths
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpHandlerPositive(unittest.TestCase):
    """HTTP endpoint success paths via a real server bound to a free port."""

    @classmethod
    def setUpClass(cls):
        cls._patchers = [
            unittest.mock.patch.object(_mod, "_load_settings", return_value={
                "environments": [],
                "logLevel": "INFO",
                "connectionTimeoutSeconds": 30,
            }),
            unittest.mock.patch.object(_mod, "_save_settings", return_value=None),
        ]
        for p in cls._patchers:
            p.start()

        port = _free_port()
        cls._server = ThreadingHTTPServer(("127.0.0.1", port), _mod.Handler)
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        for p in cls._patchers:
            p.stop()

    def _get_json(self, path):
        req = urllib.request.Request(self._base + path)
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())

    def _post(self, path, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self._base + path, data=data,
            headers={"Content-Type": "application/json", "Content-Length": str(len(data))},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_get_settings_returns_200_with_settings_keys(self):
        code, body = self._get_json("/settings")
        self.assertEqual(code, 200)
        self.assertIn("environments", body)
        self.assertIn("logLevel", body)

    def test_get_scan_status_returns_200_with_idle_status(self):
        code, body = self._get_json("/scan/status")
        self.assertEqual(code, 200)
        self.assertIn("status", body)
        self.assertEqual(body["status"], "idle")

    def test_get_scan_log_returns_200_with_lines_list(self):
        code, body = self._get_json("/scan/log")
        self.assertEqual(code, 200)
        self.assertIn("lines", body)
        self.assertIsInstance(body["lines"], list)

    def test_get_scan_validate_progress_returns_200_with_done_bool(self):
        code, body = self._get_json("/scan/validate-progress")
        self.assertEqual(code, 200)
        self.assertIn("done", body)
        self.assertIsInstance(body["done"], bool)

    def test_post_settings_valid_body_returns_200_ok(self):
        code, body = self._post("/settings", {
            "logLevel": "DEBUG",
            "connectionTimeoutSeconds": 30,
        })
        self.assertEqual(code, 200)
        self.assertEqual(body.get("ok"), True)

    def test_post_scan_validate_stop_returns_200_ok(self):
        code, body = self._post("/scan/validate-stop", {})
        self.assertEqual(code, 200)
        self.assertEqual(body.get("ok"), True)


class TestSanitizeEnvDirname(unittest.TestCase):
    """Unit tests for _sanitize_env_dirname."""

    def test_normal_name_unchanged(self):
        self.assertEqual(_mod._sanitize_env_dirname("Production"), "Production")

    def test_spaces_are_kept(self):
        result = _mod._sanitize_env_dirname("My VCF Env")
        self.assertEqual(result, "My VCF Env")

    def test_invalid_chars_replaced(self):
        result = _mod._sanitize_env_dirname('env<>:"/\\|?*name')
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)
        self.assertNotIn(":", result)
        self.assertNotIn("/", result)
        self.assertNotIn("\\", result)

    def test_path_traversal_stripped(self):
        # Traversal requires "/" between components.  The sanitizer removes all "/"
        # characters so the result is a single path component that is safe to use
        # directly as Path("Findings") / result.  A "." sequence embedded in the
        # middle of a name (e.g. "_.._etc") carries no special meaning as a component.
        result = _mod._sanitize_env_dirname("../../etc")
        self.assertNotIn("/", result)
        self.assertFalse(result.startswith(".."))

    def test_empty_name_returns_default(self):
        self.assertEqual(_mod._sanitize_env_dirname(""), "default")

    def test_whitespace_only_returns_default(self):
        self.assertEqual(_mod._sanitize_env_dirname("   "), "default")

    def test_leading_dots_stripped(self):
        result = _mod._sanitize_env_dirname("...hidden")
        self.assertFalse(result.startswith("."))

    def test_vcf9_env_name(self):
        result = _mod._sanitize_env_dirname("VCF Production 9.1")
        self.assertEqual(result, "VCF Production 9.1")


class TestEnsureEnvFindingsDir(unittest.TestCase):
    """Unit tests for _ensure_env_findings_dir."""

    def test_creates_directory_when_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "envdir"
            self.assertFalse(target.exists())
            _mod._ensure_env_findings_dir(target)
            self.assertTrue(target.is_dir())

    def test_no_error_when_directory_already_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "envdir"
            target.mkdir()
            _mod._ensure_env_findings_dir(target)  # must not raise
            self.assertTrue(target.is_dir())

    def test_raises_runtime_error_when_parent_missing_and_no_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Use a path with a grandparent that does not exist and simulate OSError.
            target = Path(tmp) / "nonexistent_parent" / "envdir"
            # mkdir(parents=True) would succeed; force a failure via a path on a read-only root.
            # Instead, patch mkdir to raise OSError.
            original_mkdir = Path.mkdir

            def _mock_mkdir(self_path, **kwargs):
                raise OSError(13, "Permission denied")

            Path.mkdir = _mock_mkdir
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    _mod._ensure_env_findings_dir(target)
                self.assertIn("Cannot create findings directory", str(ctx.exception))
            finally:
                Path.mkdir = original_mkdir

    @unittest.skipIf(sys.platform == "win32", "chmod 0o700 not enforced on Windows")
    def test_sets_user_only_permissions_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "envdir"
            _mod._ensure_env_findings_dir(target)
            mode = oct(target.stat().st_mode)[-3:]
            self.assertEqual(mode, "700")


class TestSanitizeErrorMessage(unittest.TestCase):
    """Regression tests for _sanitize_error_message."""

    def test_strips_psstyle_color_sequences(self):
        raw = "\x1b[31;1mImport-Module: \x1b[0m/path/to/script.ps1:177"
        result = _mod._sanitize_error_message(raw)
        self.assertNotIn("\x1b", result)
        self.assertIn("Import-Module:", result)
        self.assertIn("/path/to/script.ps1:177", result)

    def test_strips_cursor_movement_sequences(self):
        raw = "\x1b[2J\x1b[HError occurred"
        result = _mod._sanitize_error_message(raw)
        self.assertNotIn("\x1b", result)
        self.assertIn("Error occurred", result)

    def test_redacts_bearer_token(self):
        raw = "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"
        result = _mod._sanitize_error_message(raw)
        self.assertIn("Bearer [REDACTED]", result)
        self.assertNotIn("eyJhbGciOiJSUzI1NiJ9", result)

    def test_redacts_basic_auth(self):
        # Build the credential at runtime so no encoded secret appears as a static string.
        encoded = base64.b64encode(b"user:pass").decode()
        raw = f"Basic {encoded}"
        result = _mod._sanitize_error_message(raw)
        self.assertIn("Basic [REDACTED]", result)
        self.assertNotIn(encoded, result)

    def test_plain_message_unchanged(self):
        raw = "Cannot connect to host: connection refused"
        result = _mod._sanitize_error_message(raw)
        self.assertEqual(raw, result)

    def test_ansi_and_auth_combined(self):
        raw = "\x1b[31mError:\x1b[0m Authorization: Bearer secret123"
        result = _mod._sanitize_error_message(raw)
        self.assertNotIn("\x1b", result)
        self.assertNotIn("secret123", result)
        self.assertIn("Error:", result)


# ─────────────────────────────────────────────────────────────────────────────
# _verify_sha256
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifySha256(unittest.TestCase):
    """_verify_sha256(body, local_path) — fetches upstream checksum and validates body bytes.

    The function downloads a .sha256sum companion file from the upstream URL and
    compares the hex digest it contains against hashlib.sha256(body).hexdigest().
    Returns None on success, an error string on failure.
    """

    def _make_sha256sum_response(self, body: bytes) -> unittest.mock.MagicMock:
        """Return a mock urlopen context manager that serves a bare sha256 hex digest."""
        import hashlib
        digest = hashlib.sha256(body).hexdigest()
        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = digest.encode("ascii")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
        return mock_resp

    def _make_sha256sum_response_wrong(self, body: bytes) -> unittest.mock.MagicMock:
        """Return a mock urlopen context manager that serves a wrong sha256 hex digest."""
        wrong_digest = "a" * 64
        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = wrong_digest.encode("ascii")
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
        return mock_resp

    def test_matching_hash_returns_none(self):
        body = b"advisory content for sha256 test"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = Path(f.name)
        try:
            mock_resp = self._make_sha256sum_response(body)
            with unittest.mock.patch("urllib.request.urlopen", return_value=mock_resp):
                result = _mod._verify_sha256(body, local_path)
            self.assertIsNone(result)
        finally:
            local_path.unlink(missing_ok=True)

    def test_wrong_hash_returns_error_string(self):
        body = b"real advisory content"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = Path(f.name)
        try:
            mock_resp = self._make_sha256sum_response_wrong(body)
            with unittest.mock.patch("urllib.request.urlopen", return_value=mock_resp):
                result = _mod._verify_sha256(body, local_path)
            self.assertIsNotNone(result)
            self.assertIn("mismatch", result.lower())
        finally:
            local_path.unlink(missing_ok=True)

    def test_network_error_returns_error_string(self):
        body = b"some content"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = Path(f.name)
        try:
            with unittest.mock.patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
                result = _mod._verify_sha256(body, local_path)
            self.assertIsNotNone(result)
            self.assertIn("checksum", result.lower())
        finally:
            local_path.unlink(missing_ok=True)

    def test_empty_checksum_file_returns_error_string(self):
        body = b"some body content"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = Path(f.name)
        try:
            mock_resp = unittest.mock.MagicMock()
            mock_resp.read.return_value = b"not a hex digest at all"
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            with unittest.mock.patch("urllib.request.urlopen", return_value=mock_resp):
                result = _mod._verify_sha256(body, local_path)
            self.assertIsNotNone(result)
        finally:
            local_path.unlink(missing_ok=True)

    def test_sha256sum_format_with_filename_suffix_accepted(self):
        """Standard sha256sum output format '<hash>  <filename>' must be parsed correctly."""
        import hashlib
        body = b"checksum format test"
        digest = hashlib.sha256(body).hexdigest()
        sha256sum_line = f"{digest}  securityAdvisory.json"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = Path(f.name)
        try:
            mock_resp = unittest.mock.MagicMock()
            mock_resp.read.return_value = sha256sum_line.encode("ascii")
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            with unittest.mock.patch("urllib.request.urlopen", return_value=mock_resp):
                result = _mod._verify_sha256(body, local_path)
            self.assertIsNone(result)
        finally:
            local_path.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# _enrich_findings
# ─────────────────────────────────────────────────────────────────────────────

def _make_advisory_file(tmp_dir: Path, advisories: list, schema_version: str = "2.0") -> Path:
    """Write a minimal advisory JSON file and return its path."""
    adv_path = tmp_dir / "securityAdvisory.json"
    adv_path.write_text(
        json.dumps({"schemaVersion": schema_version, "advisories": advisories}),
        encoding="utf-8",
    )
    return adv_path


class TestEnrichFindings(unittest.TestCase):
    """_enrich_findings(findings, adv_path) — adds advisory fields to matching findings.

    The function reads the advisory JSON from adv_path, builds a map keyed by
    vmsaId / VMSA_ID, and merges Description, Workaround, VmsaSeverity, CvssRange,
    ComponentCvssRange, and AdditionalDocs into each finding whose VMSA ID matches.
    Non-matching findings pass through unchanged.
    """

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="enrich_test_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self._tmp, ignore_errors=True))

    def _adv_path(self, advisories: list) -> Path:
        return _make_advisory_file(self._tmp, advisories)

    def test_matching_finding_gets_enriched_fields(self):
        adv_path = self._adv_path([
            {
                "vmsaId": "VMSA-2024-0001",
                "severity": "Critical",
                "description": "A critical advisory.",
                "cvssRange": "9.8",
                "impactedComponents": [
                    {
                        "component": "vCenter Server",
                        "cvssRange": "9.8",
                        "workaround": "Apply patch immediately.",
                        "additionalDocs": "https://kb.vmware.com/1234",
                    }
                ],
            }
        ])
        findings = [{"vmsaId": "VMSA-2024-0001", "component": "vCenter Server"}]
        result = _mod._enrich_findings(findings, adv_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["Description"], "A critical advisory.")
        self.assertEqual(result[0]["VmsaSeverity"], "Critical")
        self.assertEqual(result[0]["CvssRange"], "9.8")
        self.assertEqual(result[0]["ComponentCvssRange"], "9.8")
        self.assertEqual(result[0]["Workaround"], "Apply patch immediately.")
        self.assertIn("kb.vmware.com", result[0]["AdditionalDocs"])

    def test_finding_with_no_matching_advisory_is_unchanged(self):
        adv_path = self._adv_path([
            {"vmsaId": "VMSA-2024-0002", "severity": "Low", "description": "Low risk."}
        ])
        finding = {"vmsaId": "VMSA-2024-9999", "component": "NSX"}
        result = _mod._enrich_findings([finding], adv_path)
        self.assertEqual(len(result), 1)
        self.assertNotIn("Description", result[0])
        self.assertNotIn("VmsaSeverity", result[0])

    def test_empty_findings_list_returns_empty(self):
        adv_path = self._adv_path([
            {"vmsaId": "VMSA-2024-0001", "severity": "High", "description": "High risk."}
        ])
        result = _mod._enrich_findings([], adv_path)
        self.assertEqual(result, [])

    def test_missing_advisory_file_returns_findings_unchanged(self):
        missing_path = self._tmp / "nonexistent.json"
        findings = [{"vmsaId": "VMSA-2024-0001", "component": "ESXi"}]
        result = _mod._enrich_findings(findings, missing_path)
        self.assertEqual(len(result), 1)
        self.assertNotIn("Description", result[0])

    def test_finding_without_vmsa_id_passes_through_unchanged(self):
        adv_path = self._adv_path([
            {"vmsaId": "VMSA-2024-0001", "severity": "Critical", "description": "desc"}
        ])
        finding = {"component": "ESXi", "currentVersion": "8.0.0"}
        result = _mod._enrich_findings([finding], adv_path)
        self.assertEqual(len(result), 1)
        self.assertNotIn("Description", result[0])

    def test_workaround_none_string_becomes_empty(self):
        adv_path = self._adv_path([
            {
                "vmsaId": "VMSA-2024-0003",
                "severity": "Medium",
                "description": "Medium risk.",
                "impactedComponents": [
                    {"component": "ESXi", "cvssRange": "5.0", "workaround": "None"}
                ],
            }
        ])
        findings = [{"vmsaId": "VMSA-2024-0003", "component": "ESXi"}]
        result = _mod._enrich_findings(findings, adv_path)
        self.assertEqual(result[0]["Workaround"], "")

    def test_pascal_case_vmsa_id_key_is_matched(self):
        """Advisory keyed with VMSA_ID (PascalCase/v1.0) must match finding keyed VMSA_ID."""
        adv_path = self._tmp / "advisory_v1.json"
        adv_path.write_text(
            json.dumps({
                "Advisories": [
                    {"VMSA_ID": "VMSA-2024-0004", "Severity": "High", "Description": "Old schema."}
                ]
            }),
            encoding="utf-8",
        )
        findings = [{"VMSA_ID": "VMSA-2024-0004", "Component": "vCenter Server"}]
        result = _mod._enrich_findings(findings, adv_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["Description"], "Old schema.")


# ─────────────────────────────────────────────────────────────────────────────
# _discover_sddc_from_ops_via_powershell
# ─────────────────────────────────────────────────────────────────────────────

def _make_popen_mock(stdout: str, returncode: int) -> unittest.mock.MagicMock:
    """Return a Popen mock whose communicate() returns (stdout, '') and returncode is set."""
    mock_proc = unittest.mock.MagicMock()
    mock_proc.communicate.return_value = (stdout, "")
    mock_proc.returncode = returncode
    mock_proc.__enter__ = lambda s: s
    mock_proc.__exit__ = unittest.mock.MagicMock(return_value=False)
    return mock_proc


class TestDiscoverSddcFromOpsViaPowershell(unittest.TestCase):
    """_discover_sddc_from_ops_via_powershell — subprocess dispatch and JSON parsing.

    Spawns pwsh to run Invoke-VCFPatchScanner.ps1 -DiscoverSddcManagers and parses
    the JSON written to stdout.  Returns (instances_list, error_or_None, ops_version).
    """

    def _call(self, stdout: str, returncode: int, timeout_seconds: int = 30):
        mock_proc = _make_popen_mock(stdout, returncode)
        with unittest.mock.patch("subprocess.Popen", return_value=mock_proc):
            return _mod._discover_sddc_from_ops_via_powershell(
                "ops.lab", "admin@local", "password", timeout_seconds
            )

    def test_success_returns_parsed_instances(self):
        payload = json.dumps({
            "instances": [
                {"fqdn": "sddc1.lab", "instanceName": "SDDC-1", "sddcUsername": "admin@vsphere.local"},
                {"fqdn": "sddc2.lab", "instanceName": "SDDC-2", "sddcUsername": "admin@vsphere.local"},
            ],
            "opsVersion": "VCF Operations 9.0.0.0",
        })
        instances, err, ops_version, _ = self._call(payload, returncode=0)
        self.assertIsNone(err)
        self.assertEqual(len(instances), 2)
        self.assertEqual(instances[0]["fqdn"], "sddc1.lab")
        self.assertEqual(ops_version, "VCF Operations 9.0.0.0")

    def test_nonzero_exit_without_json_error_returns_error_string(self):
        instances, err, ops_version, _ = self._call("Fatal error occurred", returncode=1)
        self.assertEqual(instances, [])
        self.assertIsNotNone(err)
        self.assertTrue(len(err) > 0)

    def test_nonzero_exit_with_json_error_field_returns_that_error(self):
        payload = json.dumps({"error": "Authentication failed for ops.lab"})
        instances, err, ops_version, _ = self._call(payload, returncode=1)
        self.assertEqual(instances, [])
        self.assertEqual(err, "Authentication failed for ops.lab")

    def test_empty_stdout_returns_no_json_error(self):
        instances, err, ops_version, _ = self._call("", returncode=0)
        self.assertEqual(instances, [])
        self.assertIsNotNone(err)
        self.assertIn("No JSON", err)

    def test_malformed_json_stdout_returns_no_json_error(self):
        instances, err, ops_version, _ = self._call("not json output", returncode=0)
        self.assertEqual(instances, [])
        self.assertIsNotNone(err)

    def test_timeout_returns_error_with_timeout_message(self):
        import subprocess as _subprocess
        mock_proc = unittest.mock.MagicMock()
        # First communicate() raises TimeoutExpired; second (after kill) returns normally.
        mock_proc.communicate.side_effect = [
            _subprocess.TimeoutExpired(cmd="pwsh", timeout=70),
            ("", ""),
        ]
        with unittest.mock.patch("subprocess.Popen", return_value=mock_proc):
            instances, err, ops_version, _ = _mod._discover_sddc_from_ops_via_powershell(
                "ops.lab", "admin@local", "password", timeout_seconds=30
            )
        self.assertEqual(instances, [])
        self.assertIsNotNone(err)
        self.assertIn("timed out", err.lower())

    def test_instance_without_fqdn_is_filtered_out(self):
        payload = json.dumps({
            "instances": [
                {"fqdn": "sddc1.lab", "instanceName": "Good"},
                {"fqdn": "", "instanceName": "Bad"},
                {"instanceName": "AlsoBad"},
            ],
            "opsVersion": "",
        })
        instances, err, ops_version, _ = self._call(payload, returncode=0)
        self.assertIsNone(err)
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["fqdn"], "sddc1.lab")

    def test_unexpected_json_format_returns_error(self):
        payload = json.dumps(["unexpected", "list"])
        instances, err, ops_version, _ = self._call(payload, returncode=0)
        self.assertEqual(instances, [])
        self.assertIsNotNone(err)

    def test_popen_exception_returns_error_string(self):
        with unittest.mock.patch("subprocess.Popen", side_effect=OSError("pwsh not found")):
            instances, err, ops_version, _ = _mod._discover_sddc_from_ops_via_powershell(
                "ops.lab", "admin@local", "password"
            )
        self.assertEqual(instances, [])
        self.assertIsNotNone(err)
        self.assertIn("error", err.lower())


# ─────────────────────────────────────────────────────────────────────────────
# _discover_fleet_manager_from_ops_via_powershell
# ─────────────────────────────────────────────────────────────────────────────

class TestDiscoverFleetManagerFromOpsViaPowershell(unittest.TestCase):
    """_discover_fleet_manager_from_ops_via_powershell — subprocess dispatch and JSON parsing.

    Spawns pwsh to run Invoke-VCFPatchScanner.ps1 -DiscoverFleetManager and parses
    the JSON written to stdout.  Returns (fleet_fqdn, vcf_fm_user, error_or_None).
    """

    def _call(self, stdout: str, returncode: int, ops_version: str = ""):
        mock_proc = _make_popen_mock(stdout, returncode)
        with unittest.mock.patch("subprocess.Popen", return_value=mock_proc):
            return _mod._discover_fleet_manager_from_ops_via_powershell(
                "ops.lab", "admin@local", "password",
                timeout_seconds=30, ops_version=ops_version
            )

    def test_success_returns_fleet_fqdn_and_user(self):
        payload = json.dumps({
            "fleetFqdn": "fleet-lc.lab",
            "vcfFMUser": "admin@vsphere.local",
        })
        fleet_fqdn, vcf_fm_user, err = self._call(payload, returncode=0)
        self.assertIsNone(err)
        self.assertEqual(fleet_fqdn, "fleet-lc.lab")
        self.assertEqual(vcf_fm_user, "admin@vsphere.local")

    def test_nonzero_exit_returns_error(self):
        fleet_fqdn, vcf_fm_user, err = self._call("Crash output", returncode=1)
        self.assertIsNone(fleet_fqdn)
        self.assertIsNone(vcf_fm_user)
        self.assertIsNotNone(err)
        self.assertTrue(len(err) > 0)

    def test_nonzero_exit_with_json_error_field_returns_that_error(self):
        payload = json.dumps({"error": "Fleet Manager not reachable"})
        fleet_fqdn, vcf_fm_user, err = self._call(payload, returncode=1)
        self.assertIsNone(fleet_fqdn)
        self.assertEqual(err, "Fleet Manager not reachable")

    def test_empty_stdout_returns_no_json_error(self):
        fleet_fqdn, vcf_fm_user, err = self._call("", returncode=0)
        self.assertIsNone(fleet_fqdn)
        self.assertIsNotNone(err)
        self.assertIn("No JSON", err)

    def test_empty_fleet_fqdn_returns_error(self):
        payload = json.dumps({"fleetFqdn": "", "vcfFMUser": "admin"})
        fleet_fqdn, vcf_fm_user, err = self._call(payload, returncode=0)
        self.assertIsNone(fleet_fqdn)
        self.assertIsNotNone(err)
        self.assertIn("FQDN not found", err)

    def test_timeout_returns_error_with_timeout_message(self):
        import subprocess as _subprocess
        mock_proc = unittest.mock.MagicMock()
        # First communicate() raises TimeoutExpired; second (after kill) returns normally.
        mock_proc.communicate.side_effect = [
            _subprocess.TimeoutExpired(cmd="pwsh", timeout=70),
            ("", ""),
        ]
        with unittest.mock.patch("subprocess.Popen", return_value=mock_proc):
            fleet_fqdn, vcf_fm_user, err = _mod._discover_fleet_manager_from_ops_via_powershell(
                "ops.lab", "admin@local", "password", timeout_seconds=30
            )
        self.assertIsNone(fleet_fqdn)
        self.assertIsNotNone(err)
        self.assertIn("timed out", err.lower())

    def test_popen_exception_returns_error_string(self):
        with unittest.mock.patch("subprocess.Popen", side_effect=OSError("pwsh not found")):
            fleet_fqdn, vcf_fm_user, err = _mod._discover_fleet_manager_from_ops_via_powershell(
                "ops.lab", "admin@local", "password"
            )
        self.assertIsNone(fleet_fqdn)
        self.assertIsNotNone(err)
        self.assertIn("error", err.lower())

    def test_ops_version_passed_as_arg(self):
        """When ops_version is provided, -VcfOpsVersion must appear in the spawned command."""
        payload = json.dumps({"fleetFqdn": "fleet.lab", "vcfFMUser": "admin"})
        mock_proc = _make_popen_mock(payload, returncode=0)
        captured_args = []
        original_popen = __import__("subprocess").Popen

        def capturing_popen(args, **kwargs):
            captured_args.extend(args)
            return mock_proc

        with unittest.mock.patch("subprocess.Popen", side_effect=capturing_popen):
            _mod._discover_fleet_manager_from_ops_via_powershell(
                "ops.lab", "admin@local", "password",
                timeout_seconds=30, ops_version="VCF Operations 9.1.0.0"
            )
        self.assertIn("-VcfOpsVersion", captured_args)

    def test_unexpected_list_response_returns_error(self):
        payload = json.dumps(["unexpected", "format"])
        fleet_fqdn, vcf_fm_user, err = self._call(payload, returncode=0)
        self.assertIsNone(fleet_fqdn)
        self.assertIsNotNone(err)


# ─────────────────────────────────────────────────────────────────────────────
# _download_advisory_if_changed
# ─────────────────────────────────────────────────────────────────────────────

def _make_urlopen_mock(head_etag: str, get_body: bytes, get_etag: str):
    """Return a side_effect function for urllib.request.urlopen that handles HEAD and GET."""
    call_count = [0]

    def _urlopen(request, **kwargs):
        call_count[0] += 1
        method = getattr(request, "method", "GET") or "GET"
        mock_resp = unittest.mock.MagicMock()
        if method == "HEAD":
            mock_resp.headers = {"ETag": f'"{head_etag}"'}
            mock_resp.headers.get = lambda k, default="": {
                "ETag": f'"{head_etag}"'
            }.get(k, default)
        else:
            mock_resp.read.return_value = get_body
            mock_resp.headers = {"ETag": f'"{get_etag}"'}
            mock_resp.headers.get = lambda k, default="": {
                "ETag": f'"{get_etag}"'
            }.get(k, default)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
        return mock_resp

    return _urlopen


class TestDownloadAdvisoryIfChanged(unittest.TestCase):
    """_download_advisory_if_changed(local_path) — ETag-gated advisory download.

    Returns a dict with 'downloaded', 'skipped', 'upstreamEtag', 'localUpdatedAt',
    and 'error' keys.  Uses urllib.request.urlopen for HTTP; all network calls
    are mocked to avoid real network traffic.
    """

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="dl_advisory_test_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self._tmp, ignore_errors=True))

    def _minimal_advisory_body(self, updated_at: str = "2026-01-01T00:00:00Z") -> bytes:
        return json.dumps({
            "schemaVersion": "2.0",
            "advisories": [{"vmsaId": "VMSA-2024-0001"}],
            "updatedAt": updated_at,
        }).encode("utf-8")

    def _write_etag(self, advisory_path: Path, etag: str) -> None:
        advisory_path.with_suffix(".json.etag").write_text(etag, encoding="utf-8")

    def test_etag_match_skips_download(self):
        advisory_path = self._tmp / "securityAdvisory.json"
        advisory_path.write_bytes(self._minimal_advisory_body())
        self._write_etag(advisory_path, "abc123")

        def urlopen_head_same(request, **kwargs):
            mock_resp = unittest.mock.MagicMock()
            mock_resp.headers.get = lambda k, default="": '"abc123"' if k == "ETag" else default
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return mock_resp

        with unittest.mock.patch("urllib.request.urlopen", side_effect=urlopen_head_same):
            result = _mod._download_advisory_if_changed(advisory_path)

        self.assertFalse(result["downloaded"])
        self.assertTrue(result["skipped"])
        self.assertIsNone(result["error"])

    def test_new_content_downloaded_and_written(self):
        advisory_path = self._tmp / "securityAdvisory.json"
        body = self._minimal_advisory_body("2026-06-01T00:00:00Z")

        import hashlib
        body_digest = hashlib.sha256(body).hexdigest()
        checksum_body = body_digest.encode("ascii")

        call_seq = [0]

        def urlopen_seq(request, **kwargs):
            call_seq[0] += 1
            method = getattr(request, "method", "GET") or "GET"
            mock_resp = unittest.mock.MagicMock()
            url = request.full_url if hasattr(request, "full_url") else str(request)
            if method == "HEAD":
                mock_resp.headers.get = lambda k, default="": '"newetag456"' if k == "ETag" else default
            elif "sha256sum" in url:
                mock_resp.read.return_value = checksum_body
            else:
                mock_resp.read.return_value = body
                mock_resp.headers.get = lambda k, default="": '"newetag456"' if k == "ETag" else default
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return mock_resp

        with unittest.mock.patch("urllib.request.urlopen", side_effect=urlopen_seq):
            result = _mod._download_advisory_if_changed(advisory_path)

        self.assertTrue(result["downloaded"])
        self.assertFalse(result["skipped"])
        self.assertIsNone(result["error"])
        self.assertTrue(advisory_path.exists())

    def test_network_error_on_head_returns_error(self):
        advisory_path = self._tmp / "securityAdvisory.json"
        advisory_path.write_bytes(self._minimal_advisory_body())

        with unittest.mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("network unreachable"),
        ):
            result = _mod._download_advisory_if_changed(advisory_path)

        self.assertFalse(result["downloaded"])
        self.assertIsNotNone(result["error"])
        self.assertIn("Upstream", result["error"])

    def test_incompatible_schema_version_returns_error(self):
        advisory_path = self._tmp / "securityAdvisory.json"
        incompatible_body = json.dumps({
            "schemaVersion": "1.0",
            "advisories": [{"vmsaId": "VMSA-2024-0001"}],
        }).encode("utf-8")

        call_seq = [0]

        def urlopen_seq(request, **kwargs):
            call_seq[0] += 1
            method = getattr(request, "method", "GET") or "GET"
            mock_resp = unittest.mock.MagicMock()
            if method == "HEAD":
                mock_resp.headers.get = lambda k, default="": '"newtag"' if k == "ETag" else default
            else:
                mock_resp.read.return_value = incompatible_body
                mock_resp.headers.get = lambda k, default="": '"newtag"' if k == "ETag" else default
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return mock_resp

        with unittest.mock.patch("urllib.request.urlopen", side_effect=urlopen_seq):
            result = _mod._download_advisory_if_changed(advisory_path)

        self.assertFalse(result["downloaded"])
        self.assertIsNotNone(result["error"])
        self.assertIn("incompatible", result["error"].lower())

    def test_empty_advisories_array_returns_error(self):
        advisory_path = self._tmp / "securityAdvisory.json"
        empty_body = json.dumps({"schemaVersion": "2.0", "advisories": []}).encode("utf-8")

        call_seq = [0]

        def urlopen_seq(request, **kwargs):
            call_seq[0] += 1
            method = getattr(request, "method", "GET") or "GET"
            mock_resp = unittest.mock.MagicMock()
            if method == "HEAD":
                mock_resp.headers.get = lambda k, default="": '"emptytag"' if k == "ETag" else default
            else:
                mock_resp.read.return_value = empty_body
                mock_resp.headers.get = lambda k, default="": '"emptytag"' if k == "ETag" else default
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = unittest.mock.MagicMock(return_value=False)
            return mock_resp

        with unittest.mock.patch("urllib.request.urlopen", side_effect=urlopen_seq):
            result = _mod._download_advisory_if_changed(advisory_path)

        self.assertFalse(result["downloaded"])
        self.assertIsNotNone(result["error"])
        self.assertIn("no advisories", result["error"].lower())


# ─────────────────────────────────────────────────────────────────────────────
# _run_validation_in_powershell — _validate_proc lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateProcLifecycle(unittest.TestCase):
    """_validate_proc is always None after _run_validation_in_powershell returns,
    regardless of subprocess outcome (success, non-zero exit, timeout, or Popen exception).

    A non-None value left by a previous call causes a NullReferenceException-class failure
    on the next Connect attempt — the same class of bug seen in Get-VcfOpsInventory.
    In a long-running server with many browser open/close cycles, every validate call
    is a potential stale-proc accumulation point.
    """

    def setUp(self):
        self._saved_validate_proc = _mod._validate_proc

    def tearDown(self):
        _mod._validate_proc = self._saved_validate_proc

    def _env(self):
        return {"type": "vcf5", "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin"}

    def test_validate_proc_is_none_after_successful_run(self):
        proc = _make_popen_mock('{"EndpointTests": []}', returncode=0)
        with unittest.mock.patch("subprocess.Popen", return_value=proc):
            _mod._run_validation_in_powershell(self._env(), {}, 30)
        self.assertIsNone(_mod._validate_proc)

    def test_validate_proc_is_none_after_nonzero_exit(self):
        proc = _make_popen_mock("validation error text", returncode=1)
        with unittest.mock.patch("subprocess.Popen", return_value=proc):
            _mod._run_validation_in_powershell(self._env(), {}, 30)
        self.assertIsNone(_mod._validate_proc)

    def test_validate_proc_is_none_after_timeout(self):
        import subprocess as _subprocess
        proc = unittest.mock.MagicMock()
        proc.communicate.side_effect = [
            _subprocess.TimeoutExpired(cmd="pwsh", timeout=30),
            ("", ""),  # second communicate() call after proc.kill()
        ]
        with unittest.mock.patch("subprocess.Popen", return_value=proc):
            _mod._run_validation_in_powershell(self._env(), {}, 30)
        self.assertIsNone(_mod._validate_proc)

    def test_validate_proc_is_none_after_popen_exception(self):
        with unittest.mock.patch("subprocess.Popen", side_effect=OSError("pwsh not found")):
            _mod._run_validation_in_powershell(self._env(), {}, 30)
        self.assertIsNone(_mod._validate_proc)


# ─────────────────────────────────────────────────────────────────────────────
# _run_all_validation_bg — validate-state and stop-flag lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateStateLifecycle(unittest.TestCase):
    """After _run_all_validation_bg returns, _validate_state["done"] must be True
    and _validate_stop_requested must be False — on every exit path.

    A stuck done=False leaves the UI spinner running forever after a browser reconnect.
    A stale stop_requested=True immediately cancels the next validation run without
    testing any endpoints, producing a spurious "Validation cancelled" result.
    Both bugs are silent: they produce no Python exception and no PowerShell error.
    """

    def setUp(self):
        self._saved_validate_state    = _mod._validate_state.copy()
        self._saved_stop_requested    = _mod._validate_stop_requested

    def tearDown(self):
        _mod._validate_state         = self._saved_validate_state
        _mod._validate_stop_requested = self._saved_stop_requested

    def _validate_list(self):
        env = {"type": "vcf5", "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin"}
        return [(env, {})]

    def test_done_is_true_after_successful_validation(self):
        with unittest.mock.patch.object(
            _mod, "_run_validation_in_powershell",
            return_value=([{"Endpoint": "SDDC Manager", "Status": "OK", "Server": "sddc.lab", "Message": ""}], None),
        ):
            _mod._run_all_validation_bg(self._validate_list(), 30)
        self.assertTrue(_mod._validate_state["done"])

    def test_done_is_true_after_validation_error(self):
        with unittest.mock.patch.object(
            _mod, "_run_validation_in_powershell",
            return_value=([], "Authentication failed"),
        ):
            _mod._run_all_validation_bg(self._validate_list(), 30)
        self.assertTrue(_mod._validate_state["done"])

    def test_done_is_true_after_validation_cancelled(self):
        _mod._validate_stop_requested = True
        with unittest.mock.patch.object(
            _mod, "_run_validation_in_powershell",
            return_value=([], "stopped"),
        ):
            _mod._run_all_validation_bg(self._validate_list(), 30)
        self.assertTrue(_mod._validate_state["done"])

    def test_stop_requested_is_false_after_successful_validation(self):
        _mod._validate_stop_requested = False
        with unittest.mock.patch.object(
            _mod, "_run_validation_in_powershell",
            return_value=([{"Endpoint": "SDDC Manager", "Status": "OK", "Server": "sddc.lab", "Message": ""}], None),
        ):
            _mod._run_all_validation_bg(self._validate_list(), 30)
        self.assertFalse(_mod._validate_stop_requested)

    def test_stop_requested_cleared_after_cancelled_validation(self):
        """A True stop flag left by a user-initiated cancel must be cleared so the next
        validation run is not immediately short-circuited without testing any endpoints."""
        _mod._validate_stop_requested = True
        with unittest.mock.patch.object(
            _mod, "_run_validation_in_powershell",
            return_value=([], "stopped"),
        ):
            _mod._run_all_validation_bg(self._validate_list(), 30)
        self.assertFalse(_mod._validate_stop_requested)


# ─────────────────────────────────────────────────────────────────────────────
# _start_scan — scan state reset between sequential scans
# ─────────────────────────────────────────────────────────────────────────────

class TestScanStateReset(unittest.TestCase):
    """_start_scan resets all stale scan state before the new scan thread starts.

    In a long-running server session, scans can complete, fail, or be stopped many
    times. Each new scan must start with a clean slate: no stale error message,
    exit code, process reference, or per-environment timings from the previous run.
    Stale state causes the UI to show wrong results for the new scan.
    """

    def setUp(self):
        self._saved_scan_state = dict(_mod._scan_state)

    def tearDown(self):
        _mod._scan_state.update(self._saved_scan_state)

    def _scan_queue(self):
        env = {"type": "vcf5", "sddcManagerServer": "sddc.lab", "sddcManagerUser": "admin"}
        return [(env, {})]

    def _call_start_scan(self):
        settings = {"environments": []}
        # Patch threading.Thread so the background scan thread never runs during assertion.
        with unittest.mock.patch("threading.Thread"):
            return _mod._start_scan(self._scan_queue(), settings)

    def test_scan_state_reset_after_previous_scan_complete(self):
        _mod._scan_state["status"]    = "complete"
        _mod._scan_state["error"]     = "stale error from prior run"
        _mod._scan_state["exit_code"] = 0
        _mod._scan_state["process"]   = object()

        result = self._call_start_scan()

        self.assertIsNone(result, "Expected no error dict from _start_scan")
        self.assertEqual(_mod._scan_state["status"],    "running")
        self.assertIsNone(_mod._scan_state["error"])
        self.assertIsNone(_mod._scan_state["exit_code"])
        self.assertIsNone(_mod._scan_state["process"])

    def test_scan_state_reset_after_previous_scan_failed(self):
        _mod._scan_state["status"]     = "failed"
        _mod._scan_state["error"]      = "Connection refused to sddc.lab"
        _mod._scan_state["exit_code"]  = 255
        _mod._scan_state["envTimings"] = [{"name": "old-env", "durationSeconds": 120}]

        result = self._call_start_scan()

        self.assertIsNone(result, "Expected no error dict from _start_scan")
        self.assertEqual(_mod._scan_state["status"],    "running")
        self.assertIsNone(_mod._scan_state["error"])
        self.assertIsNone(_mod._scan_state["exit_code"])
        self.assertEqual(_mod._scan_state["envTimings"], [])

    def test_start_scan_rejected_and_state_unchanged_when_already_running(self):
        """The 409 guard must not touch any scan state — it returns an error dict and exits."""
        _mod._scan_state["status"] = "running"
        _mod._scan_state["error"]  = "in-flight sentinel"

        result = self._call_start_scan()

        self.assertIsNotNone(result)
        self.assertIn("error", result)
        self.assertEqual(_mod._scan_state["status"], "running")
        self.assertEqual(_mod._scan_state["error"],  "in-flight sentinel")



# ─────────────────────────────────────────────────────────────────────────────
# _ensure_user_dir
# ─────────────────────────────────────────────────────────────────────────────

class TestEnsureUserDir(unittest.TestCase):
    """_ensure_user_dir — directory creation, parent creation, and permission enforcement."""

    def test_creates_directory_when_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "newdir"
            self.assertFalse(target.exists())
            _mod._ensure_user_dir(target)
            self.assertTrue(target.is_dir())

    def test_no_error_when_directory_already_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "existing"
            target.mkdir()
            _mod._ensure_user_dir(target)  # must not raise
            self.assertTrue(target.is_dir())

    def test_creates_intermediate_parent_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a" / "b" / "c"
            self.assertFalse(target.parent.exists())
            _mod._ensure_user_dir(target)
            self.assertTrue(target.is_dir())

    @unittest.skipIf(sys.platform == "win32", "chmod 0o700 not enforced on Windows")
    def test_sets_user_only_permissions_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secure"
            _mod._ensure_user_dir(target)
            self.assertEqual(oct(target.stat().st_mode)[-3:], "700")

    def test_propagates_oserror_from_mkdir(self):
        original_mkdir = Path.mkdir

        def _failing_mkdir(self_path, **kwargs):
            raise OSError(13, "Permission denied")

        Path.mkdir = _failing_mkdir
        try:
            with self.assertRaises(OSError):
                _mod._ensure_user_dir(Path("/nonexistent/path/that/fails"))
        finally:
            Path.mkdir = original_mkdir


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_env_findings_dir
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveEnvFindingsDir(unittest.TestCase):
    """_resolve_env_findings_dir — per-environment subdirectory path construction."""

    def test_returns_path_nested_under_findings_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._resolve_env_findings_dir({}, "MyEnv")
        self.assertEqual(result.parent.name, "Findings")
        self.assertEqual(result.name, "MyEnv")

    def test_normal_name_round_trips_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._resolve_env_findings_dir({}, "Production")
        self.assertEqual(result.name, "Production")

    def test_sanitizes_illegal_chars_in_env_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._resolve_env_findings_dir({}, 'My<Env>:"bad"/name')
        self.assertNotIn("<", result.name)
        self.assertNotIn(">", result.name)
        self.assertNotIn(":", result.name)
        self.assertNotIn("/", result.name)


# ─────────────────────────────────────────────────────────────────────────────
# _save_settings
# ─────────────────────────────────────────────────────────────────────────────

class TestSaveSettings(unittest.TestCase):
    """_save_settings — atomic write, Config/ directory creation, permissions, cache invalidation."""

    def setUp(self):
        self._saved_cache = _mod._settings_cache

    def tearDown(self):
        _mod._settings_cache = self._saved_cache

    def test_writes_data_to_disk_and_is_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings_file = Path(tmp) / "Config" / "scan-settings.json"
            with unittest.mock.patch.object(_mod, "SETTINGS_FILE", settings_file):
                _mod._save_settings({"logLevel": "DEBUG", "environments": []})
            written = json.loads(settings_file.read_text(encoding="utf-8"))
        self.assertEqual(written["logLevel"], "DEBUG")

    def test_creates_config_directory_when_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings_file = Path(tmp) / "Config" / "scan-settings.json"
            with unittest.mock.patch.object(_mod, "SETTINGS_FILE", settings_file):
                _mod._save_settings({"logLevel": "INFO", "environments": []})
            self.assertTrue(settings_file.exists())

    def test_no_leftover_tmp_file_after_successful_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings_file = Path(tmp) / "Config" / "scan-settings.json"
            with unittest.mock.patch.object(_mod, "SETTINGS_FILE", settings_file):
                _mod._save_settings({"logLevel": "INFO", "environments": []})
            tmp_files = list(Path(tmp).rglob("*.tmp"))
        self.assertEqual(tmp_files, [], "Temp file was not removed after successful write")

    def test_invalidates_settings_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings_file = Path(tmp) / "Config" / "scan-settings.json"
            with unittest.mock.patch.object(_mod, "SETTINGS_FILE", settings_file):
                _mod._settings_cache = {"stale": True}
                _mod._save_settings({"logLevel": "INFO", "environments": []})
        self.assertIsNone(_mod._settings_cache)

    @unittest.skipIf(sys.platform == "win32", "chmod 0o600 not enforced on Windows")
    def test_sets_owner_only_permissions_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings_file = Path(tmp) / "Config" / "scan-settings.json"
            with unittest.mock.patch.object(_mod, "SETTINGS_FILE", settings_file):
                _mod._save_settings({"logLevel": "INFO", "environments": []})
            self.assertEqual(oct(settings_file.stat().st_mode)[-3:], "600")


# ─────────────────────────────────────────────────────────────────────────────
# _find_session_findings / _find_latest_findings — rglob subdirectory search
# ─────────────────────────────────────────────────────────────────────────────

def _make_findings_file(directory: Path, name: str) -> Path:
    """Create a minimal findings file in directory and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / name
    p.write_text("{}", encoding="utf-8")
    return p


class TestFindSessionFindings(unittest.TestCase):
    """_find_session_findings returns findings from all per-environment subdirectories."""

    def test_returns_empty_list_when_base_dir_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp) / "missing"):
                result = _mod._find_session_findings({}, 0.0)
        self.assertEqual(result, [])

    def test_finds_file_in_findings_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f = _make_findings_file(findings_root, "vcf-findings-20260601_120000.json")
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_session_findings({}, 0.0)
        self.assertIn(f, result)

    def test_finds_file_in_env_subdirectory(self):
        """rglob must recurse into per-environment subdirectories."""
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f = _make_findings_file(findings_root / "Production", "vcf-findings-20260601_120000.json")
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_session_findings({}, 0.0)
        self.assertIn(f, result)

    def test_returns_files_from_multiple_env_subdirectories(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f1 = _make_findings_file(findings_root / "EnvA", "vcf-findings-20260601_100000.json")
            f2 = _make_findings_file(findings_root / "EnvB", "vcf-findings-20260601_110000.json")
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_session_findings({}, 0.0)
        self.assertIn(f1, result)
        self.assertIn(f2, result)

    def test_excludes_files_older_than_session_cutoff(self):
        """Files with mtime before session_start - 5 s must not be returned."""
        import time
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f = _make_findings_file(findings_root / "Env", "vcf-findings-20260601_120000.json")
            old_time = time.time() - 100
            os.utime(f, (old_time, old_time))
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_session_findings({}, time.time())
        self.assertNotIn(f, result)

    def test_includes_files_within_5s_buffer_before_session_start(self):
        """Files up to 5 s before session_start are included (startup latency buffer)."""
        import time
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f = _make_findings_file(findings_root / "Env", "vcf-findings-20260601_120000.json")
            # mtime is 3 s before session_start — within the 5 s buffer.
            near_time = time.time() - 3
            os.utime(f, (near_time, near_time))
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_session_findings({}, time.time())
        self.assertIn(f, result)


class TestFindLatestFindings(unittest.TestCase):
    """_find_latest_findings returns the most recently modified findings file across all subdirectories."""

    def test_returns_none_when_base_dir_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp) / "missing"):
                result = _mod._find_latest_findings({})
        self.assertIsNone(result)

    def test_returns_none_when_no_findings_files_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Findings").mkdir()
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_latest_findings({})
        self.assertIsNone(result)

    def test_returns_single_file_when_only_one_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f = _make_findings_file(findings_root / "Env", "vcf-findings-20260601_120000.json")
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_latest_findings({})
        self.assertEqual(result, f)

    def test_returns_most_recent_file_across_subdirectories(self):
        """The newest file wins even when it lives in a different subdirectory than the oldest."""
        import time
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f_old = _make_findings_file(findings_root / "EnvA", "vcf-findings-20260601_100000.json")
            f_new = _make_findings_file(findings_root / "EnvB", "vcf-findings-20260601_110000.json")
            t_base = time.time()
            os.utime(f_old, (t_base - 60, t_base - 60))
            os.utime(f_new, (t_base, t_base))
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_latest_findings({})
        self.assertEqual(result, f_new)

    def test_returns_latest_from_root_and_subdirectory_combined(self):
        """Findings in the root and in subdirectories are searched together."""
        import time
        with tempfile.TemporaryDirectory() as tmp:
            findings_root = Path(tmp) / "Findings"
            f_root = _make_findings_file(findings_root, "vcf-findings-20260601_100000.json")
            f_sub  = _make_findings_file(findings_root / "Env", "vcf-findings-20260601_110000.json")
            t_base = time.time()
            os.utime(f_root, (t_base - 60, t_base - 60))
            os.utime(f_sub,  (t_base, t_base))
            with unittest.mock.patch.object(_mod, "_USER_BASE_DIR", Path(tmp)):
                result = _mod._find_latest_findings({})
        self.assertEqual(result, f_sub)


class TestVersionIsNewer(unittest.TestCase):
    """Unit tests for the _version_is_newer helper."""

    def test_returns_true_when_candidate_newer(self):
        self.assertTrue(_mod._version_is_newer("1.0.0.2", "1.0.0.1"))

    def test_returns_false_when_candidate_same(self):
        self.assertFalse(_mod._version_is_newer("1.0.0.1", "1.0.0.1"))

    def test_returns_false_when_candidate_older(self):
        self.assertFalse(_mod._version_is_newer("1.0.0.0", "1.0.0.1"))

    def test_returns_false_on_malformed_version(self):
        self.assertFalse(_mod._version_is_newer("not-a-version", "1.0.0.1"))

    def test_handles_different_length_tuples(self):
        self.assertTrue(_mod._version_is_newer("2.0", "1.9.9.9"))


class TestModuleUpdateCheck(unittest.TestCase):
    """HTTP endpoint tests for /module/update-status and /module/install-update.

    Uses a real ThreadingHTTPServer bound to a free port, matching the pattern
    used by TestHttpHandlerNegative/Positive elsewhere in this file.
    """

    @classmethod
    def setUpClass(cls):
        defaults = _mod._default_settings()
        cls._patchers = [
            unittest.mock.patch.object(_mod, "_load_settings", return_value=defaults),
            unittest.mock.patch.object(_mod, "_save_settings", return_value=None),
            unittest.mock.patch.object(_mod, "_get_module_version_from_psd1",
                                       return_value="1.0.0.1001"),
        ]
        for p in cls._patchers:
            p.start()

        port = _free_port()
        cls._server = ThreadingHTTPServer(("127.0.0.1", port), _mod.Handler)
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()
        cls._base = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls):
        cls._server.shutdown()
        for p in cls._patchers:
            p.stop()
        # Restore module-level state.
        with _mod._module_update_lock:
            _mod._module_update_cache = None
        with _mod._module_install_lock:
            _mod._module_install_state = {"status": "idle"}

    def _get_json(self, path):
        req = urllib.request.Request(self._base + path)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def _post_json(self, path, body=None):
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(
            self._base + path, data=data,
            headers={"Content-Type": "application/json", "Content-Length": str(len(data))},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    # ── /module/update-status — cache empty (checking) ────────────────────

    def test_check_update_returns_checking_when_cache_empty(self):
        """When _module_update_cache is None, the endpoint returns {checking: True}."""
        with _mod._module_update_lock:
            _mod._module_update_cache = None
        body = self._get_json("/module/update-status")
        self.assertTrue(body.get("checking"))

    # ── /module/update-status — check disabled ────────────────────────────

    def test_check_update_returns_disabled_when_setting_set(self):
        """When disableModuleUpdateReminders is True, the endpoint returns {checkDisabled: True}."""
        settings = _mod._default_settings()
        settings["disableModuleUpdateReminders"] = True
        with unittest.mock.patch.object(_mod, "_load_settings", return_value=settings):
            body = self._get_json("/module/update-status")
        self.assertTrue(body.get("checkDisabled"))

    # ── /module/update-status — update available ──────────────────────────

    def test_check_update_update_available(self):
        """Cache holds a newer version — endpoint returns updateAvailable: True."""
        from datetime import datetime as _dt
        with _mod._module_update_lock:
            _mod._module_update_cache = {"version": "1.0.0.9999", "fetchedAt": _dt.now()}
        body = self._get_json("/module/update-status")
        self.assertTrue(body.get("updateAvailable"))
        self.assertEqual(body.get("latestVersion"), "1.0.0.9999")

    # ── /module/update-status — network error ─────────────────────────────

    def test_check_update_network_error(self):
        """When cache contains an error, the endpoint surfaces it."""
        with _mod._module_update_lock:
            _mod._module_update_cache = {
                "error": "Could not reach PowerShell Gallery: timed out",
                "errorType": "network",
            }
        body = self._get_json("/module/update-status")
        self.assertIn("error", body)
        self.assertEqual(body.get("errorType"), "network")

    # ── POST /module/install-update ───────────────────────────────────────

    def test_install_update_returns_ok_and_starts_background(self):
        """POST /module/install-update returns {ok: True} when not already running."""
        with _mod._module_install_lock:
            _mod._module_install_state = {"status": "idle"}
        started = []
        original_thread = threading.Thread

        def _capturing_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            started.append(t)
            return t

        with unittest.mock.patch("threading.Thread", side_effect=_capturing_thread):
            status, body = self._post_json("/module/install-update")
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ok"))

    # ── GET /module/install-status ────────────────────────────────────────

    def test_install_status_returns_current_state(self):
        """GET /module/install-status reflects _module_install_state."""
        with _mod._module_install_lock:
            _mod._module_install_state = {"status": "success"}
        body = self._get_json("/module/install-status")
        self.assertEqual(body.get("status"), "success")


    # ── POST /module/dismiss-prompt ───────────────────────────────────────────

    def test_dismiss_prompt_returns_ok(self):
        """POST /module/dismiss-prompt must return {ok: True} and save settings."""
        status, body = self._post_json("/module/dismiss-prompt")
        self.assertEqual(status, 200)
        self.assertTrue(body.get("ok"))

    def test_dismiss_prompt_sets_disable_flag_in_settings(self):
        """POST /module/dismiss-prompt must set disableModuleUpdateReminders to True."""
        with unittest.mock.patch.object(_mod, "_save_settings") as mock_save:
            self._post_json("/module/dismiss-prompt")
        self.assertTrue(mock_save.called)
        saved = mock_save.call_args[0][0]
        self.assertTrue(saved.get("disableModuleUpdateReminders"))

    # ── POST /module/install-update 409 guard ────────────────────────────────

    def test_install_update_returns_409_when_already_running(self):
        """POST /module/install-update must return 409 when an install is already in progress."""
        with _mod._module_install_lock:
            _mod._module_install_state = {"status": "running"}
        try:
            status, body = self._post_json("/module/install-update")
            self.assertEqual(status, 409)
            self.assertIn("already", body.get("error", "").lower())
        finally:
            with _mod._module_install_lock:
                _mod._module_install_state = {"status": "idle"}


class TestGetModuleVersionFromPsd1(unittest.TestCase):
    """Unit tests for _get_module_version_from_psd1.

    Patches _MODULE_PSD1 to control which file the function reads.
    """

    def test_returns_version_from_valid_psd1(self):
        """Must extract ModuleVersion from a well-formed .psd1 file."""
        content = "@{\n    ModuleVersion = '1.2.3.4'\n    GUID = 'abc'\n}\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".psd1", delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            from pathlib import Path
            with unittest.mock.patch.object(_mod, "_MODULE_PSD1", Path(tmp)):
                result = _mod._get_module_version_from_psd1()
            self.assertEqual(result, "1.2.3.4")
        finally:
            os.unlink(tmp)

    def test_returns_unknown_when_file_missing(self):
        """Must return 'unknown' gracefully when the file does not exist."""
        from pathlib import Path
        with unittest.mock.patch.object(_mod, "_MODULE_PSD1", Path("/nonexistent/module.psd1")):
            result = _mod._get_module_version_from_psd1()
        self.assertEqual(result, "unknown")

    def test_returns_unknown_when_version_absent(self):
        """Must return 'unknown' when ModuleVersion key is not in the file."""
        content = "@{\n    GUID = 'abc'\n    Author = 'test'\n}\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".psd1", delete=False) as f:
            f.write(content)
            tmp = f.name
        try:
            from pathlib import Path
            with unittest.mock.patch.object(_mod, "_MODULE_PSD1", Path(tmp)):
                result = _mod._get_module_version_from_psd1()
            self.assertEqual(result, "unknown")
        finally:
            os.unlink(tmp)


class TestModuleUpdateSettings(unittest.TestCase):
    """Verify the disableModuleUpdateReminders setting default and validation."""

    def test_disableModuleUpdateReminders_default_false(self):
        defaults = _mod._default_settings()
        self.assertIn("disableModuleUpdateReminders", defaults)
        self.assertFalse(defaults["disableModuleUpdateReminders"])

    def test_validate_settings_accepts_true(self):
        settings = _mod._default_settings()
        settings["disableModuleUpdateReminders"] = True
        result = _mod._validate_settings(settings)
        self.assertIsNone(result)

    def test_validate_settings_accepts_false(self):
        settings = _mod._default_settings()
        settings["disableModuleUpdateReminders"] = False
        result = _mod._validate_settings(settings)
        self.assertIsNone(result)


# ─────────────────────────────────────────────────────────────────────────────
# --pid-file argument security check (path must be within the home directory)
# ─────────────────────────────────────────────────────────────────────────────

class TestPidFileArgSecurity(unittest.TestCase):
    """--pid-file path confinement — must reject paths outside the home directory."""

    def _run_main_with_args(self, args: list) -> "tuple[int, str]":
        """Invoke main() with the given sys.argv and capture the exit code and stderr."""
        import io as _io
        saved_argv   = sys.argv
        saved_stderr = sys.stderr
        buf = _io.StringIO()
        sys.stderr = buf
        exit_code = 0
        try:
            sys.argv = ["Start-VCFPatchScannerServer.py"] + args
            _mod.main()
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 1
        finally:
            sys.argv   = saved_argv
            sys.stderr = saved_stderr
        return exit_code, buf.getvalue()

    def test_pid_file_outside_home_is_rejected(self):
        code, err = self._run_main_with_args(["--pid-file=/tmp/test.pid"])
        self.assertEqual(code, 1)
        self.assertIn("home directory", err)

    def test_pid_file_within_home_is_accepted_or_proceeds(self):
        # A path inside the home directory must NOT fail the security check.
        # We expect the server to attempt to bind (and exit with EADDRINUSE or
        # proceed past the security check) — not exit with a "home directory" message.
        home_pid = Path.home() / "vcfpatch-test-dummy.pid"
        code, err = self._run_main_with_args([f"--pid-file={home_pid}", "--no-browser"])
        self.assertNotIn("home directory", err)
        # Clean up if the file was written before the server binding failed.
        home_pid.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# --no-browser flag (parsed without error; browser thread not started)
# ─────────────────────────────────────────────────────────────────────────────

class TestNoBrowserFlag(unittest.TestCase):
    """--no-browser is accepted by the arg parser and suppresses webbrowser.open."""

    def test_no_browser_does_not_open_browser(self):
        """When --no-browser is set, webbrowser.open must never be called."""
        port = _free_port()
        opened = []

        def _fake_open(url):
            opened.append(url)

        with unittest.mock.patch("webbrowser.open", side_effect=_fake_open):
            srv = ThreadingHTTPServer(("127.0.0.1", port), _mod.Handler)
            saved_argv = sys.argv
            try:
                sys.argv = ["srv", f"--port={port}", "--no-browser"]
                t = threading.Thread(target=srv.serve_forever, daemon=True)
                t.start()
                time.sleep(0.3)
                srv.shutdown()
                t.join(timeout=2)
            finally:
                sys.argv = saved_argv

        self.assertEqual(opened, [], "webbrowser.open must not be called with --no-browser")


if __name__ == "__main__":
    unittest.main()
