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
# PowerShell Module: VcfPatchScanner
# VCF Patch Scanner
# Last modified: 2026-06-08
#
# Private implementation files (dot-sourced below):
#   Private/Logging.ps1     — Log initialization and Write-LogMessage
#   Private/Mapping.ps1     — Component name mappings, lookup tables (SCRIPT variables)
#   Private/Settings.ps1    — Settings file CRUD, validation, template generation
#   Private/Advisory.ps1    — Security advisory loading, parsing, schema validation
#   Private/Discovery.ps1   — VCF environment discovery and connectivity validation
#   Private/Inventory.ps1   — Live inventory collection from SDDC Manager, vCenter, Fleet Manager APIs
#   Private/Scanning.ps1    — Vulnerability matching and scanning logic
#   Private/Findings.ps1    — Findings export (JSON, CSV)
#   Private/Tools.ps1       — Python server launcher and Tools directory management
#   Private/EntryPoint.ps1  — Invoke-VCFPatchScanner orchestration
#

# Dot-source private implementation files in dependency order
$privatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'
$privateFiles = @(
    'Logging.ps1'
    'Mapping.ps1'
    'Settings.ps1'
    'Advisory.ps1'
    'Discovery.ps1'
    'Inventory.ps1'
    'Scanning.ps1'
    'Findings.ps1'
    'Tools.ps1'
    'EntryPoint.ps1'
)

foreach ($file in $privateFiles) {
    $filePath = Join-Path -Path $privatePath -ChildPath $file
    if (Test-Path -LiteralPath $filePath) {
        . $filePath
    }
    else {
        Write-Warning "Private module file not found: $filePath"
    }
}

# Module constants — set once at load time, never mutate.
$Script:VcfPatchScannerModuleLoaded    = $true
$Script:VcfPatchScannerVersion         = "1.0.0.1000"
$Script:JSON_PARSE_MAX_DEPTH        = 100
$Script:JSON_SERIALIZE_DEPTH        = 10

# Environment variable that stores the active base directory (set by Initialize-VcfPatchScanner).
$Script:VCF_PATCH_SCANNER_ENV_VAR      = "VcfPatchScannerBaseDirectory"

# Default base directory name under $HOME when Initialize-VcfPatchScanner is run without arguments.
$Script:VCF_PATCH_SCANNER_DEFAULT_DIR  = "VcfPatchScanner"

# Subdirectory names under the user base directory.
$Script:SCAN_CONFIG_DIR_NAME        = "Config"
$Script:SCAN_DATA_DIR_NAME          = "Data"
$Script:SCAN_FINDINGS_DIR_NAME      = "Findings"
$Script:SCAN_LOGS_DIR_NAME          = "Logs"
$Script:SCAN_TOOLS_DIR_NAME         = "Tools"

# File names within their respective subdirectories.
$Script:SCAN_ADVISORY_FILE_NAME     = "securityAdvisory.json"
$Script:SCAN_SETTINGS_FILE_NAME     = "scan-settings.json"

# Tool files copied to the user's Tools subdirectory on Initialize.
$Script:SCAN_TOOL_FILE_NAMES        = @(
    'Manage-VCFPatchScannerServer.py'
    'Start-VCFPatchScannerServer.py'
    'vcp-patch-ui.html'
    'Invoke-VCFPatchScanner.ps1'
)
