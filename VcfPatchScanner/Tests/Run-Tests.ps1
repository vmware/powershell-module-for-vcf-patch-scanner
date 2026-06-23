# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted for brevity]
# =============================================================================
#
# Test Runner for VcfPatchScanner Module
# Executes all Pester tests and reports results
#

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)] [ValidateSet('Detailed', 'Normal', 'Minimal')] [String]$Verbosity = 'Normal'
)

$ErrorActionPreference = 'Stop'

# Check if Pester is available
if (-not (Get-Module -Name Pester -ListAvailable)) {
    Write-Host "Pester module not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name Pester -Force -SkipPublisherCheck
}

# Get test directory
$testDir = $PSScriptRoot
$parentDir = Split-Path -Parent -Path $testDir

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host "VcfPatchScanner Module Test Suite" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host ""

# Find all test files
$testFiles = @(
    'VcfPatchScanner.Logging.Tests.ps1',
    'VcfPatchScanner.Mapping.Tests.ps1',
    'VcfPatchScanner.Settings.Tests.ps1',
    'VcfPatchScanner.Advisory.Tests.ps1',
    'VcfPatchScanner.Discovery.Tests.ps1',
    'VcfPatchScanner.Inventory.Tests.ps1',
    'VcfPatchScanner.Scanning.Tests.ps1',
    'VcfPatchScanner.Findings.Tests.ps1',
    'VcfPatchScanner.EntryPoint.Tests.ps1'
)

$pesterConfig = @{
    Path       = $testDir
    Include    = $testFiles
    Verbosity  = $Verbosity
    PassThru   = $true
    SkipAll    = $false
}

$pesterFailed = $false
$pythonFailed = $false

try {
    # Run Pester tests
    $results = Invoke-Pester @pesterConfig

    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Yellow
    Write-Host "Pester Results Summary" -ForegroundColor Yellow
    Write-Host "=" * 70 -ForegroundColor Yellow
    Write-Host "Total Tests:    $($results.TotalCount)" -ForegroundColor White
    Write-Host "Passed:         $($results.PassedCount)" -ForegroundColor Green
    Write-Host "Failed:         $($results.FailedCount)" -ForegroundColor $(if ($results.FailedCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Skipped:        $($results.SkippedCount)" -ForegroundColor Yellow
    Write-Host ""

    if ($results.FailedCount -gt 0) {
        $pesterFailed = $true
    }
}
catch {
    Write-Host "Error running Pester tests: $($_.Exception.Message)" -ForegroundColor Red
    $pesterFailed = $true
}

# Run Python unittest suites (server logic + UI static analysis + PS static analysis).
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host "Python unittest (test_server.py + test_ui_static.py + test_ps1_static.py)" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host ""

$python = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" } else { "python" }
$pythonTestFile      = Join-Path -Path $testDir -ChildPath "test_server.py"
$pythonUiTestFile    = Join-Path -Path $testDir -ChildPath "test_ui_static.py"
$pythonPs1TestFile   = Join-Path -Path $testDir -ChildPath "test_ps1_static.py"

if (-not (Get-Command $python -ErrorAction SilentlyContinue)) {
    Write-Host "WARNING: Python interpreter not found — skipping Python tests." -ForegroundColor Yellow
}
else {
    foreach ($testFile in @($pythonTestFile, $pythonUiTestFile, $pythonPs1TestFile)) {
        if (-not (Test-Path -LiteralPath $testFile)) {
            Write-Host "WARNING: Python test file not found: $testFile" -ForegroundColor Yellow
            continue
        }
        & $python -m unittest "$testFile" -v 2>&1
        if ($LASTEXITCODE -ne 0) {
            $pythonFailed = $true
            Write-Host ""
            Write-Host "FAILED: One or more Python tests failed in $testFile" -ForegroundColor Red
        }
        else {
            Write-Host ""
            Write-Host "SUCCESS: All Python tests passed in $testFile" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Yellow
Write-Host "Overall Results" -ForegroundColor Yellow
Write-Host "=" * 70 -ForegroundColor Yellow

if ($pesterFailed -or $pythonFailed) {
    if ($pesterFailed)  { Write-Host "Pester:  FAILED" -ForegroundColor Red }
    else                { Write-Host "Pester:  PASSED" -ForegroundColor Green }
    if ($pythonFailed)  { Write-Host "Python:  FAILED" -ForegroundColor Red }
    else                { Write-Host "Python:  PASSED" -ForegroundColor Green }
    Write-Host ""
    Write-Host "FAILED: One or more test suites failed" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "Pester:  PASSED" -ForegroundColor Green
    Write-Host "Python:  PASSED" -ForegroundColor Green
    Write-Host ""
    Write-Host "SUCCESS: All tests passed" -ForegroundColor Green
    exit 0
}
