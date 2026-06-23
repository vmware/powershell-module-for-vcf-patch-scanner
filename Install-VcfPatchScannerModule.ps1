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
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
# =============================================================================

#Requires -Version 7.4

<#
.SYNOPSIS
    Manually installs the VcfPatchScanner PowerShell module cross-platform.

.DESCRIPTION
    Copies VcfPatchScanner.psd1, VcfPatchScanner.psm1, Private, Data, and Tools into the
    first path in $env:PSModulePath for the current platform (Windows, Linux, or macOS).
    Validates the installed manifest before completing. Python __pycache__ directories are
    excluded from the copy.

    The module source is expected at $SourcePath/VcfPatchScanner/ (i.e. the VcfPatchScanner/
    subdirectory of this script's directory when running directly from a cloned repository).

    If the module is currently loaded in the session it is removed before the files are
    overwritten and reloaded afterward, so the in-memory version matches what was just
    installed.

    Once installed to $env:PSModulePath, PowerShell auto-imports the module the first time
    any of its commands is used in a session. No $PROFILE changes are needed.

    IMPORTANT: Do not add 'Import-Module VcfPatchScanner' to $PROFILE. The module contains
    multiple private implementation files and takes a noticeable time to load. Use
    PowerShell's built-in auto-import instead — the module loads once on first use per
    session.

    If $PROFILE contains 'Import-Module VcfPatchScanner' from an earlier install, the
    installer detects and offers to clean it up automatically.

    Use -SkipProfileUpdate to suppress all profile checks for unattended installs.

    Prerequisites:
      - PowerShell 7.4 or newer (enforced by #Requires).
      - VCF PowerCLI 9.0 or newer must already be installed.
      - Python 3.13 or newer (required by the web UI server).

.PARAMETER SkipProfileUpdate
    When specified, skips all $PROFILE inspection and cleanup. Use for unattended
    installs where profile changes are unwanted.

.PARAMETER SourcePath
    Path to the directory containing the VcfPatchScanner module subdirectory. Defaults to
    the directory containing this script ($PSScriptRoot), which is correct when running
    directly from a cloned repository.

.EXAMPLE
    .\Install-VcfPatchScannerModule.ps1

    Installs from the script's own directory. Checks $PROFILE for any VcfPatchScanner
    import lines that would slow shell startup and offers to remove them.

.EXAMPLE
    .\Install-VcfPatchScannerModule.ps1 -SourcePath "~/Downloads/VcfPatchScanner-1.0.0"

    Installs from a custom source directory.

.EXAMPLE
    .\Install-VcfPatchScannerModule.ps1 -SkipProfileUpdate

    Installs without inspecting or modifying $PROFILE (suitable for CI or scripted installs).

.NOTES
    After installation, open a new shell and run 'Initialize-VcfPatchScanner' to set up
    your working directory. PowerShell auto-imports the module on first use — no profile
    line needed.
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)] [Switch]$SkipProfileUpdate,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SourcePath = $PSScriptRoot
)

function Invoke-ProfileCleanup {

    <#
    .SYNOPSIS
        Shows the user what will be removed from $PROFILE and prompts for confirmation.
    .NOTES
        Always previews what will be deleted before writing. If the cleaned content is
        identical to the original (no match), the function skips without prompting.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [ValidateNotNull()] [String]$CleanedContent,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [ValidateNotNull()] [String]$OriginalContent,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ProfilePath
    )

    if ($OriginalContent -eq $CleanedContent) {
        Write-Host "  (Nothing matched for removal — skipping to prevent unintended edits.)" -ForegroundColor Gray
        return
    }

    # Show exactly which non-blank lines will disappear so the user can verify before confirming.
    $originalLines = $OriginalContent -split "`n"
    $cleanedLines  = $CleanedContent  -split "`n"
    $removedLines  = $originalLines | Where-Object { $cleanedLines -notcontains $_ -and -not [String]::IsNullOrWhiteSpace($_) }
    if ($removedLines) {
        Write-Host "  Lines that will be removed:" -ForegroundColor DarkGray
        $removedLines | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        Write-Host ""
    }

    $response = Read-Host "Remove it now? (Y/N, Enter=no)"
    if ($response -match '^Y(es)?$') {
        Set-Content -LiteralPath $ProfilePath -Encoding UTF8 -NoNewline -Value $CleanedContent
        Write-Host "  Removed. Shell startup is now fast." -ForegroundColor Green
    }
}

$moduleSourcePath = Join-Path -Path $SourcePath -ChildPath "VcfPatchScanner"
$itemsToCopy      = @("VcfPatchScanner.psd1", "VcfPatchScanner.psm1", "Private", "Data", "Tools")

Write-Host ""
Write-Host "VcfPatchScanner Module Installer" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "PREREQUISITE: VCF PowerCLI 9.0 or newer must be installed before importing this module." -ForegroundColor Yellow
Write-Host ""

try {
    if (-not (Test-Path -Path $moduleSourcePath -PathType Container)) {
        throw "Module source not found: $moduleSourcePath"
    }

    $pathSeparator = [System.IO.Path]::PathSeparator
    $basePath      = ($env:PSModulePath -split $pathSeparator)[0]
    $installPath   = Join-Path -Path $basePath -ChildPath "VcfPatchScanner"

    Write-Host "Source      : $moduleSourcePath"
    Write-Host "Destination : $installPath"
    Write-Host ""

    # Unload the module if it is currently in the session so the files can be
    # overwritten and the reloaded copy is consistent with what was just installed.
    $loadedModule = Get-Module -Name "VcfPatchScanner" -ErrorAction SilentlyContinue
    if ($null -ne $loadedModule) {
        Write-Host "Unloading currently loaded module (version $($loadedModule.Version))..." -ForegroundColor Gray
        Remove-Module -Name "VcfPatchScanner" -Force -ErrorAction Stop
    }

    if (-not (Test-Path -Path $installPath)) {
        Write-Host "Creating module directory..." -ForegroundColor Gray
        New-Item -Path $installPath -ItemType Directory -Force | Out-Null
    }

    foreach ($item in $itemsToCopy) {
        $itemSource = Join-Path -Path $moduleSourcePath -ChildPath $item

        if (-not (Test-Path -Path $itemSource)) {
            Write-Host "  [SKIP] $item — not found at source." -ForegroundColor Yellow
            continue
        }

        Write-Host "  Copying $item..." -ForegroundColor Gray
        # Exclude Python bytecode cache directories that may exist in a development checkout.
        Copy-Item -Path $itemSource -Destination $installPath -Recurse -Force -Exclude "__pycache__"
        # Copy-Item -Exclude does not recurse into subdirectories; remove any copied __pycache__ explicitly.
        Get-ChildItem -Path (Join-Path -Path $installPath -ChildPath $item) -Filter "__pycache__" -Recurse -Directory -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Unblock all copied files on Windows so execution policy does not block the module
    # after installation when the source was downloaded from the internet (ZIP or clone).
    # Unblock-File is a no-op on macOS/Linux where Zone.Identifier streams do not exist.
    Write-Host "Unblocking installed module files (Windows execution policy)..." -ForegroundColor Gray
    Get-ChildItem -Path $installPath -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { Unblock-File -Path $_.FullName -ErrorAction SilentlyContinue }

    Write-Host ""
    Write-Host "Validating module manifest..." -ForegroundColor Gray
    $manifestPath = Join-Path -Path $installPath -ChildPath "VcfPatchScanner.psd1"
    $null = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop

    # Reload the module into the current session so the caller can use it immediately
    # without opening a new shell. Import errors are non-fatal — the files are on disk
    # and the user can reload manually if a dependency like VCF.PowerCLI is absent.
    Write-Host "Importing module into current session..." -ForegroundColor Gray
    try {
        Import-Module -Name $manifestPath -Force -ErrorAction Stop
        $reloadedVersion = (Get-Module -Name "VcfPatchScanner").Version
        Write-Host "  Module loaded (version $reloadedVersion)." -ForegroundColor Gray
    } catch {
        Write-Host "  Import skipped: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Run 'Import-Module VcfPatchScanner' manually once all prerequisites are met." -ForegroundColor Yellow
    }

    # Check $PROFILE for any VcfPatchScanner entries that would slow shell startup.
    # The installer never writes to $PROFILE — PowerShell auto-imports the module on first
    # command use. Detect eager-load lines added by hand or earlier tooling.
    $eagerProfileLine = "Import-Module VcfPatchScanner"

    if (-not $SkipProfileUpdate) {
        $profileContent = if (Test-Path -LiteralPath $PROFILE) {
            Get-Content -LiteralPath $PROFILE -Raw -ErrorAction SilentlyContinue
        } else {
            ""
        }

        $hasEagerLine = $profileContent -match "(?m)^\s*$([regex]::Escape($eagerProfileLine))\s*$"

        if ($hasEagerLine) {
            Write-Host ""
            Write-Host "Profile warning" -ForegroundColor Yellow
            Write-Host "  $PROFILE contains 'Import-Module VcfPatchScanner'." -ForegroundColor Yellow
            Write-Host "  This adds startup latency to every new shell. PowerShell auto-imports the" -ForegroundColor Yellow
            Write-Host "  module on first use without any profile entry — the line is not needed." -ForegroundColor Yellow
            Write-Host ""
            $cleanedContent = ($profileContent -replace "(?m)^\s*# VcfPatchScanner[^\n]*\r?\n?", "") `
                -replace "(?m)^\s*$([regex]::Escape($eagerProfileLine))\r?\n?", ""
            Invoke-ProfileCleanup -ProfilePath $PROFILE -OriginalContent $profileContent -CleanedContent $cleanedContent
        } else {
            Write-Host ""
            Write-Host "  No profile changes needed — Initialize-VcfPatchScanner auto-loads on first use." -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "Installation complete." -ForegroundColor Green
    Write-Host "  Initialize-VcfPatchScanner" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
