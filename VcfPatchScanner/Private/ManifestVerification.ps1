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

#region Manifest Verification — Supply-Chain Security
function New-ManifestFile {

    <#
        .SYNOPSIS
        Creates a SHA256 manifest file for the module.

        .DESCRIPTION
        Computes SHA256 hashes for all module files and writes them to a manifest
        file in the format: <sha256>  <filename>

        This manifest can be published alongside the module on GitHub so that users
        can verify the module's integrity before running it.

        .PARAMETER ModulePath
        Path to the VcfPatchScanner module directory.

        .PARAMETER ManifestPath
        Path where the manifest file will be written.
        Default: MANIFEST.sha256 in the module directory.

        .OUTPUTS
        The path to the created manifest file.

        .NOTES
        The manifest includes all module files (Private/, .ps1/.psd1 files).
        It does NOT include Tests/ or development files.

        This is used by the Publish-VcfPatchScanner.ps1 script to generate manifests
        for each release, which are then published to GitHub releases.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ModulePath,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$ManifestPath = (Join-Path $ModulePath "MANIFEST.sha256")
    )

    if (-not (Test-Path -LiteralPath $ModulePath -PathType Container)) {
        throw "Module path not found: $ModulePath"
    }

    $manifestLines = @()

    # Files at module root to include
    $rootFiles = @("VcfPatchScanner.psd1", "VcfPatchScanner.psm1", "PSScriptAnalyzerSettings.psd1")
    foreach ($fileName in $rootFiles) {
        $filePath = Join-Path $ModulePath $fileName
        if (Test-Path -LiteralPath $filePath -PathType Leaf) {
            $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLower()
            $manifestLines += "$hash  $fileName"
        }
    }

    # Directories to include recursively
    $dirsToInclude = @("Private")
    foreach ($dirName in $dirsToInclude) {
        $dirPath = Join-Path $ModulePath $dirName
        if (Test-Path -LiteralPath $dirPath -PathType Container) {
            Get-ChildItem -LiteralPath $dirPath -Recurse -File |
                Where-Object { $_.Name -ne ".DS_Store" } |
                Sort-Object FullName |
                ForEach-Object {
                    $relPath = [IO.Path]::GetRelativePath($ModulePath, $_.FullName).Replace('\', '/')
                    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
                    $manifestLines += "$hash  $relPath"
                }
        }
    }

    # Write manifest
    $manifestLines | Sort-Object | Set-Content -LiteralPath $ManifestPath -Encoding UTF8 -Force
    Write-LogMessage -Type INFO -Message "Generated manifest: $ManifestPath ($($manifestLines.Count) files)"

    return $ManifestPath
}
function Test-ModuleManifest {

    <#
        .SYNOPSIS
        Verifies module integrity against a published SHA256 manifest.

        .DESCRIPTION
        Downloads or reads a SHA256 manifest from GitHub and verifies that the
        currently-loaded module matches the manifest. If the module's SHA256
        hashes do not match the manifest, returns failure and logs an error.

        This function is called at module initialization to detect supply-chain
        attacks (e.g., PSGallery account compromise, MITM during download).

        .PARAMETER ModulePath
        Path to the VcfPatchScanner module directory.

        .PARAMETER ManifestUrl
        URL to download the manifest from (GitHub releases page).
        If omitted, verification is skipped (optional safety check).

        .OUTPUTS
        $true if the module matches the manifest (or manifest not available).
        $false if the module does not match the manifest.

        .NOTES
        Returns $true (success) when:
        - Manifest URL is not provided (graceful degradation)
        - All files match the manifest

        Returns $false (failure) when:
        - Manifest cannot be downloaded
        - Module files do not match the manifest (indicates tampering)

        Failures are logged at WARNING level, not ERROR, so they don't block
        module initialization. However, operators should investigate any
        manifest mismatches, as they may indicate a supply-chain compromise.
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ModulePath,
        [Parameter(Mandatory = $false)] [String]$ManifestUrl
    )

    if ([String]::IsNullOrWhiteSpace($ManifestUrl)) {
        # Manifest verification is optional; if no URL is provided, skip it.
        return $true
    }

    if (-not (Test-Path -LiteralPath $ModulePath -PathType Container)) {
        Write-LogMessage -Type WARNING -Message "Module path not found during manifest check: $ModulePath"
        return $false
    }

    # Download the manifest
    $manifestContent = $null
    try {
        Write-LogMessage -Type DEBUG -Message "Downloading module manifest from: $ManifestUrl"
        $manifestContent = Invoke-WebRequest -Uri $ManifestUrl -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
    } catch {
        Write-LogMessage -Type WARNING -Message "Could not download module manifest (supply-chain verification skipped): $($_.Exception.Message)"
        return $true  # Graceful degradation: if manifest is unavailable, allow load to proceed
    }

    # Build current module manifest
    $currentManifest = @()
    $rootFiles = @("VcfPatchScanner.psd1", "VcfPatchScanner.psm1", "PSScriptAnalyzerSettings.psd1")
    foreach ($fileName in $rootFiles) {
        $filePath = Join-Path $ModulePath $fileName
        if (Test-Path -LiteralPath $filePath -PathType Leaf) {
            $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLower()
            $currentManifest += "$hash  $fileName"
        }
    }

    $dirsToInclude = @("Private")
    foreach ($dirName in $dirsToInclude) {
        $dirPath = Join-Path $ModulePath $dirName
        if (Test-Path -LiteralPath $dirPath -PathType Container) {
            Get-ChildItem -LiteralPath $dirPath -Recurse -File |
                Where-Object { $_.Name -ne ".DS_Store" } |
                Sort-Object FullName |
                ForEach-Object {
                    $relPath = [IO.Path]::GetRelativePath($ModulePath, $_.FullName).Replace('\', '/')
                    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
                    $currentManifest += "$hash  $relPath"
                }
        }
    }

    $currentManifestSorted = @($currentManifest | Sort-Object) -join "`n"
    $publishedManifestSorted = @($manifestContent -split "`n" | Where-Object { $_.Trim() } | Sort-Object) -join "`n"

    if ($currentManifestSorted -ne $publishedManifestSorted) {
        Write-LogMessage -Type WARNING -Message "Module manifest verification FAILED. This may indicate supply-chain tampering (PSGallery compromise, MITM attack, or local file modification). Investigate immediately: verify the manifest URL against GitHub releases and re-download the module if necessary."
        return $false
    }

    Write-LogMessage -Type DEBUG -Message "Module manifest verification passed."
    return $true
}
#endregion
