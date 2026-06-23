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

#region Findings Export

function Export-PatchScanFindings {

    <#
        .SYNOPSIS
        Export vulnerability findings to JSON file.

        .DESCRIPTION
        Writes findings and optional metadata to a JSON wrapper object:
        { "findings": [...], "failedEndpoints": [...], "versionCatalog": [...], "vcfMinorVersion": "..." }.
        The Python server reads all keys; failedEndpoints and versionCatalog are empty arrays when
        not applicable; vcfMinorVersion is an empty string when the environment is not VCF 9.x or
        the version could not be detected.  Creates the output directory if it does not exist.

        .PARAMETER FailedEndpoints
        Optional array of endpoints that could not be inventoried during this scan.
        Each entry should have Fqdn, Component, and ErrorMessage properties.

        .PARAMETER Findings
        Array of vulnerability findings (from Invoke-VulnerabilityScan).

        .PARAMETER OutputPath
        Full path to output JSON file. Must be an absolute path.

        .PARAMETER VcfMinorVersion
        Optional VCF minor version string detected during inventory collection (e.g. "9.0" or
        "9.1"). Empty when the environment is not VCF 9.x or the version could not be detected.

        .PARAMETER VersionCatalog
        Optional array from Get-FleetManagerReleaseVersions mapping VCF release versions
        to per-component build numbers. Included in the output so consumers can correlate
        Fleet-reported build numbers with advisory-compatible release version strings.

        .EXAMPLE
        $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory
        Export-PatchScanFindings -Findings $findings -OutputPath "C:\findings\scan-results.json"

        .EXAMPLE
        Export-PatchScanFindings -Findings $findings -FailedEndpoints $failedEndpoints `
            -VersionCatalog $catalog -VcfMinorVersion "9.1" -OutputPath "C:\findings\scan-results.json"

        .OUTPUTS
        None. Creates file at OutputPath.

        .NOTES
        Writes findings JSON atomically via a temp file in the same directory followed by a rename.
        The temp file is removed on failure. Creates the output directory when absent.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)] [AllowEmptyCollection()] [Object[]]$FailedEndpoints = @(),
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [Object[]]$Findings,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$OutputPath,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$VcfMinorVersion = '',
        [Parameter(Mandatory = $false)] [AllowEmptyCollection()] [Object[]]$VersionCatalog = @()
    )

    # OutputPath must be absolute to avoid resolution ambiguity; the Python server provides the full path.
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        throw [System.InvalidOperationException]::new("FindingsOutputPath must be an absolute path, got: $OutputPath")
    }
    $resolvedPath = $OutputPath
    $tempPath     = $null

    try {
        $directory = [System.IO.Path]::GetDirectoryName($resolvedPath)
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            Write-LogMessage -Type DEBUG -Message "Created findings directory: $directory"
        }

        $output = [PSCustomObject]@{
            findings        = @($Findings)
            failedEndpoints = @($FailedEndpoints)
            vcfMinorVersion = $VcfMinorVersion
            versionCatalog  = @($VersionCatalog)
        }
        $json     = ConvertTo-Json -InputObject $output -Depth $Script:JSON_SERIALIZE_DEPTH -ErrorAction Stop
        $tempPath = Join-Path -Path $directory -ChildPath "findings_$(New-Guid).tmp"

        # Atomic write: temp file in same directory + rename so readers never see a partial file.
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        Move-Item -LiteralPath $tempPath -Destination $resolvedPath -Force
        $tempPath = $null

        $versionSuffix = if (-not [String]::IsNullOrWhiteSpace($VcfMinorVersion)) { ", VCF $VcfMinorVersion detected" } else { "" }
        Write-LogMessage -Type INFO -Message "Findings exported to JSON: $resolvedPath ($(@($Findings).Count) findings, $(@($FailedEndpoints).Count) failed endpoints, $(@($VersionCatalog).Count) version catalog entries$versionSuffix)"
    }
    catch {
        if ($null -ne $tempPath -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        Write-LogMessage -Type ERROR -Message "Failed to export findings: $($_.Exception.Message)"
        throw
    }
}

function Export-PatchScanFindingsCSV {

    <#
        .SYNOPSIS
        Export vulnerability findings to CSV file.

        .DESCRIPTION
        Writes findings as CSV with one row per vulnerability instance.
        Useful for import into spreadsheet or reporting tools.

        .PARAMETER Findings
        Array of vulnerability findings (from Invoke-VulnerabilityScan).

        .PARAMETER OutputPath
        Full path to output CSV file (absolute or relative to module root).

        .EXAMPLE
        $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory
        Export-PatchScanFindingsCSV -Findings $findings -OutputPath "findings/scan-results.csv"

        .OUTPUTS
        None. Creates file at OutputPath.

        .NOTES
        Writes findings CSV atomically via a temp file in the same directory followed by a rename.
        The temp file is removed on failure. Creates the output directory when absent.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [Object[]]$Findings,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$OutputPath
    )

    # FindingsOutputPath must be absolute path to avoid resolution ambiguity.
    # The caller (Python server) is responsible for providing the full path.
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        throw [System.InvalidOperationException]::new("FindingsOutputPath must be an absolute path, got: $OutputPath")
    }
    $resolvedPath = $OutputPath
    $tempPath     = $null

    try {
        $directory = [System.IO.Path]::GetDirectoryName($resolvedPath)
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        $findings = @($Findings)
        $csvData  = $findings | Select-Object -Property `
            @{Name = 'Component'; Expression = { $_.component }},
            @{Name = 'CurrentVersion'; Expression = { $_.currentVersion }},
            @{Name = 'VulnerableMinimumVersion'; Expression = { $_.vulnerableMinimumVersion }},
            @{Name = 'FixedVersions'; Expression = { ($_.fixedVersions -join '; ') }},
            @{Name = 'Severity'; Expression = { $_.severity }},
            @{Name = 'CVEs'; Expression = { ($_.cves -join '; ') }},
            @{Name = 'VMSA_ID'; Expression = { $_.vmsaId }},
            @{Name = 'ServerFqdn'; Expression = { $_.serverFqdn }}

        $tempPath = Join-Path -Path $directory -ChildPath "findings_$(New-Guid).tmp"

        # Atomic write: export to temp file then rename so readers never see a partial file.
        $csvData | Export-Csv -Path $tempPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $resolvedPath -Force
        $tempPath = $null

        Write-LogMessage -Type INFO -Message "Findings exported to CSV: $resolvedPath ($($findings.Count) findings)"
    }
    catch {
        if ($null -ne $tempPath -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        Write-LogMessage -Type ERROR -Message "Failed to export CSV: $($_.Exception.Message)"
        throw
    }
}

#endregion
