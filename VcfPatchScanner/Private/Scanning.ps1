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

#region Vulnerability Scanning

function Invoke-VulnerabilityScan {

    <#
        .SYNOPSIS
        Scan environment inventory against security advisories.

        .DESCRIPTION
        Compares current environment component versions against advisory thresholds
        to identify vulnerable components. Returns findings with severity, CVEs, and
        remediation information.

        .PARAMETER Advisories
        Array of advisory documents (from Get-SecurityAdvisory).

        .PARAMETER Inventory
        Hashtable of environment inventory keyed by component name.
        Expected structure: @{ "ESXi" = @(...hosts), "vCenter" = @(...vcenter), ... }
        Each item must have Fqdn, Version, and DomainName (set during collection:
        "VCF Fleet", workload domain name, or "N/A").

        .EXAMPLE
        $advisories = Get-SecurityAdvisory -FilePath "securityAdvisoryCustom.json"
        $inventory = @{ "ESXi" = @(...); "vCenter" = @(...) }
        $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

        .OUTPUTS
        [PSCustomObject[]] Array of findings with: Component, DomainName, ClusterName, Version,
        currentBuild (optional — only present when a Fleet build number differs from Version),
        vulnerableMinimumVersion, severity, cves, vmsaId, fixedVersionUrl, serverFqdn

        .NOTES
        Skips advisories without a vmsaId. Returns findings via the comma-operator to preserve the array type on the pipeline.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$Advisories,
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [Hashtable]$Inventory
    )

    Write-LogMessage -Type INFO -Message "Starting vulnerability scan against $($Advisories.Count) advisories..."

    # Log an error for any vCenter or ESXi host running an end-of-life version (6.5, 6.7, or 7.0)
    # and exclude it from scanning. 2025+ advisories covering these versions are retained in the
    # advisory database for emergency patches, but this scanner only supports vSphere 8.x and later.
    $eolVersionPattern = '^(6\.(5|7)|7\.0)\.'
    $eolScanComponents = [System.Collections.Generic.HashSet[String]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [Void]$eolScanComponents.Add('ESXi')
    [Void]$eolScanComponents.Add('vCenter')
    $filteredInventory = @{}
    foreach ($key in $Inventory.Keys) {
        if ($eolScanComponents.Contains($key)) {
            $filteredItems = [System.Collections.Generic.List[Object]]::new()
            foreach ($item in @($Inventory[$key])) {
                $versionForEolCheck = if (-not [String]::IsNullOrWhiteSpace($item.BuildVersion)) { [String]$item.BuildVersion } else { [String]$item.Version }
                if ($versionForEolCheck -match $eolVersionPattern) {
                    Write-LogMessage -Type ERROR -Message "$key '$($item.Fqdn)' is running version $versionForEolCheck — this is an end-of-life release (6.5/6.7/7.0) that is not supported by this scanner. Upgrade to vSphere 8.x or later. Skipping this endpoint."
                } else {
                    $filteredItems.Add($item)
                }
            }
            $filteredInventory[$key] = $filteredItems.ToArray()
        } else {
            $filteredInventory[$key] = $Inventory[$key]
        }
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $scannedCount = 0
    $scanStartTime = Get-Date

    foreach ($advisory in @($Advisories)) {
        if ([String]::IsNullOrWhiteSpace($advisory.vmsaId)) {
            Write-LogMessage -Type WARNING -Message "Skipping advisory with no VMSA ID."
            continue
        }

        foreach ($component in @($advisory.impactedComponents)) {
            $componentName = [String]$component.component

            if (-not (Test-ValidAdvisoryComponent -ComponentName $componentName)) {
                continue
            }

            # Resolve any historical advisory name to the VCF 9.x inventory key. Advisory pages
            # have used different names across eras (vRealize / Aria / VCF); the alias table maps
            # them all to the key used in the inventory hashtable built from Fleet Manager data.
            $inventoryKey = if ($Script:ADVISORY_COMPONENT_ALIASES.ContainsKey($componentName)) {
                $Script:ADVISORY_COMPONENT_ALIASES[$componentName]
            } else {
                $componentName
            }

            $itemList = [System.Collections.Generic.List[Object]]::new()
            if ($null -ne $filteredInventory[$inventoryKey]) {
                foreach ($i in @($filteredInventory[$inventoryKey])) {
                    # Tag NSX Manager items so the UI can distinguish them from NSX Edge nodes.
                    if ($inventoryKey -eq 'NSX') {
                        $i | Add-Member -NotePropertyName 'EndpointSubType' -NotePropertyValue 'NSX Manager' -Force -ErrorAction SilentlyContinue
                    }
                    $itemList.Add($i)
                }
            }
            # "NSX" advisories cover both NSX Manager and NSX Edge — they ship the same codebase
            # and share the same VMSA. Merge "NSX Edge" entries so edge nodes are scanned too.
            if ($inventoryKey -eq 'NSX' -and $null -ne $filteredInventory['NSX Edge']) {
                foreach ($i in @($filteredInventory['NSX Edge'])) {
                    $i | Add-Member -NotePropertyName 'EndpointSubType' -NotePropertyValue 'NSX Edge' -Force -ErrorAction SilentlyContinue
                    $itemList.Add($i)
                }
            }
            if ($itemList.Count -eq 0) { continue }
            $inventoryItems = $itemList.ToArray()

            $minimumVersions = @($component.minimumVersions)
            $fixedVersions   = @($component.fixedVersions  | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })
            $kbArticles      = @($component.kbArticles     | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })
            # When only KB articles are available (no semantic fixed versions), treat any
            # endpoint at or above minimumVersions as always vulnerable; the KB article is
            # the remediation reference shown in the findings output.
            $kbOnly = ($fixedVersions.Count -eq 0 -and $kbArticles.Count -gt 0)
            # fixedVersions passed to Test-VersionVulnerable: empty array for KB-only rows
            # so the function's KB-skip path returns $true (vulnerable = always flag).
            # Direct if/else required — if-expression assignment unboxes @() to $null in PowerShell.
            if ($kbOnly) { $versionsForComparison = @() } else { $versionsForComparison = $fixedVersions }

            foreach ($item in @($inventoryItems)) {
                $currentVersion = [String]$item.Version
                # BuildVersion overrides Version for advisory comparison on two VCF 8 paths:
                #  1. vCenter (VCF 8, SDDC Manager): SDDC Manager reports "8.0.3.00100-24091160"
                #     but advisories use the MOB build as the 4th segment ("8.0.3.24091160").
                #     BuildVersion = MOB build form; Version = SDDC Manager form.
                #  2. ESXi (direct vCenter connection): Version is 3-part ("8.0.3"); BuildVersion
                #     is the advisory-compatible 4-part form using $_.Build ("8.0.3.24105824").
                # For VCF 9.x, Version holds the raw 5-part string (e.g. "9.1.0.0100.25428926");
                # ConvertTo-NormalizedVersion extracts segments 1,2,3,5 producing "9.1.0.25428926".
                if (-not [String]::IsNullOrWhiteSpace($item.BuildVersion)) { $currentBuild = [String]$item.BuildVersion } else { $currentBuild = $null }
                $versionForComparison = if ($null -ne $currentBuild) { $currentBuild } else { $currentVersion }

                $matchedMinimumVersion = $null
                foreach ($minimumVersion in $minimumVersions) {
                    if (Test-VersionVulnerable -CurrentVersion $versionForComparison -MinimumVersion $minimumVersion -FixedVersions $versionsForComparison) {
                        $matchedMinimumVersion = $minimumVersion
                        break
                    }
                }

                if ($null -ne $matchedMinimumVersion) {
                    # For KB-only rows, surface the KB article IDs as the fixed-version column
                    # so the operator has a direct remediation reference.
                    # [String[]] cast forces ConvertTo-Json to always emit a JSON array, even for
                    # single-element collections (PowerShell otherwise collapses them to a scalar).
                    if ($kbOnly) { $displayFixed = [String[]]@($kbArticles) } else { $displayFixed = [String[]]@($fixedVersions) }
                    $finding = [PSCustomObject]@{
                        component                = $componentName
                        endpointSubType          = if (-not [String]::IsNullOrWhiteSpace($item.EndpointSubType)) { [String]$item.EndpointSubType } else { '' }
                        domainName               = if (-not [String]::IsNullOrWhiteSpace($item.DomainName)) { [String]$item.DomainName } else { '' }
                        clusterName              = if (-not [String]::IsNullOrWhiteSpace($item.ClusterName)) { [String]$item.ClusterName } else { '' }
                        instanceName             = if (-not [String]::IsNullOrWhiteSpace($item.InstanceName)) { [String]$item.InstanceName } else { '' }
                        currentVersion           = $currentVersion
                        vulnerableMinimumVersion = $matchedMinimumVersion
                        fixedVersions            = $displayFixed
                        severity                 = $component.severity
                        cves                     = @($component.cves | Sort-Object)
                        vmsaId                   = $advisory.vmsaId
                        advisoryUrl              = [String]$advisory.advisoryUrl
                        fixedVersionUrl          = [System.Net.WebUtility]::HtmlDecode([String]$component.fixedVersionUrl)
                        serverFqdn               = $item.Fqdn
                    }
                    if ($null -ne $currentBuild) {
                        $finding | Add-Member -NotePropertyName 'currentBuild' -NotePropertyValue $currentBuild
                    }
                    [Void]$findings.Add($finding)
                }

                $scannedCount++
            }
        }
    }

    $scanDuration = (Get-Date) - $scanStartTime
    Write-LogMessage -Type INFO -Message "Advisory matching complete in $([Math]::Round($scanDuration.TotalSeconds, 1))s: $scannedCount items checked, $($findings.Count) vulnerabilities found"

    , @($findings)
}
function ConvertTo-NormalizedVersion {

    <#
        .SYNOPSIS
        Parse a version string into a [Version] object.

        .DESCRIPTION
        Normalises a raw version string into a [System.Version] object suitable for comparison.
        The following transformations are applied in order:
          1. Strips trailing edition/hotfix tokens separated by whitespace (e.g. "EP1", "HF").
          2. When the string is exactly three dotted segments followed by a dash and a numeric
             build number (e.g. "8.0.3-24022510"), the build is promoted to a fourth segment:
             "8.0.3.24022510". This matches the advisory scheme where ESXi and NSX fixed versions
             are expressed as "8.0.3.24022510". For four-part forms with a dash suffix (e.g.
             vCenter SDDC Manager's "8.0.3.00100-24091160"), the dash and everything after it
             are stripped instead — those are handled via BuildVersion in the inventory layer.
          3. For 5-part VCF 9.x version strings (e.g. "9.1.0.0100.25428926" or
             "9.1.0.0.25370933"), extracts segments 1, 2, 3, and 5 (the per-build number),
             discarding the 4th update-level segment. This produces "9.1.0.25428926" and
             "9.1.0.25370933" respectively — the form used in advisory fixedVersion fields.
        Throws [System.FormatException] when the normalized string still cannot be parsed —
        callers must wrap in try/catch when bad input is possible.

        .PARAMETER VersionString
        Raw version string, e.g. "8.0.3.00900 EP1", "8.0.3-24022510", "9.1.0.0100.25428926".

        .EXAMPLE
        $v = ConvertTo-NormalizedVersion -VersionString "8.0.3-24022510"
        # $v.Major = 8, $v.Minor = 0, $v.Build = 3, $v.Revision = 24022510

        .OUTPUTS
        [Version] Parsed version object.

        .NOTES
        Throws [System.FormatException] when the input cannot be parsed as a version.
        Callers that handle bad input (advisory scanners) should wrap in try/catch.
    #>

    [CmdletBinding()]
    [OutputType([Version])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$VersionString
    )

    # Strip trailing edition/hotfix tokens (e.g. "8.0.3.00900 EP1", "9.0.2 HF").
    $norm = $VersionString -replace '\s+(EP\d+|HF)$', ''
    # ESXi and NSX report versions as "<major>.<minor>.<patch>-<build>" where the build number
    # after the dash is the same scheme used in advisory fixed versions (e.g. "8.0.3.24022510").
    # Promote the dash-suffix build number to a fourth dotted segment so the comparison is
    # commensurable: "8.0.3-24022510" → "8.0.3.24022510". Only applied when the dotted prefix
    # is exactly three segments (major.minor.patch); four-part forms already carry the build as
    # the fourth segment (vCenter SDDC Manager form "8.0.3.00100-24091160" is handled separately
    # in Get-SddcManagerInventory via BuildVersion, so the dash is stripped there instead).
    if ($norm -match '^(\d+\.\d+\.\d+)-(\d+)$') {
        $norm = "$($Matches[1]).$($Matches[2])"
    } else {
        $norm = $norm -replace '-.*$', ''
    }
    $parts = $norm.Split('.')
    # 5-part VCF 9.x strings (e.g. "9.1.0.0100.25428926"): use segments 1,2,3,5 so that the
    # per-build number becomes the 4th comparison segment, matching advisory fixedVersion format.
    if ($parts.Count -gt 4) { $norm = "$($parts[0]).$($parts[1]).$($parts[2]).$($parts[4])" }
    return [Version]$norm
}
function Test-VersionVulnerable {

    <#
        .SYNOPSIS
        Check if a version is vulnerable based on advisory criteria.

        .DESCRIPTION
        Compares current version against minimum affected version and fixed versions.
        A version is vulnerable if:
        1. It is >= MinimumVersion AND
        2. It does NOT match any FixedVersion

        Uses semantic versioning comparison (X.Y.Z).

        .PARAMETER CurrentVersion
        Current installed version string.

        .PARAMETER MinimumVersion
        Minimum version affected by the vulnerability.

        .PARAMETER FixedVersions
        Array of versions that fix the vulnerability.

        .EXAMPLE
        $isVulnerable = Test-VersionVulnerable -CurrentVersion '8.0.2' -MinimumVersion '7.0.0' -FixedVersions @('8.0.3', '9.0.0')
        if ($isVulnerable) {
            Write-LogMessage -Type WARNING -Message 'Component version is vulnerable.'
        }

        .OUTPUTS
        [Bool] $true if vulnerable, $false if not

        .NOTES
        Returns $false (not vulnerable) when version strings cannot be parsed. KB-only advisories (empty FixedVersions) always flag as vulnerable when the current version is in the same major product line as minimum.
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$CurrentVersion,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$MinimumVersion,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$FixedVersions
    )

    try {
        $current = ConvertTo-NormalizedVersion -VersionString $CurrentVersion
        $minimum = ConvertTo-NormalizedVersion -VersionString $MinimumVersion
    }
    catch {
        Write-LogMessage -Type WARNING -Message "Cannot compare versions — unrecognised format: current='$CurrentVersion', minimum='$MinimumVersion'."
        return $false
    }

    if ($current -lt $minimum) {
        return $false
    }

    $hasNumericFixed = $false
    foreach ($fixedVersion in $FixedVersions) {
        $fixedStr = ([String]$fixedVersion).Trim()
        # KB article numbers (e.g. KB87646) are valid advisory entries that require the user
        # to apply the referenced patch; they cannot be compared numerically, so skip silently.
        if ($fixedStr -match '^KB\d+') {
            continue
        }
        $hasNumericFixed = $true
        try {
            $fixed = ConvertTo-NormalizedVersion -VersionString $fixedStr
            if ($current -ge $fixed) {
                return $false
            }
        }
        catch {
            Write-LogMessage -Type WARNING -Message "Invalid fixed-version format '$fixedVersion' — skipping."
            continue
        }
    }

    # No numeric fixed version found (KB-only advisory). Only flag as vulnerable when current is
    # in the same major product line as minimum — a higher major version postdates the advisory.
    if (-not $hasNumericFixed -and $current.Major -gt $minimum.Major) {
        return $false
    }
    return $true
}
function New-FindingsSummary {

    <#
        .SYNOPSIS
        Build summary statistics from vulnerability findings.

        .DESCRIPTION
        Aggregates an array of vulnerability finding objects into a summary object. Produces total
        finding count, unique component count, unique CVE count, and per-severity breakdown. All
        finding objects are expected to have Severity, Component, and CVEs properties.

        .PARAMETER Findings
        Array of vulnerability findings.

        .EXAMPLE
        $summary = New-FindingsSummary -Findings $allFindings
        Write-LogMessage -Type INFO -Message "Critical findings: $($summary.CriticalCount)"

        .OUTPUTS
        [PSCustomObject] Summary with counts and severity breakdown

        .NOTES
        Pure aggregation function. Does not mutate any module-scope variables.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$Findings
    )

    $findings = @($Findings)
    $severityCounts = @{}

    foreach ($finding in $findings) {
        $severity = [String]$finding.Severity
        if (-not $severityCounts.ContainsKey($severity)) {
            $severityCounts[$severity] = 0
        }
        $severityCounts[$severity]++
    }

    return [PSCustomObject]@{
        TotalFindings = $findings.Count
        UniqueComponents = ($findings.Component | Select-Object -Unique).Count
        UniqueCVEs = ($findings.CVEs | ForEach-Object { @($_) } | Select-Object -Unique | Measure-Object).Count
        BySeverity = $severityCounts
        CriticalCount = $severityCounts["Critical"] ?? 0
        HighCount = $severityCounts["High"] ?? 0
        MediumCount = $severityCounts["Medium"] ?? 0
        LowCount = $severityCounts["Low"] ?? 0
    }
}
function Merge-FindingsByComponent {

    <#
        .SYNOPSIS
        Consolidate multiple findings for the same component.

        .DESCRIPTION
        Groups vulnerability findings by their Component property and produces one merged finding
        per component. CVEs are deduplicated across all findings in the group. The highest severity
        across all findings is promoted to HighestSeverity. The instance count reflects the number
        of distinct ServerFqdn values in the group.

        .PARAMETER Findings
        Array of vulnerability findings.

        .EXAMPLE
        $merged = Merge-FindingsByComponent -Findings $rawFindings
        foreach ($componentFinding in $merged) {
            Write-LogMessage -Type INFO -Message "$($componentFinding.Component): $($componentFinding.VulnerabilityCount) vulnerabilities"
        }

        .OUTPUTS
        [PSCustomObject[]] Merged findings (one per component, CVEs aggregated)

        .NOTES
        Pure aggregation function. Groups findings by the Component property. Does not mutate any module-scope variables.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$Findings
    )

    $grouped = $Findings | Group-Object -Property Component

    $merged = foreach ($group in $grouped) {
        $componentFindings = $group.Group
        $uniqueCVEs = @($componentFindings.CVEs | ForEach-Object { @($_) } | Select-Object -Unique)
        $severityOrder = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
        $maxSeverity = ($componentFindings.Severity |
            Sort-Object { $severityOrder[[String]$_] ?? 0 } -Descending)[0]

        [PSCustomObject]@{
            Component = $group.Name
            VulnerabilityCount = $componentFindings.Count
            UniqueCVECount = $uniqueCVEs.Count
            UniqueCVEs = $uniqueCVEs
            HighestSeverity = $maxSeverity
            InstanceCount = ($componentFindings.ServerFqdn | Select-Object -Unique).Count
            Findings = $componentFindings
        }
    }

    return @($merged)
}

#endregion
