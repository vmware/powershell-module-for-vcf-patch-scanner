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

#region Entry Points

function Invoke-VCFPatchScanner {

    <#
        .SYNOPSIS
        Execute a VCF vulnerability scan.

        .DESCRIPTION
        Main orchestrator function that coordinates discovery, advisory loading,
        vulnerability scanning, and findings export. Returns structured result
        with scan metrics and output paths.

        .PARAMETER AdvisoryPath
        Path to security advisory file (default: ./securityAdvisory.json).

        .PARAMETER FindingsOutputPath
        Path where findings JSON file should be written (default: ./findings/scan-results.json).

        .PARAMETER EnvironmentType
        Environment type: vcf5, vcf9, vsphere8, vvf9.

        .PARAMETER EnvironmentConfig
        Environment configuration object (from New-PatchScanEnvironment).
        If not provided, must be loadable from settings file.

        .PARAMETER ExportCsv
        If specified, also export findings to CSV at this path.

        .PARAMETER IncludeOnlyFqdns
        Optional list of endpoint FQDNs to inventory. When non-empty, only those FQDNs
        are queried and all others are skipped. Used by the retry-failed-only scan path.

        .PARAMETER TimeoutSeconds
        Per-endpoint connection timeout in seconds passed to ConvertTo-ScanInventory (1-900, default 30).

        .PARAMETER UseLiveInventory
        When set, collects live inventory from all configured API endpoints. Omit only when
        replaying a previously collected inventory object.

        .EXAMPLE
        $envConfig = New-PatchScanEnvironment -Name "Lab" -Type vcf9 `
            -SddcManagerServer "sddc.example.com" -SddcManagerUser "administrator@vsphere.local" `
            -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" `
            -VcfFMServer "flt-fm01.example.com" -VcfFMUser "admin@vsp.local"
        Invoke-VCFPatchScanner -AdvisoryPath "advisory.json" -EnvironmentConfig $envConfig -EnvironmentType vcf9 -UseLiveInventory

        .OUTPUTS
        [PSCustomObject] Result with: Status, ScanStartedAt, ScanCompletedAt, DurationSeconds,
        AdvisoriesLoaded, AdvisoriesFiltered, FindingsCount, FailedEndpoints, FindingsPath, ExitCode

        .NOTES
        Entry point called by Invoke-VCFPatchScanner.ps1. All discovery and inventory errors are captured in FailedEndpoints; the function returns a result object rather than throwing on partial failures.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$AdvisoryPath,
        [Parameter(Mandatory = $true)]  [ValidateNotNull()]        [PSCustomObject]$EnvironmentConfig,
        [Parameter(Mandatory = $true)]  [ValidateSet('vcf5', 'vcf9', 'vsphere8', 'vvf9')] [String]$EnvironmentType,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$ExportCsv,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$FindingsOutputPath = "findings/scan-results.json",
        [Parameter(Mandatory = $false)] [AllowEmptyCollection()]   [String[]]$IncludeOnlyFqdns = @(),
        [Parameter(Mandatory = $false)] [ValidateRange(1, 900)]    [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $false)] [Switch]$UseLiveInventory,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$VcenterBuildMapFile = ''
    )

    $startTime = Get-Date
    $result = [PSCustomObject]@{
        Status = "Failed"
        ScanStartedAt = $startTime
        ScanCompletedAt = $null
        DurationSeconds = 0
        AdvisoriesLoaded = 0
        AdvisoriesFiltered = 0
        FindingsCount = 0
        FailedEndpoints = @()
        FindingsPath = $FindingsOutputPath
        ExitCode = 1
    }

    try {
        Write-LogMessage -Type INFO -Message "VCF Patch Scan starting for environment type: $EnvironmentType"

        $advisories = Get-SecurityAdvisory -FilePath $AdvisoryPath -ValidateSchema
        if ($null -eq $advisories) {
            Write-LogMessage -Type ERROR -Message "Failed to load the security advisory database from '$AdvisoryPath'."
            return $result
        }

        $result.AdvisoriesLoaded = @($advisories).Count
        $filteredAdvisories = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType $EnvironmentType
        $result.AdvisoriesFiltered = @($filteredAdvisories).Count
        Write-LogMessage -Type INFO -Message "Loaded $($result.AdvisoriesLoaded) advisories from $AdvisoryPath; $($result.AdvisoriesFiltered) applicable for $EnvironmentType"

        if ($result.AdvisoriesFiltered -eq 0) {
            Write-LogMessage -Type INFO -Message "No applicable advisories found for this environment; no vulnerabilities to scan"
            $result.Status = "Success"
            $result.ExitCode = 0
            Export-PatchScanFindings -Findings @() -OutputPath $FindingsOutputPath
            if ($ExportCsv) {
                Export-PatchScanFindingsCSV -Findings @() -OutputPath $ExportCsv
            }
            $result.FindingsPath = $FindingsOutputPath
            return $result
        }

        Write-LogMessage -Type INFO -Message "Building environment inventory..."
        $inventoryResult = ConvertTo-ScanInventory -EnvironmentConfig $EnvironmentConfig `
            -EnvironmentType $EnvironmentType -IncludeOnlyFqdns $IncludeOnlyFqdns `
            -TimeoutSeconds $TimeoutSeconds -UseLiveInventory:$UseLiveInventory `
            -VcenterBuildMapFile $VcenterBuildMapFile
        $inventory = $inventoryResult.Inventory
        $result.FailedEndpoints = @($inventoryResult.FailedEndpoints)

        $findings = Invoke-VulnerabilityScan -Advisories $filteredAdvisories -Inventory $inventory
        $result.FindingsCount = @($findings).Count

        Write-LogMessage -Type INFO -Message "Found $($result.FindingsCount) vulnerabilities"

        Write-LogMessage -Type INFO -Message "Building inventory status report..."
        $inventoryStatus = ConvertTo-InventoryStatus -Inventory $inventory -Findings $findings

        Write-LogMessage -Type INFO -Message "Exporting findings to: $FindingsOutputPath"
        $exportData = @($findings) + @($inventoryStatus)
        Export-PatchScanFindings -Findings $exportData -FailedEndpoints $result.FailedEndpoints `
            -VersionCatalog $inventoryResult.FleetCatalog -VcfMinorVersion $inventoryResult.VcfMinorVersion `
            -OutputPath $FindingsOutputPath

        if ($ExportCsv) {
            Write-LogMessage -Type INFO -Message "Exporting findings to CSV: $ExportCsv"
            Export-PatchScanFindingsCSV -Findings $findings -OutputPath $ExportCsv
        }

        $result.Status = "Success"
        $result.ExitCode = 0
        $result.ScanCompletedAt = Get-Date
        $result.DurationSeconds = [Int]($result.ScanCompletedAt - $result.ScanStartedAt).TotalSeconds
        Write-LogMessage -Type INFO -Message "VCF Patch Scan completed in $($result.DurationSeconds)s: $($result.FindingsCount) vulnerabilities found across $($result.AdvisoriesFiltered) applicable advisories"
    }
    catch {
        Write-LogMessage -Type ERROR -Message "VCF Patch Scan failed: $($_.Exception.Message)"
        $result.Status = "Failed"
        $result.ExitCode = 1
    }
    finally {
        if ($null -eq $result.ScanCompletedAt) {
            $result.ScanCompletedAt = Get-Date
            $result.DurationSeconds = [Int]($result.ScanCompletedAt - $result.ScanStartedAt).TotalSeconds
        }
    }

    return $result
}

function ConvertTo-ScanInventory {

    <#
        .SYNOPSIS
        Convert environment configuration to scannable inventory format.

        .DESCRIPTION
        Transforms the environment config object into a hashtable keyed by component name
        with arrays of servers containing Version and Fqdn properties.

        Attempts to collect live inventory from APIs; falls back to mock inventory from
        configuration if live collection fails or is unavailable. Each per-endpoint API
        call is isolated in its own try/catch so a single unreachable endpoint does not
        abort the scan — the endpoint is recorded in FailedEndpoints and collection
        continues for the remaining endpoints.

        When IncludeOnlyFqdns is non-empty only the listed FQDNs are inventoried; all
        others are skipped. This is used by the retry-failed-only scan path.

        .PARAMETER EnvironmentConfig
        Environment configuration object (from New-PatchScanEnvironment).

        .PARAMETER EnvironmentType
        Environment type determining which components are present.

        .PARAMETER IncludeOnlyFqdns
        Optional allowlist of endpoint FQDNs to inventory. When provided, any endpoint
        whose FQDN is not in this list is silently skipped. Pass the FQDNs from the
        previous scan's failedEndpoints to re-scan only those that failed.

        .PARAMETER TimeoutSeconds
        Per-endpoint connection timeout in seconds (1-900, default 30).

        .PARAMETER UseLiveInventory
        When set, attempts to collect live inventory from APIs.

        .PARAMETER VcenterBuildMapFile
        Optional path to vcenterBuildMap.json written by Convert-BroadcomAdvisoriesToSchema.ps1
        alongside securityAdvisory.json. When provided, vCenter inventory entries are enriched
        with a BuildVersion property so the UI can display the MOB build number alongside the
        advisory-compatible version string (e.g. "8.0.3.25413364 (8.0.3.00900)"). The scanner
        degrades gracefully when the file is absent — advisory comparison is unaffected.

        .EXAMPLE
        $result = ConvertTo-ScanInventory -EnvironmentConfig $envConfig -EnvironmentType 'vcf9' -TimeoutSeconds 30 -UseLiveInventory
        if ($result.FailedEndpoints.Count -gt 0) {
            Write-LogMessage -Type WARNING -Message "Some endpoints could not be inventoried."
        }

        .OUTPUTS
        [PSCustomObject] Object with Inventory ([Hashtable]) and FailedEndpoints ([Object[]]).

        .NOTES
        Reads component credentials from environment variables via Get-InventoryPassword. Sets $Script:_retryFailedFqdns when IncludeOnlyFqdns is non-empty.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNull()]  [PSCustomObject]$EnvironmentConfig,
        [Parameter(Mandatory = $true)]  [ValidateSet('vcf5', 'vcf9', 'vsphere8', 'vvf9')] [String]$EnvironmentType,
        [Parameter(Mandatory = $false)] [AllowEmptyCollection()] [String[]]$IncludeOnlyFqdns = @(),
        [Parameter(Mandatory = $false)] [ValidateRange(1, 900)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $false)] [Switch]$UseLiveInventory,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$VcenterBuildMapFile = ''
    )

    $inventory       = @{}
    $fleetCatalog    = @()
    $vcfMinorVersion = ''
    $failedEndpoints = [System.Collections.Generic.List[Object]]::new()

    if ($UseLiveInventory) {
        Write-LogMessage -Type INFO -Message "Attempting to collect live inventory from APIs (timeout: $($TimeoutSeconds)s)"

        if (-not [String]::IsNullOrWhiteSpace($VcenterBuildMapFile)) {
            $vcenterBuildMaps = Get-VcenterBuildMap -BuildMapPath $VcenterBuildMapFile
        } else {
            $vcenterBuildMaps = @{ VersionToBuild = @{}; BuildToVersion = @{} }
        }

        if ($EnvironmentType -in 'vcf5', 'vcf9') {
            $fqdn = $EnvironmentConfig.sddcManagerServer
            if ($fqdn -and $EnvironmentConfig.sddcManagerUser -and
                ($IncludeOnlyFqdns.Count -eq 0 -or $fqdn -in $IncludeOnlyFqdns)) {
                try {
                    $sddcInventory = Get-SddcManagerInventory -Server $fqdn `
                        -User $EnvironmentConfig.sddcManagerUser -TimeoutSeconds $TimeoutSeconds `
                        -VcenterBuildMaps $vcenterBuildMaps
                    $inventory += $sddcInventory

                    # Extract the two-part VCF minor version (e.g. "5.2") from the SDDC Manager
                    # version string (e.g. "5.2.0.0-24108943") so the UI label reads
                    # "VMware Cloud Foundation 5.2" rather than the generic "VMware Cloud Foundation 5".
                    # Re-derived on every scan so an upgraded environment is reflected immediately.
                    if ($EnvironmentType -eq 'vcf5' -and $inventory.ContainsKey('SDDC Manager')) {
                        $rawSddcVer = [String]($inventory['SDDC Manager'][0].Version)
                        if ($rawSddcVer -match '^(\d+\.\d+)') {
                            $vcfMinorVersion = $Matches[1]
                        }
                    }
                }
                catch {
                    Write-LogMessage -Type WARNING -Message "SDDC Manager inventory failed for '$fqdn': $($_.Exception.Message) — skipping endpoint."
                    $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $fqdn; Component = "SDDC Manager"; ErrorMessage = $_.Exception.Message })
                }
            }
        }

        if ($EnvironmentType -in 'vsphere8', 'vvf9', 'vcf5', 'vcf9') {
            $fqdn = $EnvironmentConfig.vcenterServer
            if ($fqdn -and $EnvironmentConfig.vcenterUser -and
                ($IncludeOnlyFqdns.Count -eq 0 -or $fqdn -in $IncludeOnlyFqdns)) {
                try {
                    $vcenterInventory = Get-VcenterInventory -Server $fqdn `
                        -User $EnvironmentConfig.vcenterUser -TimeoutSeconds $TimeoutSeconds `
                        -VcenterBuildMaps $vcenterBuildMaps
                    $inventory += $vcenterInventory
                }
                catch {
                    Write-LogMessage -Type WARNING -Message "vCenter inventory failed for '$fqdn': $($_.Exception.Message) — skipping endpoint."
                    $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $fqdn; Component = "vCenter"; ErrorMessage = $_.Exception.Message })
                }
            }
        }

        # For standalone vSphere 8 environments, NSX is not managed by SDDC Manager
        # so its inventory must be fetched directly from the NSX Manager REST API.
        # vcf5 and vcf9 environments receive NSX inventory through Get-SddcManagerInventory.
        # vvf9 does not use NSX.
        if ($EnvironmentType -eq 'vsphere8') {
            $fqdn = $EnvironmentConfig.nsxManagerServer
            if ($fqdn -and ($IncludeOnlyFqdns.Count -eq 0 -or $fqdn -in $IncludeOnlyFqdns)) {
                try {
                    $nsxInventory = Get-StandaloneNsxManagerInventory `
                        -NsxManagerFqdn $fqdn -TimeoutSeconds $TimeoutSeconds
                    $inventory += $nsxInventory
                }
                catch {
                    Write-LogMessage -Type WARNING -Message "NSX Manager inventory failed for '$fqdn': $($_.Exception.Message) — skipping endpoint."
                    $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $fqdn; Component = "NSX"; ErrorMessage = $_.Exception.Message })
                }

                # Edge nodes are best-effort: Get-NsxEdgeInventory returns @() silently
                # when NSX_MANAGER_PASSWORD is absent (vsphere8 env var path).
                $edgeNodes = Get-NsxEdgeInventory -NsxManagerFqdn $fqdn -TimeoutSeconds $TimeoutSeconds
                if ($edgeNodes.Count -gt 0) {
                    $inventory["NSX Edge"] = $edgeNodes
                    Write-LogMessage -Type INFO -Message "Collected $($edgeNodes.Count) NSX Edge node(s): $(($edgeNodes | ForEach-Object { $_.Fqdn }) -join ', ')"
                }
            }
        }

        $standaloneVcFqdns = @()

        if ($EnvironmentType -in 'vcf9', 'vvf9') {
            # Fleet Manager runs first so the API path it succeeds on can be used to determine
            # whether this is a VCF 9.0 (lcops) or 9.1+ (VSP fleet-lcm) environment, which
            # controls whether the native VCF Operations API call is necessary.
            $opsFromFleet = $null
            $fqdn = $EnvironmentConfig.vcfFMServer
            if ($fqdn -and $EnvironmentConfig.vcfFMUser -and
                ($IncludeOnlyFqdns.Count -eq 0 -or $fqdn -in $IncludeOnlyFqdns)) {
                try {
                    $fleetInventory = Get-FleetManagerInventory -Server $fqdn `
                        -User $EnvironmentConfig.vcfFMUser -TimeoutSeconds $TimeoutSeconds `
                        -AllowVspUserFallback:($EnvironmentType -eq 'vvf9')

                    $opsFromFleet = $fleetInventory['_OpsVersionFromFleet']
                    $fleetApiPath = [String]$fleetInventory['_FleetApiPath']
                    [Void]$fleetInventory.Remove('_OpsVersionFromFleet')
                    [Void]$fleetInventory.Remove('_FleetApiPath')

                    $vcfMinorVersion = switch ($fleetApiPath) {
                        'vsp'   { '9.1' }
                        'lcops' { '9.0' }
                        default { '' }
                    }

                    $inventory += $fleetInventory
                }
                catch {
                    Write-LogMessage -Type WARNING -Message "Fleet Manager inventory failed for '$fqdn': $($_.Exception.Message) — skipping endpoint."
                    $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $fqdn; Component = "Fleet Lifecycle"; ErrorMessage = $_.Exception.Message })
                }
            }

            # VCF Operations inventory — conditional on detected VCF minor version:
            # 9.1 (VSP path): Fleet Controller is authoritative; skip the native VCF Operations
            # API to avoid an extra credential requirement. The entry is built from Fleet data.
            # 9.0 (lcops path) or unknown: the native API is the primary source; Fleet data
            # supplements it for build-number enrichment when available.
            $fqdn = $EnvironmentConfig.vcfOpsServer
            if ($fqdn -and $EnvironmentConfig.vcfOpsUser -and
                ($IncludeOnlyFqdns.Count -eq 0 -or $fqdn -in $IncludeOnlyFqdns)) {
                if ($vcfMinorVersion -eq '9.1' -and $EnvironmentType -eq 'vcf9') {
                    if ($null -ne $opsFromFleet) {
                        $inventory['VCF Operations'] = @([PSCustomObject]@{
                            Fqdn       = $opsFromFleet.Fqdn
                            Version    = $opsFromFleet.Version
                            DomainName = "VCF Fleet"
                        })
                        Write-LogMessage -Type INFO -Message "VCF Operations (9.1): version sourced from Fleet Controller: $($opsFromFleet.Version)"
                    }
                } else {
                    try {
                        $opsInventory = Get-VcfOpsInventory -Server $fqdn `
                            -User $EnvironmentConfig.vcfOpsUser -TimeoutSeconds $TimeoutSeconds
                        # VVF9 only: standalone vCenters are genuinely standalone (no SDDC Manager).
                        # VCF9 is excluded because VCF Operations returns vCenters that also appear
                        # in SDDC Manager workload domains; scanning them separately would produce
                        # duplicate results with no reliable filter at discovery time.
                        if ($EnvironmentType -eq 'vvf9') {
                            $standaloneVcFqdns = @($opsInventory['_StandaloneVcenterFqdns'])
                            if ($standaloneVcFqdns.Count -gt 0) {
                                Write-LogMessage -Type INFO -Message "VVF9: scanning $($standaloneVcFqdns.Count) standalone vCenter(s): $(($standaloneVcFqdns | Sort-Object) -join ', ')"
                            }
                        }
                        [Void]$opsInventory.Remove('_StandaloneVcenterFqdns')
                        $inventory += $opsInventory
                    }
                    catch {
                        Write-LogMessage -Type WARNING -Message "VCF Operations inventory failed for '$fqdn': $($_.Exception.Message) — skipping endpoint."
                        $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $fqdn; Component = "VCF Operations"; ErrorMessage = $_.Exception.Message })
                    }

                    if ($null -ne $opsFromFleet -and $inventory.ContainsKey('VCF Operations')) {
                        $opsEntries = [System.Collections.Generic.List[PSCustomObject]]::new()
                        foreach ($entry in @($inventory['VCF Operations'])) {
                            if ($entry.Fqdn -ieq $opsFromFleet.Fqdn) {
                                $opsEntries.Add([PSCustomObject]@{
                                    Fqdn       = $entry.Fqdn
                                    Version    = $opsFromFleet.Version
                                    DomainName = $entry.DomainName
                                })
                            } else {
                                $opsEntries.Add($entry)
                            }
                        }
                        $inventory['VCF Operations'] = $opsEntries.ToArray()
                        Write-LogMessage -Type DEBUG -Message "VCF Operations version enriched from Fleet: $($opsFromFleet.Version)"
                    }
                }
            }

            # VVF9 9.1: standalone vCenters are stored in the environment config from wizard
            # authentication — use them directly instead of querying VCF Operations at scan time
            # (the native Ops API is skipped on 9.1; Fleet Controller is authoritative).
            # The Python server serialises the list as JSON in the VCENTER_FQDNS env var.
            # VCF9 is excluded: see comment at the vcf9/vvf9 9.0 path above.
            if ($vcfMinorVersion -eq '9.1' -and $EnvironmentType -eq 'vvf9') {
                $vcenterFqdnsJson = [System.Environment]::GetEnvironmentVariable('VCENTER_FQDNS')
                if (-not [String]::IsNullOrWhiteSpace($vcenterFqdnsJson)) {
                    try {
                        $configVcFqdns = @(ConvertFrom-Json $vcenterFqdnsJson |
                            Where-Object { -not [String]::IsNullOrWhiteSpace([String]$_) })
                        if ($configVcFqdns.Count -gt 0) {
                            $standaloneVcFqdns = $configVcFqdns
                            Write-LogMessage -Type INFO -Message "$EnvironmentType 9.1: using $($standaloneVcFqdns.Count) stored standalone vCenter FQDN(s): $(($standaloneVcFqdns | Sort-Object) -join ', ')"
                        } else {
                            Write-LogMessage -Type WARNING -Message "$EnvironmentType 9.1: VCENTER_FQDNS parsed but contained no non-empty entries — standalone vCenter inventory skipped."
                        }
                    }
                    catch {
                        Write-LogMessage -Type WARNING -Message "$EnvironmentType 9.1: failed to parse VCENTER_FQDNS — standalone vCenter inventory skipped: $($_.Exception.Message)"
                    }
                } else {
                    Write-LogMessage -Type WARNING -Message "$EnvironmentType 9.1: VCENTER_FQDNS not set — standalone vCenter inventory skipped. Re-authenticate in the environment editor to populate the vCenter list."
                }
            }
        }

        foreach ($vcFqdn in $standaloneVcFqdns) {
            if ([String]::IsNullOrWhiteSpace($EnvironmentConfig.vcenterUser)) { continue }
            if ($IncludeOnlyFqdns.Count -gt 0 -and $vcFqdn -notin $IncludeOnlyFqdns) { continue }
            try {
                $vcInventory = Get-VcenterInventory -Server $vcFqdn `
                    -User $EnvironmentConfig.vcenterUser -TimeoutSeconds $TimeoutSeconds `
                    -VcenterBuildMaps $vcenterBuildMaps
                $inventory += $vcInventory
            }
            catch {
                Write-LogMessage -Type WARNING -Message "Standalone vCenter inventory failed for '$vcFqdn': $($_.Exception.Message) — skipping endpoint."
                $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $vcFqdn; Component = "vCenter"; ErrorMessage = $_.Exception.Message })
            }
        }

        # vRSLCM is optional for VCF 5.x environments.
        if ($EnvironmentType -eq 'vcf5') {
            $vrslcmPass = [System.Environment]::GetEnvironmentVariable("VRSLCM_PASSWORD")
            $fqdn       = $EnvironmentConfig.vrslcmServer
            $vrslcmUser = if (-not [String]::IsNullOrWhiteSpace($EnvironmentConfig.vrslcmUser)) {
                $EnvironmentConfig.vrslcmUser
            } else {
                "admin@local"
            }

            # Auto-discover vRSLCM from SDDC Manager when not explicitly configured.
            # Only attempted when VRSLCM_PASSWORD is set — without it the inventory
            # step below would fail and there is nothing useful to discover.
            if ([String]::IsNullOrWhiteSpace($fqdn) -and -not [String]::IsNullOrWhiteSpace($vrslcmPass)) {
                $sddcServer = $EnvironmentConfig.sddcManagerServer
                $sddcUser   = $EnvironmentConfig.sddcManagerUser
                if (-not [String]::IsNullOrWhiteSpace($sddcServer) -and -not [String]::IsNullOrWhiteSpace($sddcUser)) {
                    Write-LogMessage -Type INFO -Message "vRSLCM not configured — auto-discovering from SDDC Manager: $sddcServer..."
                    $discovery = Get-VrslcmFromSddcManager -Server $sddcServer -User $sddcUser -TimeoutSeconds $TimeoutSeconds
                    if (-not [String]::IsNullOrWhiteSpace($discovery.VrslcmFqdn)) {
                        $fqdn = $discovery.VrslcmFqdn
                        Write-LogMessage -Type INFO -Message "vRSLCM auto-discovered: $fqdn"
                    } elseif ($null -eq $discovery.Error) {
                        Write-LogMessage -Type INFO -Message "No vRSLCM registered with SDDC Manager $sddcServer — skipping vRSLCM inventory."
                    } else {
                        Write-LogMessage -Type DEBUG -Message "vRSLCM auto-discovery failed: $($discovery.Error)"
                    }
                }
            }

            if (-not [String]::IsNullOrWhiteSpace($fqdn) -and -not [String]::IsNullOrWhiteSpace($vrslcmPass) -and
                ($IncludeOnlyFqdns.Count -eq 0 -or $fqdn -in $IncludeOnlyFqdns)) {
                try {
                    $vrslcmInventory = Get-VrslcmInventory -Server $fqdn `
                        -User $vrslcmUser -Password $vrslcmPass -TimeoutSeconds $TimeoutSeconds
                    $inventory += $vrslcmInventory
                }
                catch {
                    Write-LogMessage -Type WARNING -Message "vRSLCM inventory failed for '$fqdn': $($_.Exception.Message) — skipping endpoint."
                    $failedEndpoints.Add([PSCustomObject]@{ Fqdn = $fqdn; Component = "vRSLCM"; ErrorMessage = $_.Exception.Message })
                }
            }
        }

        if ($inventory.Count -gt 0) {
        # Fleet-tier components (Fleet Lifecycle, VCF Operations) already carry
        # DomainName = "VCF Fleet" from their collection functions. SDDC Manager-managed
            # components (vCenter, NSX, ESXi, SDDC Manager) carry their workload domain name
            # from Invoke-VcfGetDomains. For standalone environments (vsphere8, vvf9) the
            # VCF Domain concept does not apply — DomainName is left empty.
            foreach ($componentType in @($inventory.Keys)) {
                $inventory[$componentType] = @($inventory[$componentType] | ForEach-Object {
                    $nameToSet = if (-not [String]::IsNullOrWhiteSpace($_.DomainName)) {
                        [String]$_.DomainName
                    } else {
                        ''
                    }
                    Add-Member -InputObject $_ -NotePropertyName DomainName -NotePropertyValue $nameToSet -Force -PassThru
                })
            }
            if ($EnvironmentType -eq 'vcf9') {
                $cfgInstanceName = if (-not [String]::IsNullOrWhiteSpace($EnvironmentConfig.sddcManagerInstanceName)) {
                    [String]$EnvironmentConfig.sddcManagerInstanceName
                } else { '' }
                foreach ($componentType in @($inventory.Keys)) {
                    $inventory[$componentType] = @($inventory[$componentType] | ForEach-Object {
                        Add-Member -InputObject $_ -NotePropertyName InstanceName -NotePropertyValue $cfgInstanceName -Force -PassThru
                    })
                }
            }
            $failedCount = $failedEndpoints.Count
            Write-LogMessage -Type INFO -Message "Live inventory collected: $($inventory.Count) component types, $failedCount endpoint(s) failed."
            return [PSCustomObject]@{ Inventory = $inventory; FailedEndpoints = $failedEndpoints.ToArray(); FleetCatalog = $fleetCatalog; VcfMinorVersion = $vcfMinorVersion }
        }
        else {
            Write-LogMessage -Type INFO -Message "Live inventory collection returned no data; falling back to mock inventory from configuration"
        }
    }

    Write-LogMessage -Type INFO -Message "Using mock inventory from environment configuration"

    switch ($EnvironmentType) {
        'vcf5' {
            if ($EnvironmentConfig.sddcManagerServer) {
                $inventory['SDDC Manager'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.sddcManagerServer; Version = "Unknown"; DomainName = "" }
                )
            }
            if ($EnvironmentConfig.vcenterServer) {
                $inventory['vCenter'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vcenterServer; Version = "Unknown"; DomainName = "" }
                )
            }
            # vRSLCM version only discoverable via live API; do not add placeholder when offline.
            if ($EnvironmentConfig.vrslcmServer) {
                $inventory['Fleet Lifecycle'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vrslcmServer; Version = "Unknown"; DomainName = "vRSLCM" }
                )
            }
        }
        'vcf9' {
            $mockInstanceName = if (-not [String]::IsNullOrWhiteSpace($EnvironmentConfig.sddcManagerInstanceName)) {
                [String]$EnvironmentConfig.sddcManagerInstanceName
            } else { '' }
            if ($EnvironmentConfig.sddcManagerServer) {
                # DomainName is empty — the management domain name is only discoverable via
                # the live SDDC Manager API (Invoke-VcfGetDomains) and is not available here.
                $inventory['SDDC Manager'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.sddcManagerServer; Version = "Unknown"; DomainName = ""; InstanceName = $mockInstanceName }
                )
                # vCenter and NSX FQDNs are only discoverable via live SDDC Manager inventory.
                # Do NOT add placeholder FQDNs here — fake endpoints produce misleading findings.
            }
            if ($EnvironmentConfig.vcfOpsServer) {
                $inventory['VCF Operations'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vcfOpsServer; Version = "Unknown"; DomainName = "VCF Fleet"; InstanceName = $mockInstanceName }
                )
            }
            if ($EnvironmentConfig.vcfFMServer) {
                $inventory['Fleet Lifecycle'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vcfFMServer; Version = "Unknown"; DomainName = "VCF Fleet"; InstanceName = $mockInstanceName }
                )
            }
        }
        'vsphere8' {
            if ($EnvironmentConfig.vcenterServer) {
                $inventory['vCenter'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vcenterServer; Version = "Unknown"; DomainName = "" }
                )
            }
            if ($EnvironmentConfig.nsxManagerServer) {
                $inventory['NSX'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.nsxManagerServer; Version = "Unknown"; DomainName = "" }
                )
            }
        }
        'vvf9' {
            if ($EnvironmentConfig.vcfOpsServer) {
                $inventory['VCF Operations'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vcfOpsServer; Version = "Unknown"; DomainName = "VCF Fleet"; InstanceName = $mockInstanceName }
                )
            }
            if ($EnvironmentConfig.vcfFMServer) {
                $inventory['Fleet Lifecycle'] = @(
                    [PSCustomObject]@{ Fqdn = $EnvironmentConfig.vcfFMServer; Version = "Unknown"; DomainName = "VCF Fleet"; InstanceName = $mockInstanceName }
                )
            }
            # vCenter FQDNs are auto-discovered from VCF Operations at scan time and cannot be mocked.
            # vvf9 does not use NSX.
        }
    }

    return [PSCustomObject]@{ Inventory = $inventory; FailedEndpoints = @(); FleetCatalog = $fleetCatalog; VcfMinorVersion = $vcfMinorVersion }
}

function ConvertTo-InventoryStatus {

    <#
        .SYNOPSIS
        Convert scanned inventory to inventory status report.

        .DESCRIPTION
        Creates a consolidated status report for all scanned endpoints. One row per unique
        component+FQDN pair. Shows components with no vulnerabilities as "Safe" status. Each
        item's DomainName is read from the inventory object itself (set during collection:
        "VCF Fleet", workload domain name, or "N/A").

        Multiple Fleet components (e.g. Fleet Lifecycle, Salt Master, Salt RaaS) can share
        the same FQDN. Deduplication is keyed on component+FQDN rather than FQDN alone so
        all co-located Fleet components appear separately in the report.

        .PARAMETER Findings
        Array of vulnerability findings from Invoke-VulnerabilityScan.

        .PARAMETER Inventory
        Hashtable of scanned inventory keyed by component name.

        .EXAMPLE
        $statusReport = ConvertTo-InventoryStatus -Findings $scanFindings -Inventory $inventory
        $criticalHosts = $statusReport | Where-Object { $_.Status -eq 'Vulnerable' }

        .OUTPUTS
        [PSCustomObject[]] Array of endpoint status items (one per component+FQDN pair)

        .NOTES
        Pure transformation function. Groups inventory items with their associated findings to produce the per-host status report.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$Findings,
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [Hashtable]$Inventory
    )

    $endpointStatus = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Build a set of "component|fqdn" pairs that already have vulnerability findings so we
    # do not emit a duplicate "Not Vulnerable" row alongside a real finding for the same pair.
    $endpointsWithFindings = [System.Collections.Generic.HashSet[String]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in @($Findings)) {
        [Void]$endpointsWithFindings.Add("$($f.component)|$($f.serverFqdn)")
    }

    # Deduplicate by component+fqdn so co-located Fleet services (Salt Master, Salt RaaS, etc.
    # sharing the same host FQDN) each get their own inventory status row.
    $processedKeys = [System.Collections.Generic.HashSet[String]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($componentName in $Inventory.Keys) {
        $inventoryItems = @($Inventory[$componentName])

        foreach ($item in $inventoryItems) {
            $fqdn = $item.Fqdn
            $dedupKey = "$componentName|$fqdn"

            if (-not $processedKeys.Add($dedupKey)) {
                continue
            }

            # Only generate a "Not Vulnerable" row when no finding already covers this pair.
            if ($endpointsWithFindings.Contains($dedupKey)) {
                continue
            }

            $statusEntry = [PSCustomObject]@{
                    component      = $componentName
                    domainName     = if (-not [String]::IsNullOrWhiteSpace($item.DomainName)) { [String]$item.DomainName } else { '' }
                    clusterName    = if (-not [String]::IsNullOrWhiteSpace($item.ClusterName)) { [String]$item.ClusterName } else { '' }
                    instanceName   = if (-not [String]::IsNullOrWhiteSpace($item.InstanceName)) { [String]$item.InstanceName } else { '' }
                    serverFqdn     = $fqdn
                    currentVersion = $item.Version
                    Status         = "Safe"
                    severity       = "None"
                    vmsaId         = $null
                    cves           = $null
                    FindingsCount  = 0
                }
            if (-not [String]::IsNullOrWhiteSpace($item.BuildVersion)) {
                $statusEntry | Add-Member -NotePropertyName 'currentBuild' -NotePropertyValue ([String]$item.BuildVersion)
            }
            [Void]$endpointStatus.Add($statusEntry)
        }
    }

    , @($endpointStatus)
}

#endregion
