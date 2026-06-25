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

#region Live Inventory Collection

function Get-VcenterBuildMap {

    <#
        .SYNOPSIS
        Load the vCenter version-to-MOB-build-number lookup table from a companion JSON file.

        .DESCRIPTION
        Reads vcenterBuildMap.json written by Convert-BroadcomAdvisoriesToSchema.ps1 (which
        scrapes Broadcom KB 326316 for every vCenter version and its matching MOB build number)
        and returns two lookup directions:
          VersionToBuild — forward map: "8.0.3.00900" → "25413364" (advisory version → MOB build)
          BuildToVersion — reverse map: "25413364" → "8.0.3.00900" (MOB build → advisory version)

        Returns empty maps when the file is absent so scans proceed without build enrichment
        rather than failing. The enrichment is purely display — advisory comparison is unaffected.

        .PARAMETER BuildMapPath
        Full path to vcenterBuildMap.json (generated alongside securityAdvisory.json by the
        advisory conversion script).

        .EXAMPLE
        $maps = Get-VcenterBuildMap -BuildMapPath '/home/user/Data/vcenterBuildMap.json'
        $mob  = $maps.VersionToBuild['8.0.3.00900']   # returns "25413364"
        $ver  = $maps.BuildToVersion['25413364']        # returns "8.0.3.00900"

        .OUTPUTS
        [Hashtable] with keys VersionToBuild and BuildToVersion (each a [Hashtable]).

        .NOTES
        Does not throw on missing file — returns empty maps so scans proceed without build enrichment.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$BuildMapPath
    )

    $empty = @{ VersionToBuild = @{}; BuildToVersion = @{} }

    if (-not (Test-Path -LiteralPath $BuildMapPath -PathType Leaf)) {
        Write-LogMessage -Type DEBUG -Message "vCenter build map not found at '$BuildMapPath' — build numbers will not be enriched."
        return $empty
    }

    try {
        $data           = Get-Content -LiteralPath $BuildMapPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $versionToBuild = @{}
        $buildToVersion = @{}

        # $data.versionToBuild is a PSCustomObject from JSON deserialization; PSObject.Properties
        # is the correct enumeration method for PSCustomObject (not GetEnumerator, which is for hashtables).
        if ($null -ne $data.versionToBuild) {
            foreach ($prop in $data.versionToBuild.PSObject.Properties) {
                $ver   = [String]$prop.Name
                $build = [String]$prop.Value
                if (-not [String]::IsNullOrWhiteSpace($ver) -and -not [String]::IsNullOrWhiteSpace($build)) {
                    $versionToBuild[$ver] = $build
                    if (-not $buildToVersion.ContainsKey($build)) {
                        $buildToVersion[$build] = $ver
                    }
                }
            }
        }

        Write-LogMessage -Type DEBUG -Message "Loaded vCenter build map: $($versionToBuild.Count) entries from '$BuildMapPath'."
        return @{ VersionToBuild = $versionToBuild; BuildToVersion = $buildToVersion }
    }
    catch {
        Write-LogMessage -Type WARNING -Message "Failed to load vCenter build map from '$BuildMapPath': $($_.Exception.Message)"
        return $empty
    }
}
function Get-StandaloneNsxManagerInventory {

    <#
        .SYNOPSIS
        Collect NSX Manager version for a standalone (non-SDDC-managed) environment.

        .DESCRIPTION
        Queries GET /api/v1/node on the NSX Manager using Basic auth (admin account and
        NSX_MANAGER_PASSWORD environment variable) to retrieve the installed product version.

        Used for vsphere8 and vvf9 environments where NSX is not managed by SDDC Manager.
        For vcf5 and vcf9 environments, NSX version is discovered via SDDC Manager inventory.

        Returns an empty hashtable when NSX_MANAGER_PASSWORD is absent, when the FQDN is not
        configured, or when the API call fails.  Failure is non-fatal — the caller continues.

        .PARAMETER DomainName
        Domain label to attach to the returned inventory entry (default: "N/A").

        .PARAMETER NsxManagerFqdn
        FQDN or IP address of the NSX Manager cluster VIP.

        .PARAMETER TimeoutSeconds
        Per-request timeout in seconds (1-300, default 30).

        .EXAMPLE
        $nsxInv = Get-StandaloneNsxManagerInventory -NsxManagerFqdn "nsx.corp.example.com"
        if ($nsxInv.Count -gt 0) {
            Write-LogMessage -Type INFO -Message "NSX Manager: $($nsxInv['NSX'][0].Fqdn) v$($nsxInv['NSX'][0].Version)"
        }

        .OUTPUTS
        [Hashtable] @{ "NSX" = @([PSCustomObject]) } or empty hashtable when unavailable.

        .NOTES
        Reads NSX_MANAGER_PASSWORD from the environment via Get-InventoryPassword. Skips
        silently when the variable is absent. NSX version format "4.2.1.0.0.24105824" is
        normalised to "4.2.1.0.0-24105824" so ConvertTo-NormalizedVersion can strip the
        build suffix consistently.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$DomainName = "",
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$NsxManagerFqdn,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)]    [Int]$TimeoutSeconds = 30
    )

    $password = Get-InventoryPassword -ComponentName "NSX Manager" -EnvVarName "NSX_MANAGER_PASSWORD"
    if ($null -eq $password) { return @{} }

    $basicAuth = [Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes("admin:$password")
    )
    $headers = @{ "Authorization" = "Basic $basicAuth"; "Accept" = "application/json" }

    try {
        $nodeInfo = Invoke-RestMethod -Uri "https://$NsxManagerFqdn/api/v1/node" `
            -Headers $headers -Method GET `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $rawVersion = [String]$nodeInfo.product_version
        $version = if ([String]::IsNullOrWhiteSpace($rawVersion)) {
            "Unknown"
        } else {
            # Normalize "4.2.1.0.0.24105824" → "4.2.1.0.0-24105824" so the build
            # suffix can be stripped by ConvertTo-NormalizedVersion consistently.
            $rawVersion -replace '\.(\d{7,})$', '-$1'
        }

        Write-LogMessage -Type INFO -Message "Collected NSX Manager (standalone): $NsxManagerFqdn v$version"
        return @{
            "NSX" = @([PSCustomObject]@{
                Fqdn       = $NsxManagerFqdn
                Version    = $version
                DomainName = $DomainName
            })
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Standalone NSX Manager inventory failed for $NsxManagerFqdn : $($_.Exception.Message)"
        return @{}
    }
}
function Get-NsxAdminPasswordFromSddc {

    <#
        .SYNOPSIS
        Retrieve the NSX Manager admin password from the SDDC Manager credentials API.

        .DESCRIPTION
        Calls Invoke-VcfGetCredentials -ResourceType NSXT_MANAGER -AccountType USER to
        retrieve NSX Manager credentials managed by SDDC Manager, then returns the password
        for the "admin" account.

        This is the canonical approach for VCF 5.x environments — the NSX admin password is
        stored and managed by SDDC Manager and should never be prompted from the user. See
        https://knowledge.broadcom.com/external/article/434886 for the API reference.

        Returns $null when no matching credential is found or when the API call fails.
        The caller must treat a $null return as a non-fatal condition.

        .EXAMPLE
        $nsxPassword = Get-NsxAdminPasswordFromSddc
        if ($null -ne $nsxPassword) {
            $edges = Get-NsxEdgeInventory -NsxManagerFqdn "nsx.example.com" -Password $nsxPassword
        }

        .OUTPUTS
        [String] The admin account password, or $null when unavailable.

        .NOTES
        Must be called after Connect-VcfSddcManagerServer has established an active session.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param ()

    try {
        $credPage = Invoke-VcfGetCredentials -ResourceType "NSXT_MANAGER" -AccountType "USER" -ErrorAction Stop
        foreach ($cred in @($credPage.Elements)) {
            if ($null -eq $cred) { continue }
            if ([String]$cred.Username -ieq "admin" -and -not [String]::IsNullOrWhiteSpace($cred.Password)) {
                Write-LogMessage -Type DEBUG -Message "NSX Manager admin credential retrieved from SDDC Manager."
                return [String]$cred.Password
            }
        }
        Write-LogMessage -Type DEBUG -Message "NSX Manager admin credential not found in SDDC Manager credentials store."
        return $null
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Could not retrieve NSX Manager admin credential from SDDC Manager: $($_.Exception.Message)"
        return $null
    }
}
function Get-NsxEdgeInventory {

    <#
        .SYNOPSIS
        Collect NSX Edge node inventory from an NSX Manager REST API.

        .DESCRIPTION
        Queries GET /api/v1/transport-nodes?node_types=EdgeNode to enumerate edge nodes, then
        queries GET /api/v1/transport-nodes/{id}/status for each node to retrieve its
        software_version. Returns an array of inventory objects suitable for inclusion in the
        "NSX Edge" inventory key. Authenticates with Basic auth using the NSX Manager admin
        account and the NSX_MANAGER_PASSWORD environment variable.

        Returns an empty array when the password is not configured or when no edge nodes are
        found — the caller must treat this as a non-fatal best-effort step.

        .PARAMETER NsxManagerFqdn
        FQDN or IP address of the NSX Manager cluster VIP.

        .PARAMETER DomainName
        Workload domain name to attach to each edge node entry (e.g. "vcf-pd-m01").

        .PARAMETER Password
        NSX Manager admin account password. When provided, takes precedence over the
        NSX_MANAGER_PASSWORD environment variable. Pass the value returned by
        Get-NsxAdminPasswordFromSddc for VCF 5.x environments. For vsphere8/vvf9
        environments the env var is used when this parameter is omitted.

        .PARAMETER TimeoutSeconds
        Per-request timeout in seconds (1-300, default 30).

        .EXAMPLE
        $nsxPassword = Get-NsxAdminPasswordFromSddc
        $edges = Get-NsxEdgeInventory -NsxManagerFqdn "nsx.example.com" -DomainName "mgmt-domain" -Password $nsxPassword
        foreach ($e in $edges) { Write-LogMessage -Type INFO -Message "Edge: $($e.Fqdn) v$($e.Version)" }

        .OUTPUTS
        [PSCustomObject[]] Array of edge node inventory objects with Fqdn, Version, DomainName.

        .NOTES
        For VCF 5.x environments the password is supplied via -Password (retrieved from SDDC
        Manager via Get-NsxAdminPasswordFromSddc). For vsphere8/vvf9 environments the
        NSX_MANAGER_PASSWORD environment variable is the fallback when -Password is omitted.
        Returns an empty array on failure rather than throwing — edge inventory is best-effort
        and must not abort the main scan.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$NsxManagerFqdn,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$DomainName = "",
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [AllowNull()]       [String]$Password = $null,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)]                  [Int]$TimeoutSeconds = 30
    )

    # Prefer the explicitly supplied password; fall back to the environment variable for
    # vsphere8/vvf9 callers that set NSX_MANAGER_PASSWORD without using this parameter.
    $nsxPass = $Password
    if ([String]::IsNullOrWhiteSpace($nsxPass)) {
        $nsxPass = [System.Environment]::GetEnvironmentVariable("NSX_MANAGER_PASSWORD")
    }
    if ([String]::IsNullOrWhiteSpace($nsxPass)) {
        return @()
    }

    $basicAuth = [Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes("admin:$nsxPass")
    )
    $headers = @{ "Authorization" = "Basic $basicAuth"; "Accept" = "application/json" }
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $transportNodes = Invoke-RestMethod `
            -Uri "https://$NsxManagerFqdn/api/v1/transport-nodes?node_types=EdgeNode&page_size=100" `
            -Headers $headers -Method GET `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        foreach ($node in @($transportNodes.results)) {
            if ($null -eq $node) { continue }
            $nodeId   = [String]$node.node_id
            $hostname = [String]$node.node_deployment_info.node_settings.hostname
            if ([String]::IsNullOrWhiteSpace($hostname)) {
                $hostname = [String]$node.display_name
            }

            $version = "Unknown"
            try {
                $status  = Invoke-RestMethod `
                    -Uri "https://$NsxManagerFqdn/api/v1/transport-nodes/$nodeId/status" `
                    -Headers $headers -Method GET `
                    -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
                $rawVer = [String]$status.node_status.software_version
                if (-not [String]::IsNullOrWhiteSpace($rawVer)) {
                    # NSX Edge reports version as "4.2.0.0.0.24105824" — dot-separated with
                    # the build number as the sixth segment. Normalize to a dash form so
                    # ConvertTo-NormalizedVersion can strip the build suffix consistently.
                    $version = $rawVer -replace '\.(\d{7,})$', '-$1'
                }
            }
            catch {
                Write-LogMessage -Type DEBUG -Message "NSX Edge version query failed for $hostname ($nodeId): $($_.Exception.Message)"
            }

            $results.Add([PSCustomObject]@{
                Fqdn       = $hostname
                Version    = $version
                DomainName = $DomainName
            })
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "NSX Edge inventory query failed for $NsxManagerFqdn : $($_.Exception.Message)"
    }

    return $results.ToArray()
}
function Get-SddcManagerInventory {

    <#
        .SYNOPSIS
        Collect infrastructure inventory from SDDC Manager.

        .DESCRIPTION
        Connects to SDDC Manager via VCF PowerCLI (Connect-VcfSddcManagerServer) and retrieves
        versions of SDDC Manager itself, all managed vCenter servers, NSX Manager clusters, and
        NSX Edge nodes registered with each NSX Manager.

        .PARAMETER Server
        SDDC Manager FQDN or IP address.

        .PARAMETER User
        Username for SDDC Manager authentication.

        .PARAMETER TimeoutSeconds
        Connection timeout in seconds (1-300, default 30).

        .PARAMETER VcenterBuildMaps
        Optional lookup table from Get-VcenterBuildMap. When provided, each vCenter entry is
        enriched with a BuildVersion property (e.g. "8.0.3.25413364") derived from the MOB
        build number that corresponds to the advisory-compatible version ("8.0.3.00900").

        .EXAMPLE
        $inventory = Get-SddcManagerInventory -Server "sddc.example.com" -User "administrator@vsphere.local"

        .OUTPUTS
        [Hashtable] Inventory keyed by component name: @{ "SDDC Manager" = @(...), "vCenter" = @(...), "NSX" = @(...), "NSX Edge" = @(...) }

        .NOTES
        Reads SDDC_MANAGER_PASSWORD from the environment via Get-InventoryPassword. Returns an empty hashtable on connectivity or authentication failure (logs WARNING).
        NSX Edge inventory is collected via Get-NsxEdgeInventory. The NSX admin password is
        retrieved from the SDDC Manager credentials API (GET /v1/credentials) via
        Get-NsxAdminPasswordFromSddc — no separate NSX password is required from the user.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)]    [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $false)] [ValidateNotNull()]        [Hashtable]$VcenterBuildMaps = @{ VersionToBuild = @{}; BuildToVersion = @{} }
    )

    Write-LogMessage -Type INFO -Message "Collecting SDDC Manager inventory from: $Server..."

    $inventory = @{}
    $conn = $null
    $securePassword = $null

    try {
        $password = Get-InventoryPassword -ComponentName "SDDC Manager" -EnvVarName "SDDC_MANAGER_PASSWORD"
        if ($null -eq $password) { return $inventory }

        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($User, $securePassword)

        Write-LogMessage -Type INFO -Message "Connecting to SDDC Manager `"$Server`"..."
        # -IgnoreInvalidCertificate: SDDC Manager uses a self-signed certificate in most deployments.
        $conn = Connect-VcfSddcManagerServer -Server $Server -Credential $credential -IgnoreInvalidCertificate -ErrorAction Stop

        # Retrieve the NSX Manager admin password from the SDDC Manager credentials store.
        # VCF manages this password internally; users must not be prompted for it separately.
        $nsxAdminPassword = Get-NsxAdminPasswordFromSddc

        $sddcResponse = Invoke-VcfGetSddcManagers -ErrorAction Stop
        $sddcElements = @($sddcResponse.Elements)
        $sddc = if ($sddcElements.Count -gt 0) { $sddcElements[0] } else { $null }
        $sddcFqdn    = if ($null -ne $sddc -and -not [String]::IsNullOrWhiteSpace($sddc.Fqdn))    { [String]$sddc.Fqdn }    else { $Server }
        $sddcVersion = if ($null -ne $sddc -and -not [String]::IsNullOrWhiteSpace($sddc.Version)) { [String]$sddc.Version } else { "Unknown" }

        # Retrieve workload domain information to associate components with their VCF domain.
        # SDDC Manager's own domain.name is the VCF instance identifier (management domain).
        $vcenterFqdnToDomainName = @{}
        # Domain ID → name map: used as a fallback for ESX hosts whose DomainReference.Name
        # may be absent in some API versions (only the ID is guaranteed to be populated).
        $domainIdToName = @{}
        $sddcDomainName = if ($null -ne $sddc -and -not [String]::IsNullOrWhiteSpace($sddc.Domain.Name)) { [String]$sddc.Domain.Name } else { "" }
        try {
            $domainsResponse = Invoke-VcfGetDomains -PageSize 100 -ErrorAction Stop
            $managementDomainName = ""
            foreach ($domain in @($domainsResponse.Elements)) {
                if ([String]::IsNullOrWhiteSpace($domain.Name)) { continue }
                if ([String]$domain.DomainType -ieq "MANAGEMENT") {
                    $managementDomainName = [String]$domain.Name
                }
                if (-not [String]::IsNullOrWhiteSpace($domain.Id)) {
                    $domainIdToName[[String]$domain.Id] = [String]$domain.Name
                }
                foreach ($vcRef in @($domain.Vcenters)) {
                    if (-not [String]::IsNullOrWhiteSpace($vcRef.Fqdn)) {
                        $vcenterFqdnToDomainName[$vcRef.Fqdn.ToLower()] = [String]$domain.Name
                    }
                }
            }
            # $sddc.Domain.Name is not always populated by the API; resolve from the domain ID
            # map first, then fall back to whichever domain carries DomainType = MANAGEMENT.
            if ([String]::IsNullOrWhiteSpace($sddcDomainName)) {
                $sddcDomainId = if ($null -ne $sddc -and $null -ne $sddc.Domain) { [String]$sddc.Domain.Id } else { "" }
                if (-not [String]::IsNullOrWhiteSpace($sddcDomainId) -and $domainIdToName.ContainsKey($sddcDomainId)) {
                    $sddcDomainName = $domainIdToName[$sddcDomainId]
                } elseif (-not [String]::IsNullOrWhiteSpace($managementDomainName)) {
                    $sddcDomainName = $managementDomainName
                }
            }
            Write-LogMessage -Type INFO -Message "Retrieved domain-to-vCenter mappings for $($vcenterFqdnToDomainName.Count) vCenter(s), $($domainIdToName.Count) domain(s)"
        } catch {
            Write-LogMessage -Type WARNING -Message "Could not retrieve workload domain info from SDDC Manager: $($_.Exception.Message)"
        }

        # Cluster ID → name map: used as a fallback for ESX hosts whose Cluster reference
        # carries only an ID in VCF 9.x (the Name field is absent from the hosts API response).
        $clusterIdToName = @{}
        try {
            $clusterPage = 0
            $clusterTotalPages = 1
            do {
                $clusterResponse = Invoke-VcfGetClusters -PageNumber $clusterPage -PageSize 100 -ErrorAction Stop
                foreach ($clusterObj in @($clusterResponse.Elements)) {
                    if ($null -eq $clusterObj) { continue }
                    $cId   = [String]$clusterObj.Id
                    $cName = [String]$clusterObj.Name
                    if (-not [String]::IsNullOrWhiteSpace($cId) -and -not [String]::IsNullOrWhiteSpace($cName)) {
                        $clusterIdToName[$cId] = $cName
                    }
                }
                if ($null -ne $clusterResponse.PageMetadata -and $null -ne $clusterResponse.PageMetadata.TotalPages) {
                    $clusterTotalPages = [Int]$clusterResponse.PageMetadata.TotalPages
                }
                $clusterPage++
            } while ($clusterPage -lt $clusterTotalPages)
            Write-LogMessage -Type INFO -Message "Retrieved cluster ID-to-name mappings for $($clusterIdToName.Count) cluster(s)"
        } catch {
            Write-LogMessage -Type WARNING -Message "Could not retrieve cluster info from SDDC Manager: $($_.Exception.Message)"
        }

        $inventory["SDDC Manager"] = @([PSCustomObject]@{
            Fqdn       = $sddcFqdn
            Version    = $sddcVersion
            DomainName = $sddcDomainName
        })
        Write-LogMessage -Type INFO  -Message "Collected SDDC Manager: $sddcFqdn (domain: $sddcDomainName)"
        Write-LogMessage -Type DEBUG -Message "SDDC Manager version: $sddcVersion"

        $vcResponse = Invoke-VcfGetVcenters -PageNumber 0 -PageSize 100 -ErrorAction Stop
        $vcElements = @($vcResponse.Elements)
        if ($vcElements.Count -gt 0) {
            $inventory["vCenter"] = @($vcElements | ForEach-Object {
                $vcFqdn  = [String]$_.Fqdn
                $rawVcVer = if (-not [String]::IsNullOrWhiteSpace($_.Version)) { [String]$_.Version } else { "Unknown" }
                $vcVer   = $rawVcVer
                $vcDomain = if ($vcenterFqdnToDomainName.ContainsKey($vcFqdn.ToLower())) { $vcenterFqdnToDomainName[$vcFqdn.ToLower()] } else { "" }
                $vcEntry  = [PSCustomObject]@{ Fqdn = $vcFqdn; Version = $vcVer; DomainName = $vcDomain }

                # VCF 8: SDDC Manager reports "8.0.3.00100-24091160" but advisories use the MOB
                # build number as the 4th dotted segment (e.g. "8.0.3.24853646"). Extract the build
                # from the dash suffix and set BuildVersion so advisory comparison uses it.
                if ($rawVcVer -match '^(\d+\.\d+\.\d+)\.\d+-(\d{6,})$') {
                    $vcEntry | Add-Member -NotePropertyName 'BuildVersion' -NotePropertyValue "$($Matches[1]).$($Matches[2])"
                } elseif ($VcenterBuildMaps.VersionToBuild.ContainsKey($rawVcVer)) {
                    # Fallback for 4-part VCF 8 versions without a dash suffix: map update level → MOB.
                    $mob    = $VcenterBuildMaps.VersionToBuild[$rawVcVer]
                    $parts  = $rawVcVer.Split('.')
                    $prefix = ($parts[0..[Math]::Min(2, $parts.Count - 1)] -join '.')
                    $vcEntry | Add-Member -NotePropertyName 'BuildVersion' -NotePropertyValue "$prefix.$mob"
                }
                $vcEntry
            })
            Write-LogMessage -Type INFO -Message "Collected $($inventory['vCenter'].Count) vCenter(s): $(($inventory['vCenter'] | ForEach-Object { $_.Fqdn }) -join ', ')"
        }

        $nsxResponse = Invoke-VcfGetNsxClusters -PageNumber 0 -PageSize 100 -ErrorAction Stop
        $nsxElements = @($nsxResponse.Elements)
        if ($nsxElements.Count -gt 0) {
            $nsxEdgeList = [System.Collections.Generic.List[PSCustomObject]]::new()
            $inventory["NSX"] = @($nsxElements | ForEach-Object {
                $nsxVipFqdn = if (-not [String]::IsNullOrWhiteSpace($_.VipFqdn)) { [String]$_.VipFqdn } else { [String]$_.Vip }
                $nsxDomains = @($_.Domains)
                $nsxDomainName = if ($nsxDomains.Count -gt 0 -and -not [String]::IsNullOrWhiteSpace($nsxDomains[0].Name)) {
                    [String]$nsxDomains[0].Name
                } else { "" }

                # Collect NSX Edge nodes registered with this NSX Manager.
                # -Password: supplies the admin credential retrieved from SDDC Manager above;
                # skipped silently when the password could not be retrieved.
                $edgeNodes = Get-NsxEdgeInventory -NsxManagerFqdn $nsxVipFqdn -DomainName $nsxDomainName -Password $nsxAdminPassword -TimeoutSeconds $TimeoutSeconds
                foreach ($edgeNode in $edgeNodes) { $nsxEdgeList.Add($edgeNode) }

                [PSCustomObject]@{
                    Fqdn       = $nsxVipFqdn
                    Version    = if (-not [String]::IsNullOrWhiteSpace($_.Version)) { [String]$_.Version } else { "Unknown" }
                    DomainName = $nsxDomainName
                }
            })
            Write-LogMessage -Type INFO -Message "Collected $($inventory['NSX'].Count) NSX cluster(s): $(($inventory['NSX'] | ForEach-Object { $_.Fqdn }) -join ', ')"

            if ($nsxEdgeList.Count -gt 0) {
                $inventory["NSX Edge"] = $nsxEdgeList.ToArray()
                Write-LogMessage -Type INFO -Message "Collected $($nsxEdgeList.Count) NSX Edge node(s): $(($nsxEdgeList | ForEach-Object { $_.Fqdn }) -join ', ')"
            }
        }

        $hostList = [System.Collections.Generic.List[PSCustomObject]]::new()
        $hostPage = 0
        $hostTotalPages = 1
        do {
            $hostResponse = Invoke-VcfGetHosts -PageNumber $hostPage -PageSize 100 -ErrorAction Stop
            if ($null -eq $hostResponse -or $null -eq $hostResponse.Elements) { break }
            foreach ($hostObj in @($hostResponse.Elements)) {
                if ($null -eq $hostObj) { continue }
                $esxVer = [String]$hostObj.EsxiVersion
                # VCF 9.x image-based hosts may have a null EsxiVersion field; fall back to
                # SoftwareInfo.BaseImage.Version which is populated for lifecycle-image deployments.
                if ([String]::IsNullOrWhiteSpace($esxVer) -and $null -ne $hostObj.SoftwareInfo -and $null -ne $hostObj.SoftwareInfo.BaseImage) {
                    $esxVer = [String]$hostObj.SoftwareInfo.BaseImage.Version
                }
                # Prefer the inline domain name; fall back to the ID-keyed map when the
                # DomainReference carries only an ID (common in VCF 9.x image-based deployments).
                $hostDomainName = if (-not [String]::IsNullOrWhiteSpace($hostObj.Domain.Name)) {
                    [String]$hostObj.Domain.Name
                } elseif ($null -ne $hostObj.Domain -and -not [String]::IsNullOrWhiteSpace($hostObj.Domain.Id) -and $domainIdToName.ContainsKey([String]$hostObj.Domain.Id)) {
                    $domainIdToName[[String]$hostObj.Domain.Id]
                } else { "" }
                # Prefer the inline cluster name; fall back to the ID-keyed map when the
                # Cluster reference carries only an ID (common in VCF 9.x deployments).
                $hostClusterName = if ($null -ne $hostObj.Cluster -and -not [String]::IsNullOrWhiteSpace($hostObj.Cluster.Name)) {
                    [String]$hostObj.Cluster.Name
                } elseif ($null -ne $hostObj.Cluster -and -not [String]::IsNullOrWhiteSpace($hostObj.Cluster.Id) -and $clusterIdToName.ContainsKey([String]$hostObj.Cluster.Id)) {
                    $clusterIdToName[[String]$hostObj.Cluster.Id]
                } else { "" }
                $hostList.Add([PSCustomObject]@{
                    Fqdn        = [String]$hostObj.Fqdn
                    Version     = if ([String]::IsNullOrWhiteSpace($esxVer)) { "Unknown" } else { $esxVer.Trim() }
                    DomainName  = $hostDomainName
                    ClusterName = $hostClusterName
                })
            }
            if ($null -ne $hostResponse.PageMetadata -and $null -ne $hostResponse.PageMetadata.TotalPages) {
                $hostTotalPages = [Int]$hostResponse.PageMetadata.TotalPages
            }
            $hostPage++
        } while ($hostPage -lt $hostTotalPages)

        if ($hostList.Count -gt 0) {
            $inventory["ESXi"] = @($hostList.ToArray())
            Write-LogMessage -Type INFO -Message "Collected $($inventory['ESXi'].Count) ESXi host(s)"
        }

        Write-LogMessage -Type INFO -Message "SDDC Manager inventory collection complete: $($inventory.Count) component type(s)"
    }
    catch {
        Write-LogMessage -Type WARNING -Message "SDDC Manager inventory collection failed: $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $Server -Context 'SDDC Manager')"
    }
    finally {
        if ($null -ne $conn) { Disconnect-VcfSddcManagerServer -Server $conn -Force -ErrorAction SilentlyContinue | Out-Null }
        if ($null -ne $securePassword) { $securePassword.Dispose() }
    }

    return $inventory
}
function ConvertTo-VcfOpsAuthParts {

    <#
        .SYNOPSIS
        Split a VCF Operations username into bare username and auth source.

        .DESCRIPTION
        Splits a username in user@authsource format into its two components. If no '@' is
        present the auth source defaults to 'Local', which is the VCF Operations default.

        .PARAMETER User
        VCF Operations username, e.g. admin@local or admin.

        .EXAMPLE
        $parts = ConvertTo-VcfOpsAuthParts -User "admin@local"
        Connect-VcfOpsServer -User $parts.BareUser -AuthSource $parts.AuthSource ...

        .OUTPUTS
        [PSCustomObject] Object with BareUser and AuthSource string properties.

        .NOTES
        Pure utility function. Does not mutate any module-scope variables.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User
    )

    if ($User -match "@(.+)$") {
        # Normalize "local" → "Local": Connect-VcfOpsServer is case-sensitive for this token.
        $rawSource = $Matches[1]
        $authSource = if ($rawSource -ieq "local") { "Local" } else { $rawSource }
        return [PSCustomObject]@{
            BareUser   = $User.Substring(0, $User.LastIndexOf('@'))
            AuthSource = $authSource
        }
    }
    return [PSCustomObject]@{ BareUser = $User; AuthSource = "Local" }
}
function Get-VspBearerToken {

    <#
        .SYNOPSIS
        Acquire a VSP bearer token from POST /api/v1/identity/token.

        .DESCRIPTION
        Submits a password-grant form to the VSP Fleet Controller identity endpoint and
        extracts the access token from the response. Returns an empty string if the
        request fails or the response contains no recognisable token property.

        .PARAMETER Server
        VSP Fleet Controller FQDN or IP.

        .PARAMETER User
        Username (e.g. admin@vsp.local).

        .PARAMETER Password
        Plain-text password.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300, default 30).

        .EXAMPLE
        $token = Get-VspBearerToken -Server "flt-fc01.sfo.example.com" -User "admin@vsp.local" -Password $pw
        if (-not [String]::IsNullOrWhiteSpace($token)) { ... }

        .OUTPUTS
        [String] Bearer token or empty string if unavailable.

        .NOTES
        Returns an empty string on failure rather than throwing. Callers must check for empty/whitespace before using the token.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Password,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    try {
        $tokenBody = "grant_type=password&username=$([System.Uri]::EscapeDataString($User))&password=$([System.Uri]::EscapeDataString($Password))"
        $tokenResponse = Invoke-RestMethod -Uri "https://$Server/api/v1/identity/token" `
            -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        foreach ($prop in @('access_token', 'AccessToken', 'token')) {
            $candidate = $tokenResponse.$prop
            if (-not [String]::IsNullOrWhiteSpace($candidate)) {
                return [String]$candidate
            }
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "VSP bearer token request failed for $Server — $($_.Exception.Message)"
    }

    return ""
}
function Get-VcfOpsRestToken {

    <#
        .SYNOPSIS
        Acquire a vRealizeOpsToken from the VCF Operations REST API.

        .DESCRIPTION
        Submits credentials to POST /suite-api/api/auth/token/acquire and returns the token
        string. Used as a prerequisite for calling VCF Operations internal REST endpoints that
        require vRealizeOpsToken authentication (distinct from the VSP bearer token used by
        Fleet Manager).

        Returns an empty string when authentication fails rather than throwing, so callers
        can distinguish an authentication failure from a connectivity failure.

        .PARAMETER Password
        Plain-text password.

        .PARAMETER Server
        VCF Operations FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300, default 30).

        .PARAMETER User
        Username, e.g. admin@local.

        .EXAMPLE
        $token = Get-VcfOpsRestToken -Server "ops.example.com" -User "admin@local" -Password $plainTextPassword
        if (-not [String]::IsNullOrWhiteSpace($token)) { ... }

        .OUTPUTS
        [String] vRealizeOpsToken or empty string if authentication fails.

        .NOTES
        Returns an empty string on failure rather than throwing. Callers must check for empty/whitespace before using the token.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Password,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User
    )

    try {
        $authParts = ConvertTo-VcfOpsAuthParts -User $User
        $body = [PSCustomObject]@{
            authSource = $authParts.AuthSource
            password   = $Password
            username   = $authParts.BareUser
        } | ConvertTo-Json -Depth 2 -Compress

        $response = Invoke-RestMethod -Uri "https://$Server/suite-api/api/auth/token/acquire" `
            -Method POST -Body $body -ContentType "application/json" `
            -Headers @{ "Accept" = "application/json" } `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        if (-not [String]::IsNullOrWhiteSpace($response.token)) {
            return [String]$response.token
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "VCF Ops REST token request failed for $Server — $($_.Exception.Message)"
    }

    return ""
}
function Get-VcfOpsInventory {

    <#
        .SYNOPSIS
        Collect VCF Operations inventory.

        .DESCRIPTION
        Connects to VCF Operations via VCF PowerCLI (Connect-VcfOpsServer) and retrieves
        the appliance version using Invoke-VcfOpsGetCurrentVersionOfServer.

        .PARAMETER Server
        VCF Operations FQDN or IP address.

        .PARAMETER User
        Username for VCF Operations authentication (format: user@AuthSource).

        .PARAMETER TimeoutSeconds
        Connection timeout in seconds (1-300, default 30).

        .EXAMPLE
        $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

        .OUTPUTS
        [Hashtable] Inventory keyed by component name: @{ "VCF Operations" = @(...) }

        .NOTES
        Reads VCF_OPS_PASSWORD from the environment via Get-InventoryPassword. Returns an empty hashtable on connectivity or authentication failure (logs WARNING).
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    Write-LogMessage -Type INFO -Message "Collecting VCF Operations inventory from: $Server..."

    $inventory = @{}
    $conn = $null

    try {
        $password = Get-InventoryPassword -ComponentName "VCF Operations" -EnvVarName "VCF_OPS_PASSWORD"
        if ($null -eq $password) { return $inventory }

        $authParts = ConvertTo-VcfOpsAuthParts -User $User
        Write-LogMessage -Type INFO -Message "Connecting to VCF Operations `"$Server`"..."
        # -IgnoreInvalidCertificate: VCF Operations uses a self-signed certificate; without
        # this flag the cmdlet rejects the cert and the server responds with an HTML error page.
        $conn = Connect-VcfOpsServer -Server $Server -User $authParts.BareUser -Password $password -AuthSource $authParts.AuthSource -IgnoreInvalidCertificate -ErrorAction Stop

        $verDoc = Invoke-VcfOpsGetCurrentVersionOfServer -ErrorAction Stop
        $version = "Unknown"
        if ($null -ne $verDoc) {
            foreach ($prop in @('Version', 'version', 'ReleaseName', 'releaseName')) {
                $candidate = $verDoc.$prop
                if (-not [String]::IsNullOrWhiteSpace($candidate)) {
                    $candidateStr = $candidate.Trim()
                    # Extract bare version number — the property may include a product name prefix
                    # (e.g. "VCF Operations 9.1.0.0"); capture the first dotted-decimal sequence.
                    if ($candidateStr -match '\b(\d+(?:\.\d+)+)\b') {
                        $version = $Matches[1]
                    } else {
                        $version = $candidateStr
                    }
                    break
                }
            }
        }

        $inventory["VCF Operations"] = @([PSCustomObject]@{
            Fqdn       = $Server
            Version    = $version
            DomainName = "VCF Fleet"
        })
        Write-LogMessage -Type INFO  -Message "Collected VCF Operations: $Server"
        Write-LogMessage -Type DEBUG -Message "VCF Operations version: $version"

        $standaloneVcFqdns = [System.Collections.Generic.List[String]]::new()
        try {
            $vmwareAdapters = Invoke-VcfOpsEnumerateAdapterInstances -AdapterKindKey "VMWARE" -ErrorAction Stop
            foreach ($dto in @($vmwareAdapters.AdapterInstancesInfoDto)) {
                if ($null -eq $dto) { continue }
                $vcUrl = ($dto.ResourceKey.ResourceIdentifiers |
                    Where-Object { $_.IdentifierType.Name -ieq "VCURL" }).Value
                if ([String]::IsNullOrWhiteSpace($vcUrl)) {
                    $adapterName = [String]$dto.ResourceKey.Name
                    if ($adapterName -match '(?i)\bfor\s+(\S+)\s*$') { $vcUrl = $Matches[1] }
                }
                if ([String]::IsNullOrWhiteSpace($vcUrl)) { continue }
                $standaloneVcFqdns.Add([String]$vcUrl.Trim())
            }
            # Logged at DEBUG so the caller (EntryPoint.ps1) can emit an appropriate INFO
            # message only for the environment types that actually scan these endpoints.
            if ($standaloneVcFqdns.Count -gt 0) {
                Write-LogMessage -Type DEBUG -Message "Discovered $($standaloneVcFqdns.Count) standalone vCenter(s) from VCF Operations: $(($standaloneVcFqdns | Sort-Object) -join ', ')"
            } else {
                Write-LogMessage -Type DEBUG -Message "No standalone vCenters registered with VCF Operations."
            }
        }
        catch {
            Write-LogMessage -Type DEBUG -Message "Standalone vCenter enumeration failed: $($_.Exception.Message)"
        }
        $inventory['_StandaloneVcenterFqdns'] = $standaloneVcFqdns.ToArray()
    }
    catch {
        Write-LogMessage -Type WARNING -Message "VCF Operations inventory collection failed: $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $Server -Context 'VCF Operations')"
    }
    finally {
        if ($null -ne $conn) { Disconnect-VcfOpsServer -Server $conn -Force -ErrorAction SilentlyContinue | Out-Null }
    }

    return $inventory
}
function Get-VcenterInventory {

    <#
        .SYNOPSIS
        Collect ESXi and vCenter inventory from vCenter Server.

        .DESCRIPTION
        Queries vCenter API to retrieve ESXi host versions and vCenter version.
        Returns inventory in scannable format.

        .PARAMETER Server
        vCenter FQDN or IP address.

        .PARAMETER User
        Username for vCenter authentication.

        .PARAMETER TimeoutSeconds
        Timeout for API calls (1-300, default 30).

        .PARAMETER VcenterBuildMaps
        Optional lookup table from Get-VcenterBuildMap. When provided:
          - Forward map resolves advisory-compatible version to MOB build number
            (e.g. "8.0.3.00900" → "25413364") to construct BuildVersion.
          - Reverse map resolves MOB build number to full advisory-compatible version
            when $connection.Version returns only a 3-part string (e.g. "8.0.3").

        .EXAMPLE
        $inventory = Get-VcenterInventory -Server "vcenter.example.com" -User "administrator@vsphere.local"

        .OUTPUTS
        [Hashtable] Inventory keyed by component: @{ "ESXi" = @(...), "vCenter" = @(...) }

        .NOTES
        Reads VCENTER_PASSWORD from the environment via Get-InventoryPassword. Disconnects VIServer in a finally block to prevent session leaks.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)]    [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $false)] [ValidateNotNull()]        [Hashtable]$VcenterBuildMaps = @{ VersionToBuild = @{}; BuildToVersion = @{} }
    )

    Write-LogMessage -Type INFO -Message "Collecting vCenter inventory from: $Server..."

    $inventory = @{}
    $connection = $null

    try {
        $password = Get-InventoryPassword -ComponentName "vCenter" -EnvVarName "VCENTER_PASSWORD"
        if ($null -eq $password) { return $inventory }

        $connection = Connect-VIServer -Server $Server -User $User -Password $password `
            -Force -ErrorAction Stop

        $esxiHosts = @(Get-VMHost -Server $connection -ErrorAction Stop |
            Where-Object { $_.ConnectionState -eq 'Connected' })

        # Build a hostname → cluster-name map from all clusters in vCenter. This is done
        # in a single pass so the per-host lookup is O(1) rather than one API call each.
        $clusterMap = @{}
        foreach ($cluster in @(Get-Cluster -Server $connection -ErrorAction SilentlyContinue)) {
            $cName = [String]$cluster.Name
            foreach ($h in @(Get-VMHost -Location $cluster -Server $connection -ErrorAction SilentlyContinue)) {
                $clusterMap[[String]$h.Name] = $cName
            }
        }

        if ($esxiHosts.Count -gt 0) {
            $inventory["ESXi"] = @($esxiHosts | ForEach-Object {
                $hostName   = [String]$_.Name
                $rawHostVersion = [String]$_.Version
                $hostVersion    = $rawHostVersion
                $hostBuild      = if ($_.Build -and [String]$_.Build -match '^\d{5,}$') { [String]$_.Build } else { $null }
                # Use the major.minor.patch prefix from the version string regardless of how
                # many parts it has (e.g. "8.0.3" → "8.0.3", "8.0.3.0" → "8.0.3").
                $vParts   = $rawHostVersion.Split('.')
                $prefix   = ($vParts[0..[Math]::Min(2, $vParts.Count - 1)] -join '.')
                $entry = [PSCustomObject]@{
                    Fqdn        = $hostName
                    Version     = $hostVersion
                    DomainName  = ""
                    ClusterName = if ($clusterMap.ContainsKey($hostName)) { $clusterMap[$hostName] } else { "" }
                }
                if ($null -ne $hostBuild) {
                    $entry | Add-Member -NotePropertyName 'BuildVersion' -NotePropertyValue "$prefix.$hostBuild"
                }
                $entry
            })
            Write-LogMessage -Type INFO -Message "Collected $($esxiHosts.Count) ESXi hosts from vCenter"
        }

        $vcenterVersion = if ($connection.Version) { [String]$connection.Version } else { "Unknown" }
        # $connection.Build is the raw MOB/vpxd.log build number (e.g. "25413364"). It is present
        # on the VIServer object in VCF PowerCLI 9 and used as a fallback when the version string
        # is 3-part (e.g. "8.0.3") so we can still construct BuildVersion and resolve the full
        # advisory-compatible 4-part version via the reverse lookup.
        $rawBuild = if ($connection.Build -and [String]$connection.Build -match '^\d{6,}$') { [String]$connection.Build } else { $null }

        # Forward lookup: version → MOB (works when $connection.Version is 4-part, e.g. "8.0.3.00900")
        if ($VcenterBuildMaps.VersionToBuild.ContainsKey($vcenterVersion)) {
            $mob    = $VcenterBuildMaps.VersionToBuild[$vcenterVersion]
            $parts  = $vcenterVersion.Split('.')
            $prefix = ($parts[0..[Math]::Min(2, $parts.Count - 1)] -join '.')
            $vcEntry = [PSCustomObject]@{ Fqdn = $Server; Version = $vcenterVersion; DomainName = "" }
            $vcEntry | Add-Member -NotePropertyName 'BuildVersion' -NotePropertyValue "$prefix.$mob"
            $inventory["vCenter"] = @($vcEntry)
        } elseif ($null -ne $rawBuild) {
            # Fallback when $connection.Version is 3-part: use raw build number directly and
            # try to resolve the full advisory-compatible version via the reverse map.
            $parts     = $vcenterVersion.Split('.')
            $prefix    = ($parts[0..[Math]::Min(2, $parts.Count - 1)] -join '.')
            $buildVer  = "$prefix.$rawBuild"
            $fullVer   = if ($VcenterBuildMaps.BuildToVersion.ContainsKey($rawBuild)) { $VcenterBuildMaps.BuildToVersion[$rawBuild] } else { $vcenterVersion }
            $vcEntry   = [PSCustomObject]@{ Fqdn = $Server; Version = $fullVer; DomainName = "" }
            $vcEntry | Add-Member -NotePropertyName 'BuildVersion' -NotePropertyValue $buildVer
            $inventory["vCenter"] = @($vcEntry)
        } else {
            $inventory["vCenter"] = @([PSCustomObject]@{ Fqdn = $Server; Version = $vcenterVersion; DomainName = "" })
        }
        Write-LogMessage -Type INFO -Message "Collected vCenter: $Server v$vcenterVersion"
    }
    catch {
        Write-LogMessage -Type WARNING -Message "vCenter inventory collection failed: $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $Server -Context 'vCenter')"
    }
    finally {
        if ($null -ne $connection) {
            Disconnect-VIServer -Server $connection -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    return $inventory
}
function Get-FleetManagerInventory {

    <#
        .SYNOPSIS
        Collect Fleet Lifecycle Manager inventory.

        .DESCRIPTION
        Supports both VCF 9.1.x (VSP Fleet LCM) and VCF 9.0.x (Fleet Manager) endpoints.

        VCF 9.1.x path: acquires a bearer token from POST /api/v1/identity/token (form-encoded
        grant_type=password), then fetches GET /fleet-lcm/v1/components to read the installed
        version of the Fleet Lifecycle component.

        VCF 9.0.x fallback: uses Basic auth (base64(user:password)) and calls
        GET /lcm/lcops/api/v2/settings/system-details to read the appliance version.

        When AllowVspUserFallback is set and the initial VSP attempt fails with the provided User,
        a second VSP attempt is made with admin@vsp.local. Use this for VVF 9 environments where
        the wizard defaults to admin@local but the server may be VCF 9.1+.

        .PARAMETER Server
        Fleet Controller (VCF 9.1.x) or Fleet Manager (VCF 9.0.x) FQDN or IP address.

        .PARAMETER User
        Username for authentication. VCF 9.1.x expects admin@vsp.local (VSP bearer token auth);
        VCF 9.0.x expects admin@local (lcops Basic auth). Both are tried automatically.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300, default 30).

        .EXAMPLE
        $inventory = Get-FleetManagerInventory -Server "flt-fc01.example.com" -User "admin@vsp.local"

        .OUTPUTS
        [Hashtable] Inventory keyed by component: @{ "Fleet Lifecycle" = @(...) }

        .NOTES
        Reads VCF_FM_PASSWORD from the environment via Get-InventoryPassword. Sets _FleetApiPath sentinel key in the returned hashtable so EntryPoint can determine the VCF minor version.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $false)] [Switch]$AllowVspUserFallback,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User
    )

    Write-LogMessage -Type INFO -Message "Connecting to Fleet Lifecycle Manager `"$Server`"..."

    $inventory = @{}

    $password = Get-InventoryPassword -ComponentName "Fleet Manager" -EnvVarName "VCF_FM_PASSWORD"
    if ($null -eq $password) { return $inventory }

    $inventory = Get-VspFleetLcmInventory -Server $Server -User $User -Password $password -TimeoutSeconds $TimeoutSeconds
    if ($inventory.Count -gt 0) {
        # Sentinel consumed by EntryPoint to determine VCF minor version (9.1) and skip the
        # native VCF Operations API call, which is redundant when Fleet is authoritative.
        $inventory['_FleetApiPath'] = 'vsp'
        return $inventory
    }

    if ($AllowVspUserFallback -and $User -ine 'admin@vsp.local') {
        $inventory = Get-VspFleetLcmInventory -Server $Server -User 'admin@vsp.local' -Password $password -TimeoutSeconds $TimeoutSeconds
        if ($inventory.Count -gt 0) {
            $inventory['_FleetApiPath'] = 'vsp'
            return $inventory
        }
    }

    $inventory = Get-LcopsFleetManagerInventory -Server $Server -User $User -Password $password -TimeoutSeconds $TimeoutSeconds
    if ($inventory.Count -eq 0) {
        Write-LogMessage -Type WARNING -Message "Fleet Manager inventory unavailable on $Server — neither Fleet Lifecycle (VCF 9.1) nor Fleet Management (VCF 9.0) path responded. Check credentials and server reachability."
    } else {
        $inventory['_FleetApiPath'] = 'lcops'
    }
    return $inventory
}
function Get-VspFleetLcmInventory {

    <#
        .SYNOPSIS
        Collect Fleet Lifecycle Manager inventory from the VSP fleet-lcm API (VCF 9.1.x).

        .DESCRIPTION
        Acquires a bearer token from POST /api/v1/identity/token, then fetches:
          - GET /fleet-lcm/v1/system — reads the Fleet Controller's own currentVersion.
          - GET /fleet-lcm/v1/components (paginated) — reads all managed fleet components
            (e.g. VCF Automation, Identity Broker, Salt Master) and their versions.

        Component types already collected from native APIs (VCF Operations via
        Connect-VcfOpsServer; Fleet Lifecycle itself from /v1/system) are
        excluded to avoid duplicate inventory entries. All other component types are
        mapped to advisory names via VSP_FLEET_LCM_COMPONENT_TYPE_TO_ADVISORY_NAME
        and added with DomainName = "VCF Fleet".

        .PARAMETER Server
        VSP Fleet Controller FQDN or IP.

        .PARAMETER User
        Username (e.g. admin@vsp.local).

        .PARAMETER Password
        Plain-text password.

        .PARAMETER TimeoutSeconds
        Request timeout (1-300, default 30).

        .EXAMPLE
        $inv = Get-VspFleetLcmInventory -Server "flt-fc01.sfo.rainpole.io" -User "admin@vsp.local" -Password $plainTextPw

        .OUTPUTS
        [Hashtable] Inventory or empty hashtable if not applicable.

        .NOTES
        Returns an empty hashtable when the VSP bearer token cannot be acquired, allowing the caller to fall back to the lcops path silently.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Password,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    $inventory = @{}

    try {
        $bearerToken = Get-VspBearerToken -Server $Server -User $User -Password $Password -TimeoutSeconds $TimeoutSeconds

        if ([String]::IsNullOrWhiteSpace($bearerToken)) {
            return $inventory
        }

        Write-LogMessage -Type INFO -Message "Acquired VSP bearer token from: $Server"

        $headers = @{ "Authorization" = "Bearer $bearerToken"; "Accept" = "application/json" }
        $systemResponse = Invoke-RestMethod -Uri "https://$Server/fleet-lcm/v1/system" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $version = ""
        foreach ($prop in @('currentVersion', 'version', 'Version')) {
            $candidate = $systemResponse.$prop
            if (-not [String]::IsNullOrWhiteSpace($candidate)) {
                $version = ([String]$candidate).Trim()
                break
            }
        }

        Write-LogMessage -Type DEBUG -Message "Fleet-lcm /system currentVersion=$version from $Server"

        if ([String]::IsNullOrWhiteSpace($version)) {
            $rawJson = $systemResponse | ConvertTo-Json -Depth 2 -Compress -ErrorAction SilentlyContinue
            Write-LogMessage -Type DEBUG -Message "Fleet-lcm /system raw response: $rawJson"
        }

        $fmVersion = if ([String]::IsNullOrWhiteSpace($version)) { "Unknown" } else { $version }
        $inventory['Fleet Lifecycle'] = @([PSCustomObject]@{
            Fqdn       = $Server
            Version    = $fmVersion
            DomainName = "VCF Fleet"
        })
        Write-LogMessage -Type INFO  -Message "Collected Fleet Lifecycle: $Server"
        Write-LogMessage -Type DEBUG -Message "Fleet Lifecycle version: $fmVersion (VSP path)"

        $componentLists      = @{}
        $pageNumber          = 0
        $totalPages          = 1
        $opsFqdnFromFleet    = $null
        $opsVersionFromFleet = $null

        while ($pageNumber -lt $totalPages -and $pageNumber -lt $Script:VSP_FLEET_LCM_INVENTORY_MAX_PAGES) {
            $compUri = "https://$Server/fleet-lcm/v1/components?pageNumber=$pageNumber&pageSize=$Script:VSP_FLEET_LCM_INVENTORY_PAGE_SIZE"
            $compResponse = Invoke-RestMethod -Uri $compUri `
                -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

            if ($null -ne $compResponse.pageMetadata -and $null -ne $compResponse.pageMetadata.totalPages) {
                $totalPages = [Int]$compResponse.pageMetadata.totalPages
            }

            foreach ($comp in $compResponse.components) {
                $typeKey = ([String]$comp.componentType).ToLower().Trim()
                if ($typeKey -eq 'vcf_fleet_lcm') { continue }
                if ($typeKey -eq 'ops') {
                    # VCF Operations is collected via Get-VcfOpsInventory (native API), but
                    # that API returns only the base version (e.g. "9.1.0.0"). Fleet LCM
                    # carries the full build number. Capture it here; the EntryPoint will
                    # patch the native version after both inventories have been merged.
                    $fqdn = [String]$comp.fqdn
                    if ([String]::IsNullOrWhiteSpace($fqdn) -and $null -ne $comp.nodes -and $comp.nodes.Count -gt 0) {
                        $fqdn = [String]$comp.nodes[0].fqdn
                    }
                    $ver = if (-not [String]::IsNullOrWhiteSpace($comp.version)) { [String]$comp.version } else { "" }
                    if (-not [String]::IsNullOrWhiteSpace($ver)) {
                        $opsFqdnFromFleet    = $fqdn
                        $opsVersionFromFleet = $ver
                        Write-LogMessage -Type DEBUG -Message "Fleet LCM ops component: fqdn=$fqdn version=$ver"
                    }
                    continue
                }

                $advisoryName = $Script:VSP_FLEET_LCM_COMPONENT_TYPE_TO_ADVISORY_NAME[$typeKey]
                if ([String]::IsNullOrWhiteSpace($advisoryName)) {
                    Write-LogMessage -Type DEBUG -Message "Fleet component type '$typeKey' has no advisory mapping — skipping"
                    continue
                }

                $compFqdn = [String]$comp.fqdn
                if ([String]::IsNullOrWhiteSpace($compFqdn) -and $null -ne $comp.nodes -and $comp.nodes.Count -gt 0) {
                    $compFqdn = [String]$comp.nodes[0].fqdn
                }
                if ([String]::IsNullOrWhiteSpace($compFqdn)) {
                    Write-LogMessage -Type DEBUG -Message "Fleet component '$advisoryName' (type: $typeKey) has no FQDN — skipping"
                    continue
                }

                $compVersion = if (-not [String]::IsNullOrWhiteSpace($comp.version)) { [String]$comp.version } else { "Unknown" }

                if (-not $componentLists.ContainsKey($advisoryName)) {
                    $componentLists[$advisoryName] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $componentLists[$advisoryName].Add([PSCustomObject]@{
                    Fqdn       = $compFqdn
                    Version    = $compVersion
                    DomainName = "VCF Fleet"
                })
                Write-LogMessage -Type DEBUG -Message "Fleet LCM component: $advisoryName at $compFqdn version=$compVersion"
            }

            $pageNumber++
        }

        foreach ($key in @($componentLists.Keys)) {
            $inventory[$key] = $componentLists[$key].ToArray()
        }

        # Expose the VCF Operations full build number as a sentinel key so the caller
        # (EntryPoint) can patch the native-API version after the inventory is merged.
        if (-not [String]::IsNullOrWhiteSpace($opsVersionFromFleet)) {
            $inventory['_OpsVersionFromFleet'] = [PSCustomObject]@{
                Fqdn    = $opsFqdnFromFleet
                Version = $opsVersionFromFleet
            }
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "VSP fleet-lcm path not available on $Server — $($_.Exception.Message)"
    }

    return $inventory
}
function Resolve-ProductNodeFqdn {

    <#
        .SYNOPSIS
        Resolve an FQDN from a Fleet Manager or vRSLCM product node properties bag.

        .DESCRIPTION
        Iterates the supplied node collection and probes each node's properties for the
        keys in $Script:FQDN_PROBE_KEYS, returning the first non-whitespace value found.
        Returns an empty string when no FQDN is resolvable.

        Call twice for products that have a clusterVIP fallback — once with the node
        collection, once with the clusterVIP.clusterVips collection if the first call
        returns empty.

        .PARAMETER Nodes
        Product node collection from the Fleet Manager or vRSLCM environments API.
        Accepts an empty collection (returns empty string).

        .EXAMPLE
        $fqdn = Resolve-ProductNodeFqdn -Nodes @($product.nodes)
        if ([String]::IsNullOrWhiteSpace($fqdn) -and $null -ne $product.clusterVIP) {
            $fqdn = Resolve-ProductNodeFqdn -Nodes @($product.clusterVIP.clusterVips)
        }

        .OUTPUTS
        [String] Resolved FQDN or empty string when not resolvable.

        .NOTES
        Pure utility function. Does not mutate any module-scope variables. Returns an empty string (not null) for safe string checks.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$Nodes
    )

    foreach ($node in $Nodes) {
        foreach ($key in $Script:FQDN_PROBE_KEYS) {
            $candidate = $node.properties.$key
            if (-not [String]::IsNullOrWhiteSpace($candidate)) { return [String]$candidate }
        }
    }
    return ""
}
function Get-LcopsFleetManagerInventory {

    <#
        .SYNOPSIS
        Collect Fleet Lifecycle Manager inventory via Basic auth (VCF 9.0.x).

        .DESCRIPTION
        Builds a Basic auth header (base64(user:password)) and calls:
          - GET /lcm/lcops/api/v2/settings/system-details — reads the appliance version.
          - GET /lcm/lcops/api/v2/environments — reads all managed products (e.g. VCF
            Automation, VCF Identity) and their versions.

        The VCF Operations product (type "vrops") is not added to the inventory directly —
        it is collected via the native VCF Operations API — but its version and FQDN are
        captured under the sentinel key _OpsVersionFromFleet (same pattern as the 9.1 path)
        so EntryPoint can patch the base version returned by the native API with the full
        build number provided by Fleet Manager. Products with no resolvable FQDN are skipped.

        .PARAMETER Server
        Fleet Manager FQDN or IP.

        .PARAMETER User
        Username (e.g. admin@local).

        .PARAMETER Password
        Plain-text password.

        .PARAMETER TimeoutSeconds
        Request timeout (1-300, default 30).

        .EXAMPLE
        $inv = Get-LcopsFleetManagerInventory -Server "flt-lcm01.sfo.rainpole.io" -User "admin@local" -Password $plainTextPw

        .OUTPUTS
        [Hashtable] Inventory or empty hashtable on failure.

        .NOTES
        Returns an empty hashtable on failure (logs DEBUG). Sets _OpsVersionFromFleet sentinel key when Fleet Manager carries a full VCF Operations build number.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Password,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    $inventory = @{}

    try {
        $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${User}:${Password}"))
        $headers  = @{ "Authorization" = "Basic $encoded"; "Accept" = "application/json" }

        $systemDetails = Invoke-RestMethod -Uri "https://$Server/lcm/lcops/api/v2/settings/system-details" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $version = ""
        foreach ($prop in @('version', 'Version')) {
            $candidate = $systemDetails.$prop
            if (-not [String]::IsNullOrWhiteSpace($candidate)) {
                $version = ([String]$candidate).Trim()
                break
            }
        }

        $versionFinal = if ([String]::IsNullOrWhiteSpace($version)) { "Unknown" } else { $version }
        $inventory["Fleet Lifecycle"] = @([PSCustomObject]@{ Fqdn = $Server; Version = $versionFinal; DomainName = "VCF Fleet" })
        Write-LogMessage -Type INFO  -Message "Collected Fleet Lifecycle: $Server"
        Write-LogMessage -Type DEBUG -Message "Fleet Lifecycle version: $versionFinal (9.0 path)"

        # Resolve FQDNs from node property bags using the shared probe-key list.
        $environments = Invoke-RestMethod -Uri "https://$Server/lcm/lcops/api/v2/environments" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $componentLists      = @{}
        $opsFqdnFromFleet    = $null
        $opsVersionFromFleet = $null

        foreach ($env in $environments) {
            foreach ($product in $env.products) {
                $typeKey = ([String]$product.id).ToLower().Trim()

                if ($typeKey -eq 'vrops') {
                    # VCF Operations is collected via its native API, which returns only the base
                    # version (e.g. "9.0.0.0"). The lcops environments API carries the full build
                    # number. Capture it here under the same _OpsVersionFromFleet sentinel used by
                    # the VCF 9.1 path so EntryPoint can patch the native version after the merge.
                    $ver = if (-not [String]::IsNullOrWhiteSpace($product.version)) { [String]$product.version } else { "" }
                    if (-not [String]::IsNullOrWhiteSpace($ver)) {
                        $opsFqdnFromFleet    = Resolve-ProductNodeFqdn -Nodes @($product.nodes)
                        $opsVersionFromFleet = $ver
                        Write-LogMessage -Type DEBUG -Message "Fleet 9.0 ops component: fqdn=$opsFqdnFromFleet version=$ver"
                    }
                    continue
                }

                if ($typeKey -eq 'vrslcm') { continue }

                $advisoryName = $Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_TO_ADVISORY_NAME[$typeKey]
                if ([String]::IsNullOrWhiteSpace($advisoryName)) {
                    Write-LogMessage -Type DEBUG -Message "Fleet 9.0 product type '$typeKey' has no advisory mapping — skipping"
                    continue
                }

                $productVersion = if (-not [String]::IsNullOrWhiteSpace($product.version)) { [String]$product.version } else { "Unknown" }

                $resolvedFqdn = Resolve-ProductNodeFqdn -Nodes @($product.nodes)
                if ([String]::IsNullOrWhiteSpace($resolvedFqdn) -and $null -ne $product.clusterVIP) {
                    $resolvedFqdn = Resolve-ProductNodeFqdn -Nodes @($product.clusterVIP.clusterVips)
                }

                if ([String]::IsNullOrWhiteSpace($resolvedFqdn)) {
                    Write-LogMessage -Type DEBUG -Message "Fleet 9.0 product '$advisoryName' (type: $typeKey) has no resolvable FQDN — skipping"
                    continue
                }

                if (-not $componentLists.ContainsKey($advisoryName)) {
                    $componentLists[$advisoryName] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $componentLists[$advisoryName].Add([PSCustomObject]@{
                    Fqdn       = $resolvedFqdn
                    Version    = $productVersion
                    DomainName = "VCF Fleet"
                })
                Write-LogMessage -Type DEBUG -Message "Fleet LCM component: $advisoryName at $resolvedFqdn"
            }
        }

        foreach ($key in @($componentLists.Keys)) {
            $inventory[$key] = $componentLists[$key].ToArray()
        }

        # Expose the VCF Operations full build number as the same sentinel used by the 9.1 path.
        if (-not [String]::IsNullOrWhiteSpace($opsVersionFromFleet)) {
            $inventory['_OpsVersionFromFleet'] = [PSCustomObject]@{
                Fqdn    = $opsFqdnFromFleet
                Version = $opsVersionFromFleet
            }
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Fleet Manager (9.0 lcops path) not available on $Server — $($_.Exception.Message)"
    }

    return $inventory
}
function Get-VrslcmInventory {

    <#
        .SYNOPSIS
        Collect vRealize Suite Lifecycle Manager (vRSLCM) inventory and managed product versions.

        .DESCRIPTION
        Connects to a vRSLCM appliance using Basic authentication against the
        /lcm/lcops/api/v2 REST API and retrieves:
        - The vRSLCM appliance version (from /settings/system-details).
        - All products deployed through vRSLCM (from /environments), keyed by their
          advisory component name so they can be matched against security advisories.

        Products are returned under the key "vRSLCM" for the vRSLCM appliance itself,
        and under their individual advisory names (e.g. "VCF Automation", "VCF Operations
        for Logs", "VCF Identity") for managed products — consistent with the advisory database schema.

        .PARAMETER Server
        vRSLCM appliance FQDN or IP address.

        .PARAMETER User
        Username for vRSLCM authentication (e.g. admin@local).

        .PARAMETER Password
        Plain-text password for authentication.

        .PARAMETER TimeoutSeconds
        HTTP request timeout in seconds (1-300, default 30).

        .EXAMPLE
        $pw = [System.Environment]::GetEnvironmentVariable("VRSLCM_PASSWORD")
        $inv = Get-VrslcmInventory -Server "vrslcm.example.com" -User "admin@local" -Password $pw
        $inv.Keys | ForEach-Object { Write-Output "$_ : $($inv[$_][0].Version)" }

        .OUTPUTS
        [Hashtable] Inventory keyed by advisory component name. Each value is an array of
        [PSCustomObject] with Fqdn, Version, and DomainName ("vRSLCM").
        Returns empty hashtable on connection or authentication failure.

        .NOTES
        Uses /lcm/lcops/api/v2/settings/system-details for the vRSLCM appliance version.
        Uses /lcm/lcops/api/v2/environments to enumerate managed product nodes and versions.
        Product IDs returned by the environments API are mapped via
        $Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_TO_ADVISORY_NAME for advisory matching.
        TLS certificate validation is skipped (lab environments).
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Password,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User
    )

    $inventory = @{}

    Write-LogMessage -Type INFO -Message "Collecting vRSLCM inventory from: $Server..."

    try {
        $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${User}:${Password}"))
        $headers = @{ "Authorization" = "Basic $encoded"; "Accept" = "application/json" }

        # Collect vRSLCM appliance version.
        $systemDetails = Invoke-RestMethod -Uri "https://$Server/lcm/lcops/api/v2/settings/system-details" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $versionRaw   = [String]$systemDetails.version
        $versionFinal = if ([String]::IsNullOrWhiteSpace($versionRaw)) { "Unknown" } else { $versionRaw.Trim() }

        $inventory["vRSLCM"] = @(
            [PSCustomObject]@{ Fqdn = $Server; Version = $versionFinal; DomainName = $null }
        )
        Write-LogMessage -Type INFO -Message "Collected vRSLCM appliance: $Server v$versionFinal"

        # Collect managed products from each environment.
        $environments = Invoke-RestMethod -Uri "https://$Server/lcm/lcops/api/v2/environments" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $componentLists = @{}

        foreach ($env in $environments) {
            $envDomainName = ([String]$env.name).Trim()
            foreach ($product in $env.products) {
                $typeKey = ([String]$product.id).ToLower().Trim()

                $advisoryName = $Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_TO_ADVISORY_NAME[$typeKey]
                if ([String]::IsNullOrWhiteSpace($advisoryName)) {
                    Write-LogMessage -Type DEBUG -Message "vRSLCM product type '$typeKey' has no advisory mapping — skipping"
                    continue
                }

                $productVersion = if (-not [String]::IsNullOrWhiteSpace($product.version)) { [String]$product.version } else { "Unknown" }

                $resolvedFqdn = Resolve-ProductNodeFqdn -Nodes @($product.nodes)
                $fqdnFinal    = if ([String]::IsNullOrWhiteSpace($resolvedFqdn)) { $Server } else { $resolvedFqdn }

                if (-not $componentLists.ContainsKey($advisoryName)) {
                    $componentLists[$advisoryName] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $componentLists[$advisoryName].Add([PSCustomObject]@{
                    Fqdn       = $fqdnFinal
                    Version    = $productVersion
                    DomainName = $envDomainName
                })
                Write-LogMessage -Type INFO -Message "Collected vRSLCM managed product: $advisoryName ($fqdnFinal v$productVersion)"
            }
        }

        foreach ($key in $componentLists.Keys) {
            $inventory[$key] = $componentLists[$key].ToArray()
        }
    }
    catch {
        Write-LogMessage -Type WARNING -Message "vRSLCM inventory collection failed for $Server — $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $Server -Context 'vRSLCM')"
    }

    return $inventory
}

#endregion
