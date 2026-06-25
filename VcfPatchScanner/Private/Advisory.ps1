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

#region Advisory Loading and Parsing

$Script:ADVISORY_SCHEMA_VERSION = "2.0"

# Product family → component membership map used by Select-AdvisoryByProductFamily.
# VCF is a superset of VVF, which is a superset of vSphere.
# 'ESX' is listed alongside 'ESXi' because some advisories use the shorter form; both refer
# to the same hypervisor. The scraper normalises to 'ESXi' where possible.
# 'VCF Operations Workload Mobility' is the product-line name for HCX.
# Both the current Broadcom UI names and the older "VCF XXX" advisory names are listed so
# advisories authored in either naming era are correctly classified.
$Script:PRODUCT_FAMILY_COMPONENTS = @{
    VCF     = @('ESXi', 'ESX', 'vCenter', 'NSX', 'SDDC Manager',
                'VCF Operations', 'VCF Operations for Logs', 'VCF Operations for Networks',
                'VCF Operations Workload Mobility',
                'VCF Automation', 'VCF Services Runtime',
                'Fleet Lifecycle', 'VCF Fleet Management',
                'Identity Broker', 'VCF Identity', 'VCF Identity Broker',
                'VMware Identity Manager', 'VMware Workspace ONE Access', 'VMware Aria Identity Manager',
                'Salt Master', 'VCF Salt Master',
                'Salt RaaS', 'VCF Salt RaaS',
                'Software Depot', 'VCF Software Depot',
                'SDDC Lifecycle', 'VCF SDDC Lifecycle',
                'Telemetry', 'VCF Telemetry')
    VVF     = @('ESXi', 'ESX', 'vCenter', 'VCF Operations', 'VCF Operations for Logs')
    vSphere = @('ESXi', 'ESX', 'vCenter')
}

function Invoke-AdvisoryDownloadIfChanged {

    <#
        .SYNOPSIS
        Download the upstream advisory database only when it has changed, using ETag caching.

        .DESCRIPTION
        Issues a lightweight HEAD request to retrieve the upstream ETag. If the ETag matches
        the value stored in the sidecar cache file (<DestinationPath>.etag), the download is
        skipped entirely. Otherwise, the full file is fetched via GET, validated for schema
        compatibility (major version must be 2.x), and written atomically using a temp-file
        rename. The new ETag is persisted to the sidecar on success.

        The sidecar ETag file lives beside the destination file with a ".etag" extension, e.g.
        "securityAdvisory.json.etag". It contains only the raw ETag string, no quotes.

        .PARAMETER DestinationPath
        Absolute path where the advisory JSON file should be written. Must already exist (use
        the module's built-in Data/securityAdvisory.json) or the directory must be writable.

        .PARAMETER TimeoutSeconds
        Network timeout in seconds applied to both the HEAD check and the full file download. Default: 10.
        Increase to 30 or more on slow connections to avoid premature download failures.

        .PARAMETER Uri
        URI of the upstream advisory JSON file.

        .EXAMPLE
        $result = Invoke-AdvisoryDownloadIfChanged -DestinationPath "C:\VcfPatchScanner\Data\securityAdvisory.json"
        if ($result.Downloaded) { Write-LogMessage -Type INFO -Message "Advisory database updated to $($result.UpdatedAt)" }

        .NOTES
        Returns [PSCustomObject] with:
          Downloaded ([Bool])    — true when the file was replaced.
          Skipped    ([Bool])    — true when ETags matched; file unchanged.
          UpstreamEtag ([String]) — ETag returned by the server.
          UpdatedAt  ([String])  — updatedAt from the newly-written file, or from the existing file when skipped.
          ErrorMessage ([String]) — non-empty on failure.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$DestinationPath,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)]    [Int]$TimeoutSeconds = 10,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$Uri = "https://raw.githubusercontent.com/vmware/powershell-module-for-vcf-patch-scanner/main/VcfPatchScanner/Data/securityAdvisory.json"
    )

    $etagPath = "$DestinationPath.etag"
    $localEtag = ""
    if (Test-Path -LiteralPath $etagPath -PathType Leaf) {
        $localEtag = (Get-Content -LiteralPath $etagPath -Raw).Trim()
    }

    # HEAD request — only download if ETag changed.
    $upstreamEtag = ""
    try {
        $headResp = Invoke-WebRequest -Uri $Uri -Method Head -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        $upstreamEtag = ($headResp.Headers["ETag"] ?? "").Trim('"')
    } catch {
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $false
            UpstreamEtag = ""
            UpdatedAt    = ""
            ErrorMessage = "HEAD request failed: $($_.Exception.Message)"
        }
    }

    if ($localEtag -and $upstreamEtag -and $localEtag -eq $upstreamEtag) {
        $existingUpdatedAt = ""
        if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
            try {
                $doc = Get-Content -LiteralPath $DestinationPath -Raw | ConvertFrom-Json -Depth 3
                $existingUpdatedAt = if ($doc.updatedAt) { [String]$doc.updatedAt } elseif ($doc.generatedAt) { [String]$doc.generatedAt } else { "" }
            } catch { }
        }
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $true
            UpstreamEtag = $upstreamEtag
            UpdatedAt    = $existingUpdatedAt
            ErrorMessage = ""
        }
    }

    # GET the full file.
    $tempPath = "$DestinationPath.$(New-Guid).tmp"
    try {
        $getResp = Invoke-WebRequest -Uri $Uri -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        $body    = $getResp.Content
        $getEtag = ($getResp.Headers["ETag"] ?? "").Trim('"')
        if (-not $getEtag) { $getEtag = $upstreamEtag }
    } catch {
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $false
            UpstreamEtag = $upstreamEtag
            UpdatedAt    = ""
            ErrorMessage = "Download failed: $($_.Exception.Message)"
        }
    }

    # Validate schema before touching the file on disk.
    try {
        $document = $body | ConvertFrom-Json -Depth $Script:JSON_PARSE_MAX_DEPTH -ErrorAction Stop
    } catch {
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $false
            UpstreamEtag = $upstreamEtag
            UpdatedAt    = ""
            ErrorMessage = "Upstream file is not valid JSON: $($_.Exception.Message)"
        }
    }

    $schemaVersion = if ($document.schemaVersion) { [String]$document.schemaVersion } elseif ($document.SchemaVersion) { [String]$document.SchemaVersion } else { "" }
    if (-not $schemaVersion.StartsWith("2.")) {
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $false
            UpstreamEtag = $upstreamEtag
            UpdatedAt    = ""
            ErrorMessage = "Upstream schema version '$schemaVersion' is incompatible (expected 2.x)."
        }
    }

    $advisories = if ($document.advisories) { @($document.advisories) } elseif ($document.Advisories) { @($document.Advisories) } else { @() }
    if ($advisories.Count -eq 0) {
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $false
            UpstreamEtag = $upstreamEtag
            UpdatedAt    = ""
            ErrorMessage = "Upstream file contains no advisories."
        }
    }

    $updatedAt = if ($document.updatedAt) { [String]$document.updatedAt } elseif ($document.generatedAt) { [String]$document.generatedAt } else { "" }

    # Atomic write: temp file → rename.
    try {
        $destDir = Split-Path -Path $DestinationPath -Parent
        if (-not (Test-Path -Path $destDir -PathType Container)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($tempPath, $body, $utf8NoBom)
        Move-Item -LiteralPath $tempPath -Destination $DestinationPath -Force
    } catch {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        return [PSCustomObject]@{
            Downloaded   = $false
            Skipped      = $false
            UpstreamEtag = $upstreamEtag
            UpdatedAt    = ""
            ErrorMessage = "Could not write advisory file: $($_.Exception.Message)"
        }
    }

    # Persist the new ETag.
    try {
        [System.IO.File]::WriteAllText($etagPath, $getEtag, [System.Text.Encoding]::UTF8)
    } catch { }

    return [PSCustomObject]@{
        Downloaded   = $true
        Skipped      = $false
        UpstreamEtag = $getEtag
        UpdatedAt    = $updatedAt
        ErrorMessage = ""
    }
}
function Get-SecurityAdvisory {

    <#
        .SYNOPSIS
        Load security advisory documents from a local file or upstream URI.

        .DESCRIPTION
        When FilePath is supplied, loads and optionally validates the local advisory JSON.
        When Uri is supplied, uses ETag-based caching to download the file only if it has
        changed since the last fetch, then loads from the updated local copy. DestinationPath
        is required with Uri to specify where to store the downloaded file.

        .PARAMETER DestinationPath
        Required when Uri is specified. Absolute path to the local advisory file that receives
        the downloaded content and stores the sidecar ETag cache.

        .PARAMETER FilePath
        Path to a local advisory JSON file. Must be an absolute path.

        .PARAMETER TimeoutSeconds
        Network timeout in seconds used when Uri is specified. Default: 10.

        .PARAMETER Uri
        URI of the upstream advisory JSON. When supplied, an ETag-aware HEAD+GET sequence
        is used so the full file is only downloaded when its content has changed.

        .PARAMETER ValidateSchema
        When specified, enforces schema version compatibility after loading.

        .EXAMPLE
        $advisories = Get-SecurityAdvisory -FilePath "C:\VcfPatchScanner\Data\securityAdvisory.json"

        .EXAMPLE
        $advisories = Get-SecurityAdvisory `
            -Uri "https://raw.githubusercontent.com/vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json" `
            -DestinationPath "C:\VcfPatchScanner\Data\securityAdvisory.json"

        .NOTES
        Throws [System.ArgumentException] when neither FilePath nor Uri is supplied, or when
        Uri is supplied without DestinationPath.
        Throws [System.IO.FileNotFoundException] when FilePath does not exist on disk.
        Throws [System.InvalidOperationException] on schema version mismatch, JSON parse failure,
        or download error.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$DestinationPath,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$FilePath,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)]    [Int]$TimeoutSeconds = 10,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$Uri,
        [Parameter(Mandatory = $false)] [Switch]$ValidateSchema
    )

    if ([String]::IsNullOrWhiteSpace($FilePath) -and [String]::IsNullOrWhiteSpace($Uri)) {
        throw [System.ArgumentException]::new("Either FilePath or Uri must be provided.")
    }

    if (-not [String]::IsNullOrWhiteSpace($Uri)) {
        if ([String]::IsNullOrWhiteSpace($DestinationPath)) {
            throw [System.ArgumentException]::new("DestinationPath is required when Uri is specified.")
        }
        if (-not [System.IO.Path]::IsPathRooted($DestinationPath)) {
            throw [System.InvalidOperationException]::new("DestinationPath must be absolute, got: $DestinationPath")
        }

        $result = Invoke-AdvisoryDownloadIfChanged -Uri $Uri -DestinationPath $DestinationPath -TimeoutSeconds $TimeoutSeconds
        if ($result.ErrorMessage) {
            throw [System.InvalidOperationException]::new("Advisory download failed: $($result.ErrorMessage)")
        }
        if ($result.Downloaded) {
            Write-LogMessage -Type INFO -Message "Advisory database updated (updatedAt: $($result.UpdatedAt))."
        } else {
            Write-LogMessage -Type DEBUG -Message "Advisory database is current — ETag matched, no download needed."
        }
        # Load from the (possibly just-updated) local file.
        $FilePath = $DestinationPath
    }

    if ($FilePath -match '[/\\]\.\.[/\\]' -or $FilePath -match '[/\\]\.\.$') {
        throw [System.InvalidOperationException]::new("Advisory file path contains invalid traversal sequences: $FilePath")
    }
    if (-not [System.IO.Path]::IsPathRooted($FilePath)) {
        throw [System.InvalidOperationException]::new("Advisory file path must be absolute, got: $FilePath")
    }
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new("Advisory file not found: $FilePath")
    }

    $fileInfo = Get-Item -LiteralPath $FilePath
    $maxSizeBytes = 50MB
    if ($fileInfo.Length -gt $maxSizeBytes) {
        throw [System.InvalidOperationException]::new("Advisory file exceeds maximum size of $($maxSizeBytes / 1MB) MB: $($fileInfo.Length / 1MB) MB")
    }

    try {
        $content  = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
        $document = ConvertFrom-Json -InputObject $content -Depth $Script:JSON_PARSE_MAX_DEPTH -ErrorAction Stop

        if ($ValidateSchema) {
            Test-AdvisorySchemaValidity -AdvisoryDocument $document
        }

        if ($null -ne $document.advisories -and $document.advisories -is [System.Collections.IEnumerable]) {
            return @($document.advisories)
        }
        if ($null -ne $document.Advisories -and $document.Advisories -is [System.Collections.IEnumerable]) {
            return @($document.Advisories)
        }
        if ($document -is [System.Collections.IEnumerable] -and $document -isnot [String]) {
            return @($document)
        }
        return @($document)
    } catch {
        throw [System.InvalidOperationException]::new("Failed to parse advisory file: $($_.Exception.Message)", $_.Exception)
    }
}
function ConvertFrom-AdvisoryDocument {

    <#
        .SYNOPSIS
        Parse and validate an advisory document structure.

        .DESCRIPTION
        Validates that the supplied advisory object contains the required fields
        (vmsaId and severity). Logs a WARNING when impactedComponents is absent.
        Returns the advisory unchanged when it passes validation; throws on missing
        mandatory fields.

        .PARAMETER Advisory
        Advisory document to parse (PSCustomObject from ConvertFrom-Json).

        .EXAMPLE
        $validated = ConvertFrom-AdvisoryDocument -Advisory $rawAdvisory

        .OUTPUTS
        [PSCustomObject] The validated advisory object, returned as-is.

        .NOTES
        Throws [System.InvalidOperationException] when vmsaId or severity is absent.
        Used internally by Select-AdvisoryByEnvironmentType, Select-AdvisoryByProductFamily,
        Select-AdvisoryByComponent, and Get-AdvisoryComponentMatches.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [PSCustomObject]$Advisory
    )

    if ([String]::IsNullOrWhiteSpace($Advisory.vmsaId)) {
        throw [System.InvalidOperationException]::new("Advisory missing vmsaId")
    }

    if ([String]::IsNullOrWhiteSpace($Advisory.severity)) {
        throw [System.InvalidOperationException]::new("Advisory $($Advisory.vmsaId) missing severity")
    }

    if ($null -eq $Advisory.impactedComponents -or $Advisory.impactedComponents.Count -eq 0) {
        Write-LogMessage -Type WARNING -Message "Advisory $($Advisory.vmsaId) has no impactedComponents"
    }

    return $Advisory
}
function Get-AdvisoryComponentMatches {

    <#
        .SYNOPSIS
        Get advisories that match a specific component name.

        .DESCRIPTION
        Iterates the advisory array and returns flattened advisory-component pairs whose
        component name exactly matches ComponentName (case-sensitive). Each result object
        carries vmsaId, severity, component metadata (minimumVersions, fixedVersions,
        kbArticles, cves), and fixedVersionUrl.

        .PARAMETER Advisories
        Array of advisory documents as returned by Get-SecurityAdvisory.

        .PARAMETER ComponentName
        Canonical component name to match (e.g. "ESXi", "NSX", "vCenter").
        Matching is case-sensitive to align with the Component Registry.

        .EXAMPLE
        $advisories = Get-SecurityAdvisory -FilePath $advisoryFilePath
        $esxiMatches = Get-AdvisoryComponentMatches -Advisories $advisories -ComponentName 'ESXi'

        .OUTPUTS
        [PSCustomObject[]] Matched advisory-component pairs with fields: vmsaId, severity,
        componentName, minimumVersions, fixedVersions, kbArticles, cves, fixedVersionUrl.

        .NOTES
        Invalid advisories (missing vmsaId or severity) are logged at WARNING level and skipped.
        Returns an empty array when no advisories match the component name.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [Object[]]$Advisories,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ComponentName
    )

    $advisoryMatches = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($advisory in $Advisories) {
        try {
            $validatedAdvisory = ConvertFrom-AdvisoryDocument -Advisory $advisory
        }
        catch {
            Write-LogMessage -Type WARNING -Message "Skipping invalid advisory: $($_.Exception.Message)"
            continue
        }

        foreach ($component in @($validatedAdvisory.impactedComponents)) {
            $componentNameFromAdvisory = [String]$component.component
            if ($componentNameFromAdvisory -eq $ComponentName) {
                $advisoryMatches.Add([PSCustomObject]@{
                    vmsaId          = $validatedAdvisory.vmsaId
                    severity        = $validatedAdvisory.severity
                    componentName   = $componentNameFromAdvisory
                    minimumVersions = $component.minimumVersions
                    fixedVersions   = $component.fixedVersions
                    kbArticles      = $component.kbArticles
                    cves            = $component.cves
                    fixedVersionUrl = $component.fixedVersionUrl
                })
            }
        }
    }

    return @($advisoryMatches)
}
function Test-AdvisorySchemaValidity {

    <#
        .SYNOPSIS
        Validate advisory document schema version and structure.

        .DESCRIPTION
        Ensures the advisory document meets the expected schema version and contains required fields.
        Schema version 2.0 requires: schemaVersion "2.x", advisories array.
        Each advisory requires: vmsaId, severity, impactedComponents.
        Each component requires: component, minimumVersions, and either fixedVersions or kbArticles.

        .PARAMETER AdvisoryDocument
        Advisory document (root object or wrapper).

        .EXAMPLE
        Test-AdvisorySchemaValidity -AdvisoryDocument $document

        .OUTPUTS
        [Void] Throws on schema mismatch or missing required fields.

        .NOTES
        Throws [System.InvalidOperationException] on schema major-version mismatch, missing vmsaId or
        severity, or missing minimumVersions on any component entry.
        Logs a WARNING (does not throw) when impactedComponents is absent on an advisory.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [PSCustomObject]$AdvisoryDocument
    )

    $schemaVersion = if ($null -ne $AdvisoryDocument.schemaVersion) {
        [String]$AdvisoryDocument.schemaVersion
    } elseif ($null -ne $AdvisoryDocument.SchemaVersion) {
        [String]$AdvisoryDocument.SchemaVersion
    } else {
        "1.0"
    }

    $schemaMajor = [Int]($schemaVersion.Split('.')[0])
    $expectedMajor = [Int]($Script:ADVISORY_SCHEMA_VERSION.Split('.')[0])
    if ($schemaMajor -ne $expectedMajor) {
        throw [System.InvalidOperationException]::new(
            "Advisory database is schema v$schemaVersion; this scanner release requires v$($Script:ADVISORY_SCHEMA_VERSION). " +
            "Run Convert-BroadcomAdvisoriesToSchema.ps1 to regenerate the advisory database.")
    }

    $advisories = if ($null -ne $AdvisoryDocument.advisories) {
        @($AdvisoryDocument.advisories)
    } elseif ($null -ne $AdvisoryDocument.Advisories) {
        @($AdvisoryDocument.Advisories)
    } else {
        @($AdvisoryDocument)
    }

    foreach ($advisory in $advisories) {
        if ([String]::IsNullOrWhiteSpace($advisory.vmsaId)) {
            throw [System.InvalidOperationException]::new("Advisory missing required field: vmsaId")
        }

        if ([String]::IsNullOrWhiteSpace($advisory.severity)) {
            throw [System.InvalidOperationException]::new("Advisory $($advisory.vmsaId) missing required field: severity")
        }

        if ($null -eq $advisory.impactedComponents -or $advisory.impactedComponents.Count -eq 0) {
            Write-LogMessage -Type WARNING -Message "Advisory $($advisory.vmsaId) has no impactedComponents"
        }
        else {
            foreach ($component in @($advisory.impactedComponents)) {
                if ([String]::IsNullOrWhiteSpace($component.component)) {
                    throw [System.InvalidOperationException]::new("Advisory $($advisory.vmsaId) component missing required field: component")
                }

                if (@($component.minimumVersions).Count -eq 0) {
                    throw [System.InvalidOperationException]::new("Advisory $($advisory.vmsaId) component $($component.component) missing required field: minimumVersions")
                }

                if ($null -eq $component.fixedVersions -and $null -eq $component.kbArticles) {
                    throw [System.InvalidOperationException]::new("Advisory $($advisory.vmsaId) component $($component.component) missing both fixedVersions and kbArticles")
                }
            }
        }
    }
}
function Select-AdvisoryByEnvironmentType {

    <#
        .SYNOPSIS
        Select advisories applicable to an environment type.

        .DESCRIPTION
        Returns advisories that contain at least one component applicable to the given
        environment type. Each environment type maps to a known set of component names;
        advisories whose components do not intersect that set are excluded.

        .PARAMETER Advisories
        Array of advisory documents returned by Get-SecurityAdvisory.

        .PARAMETER EnvironmentType
        Environment type: vcf5, vcf9, vsphere8, vvf9.

        .EXAMPLE
        $advisories = Get-SecurityAdvisory -FilePath $advisoryFilePath
        $vcf9Advisories = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType vcf9

        .OUTPUTS
        [PSCustomObject[]] Applicable advisories for the environment type.

        .NOTES
        Pure filter function. Does not mutate any module-scope variables.
        Uses case-sensitive component name comparison to align with the Component Registry.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [Object[]]$Advisories,
        [Parameter(Mandatory = $true)] [ValidateSet('vcf5', 'vcf9', 'vsphere8', 'vvf9')] [String]$EnvironmentType
    )

    $applicableAdvisories = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($advisory in $Advisories) {
        try {
            $validatedAdvisory = ConvertFrom-AdvisoryDocument -Advisory $advisory
        }
        catch {
            Write-LogMessage -Type WARNING -Message "Skipping invalid advisory: $($_.Exception.Message)"
            continue
        }

        $isApplicable = $false

        foreach ($component in @($validatedAdvisory.impactedComponents)) {
            $componentName = [String]$component.component

            switch ($EnvironmentType) {
                'vcf5' {
                    # ESX is an alias for ESXi; VCF Operations Workload Mobility is HCX.
                    # All vRealize/Aria era product names are included: vRSLCM manages vrops/vra/vrli/vrni
                    # and reports them under the VCF-era inventory keys. Advisory alias resolution in
                    # Invoke-VulnerabilityScan maps each historical name to the correct inventory key.
                    if (@('ESXi', 'ESX', 'vCenter', 'NSX', 'SDDC Manager',
                          'VCF Operations Workload Mobility',
                          'VMware Identity Manager', 'VMware Workspace ONE Access',
                          'VMware Aria Identity Manager', 'VMware Identity Manager Connector',
                          'VMware Aria Operations', 'VMware vRealize Operations', 'VMware vRealize Operations Manager', 'VCF Operations',
                          'VMware Aria Automation', 'VMware vRealize Automation', 'VMware vRealize Orchestrator', 'VCF Automation',
                          'VMware Aria Operations for Logs', 'VMware vRealize Log Insight', 'VCF Operations for Logs',
                          'VMware Aria Operations for Networks', 'VMware vRealize Network Insight', 'VCF Operations for Networks') -contains $componentName) {
                        $isApplicable = $true
                    }
                }
                'vcf9' {
                    # ESX is an alias for ESXi; VCF Operations Workload Mobility is HCX.
                    # Both current Broadcom UI names and older "VCF XXX" advisory names are included.
                    if (@('ESXi', 'ESX', 'vCenter', 'NSX', 'SDDC Manager',
                          'VCF Operations', 'VCF Operations for Logs', 'VCF Operations for Networks',
                          'VCF Operations Workload Mobility',
                          'VCF Automation', 'VCF Services Runtime',
                          'Fleet Lifecycle', 'VCF Fleet Management',
                          'Identity Broker', 'VCF Identity', 'VCF Identity Broker',
                          'Salt Master', 'VCF Salt Master',
                          'Salt RaaS', 'VCF Salt RaaS',
                          'Software Depot', 'VCF Software Depot',
                          'SDDC Lifecycle', 'VCF SDDC Lifecycle',
                          'Telemetry', 'VCF Telemetry') -contains $componentName) {
                        $isApplicable = $true
                    }
                }
                'vsphere8' {
                    # ESX is an alias for ESXi. NSX is optional for standalone vSphere 8.
                    if (@('ESXi', 'ESX', 'vCenter', 'NSX') -contains $componentName) {
                        $isApplicable = $true
                    }
                }
                'vvf9' {
                    # VVF base includes ESXi, vCenter, VCF Operations, and VCF Operations for Logs only.
                    # NSX, VCF Automation, and VCF Operations for Networks are not part of the VVF base offer.
                    # ESX is an alias for ESXi.
                    if (@('ESXi', 'ESX', 'vCenter', 'VCF Operations', 'VCF Operations for Logs') -contains $componentName) {
                        $isApplicable = $true
                    }
                }
            }

            if ($isApplicable) {
                break
            }
        }

        if ($isApplicable) {
            $applicableAdvisories.Add($validatedAdvisory)
        }
    }

    return @($applicableAdvisories)
}
function Select-AdvisoryByProductFamily {

    <#
        .SYNOPSIS
        Select advisories applicable to a product family.

        .DESCRIPTION
        Returns advisories that contain at least one component belonging to the specified
        product family. The family-to-component mapping is defined in
        $Script:PRODUCT_FAMILY_COMPONENTS and documented in ADVISORY_SCHEMA.md.

        Product families and their included components:
          VCF     — ESXi, vCenter, NSX, SDDC Manager, VCF Operations,
                    VCF Operations for Logs, VCF Operations for Networks,
                    VCF Automation, VCF Services Runtime,
                    Fleet Lifecycle, Identity Broker, Salt Master, Salt RaaS,
                    Software Depot, SDDC Lifecycle, Telemetry
                    (and legacy "VCF XXX" advisory names for each of the above)
          VVF     — ESXi, vCenter, NSX, VCF Operations,
                    VCF Operations for Logs, VCF Operations for Networks
          vSphere — ESXi, vCenter

        .PARAMETER Advisories
        Array of advisory objects as returned by Get-SecurityAdvisory.

        .PARAMETER ProductFamily
        Target product family: VCF, VVF, or vSphere.

        .EXAMPLE
        $advisories = Get-SecurityAdvisory -FilePath $advisoryFilePath
        $vcfAdvisories = Select-AdvisoryByProductFamily -Advisories $advisories -ProductFamily VCF

        .EXAMPLE
        $criticalVcf = Get-SecurityAdvisory -FilePath $advisoryFilePath |
            Where-Object { $_.severity -eq 'Critical' } |
            Select-AdvisoryByProductFamily -ProductFamily VCF

        .OUTPUTS
        [PSCustomObject[]] Advisories that contain at least one component in the product family.

        .NOTES
        Supports pipeline input via $Advisories. Logs the total input count and output count at INFO level.
        Uses case-sensitive component name comparison to align with the Component Registry.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)] [ValidateNotNull()] [Object[]]$Advisories,
        [Parameter(Mandatory = $true)] [ValidateSet('VCF', 'VVF', 'vSphere')] [String]$ProductFamily
    )

    begin {
        $familyComponents = $Script:PRODUCT_FAMILY_COMPONENTS[$ProductFamily]
        $result = [System.Collections.Generic.List[PSCustomObject]]::new()
        $totalInput = 0
    }
    process {
        foreach ($advisory in $Advisories) {
            $totalInput++
            try {
                $validatedAdvisory = ConvertFrom-AdvisoryDocument -Advisory $advisory
            }
            catch {
                Write-LogMessage -Type WARNING -Message "Skipping invalid advisory: $($_.Exception.Message)"
                continue
            }
            foreach ($component in @($validatedAdvisory.impactedComponents)) {
                if ($familyComponents -contains [String]$component.component) {
                    $result.Add($validatedAdvisory)
                    break
                }
            }
        }
    }
    end {
        Write-LogMessage -Type INFO -Message "Filtered advisories for product family '$ProductFamily': $($result.Count) applicable out of $totalInput"
        return @($result)
    }
}
function Select-AdvisoryByComponent {

    <#
        .SYNOPSIS
        Select advisories affecting one or more specific components.

        .DESCRIPTION
        Returns advisories that contain at least one component entry whose component name
        matches any of the supplied names. Component names must match the canonical values
        in the Component Registry (see ADVISORY_SCHEMA.md). Matching is case-sensitive to
        align with the registry.

        .PARAMETER Advisories
        Array of advisory objects as returned by Get-SecurityAdvisory.

        .PARAMETER Component
        One or more canonical component names to filter on (e.g. 'ESXi', 'vCenter', 'NSX').

        .EXAMPLE
        $advisories = Get-SecurityAdvisory -FilePath $advisoryFilePath
        $esxiAdvisories = Select-AdvisoryByComponent -Advisories $advisories -Component 'ESXi'

        .EXAMPLE
        $infraAdvisories = Select-AdvisoryByComponent -Advisories $advisories -Component 'ESXi', 'vCenter', 'NSX'

        .OUTPUTS
        [PSCustomObject[]] Advisories that contain at least one of the requested components.

        .NOTES
        Supports pipeline input via $Advisories. Logs the total input count and output count at INFO level.
        Uses case-sensitive component name comparison to align with the Component Registry.
    #>

    [CmdletBinding()]
    [OutputType([Object[]])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)] [ValidateNotNull()] [Object[]]$Advisories,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String[]]$Component
    )

    begin {
        $result = [System.Collections.Generic.List[PSCustomObject]]::new()
        $totalInput = 0
    }
    process {
        foreach ($advisory in $Advisories) {
            $totalInput++
            try {
                $validatedAdvisory = ConvertFrom-AdvisoryDocument -Advisory $advisory
            }
            catch {
                Write-LogMessage -Type WARNING -Message "Skipping invalid advisory: $($_.Exception.Message)"
                continue
            }
            foreach ($comp in @($validatedAdvisory.impactedComponents)) {
                if ($Component -contains [String]$comp.component) {
                    $result.Add($validatedAdvisory)
                    break
                }
            }
        }
    }
    end {
        $componentList = $Component -join ', '
        Write-LogMessage -Type INFO -Message "Filtered advisories for component(s) [$componentList]: $($result.Count) applicable out of $totalInput"
        return @($result)
    }
}

#endregion
