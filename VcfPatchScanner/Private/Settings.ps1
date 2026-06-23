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

#region Settings Management

function Get-PatchScanSettings {

    <#
        .SYNOPSIS
        Load patch scan settings from file.

        .DESCRIPTION
        Loads settings from a JSON file. If no SettingsFile is provided, uses the default
        'scan-settings.json' in the module root directory.

        .PARAMETER SettingsFile
        Path to settings file (absolute or relative to module root). Optional.

        .EXAMPLE
        $settings = Get-PatchScanSettings
        $settings = Get-PatchScanSettings -SettingsFile "custom-settings.json"

        .OUTPUTS
        [PSCustomObject] Settings object with properties: environments, findingsOutputDirectory, etc.

        .NOTES
        Returns a default settings structure when the file is absent — does not throw. Callers should check Environments array to detect a first-run state.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SettingsFile
    )

    $moduleRoot = Split-Path -Parent $PSScriptRoot
    $resolvedPath = if ([String]::IsNullOrWhiteSpace($SettingsFile)) {
        if ([String]::IsNullOrWhiteSpace($env:VcfPatchScannerBaseDirectory)) {
            $err = "$($Script:VCF_PATCH_SCANNER_ENV_VAR) is not set. Run Initialize-VcfPatchScanner before using the scanner."
            Write-LogMessage -Type ERROR -Message $err
            throw [System.InvalidOperationException]::new($err)
        }
        $baseTrimmed = $env:VcfPatchScannerBaseDirectory.Trim()
        $candidate = Join-Path -Path $baseTrimmed -ChildPath $Script:SCAN_CONFIG_DIR_NAME -AdditionalChildPath $Script:SCAN_SETTINGS_FILE_NAME
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $err = "Settings file not found at '$candidate'. Re-run Initialize-VcfPatchScanner to recreate it."
            Write-LogMessage -Type ERROR -Message $err
            throw [System.InvalidOperationException]::new($err)
        }
        $candidate
    } else {
        if ($SettingsFile -match '[/\\]\.\.[/\\]' -or $SettingsFile -match '[/\\]\.\.$') {
            throw [System.InvalidOperationException]::new("Settings file path contains invalid traversal sequences: $SettingsFile")
        }

        if ([System.IO.Path]::IsPathRooted($SettingsFile)) {
            $SettingsFile
        } else {
            Join-Path -Path $moduleRoot -ChildPath $SettingsFile
        }
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new("Settings file not found: $resolvedPath")
    }

    $fileInfo = Get-Item -LiteralPath $resolvedPath
    $maxSizeBytes = 5MB
    if ($fileInfo.Length -gt $maxSizeBytes) {
        throw [System.InvalidOperationException]::new("Settings file is too large ($([Math]::Round($fileInfo.Length / 1MB, 2)) MB) — the maximum is $($maxSizeBytes / 1MB) MB.")
    }

    try {
        $content = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop
        $settings = ConvertFrom-Json -InputObject $content -Depth $Script:JSON_PARSE_MAX_DEPTH -ErrorAction Stop
        return $settings
    }
    catch {
        throw [System.InvalidOperationException]::new("Failed to load settings from $resolvedPath`: $($_.Exception.Message)", $_.Exception)
    }
}

function Set-PatchScanSettings {

    <#
        .SYNOPSIS
        Save patch scan settings to file.

        .DESCRIPTION
        Saves settings object to a JSON file. Creates the file if it doesn't exist.
        Overwrites existing file if it does.

        .PARAMETER Settings
        Settings object to save.

        .PARAMETER OutputPath
        Path where settings file should be written (absolute or relative to module root).
        Default: scan-settings.json in module root.

        .EXAMPLE
        $settings = New-PatchScanEnvironmentTemplate
        Set-PatchScanSettings -Settings $settings -OutputPath "custom-settings.json"

        .OUTPUTS
        None

        .NOTES
        Writes settings atomically via a temp file in the same directory followed by a rename.
        The temp file is removed on failure. Creates the output directory when absent.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [PSCustomObject]$Settings,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$OutputPath
    )

    $moduleRoot = Split-Path -Parent $PSScriptRoot
    $resolvedPath = if ([String]::IsNullOrWhiteSpace($OutputPath)) {
        Join-Path -Path $moduleRoot -ChildPath "scan-settings.json"
    }
    else {
        if ([System.IO.Path]::IsPathRooted($OutputPath)) {
            $OutputPath
        }
        else {
            Join-Path -Path $moduleRoot -ChildPath $OutputPath
        }
    }

    $tempPath = $null

    try {
        $directory = [System.IO.Path]::GetDirectoryName($resolvedPath)
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        $json     = $Settings | ConvertTo-Json -Depth $Script:JSON_SERIALIZE_DEPTH -ErrorAction Stop
        $tempPath = Join-Path -Path $directory -ChildPath "settings_$(New-Guid).tmp"

        # Atomic write: temp file in same directory + rename so readers never see a partial file.
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBom)
        Move-Item -LiteralPath $tempPath -Destination $resolvedPath -Force
        $tempPath = $null

        Write-LogMessage -Type INFO -Message "Settings saved to $resolvedPath"
    }
    catch {
        if ($null -ne $tempPath -and (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw [System.IO.IOException]::new("Failed to save settings to $resolvedPath`: $($_.Exception.Message)", $_.Exception)
    }
}

function New-PatchScanEnvironmentTemplate {

    <#
        .SYNOPSIS
        Generate a blank patch scan settings template.

        .DESCRIPTION
        Creates a template settings object with default values and empty environment array.
        Useful for programmatic settings creation or as a starting point for manual editing.

        .EXAMPLE
        $settings = New-PatchScanEnvironmentTemplate
        $settings.environments += @{ name = "prod"; type = "vcf9"; sddcManagerServer = "sddc.example.com"; ... }
        Set-PatchScanSettings -Settings $settings

        .OUTPUTS
        [PSCustomObject] Template settings object

        .NOTES
        Returns a template with placeholder strings. Callers must replace all placeholder values before passing to Set-PatchScanSettings.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param ()

    $template = [PSCustomObject]@{
        environments = @()
        findingsOutputDirectory = "findings"
        logDirectory = "Logs"
        logLevel = "INFO"
        securityAdvisoryFile = "Data/securityAdvisory.json"
        ignoreCertificate = $true
        connectionTimeoutSeconds = 30
        lightMode = $true
        sddcManagerServer = ""
        sddcManagerUser = ""
        vcfFMServer = ""
        vcfFMUser = ""
        vcfMajorVersion = "9"
        vcfOpsServer = ""
        vcfOpsUser = ""
    }

    return $template
}

function New-PatchScanEnvironment {

    <#
        .SYNOPSIS
        Create a new environment configuration object.

        .DESCRIPTION
        Builds a PSCustomObject representing a single scannable environment. The object
        is consumed by Invoke-VCFPatchScanner and can be persisted via Set-PatchScanSettings.
        Required parameters depend on the environment type: vcf9 requires VcfOpsServer and
        VcfOpsUser; vcf5 and vcf9 require SddcManagerServer and SddcManagerUser; vsphere8
        and vvf9 require VcenterServer and VcenterUser. NsxManagerServer and NsxManagerUser
        are optional for vsphere8 and required for vvf9. VrslcmServer and VrslcmUser are
        optional for vcf5.

        .PARAMETER Name
        Display name for the environment.

        .PARAMETER Type
        Environment type: vcf5, vcf9, vsphere8, or vvf9.

        .PARAMETER SddcManagerServer
        SDDC Manager FQDN or IP (required for vcf5, vcf9).

        .PARAMETER SddcManagerInstanceName
        Human-readable VCF instance name (e.g. "San Francisco") discovered from VCF Operations.
        Stamped onto all VCF 9 inventory items so findings can be grouped by instance. VCF 9 only.

        .PARAMETER SddcManagerUser
        SDDC Manager username (required for vcf5, vcf9).

        .PARAMETER VcfOpsServer
        VCF Operations server FQDN or IP (VCF 9 only).

        .PARAMETER VcfOpsUser
        VCF Operations username (VCF 9 only).

        .PARAMETER VcfFMServer
        Fleet Manager / Ops Fleet Manager FQDN or IP (VCF 9 only).

        .PARAMETER VcfFMUser
        Fleet Manager / Ops Fleet Manager username (VCF 9 only).

        .PARAMETER VcenterServer
        vCenter FQDN or IP (vsphere8, vvf9 only).

        .PARAMETER VcenterUser
        vCenter username (vsphere8, vvf9 only).

        .EXAMPLE
        $env = New-PatchScanEnvironment -Name "Production" -Type vcf9 -SddcManagerServer "sddc.example.com" -SddcManagerUser "admin@vsphere.local"

        .OUTPUTS
        [PSCustomObject] Environment configuration

        .NOTES
        Validates required fields before appending. Throws [System.ArgumentException] on missing or duplicate environment name.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)]  [ValidateNotNullOrEmpty()] [String]$Name,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$NsxManagerServer,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$NsxManagerUser,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$SddcManagerInstanceName = '',
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SddcManagerServer,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SddcManagerUser,
        [Parameter(Mandatory = $true)]  [ValidateSet('vcf5', 'vcf9', 'vsphere8', 'vvf9')] [String]$Type,
        [Parameter(Mandatory = $false)] [Switch]$UseSinglePassword,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcenterServer,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcenterUser,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfFMServer,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfFMUser,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfOpsServer,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfOpsUser,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VrslcmServer,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VrslcmUser
    )

    $env = [PSCustomObject]@{
        name = $Name.Trim()
        type = $Type
        id = [System.Guid]::NewGuid().ToString()
        useSinglePassword = $UseSinglePassword.IsPresent
    }

    if (-not [String]::IsNullOrWhiteSpace($NsxManagerServer)) {
        $env | Add-Member -NotePropertyName nsxManagerServer -NotePropertyValue $NsxManagerServer.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($NsxManagerUser)) {
        $env | Add-Member -NotePropertyName nsxManagerUser -NotePropertyValue $NsxManagerUser.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($SddcManagerInstanceName)) {
        $env | Add-Member -NotePropertyName sddcManagerInstanceName -NotePropertyValue $SddcManagerInstanceName.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($SddcManagerServer)) {
        $env | Add-Member -NotePropertyName sddcManagerServer -NotePropertyValue $SddcManagerServer.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($SddcManagerUser)) {
        $env | Add-Member -NotePropertyName sddcManagerUser -NotePropertyValue $SddcManagerUser.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VcenterServer)) {
        $env | Add-Member -NotePropertyName vcenterServer -NotePropertyValue $VcenterServer.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VcenterUser)) {
        $env | Add-Member -NotePropertyName vcenterUser -NotePropertyValue $VcenterUser.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VcfFMServer)) {
        $env | Add-Member -NotePropertyName vcfFMServer -NotePropertyValue $VcfFMServer.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VcfFMUser)) {
        $env | Add-Member -NotePropertyName vcfFMUser -NotePropertyValue $VcfFMUser.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VcfOpsServer)) {
        $env | Add-Member -NotePropertyName vcfOpsServer -NotePropertyValue $VcfOpsServer.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VcfOpsUser)) {
        $env | Add-Member -NotePropertyName vcfOpsUser -NotePropertyValue $VcfOpsUser.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VrslcmServer)) {
        $env | Add-Member -NotePropertyName vrslcmServer -NotePropertyValue $VrslcmServer.Trim()
    }
    if (-not [String]::IsNullOrWhiteSpace($VrslcmUser)) {
        $env | Add-Member -NotePropertyName vrslcmUser -NotePropertyValue $VrslcmUser.Trim()
    }

    return $env
}

#endregion
