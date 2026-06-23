<#
    .SYNOPSIS
    Command-line entry point for the VcfPatchScanner module, invoked by Start-VCFPatchScannerServer.py.

    .DESCRIPTION
    Accepts environment and credential parameters from the Python web UI server, initializes
    the VcfPatchScanner module, and dispatches to one of four operating modes:
      - Discovery (DiscoverSddcManagers / DiscoverFleetManager): outputs JSON to stdout, exits.
      - Credential validation (ValidateCredentialsOnly): outputs JSON to stdout, exits.
      - Full vulnerability scan: runs Invoke-VCFPatchScanner, writes findings JSON, exits.

    Credentials are never passed as CLI arguments. They are read from environment variables
    set by the Python server from the allowlist-filtered subprocess environment:
      SDDC_MANAGER_PASSWORD, VCF_OPS_PASSWORD, VCF_FM_PASSWORD, VCENTER_PASSWORD,
      NSX_MANAGER_PASSWORD (vsphere8/vvf9 only — vcf5 retrieves it via SDDC Manager API),
      VRSLCM_PASSWORD.

    .PARAMETER VcfMajorVersion
    Environment type. One of: vcf5, vcf9, vsphere8, vvf9.

    .PARAMETER LogLevel
    PowerShell log level forwarded to Initialize-PatchScanLogging. Default: INFO.

    .PARAMETER LogDirectory
    Absolute path to the log directory. When empty the module uses its default.

    .PARAMETER SecurityAdvisoryFile
    Path to the security advisory reference JSON. Default: Data/securityAdvisory.json.

    .PARAMETER FindingsOutputPath
    Absolute path where the findings JSON file is written by the scan.

    .PARAMETER ConnectionTimeoutSeconds
    Per-endpoint connection timeout in seconds. Range 1-900. Default: 30.

    .PARAMETER DiscoverFleetManager
    When set, discovers the Fleet Manager FQDN from VCF Operations and exits.

    .PARAMETER DiscoverVrslcm
    When set, queries SDDC Manager GET /v1/vrslcms for a registered vRSLCM instance and
    outputs JSON to stdout, then exits. VCF 5.x only.

    .PARAMETER VcfOpsVersion
    VCF Operations version string (e.g. "VCF Operations 9.1.0.0"). When provided, the
    Fleet Manager discovery selects the version-appropriate API: 9.1+ uses the Suite API
    internal components endpoint; 9.0 uses the CASA capabilities endpoint.

    .PARAMETER FetchSddcCredential
    When set, retrieves the SDDC Manager username and password from the Fleet Manager locker
    (VCF 9.0 LCops Fleet Manager only) and outputs JSON to stdout, then exits.

    .PARAMETER DiscoverSddcManagers
    When set, discovers SDDC Manager FQDNs from VCF Operations and exits.

    .PARAMETER EnvironmentDisplayName
    Human-readable label for this environment. ANSI escape codes and control characters
    are stripped before use to prevent log injection.

    .PARAMETER FailedEndpointFqdns
    JSON array string of FQDNs to re-inventory (retry-failed-only mode). Only valid RFC 1123
    hostnames are accepted; invalid entries are silently dropped.

    .PARAMETER IgnoreInvalidCertificate
    When set, TLS certificate validation is skipped for all endpoint connections.

    .PARAMETER RetryFailedEndpointsOnly
    When set with FailedEndpointFqdns, restricts inventory to the listed endpoints.

    .PARAMETER ValidateCredentialsOnly
    When set, tests credentials for all configured endpoints and outputs JSON, then exits.

    .PARAMETER SddcManagerInstanceName
    Human-readable VCF 9 instance name (e.g. "San Francisco") discovered from VCF Operations.
    Stamped onto all VCF 9 inventory items so findings can be grouped by instance.

    .PARAMETER SddcManagerServer
    SDDC Manager FQDN or IP. Required for vcf5 and vcf9.

    .PARAMETER SddcManagerUser
    SDDC Manager username. Required for vcf5 and vcf9.

    .PARAMETER VrslcmServer
    vRealize Suite Lifecycle Manager FQDN. Optional for vcf5.

    .PARAMETER VrslcmUser
    vRealize Suite Lifecycle Manager username. Optional for vcf5.

    .PARAMETER VcfOpsServer
    VCF Operations FQDN. Required for vcf9.

    .PARAMETER VcfOpsUser
    VCF Operations username. Required for vcf9.

    .PARAMETER VcfFMServer
    VCF Fleet Manager / Fleet Lifecycle Manager FQDN. Required for vcf9.

    .PARAMETER VcfFMUser
    VCF Fleet Manager / Fleet Lifecycle Manager username. Required for vcf9.

    .PARAMETER VcfMinorVersion
    VCF minor version string (e.g. "9.1"). Optional; used to label Fleet Manager endpoints
    correctly in validation results when the auth path cannot determine the version automatically.

    .PARAMETER VcenterServer
    vCenter Server FQDN. Required for vsphere8 and vvf9.

    .PARAMETER VcenterUser
    vCenter username. Required for vsphere8 and vvf9.

    .PARAMETER NsxManagerServer
    NSX Manager FQDN. Required for vvf9; optional for vsphere8.

    .PARAMETER NsxManagerUser
    NSX Manager username. Required when NsxManagerServer is configured.

    .EXAMPLE
    pwsh -NonInteractive -File Invoke-VCFPatchScanner.ps1 -VcfMajorVersion vcf9 -SddcManagerServer sddc.corp.local -SddcManagerUser administrator@vsphere.local

    .EXAMPLE
    pwsh -NonInteractive -File Invoke-VCFPatchScanner.ps1 -DiscoverSddcManagers -VcfOpsServer ops.corp.local -VcfOpsUser admin@local -LogLevel WARNING

    .NOTES
    This script is the contract boundary between Start-VCFPatchScannerServer.py and the
    VcfPatchScanner PowerShell module. Changes to parameter names must be reflected in the
    Python server's _ENV_TYPE_FIELDS and _build_ps_args dictionaries.
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)] [ValidateRange(1, 900)] [Int]$ConnectionTimeoutSeconds = 30,
    [Parameter(Mandatory = $false)] [Switch]$DiscoverFleetManager,
    [Parameter(Mandatory = $false)] [Switch]$DiscoverSddcManagers,
    [Parameter(Mandatory = $false)] [Switch]$DiscoverVrslcm,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$EnvironmentDisplayName,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$FailedEndpointFqdns,
    [Parameter(Mandatory = $false)] [Switch]$FetchSddcCredential,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$FindingsOutputPath,
    [Parameter(Mandatory = $false)] [Switch]$IgnoreInvalidCertificate,
    [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$LogDirectory = '',
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$LogLevel = 'INFO',
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$NsxManagerServer,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$NsxManagerUser,
    [Parameter(Mandatory = $false)] [Switch]$RetryFailedEndpointsOnly,
    [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$SddcManagerInstanceName = '',
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SddcManagerServer,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SddcManagerUser,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$SecurityAdvisoryFile = 'Data/securityAdvisory.json',
    [Parameter(Mandatory = $false)] [Switch]$ValidateCredentialsOnly,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcenterBuildMapFile,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcenterServer,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcenterUser,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfFMServer,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfFMUser,
    [Parameter(Mandatory = $false)] [ValidateSet('vcf5', 'vcf9', 'vsphere8', 'vvf9')] [String]$VcfMajorVersion,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfMinorVersion,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfOpsServer,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfOpsUser,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VcfOpsVersion,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VrslcmServer,
    [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$VrslcmUser
)

# Suppress PSStyle ANSI escape codes so stderr captured by the server is plain text.
# $PSStyle is available in PowerShell 7.2+; the guard makes this a no-op on older versions.
if ($null -ne $PSStyle) { $PSStyle.OutputRendering = 'PlainText' }

# Validate required environment variable before importing the module — fail fast with a
# clear setup message rather than allowing the module to silently write to a null location.
if ([String]::IsNullOrWhiteSpace($env:VcfPatchScannerBaseDirectory)) {
    Write-Host "ERROR: VcfPatchScannerBaseDirectory is not set. Run Initialize-VcfPatchScanner before using the scanner." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $env:VcfPatchScannerBaseDirectory.Trim() -PathType Container)) {
    Write-Host "ERROR: VcfPatchScannerBaseDirectory points to a path that does not exist: '$($env:VcfPatchScannerBaseDirectory.Trim())'. Re-run Initialize-VcfPatchScanner." -ForegroundColor Red
    exit 1
}

# Import the module.
# Prefer the path injected by Start-VCFPatchScannerServer.py (VCFPATCHSCANNER_MODULE_PSD1), which is
# always correct regardless of where the Tools directory is deployed.  Fall back to the path
# relative to this script for direct invocation (e.g. development or testing).
$envModulePsd1 = ([String]$env:VCFPATCHSCANNER_MODULE_PSD1).Trim()
if (-not [String]::IsNullOrWhiteSpace($envModulePsd1) -and (Test-Path -LiteralPath $envModulePsd1 -PathType Leaf)) {
    $modulePath = $envModulePsd1
} else {
    $modulePath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'VcfPatchScanner.psd1'
}
try {
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}
catch {
    if ($ValidateCredentialsOnly -or $DiscoverSddcManagers -or $DiscoverFleetManager -or $DiscoverVrslcm -or $FetchSddcCredential) {
        # Write-Output (stdout) rather than Write-Host (information stream) so the Python
        # server can read this message; stdout=PIPE does not capture Write-Host output.
        @{ instances = @(); opsVersion = ""; vcenterFqdns = @(); error = "The server could not load its module. Run Initialize-VcfPatchScanner and restart the server. (Detail: $($_.Exception.Message))" } | ConvertTo-Json -Compress
        exit 1
    }
    throw
}

# Guard against an older module version that pre-dates functions required by this script.
# When VCFPATCHSCANNER_MODULE_PSD1 points to a stale PSModulePath installation the module
# loads successfully (no Import-Module error) but the function is absent — producing an
# opaque CommandNotFoundException in the UI.  Detect the mismatch here and emit a clear,
# actionable JSON error instead.
$requiredDiscoveryFunctions = @(
    'Get-SddcManagerListFromVcfOps'
    'Get-FleetManagerFromVcfOps'
    'Get-SddcCredentialFromFleetManager'
    'Initialize-PatchScanLogging'
)
$missingFunctions = $requiredDiscoveryFunctions | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) }
if ($missingFunctions) {
    $missingList = $missingFunctions -join ', '
    $outOfDateMsg = "The server installation is outdated. Please run Initialize-VcfPatchScanner to update, then restart the server."
    if ($ValidateCredentialsOnly -or $DiscoverSddcManagers -or $DiscoverFleetManager -or $DiscoverVrslcm -or $FetchSddcCredential) {
        @{ instances = @(); opsVersion = ""; vcenterFqdns = @(); error = $outOfDateMsg } | ConvertTo-Json -Compress
        exit 1
    }
    throw [System.InvalidOperationException]::new($outOfDateMsg)
}

# Strip ANSI CSI sequences, OSC sequences, null bytes, carriage returns, and JSON-unsafe
# characters from the display name before it reaches log lines, findings JSON, or filenames.
if ([String]::IsNullOrWhiteSpace($EnvironmentDisplayName)) {
    $sanitizedDisplayName = "Scan-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
} else {
    $sanitizedDisplayName = $EnvironmentDisplayName `
        -replace '\x1b\[[0-9;]*[a-zA-Z]', '' `
        -replace '\x1b\][^\x07\x1b]*(\x07|\x1b\\)', '' `
        -replace '[\x00\r]', '' `
        -replace '[\\"]', ''
    $sanitizedDisplayName = $sanitizedDisplayName.Trim()
    if ([String]::IsNullOrWhiteSpace($sanitizedDisplayName)) {
        $sanitizedDisplayName = "Scan-$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
}

# Discovery-only switches exit before anything needs $envConfig, so skip building it.
# ValidateCredentialsOnly and scan paths always receive -VcfMajorVersion from the Python server.
$isDiscoveryOnly = $DiscoverSddcManagers -or $DiscoverFleetManager -or $DiscoverVrslcm -or $FetchSddcCredential

if (-not $isDiscoveryOnly) {
    if ([String]::IsNullOrWhiteSpace($VcfMajorVersion)) {
        Write-Host "ERROR: -VcfMajorVersion is required for scan and credential-validation operations. Valid values: vcf5, vcf9, vsphere8, vvf9." -ForegroundColor Red
        exit 1
    }

    $configParams = @{
        Name = $sanitizedDisplayName
        Type = $VcfMajorVersion
    }

    # Add VCF 5/9 parameters
    if (-not [String]::IsNullOrWhiteSpace($SddcManagerInstanceName)) { $configParams['SddcManagerInstanceName'] = $SddcManagerInstanceName }
    if ($SddcManagerServer) { $configParams['SddcManagerServer'] = $SddcManagerServer }
    if ($SddcManagerUser)   { $configParams['SddcManagerUser']   = $SddcManagerUser }

    # Add VCF 5.x optional parameters
    if ($VrslcmServer) { $configParams['VrslcmServer'] = $VrslcmServer }
    if ($VrslcmUser)   { $configParams['VrslcmUser']   = $VrslcmUser }

    # Add VCF 9 parameters
    if ($VcfOpsServer) { $configParams['VcfOpsServer'] = $VcfOpsServer }
    if ($VcfOpsUser)   { $configParams['VcfOpsUser']   = $VcfOpsUser }
    if ($VcfFMServer)  { $configParams['VcfFMServer']  = $VcfFMServer }
    if ($VcfFMUser)    { $configParams['VcfFMUser']    = $VcfFMUser }

    # Add vSphere/VVF parameters
    if ($VcenterServer)    { $configParams['VcenterServer']    = $VcenterServer }
    if ($VcenterUser)      { $configParams['VcenterUser']      = $VcenterUser }
    if ($NsxManagerServer) { $configParams['NsxManagerServer'] = $NsxManagerServer }
    if ($NsxManagerUser)   { $configParams['NsxManagerUser']   = $NsxManagerUser }

    try {
        $envConfig = New-PatchScanEnvironment @configParams
    }
    catch {
        # A ParameterBindingException here means Invoke-VCFPatchScanner.ps1 passed a parameter
        # that New-PatchScanEnvironment does not declare — a code defect, not a user error.
        Write-Host "ERROR: Environment configuration failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Discover SDDC Manager FQDNs via VCF Operations and output JSON to stdout.
# $InformationPreference silences Write-Host (which Write-LogMessage uses) so that
# stdout contains only the JSON result line. Diagnostics still go to the log file.
if ($DiscoverSddcManagers) {
    $InformationPreference = 'SilentlyContinue'
    Initialize-PatchScanLogging -LogLevel $LogLevel -LogDirectory $LogDirectory | Out-Null
    try {
        $discoveryResult = Get-SddcManagerListFromVcfOps -VcfOpsServer $VcfOpsServer -VcfOpsUser $VcfOpsUser -TimeoutSeconds $ConnectionTimeoutSeconds
        $instanceList = @($discoveryResult.Instances | ForEach-Object {
            @{ fqdn = $_.Fqdn; instanceName = $_.InstanceName; sddcUsername = $_.SddcUsername }
        })
        @{
            instances    = $instanceList
            opsVersion   = $discoveryResult.OpsVersion
            vcenterFqdns = @($discoveryResult.VcenterFqdns)
            error        = $null
        } | ConvertTo-Json -Compress -Depth 3
        exit 0
    }
    catch {
        @{ instances = @(); opsVersion = ""; vcenterFqdns = @(); error = $_.Exception.Message } | ConvertTo-Json -Compress
        exit 1
    }
}

# Retrieve SDDC Manager credential from the Fleet Manager locker (VCF 9.0 only).
if ($FetchSddcCredential) {
    $InformationPreference = 'SilentlyContinue'
    Initialize-PatchScanLogging -LogLevel $LogLevel -LogDirectory $LogDirectory | Out-Null
    try {
        $result = Get-SddcCredentialFromFleetManager -FmServer $VcfFMServer -TimeoutSeconds $ConnectionTimeoutSeconds
        @{ sddcUsername = $result.SddcUsername; sddcPassword = $result.SddcPassword; error = $null } | ConvertTo-Json -Compress
        exit 0
    }
    catch {
        @{ sddcUsername = $null; sddcPassword = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
        exit 1
    }
}

# Discover Fleet Manager FQDN from VCF Operations 9.1 and output JSON to stdout.
# Available on VCF Operations 9.1+; returns an error for 9.0 (no VSP component registered).
if ($DiscoverFleetManager) {
    $InformationPreference = 'SilentlyContinue'
    Initialize-PatchScanLogging -LogLevel $LogLevel -LogDirectory $LogDirectory | Out-Null
    try {
        $fmResult = Get-FleetManagerFromVcfOps -VcfOpsServer $VcfOpsServer -VcfOpsUser $VcfOpsUser `
            -TimeoutSeconds $ConnectionTimeoutSeconds `
            -VcfOpsVersion ($VcfOpsVersion ?? '')
        @{ fleetFqdn = $fmResult.FleetFqdn; vcfFMUser = $fmResult.VcfFMUser; error = $null } | ConvertTo-Json -Compress
        exit 0
    }
    catch {
        @{ fleetFqdn = $null; vcfFMUser = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
        exit 1
    }
}

# Discover vRSLCM FQDN registered with SDDC Manager (VCF 5.x only) and output JSON to stdout.
if ($DiscoverVrslcm) {
    $InformationPreference = 'SilentlyContinue'
    Initialize-PatchScanLogging -LogLevel $LogLevel -LogDirectory $LogDirectory | Out-Null
    try {
        $vrslcmResult = Get-VrslcmFromSddcManager -Server $SddcManagerServer -User $SddcManagerUser `
            -TimeoutSeconds $ConnectionTimeoutSeconds
        @{
            vrslcmFqdn    = $vrslcmResult.VrslcmFqdn
            vrslcmVersion = $vrslcmResult.VrslcmVersion
            error         = $vrslcmResult.Error
        } | ConvertTo-Json -Compress
        exit 0
    }
    catch {
        @{ vrslcmFqdn = $null; vrslcmVersion = ""; error = $_.Exception.Message } | ConvertTo-Json -Compress
        exit 1
    }
}

# Validate credentials for all configured endpoints and exit with 0 (success) or 1 (failure).
# Suppress Write-Host output so stdout carries only the JSON result line (same pattern as DiscoverSddcManagers).
if ($ValidateCredentialsOnly) {
    $InformationPreference = 'SilentlyContinue'
    Initialize-PatchScanLogging -LogLevel $LogLevel -LogDirectory $LogDirectory | Out-Null
    Write-LogMessage -Type INFO -Message "Running in validation-only mode"
    try {
        $connParams = @{ EnvironmentType = $VcfMajorVersion; TimeoutSeconds = $ConnectionTimeoutSeconds }
        if ($SddcManagerServer) { $connParams['SddcManagerServer'] = $SddcManagerServer }
        if ($SddcManagerUser)   { $connParams['SddcManagerUser']   = $SddcManagerUser }
        if ($VrslcmServer)      { $connParams['VrslcmServer']      = $VrslcmServer }
        if ($VrslcmUser)        { $connParams['VrslcmUser']        = $VrslcmUser }
        if ($VcfOpsServer)      { $connParams['VcfOpsServer']      = $VcfOpsServer }
        if ($VcfOpsUser)        { $connParams['VcfOpsUser']        = $VcfOpsUser }
        if ($VcfFMServer)       { $connParams['VcfFMServer']       = $VcfFMServer }
        if ($VcfFMUser)         { $connParams['VcfFMUser']         = $VcfFMUser }
        if ($VcfMinorVersion)   { $connParams['VcfMinorVersion']   = $VcfMinorVersion }
        if ($VcenterServer)     { $connParams['VcenterServer']     = $VcenterServer }
        if ($VcenterUser)       { $connParams['VcenterUser']       = $VcenterUser }
        if ($NsxManagerServer)  { $connParams['NsxManagerServer']  = $NsxManagerServer }
        if ($NsxManagerUser)    { $connParams['NsxManagerUser']    = $NsxManagerUser }
        $connResult = Test-PatchScanConnection @connParams
        $connResult | ConvertTo-Json -Depth 3 -Compress
        exit ([Int](-not $connResult.Success))
    }
    catch {
        Write-LogMessage -Type ERROR -Message "Validation error: $($_.Exception.Message)"
        Write-LogMessage -Type DEBUG -Message "Exception type: $($_.Exception.GetType().FullName)"
        exit 1
    }
}

# Run the vulnerability scan
Initialize-PatchScanLogging -LogLevel $LogLevel -LogDirectory $LogDirectory | Out-Null

$scanParams = @{
    AdvisoryPath      = $SecurityAdvisoryFile
    EnvironmentConfig = [PSCustomObject]$envConfig
    EnvironmentType   = $VcfMajorVersion
    TimeoutSeconds    = $ConnectionTimeoutSeconds
    UseLiveInventory  = $true
}
if (-not [String]::IsNullOrWhiteSpace($VcenterBuildMapFile)) {
    $scanParams['VcenterBuildMapFile'] = $VcenterBuildMapFile
}

# Use provided findings path or default
if (-not [String]::IsNullOrWhiteSpace($FindingsOutputPath)) {
    $scanParams['FindingsOutputPath'] = $FindingsOutputPath
}

# Retry-failed-only: restrict inventory to the previously failed FQDNs.
if ($RetryFailedEndpointsOnly -and -not [String]::IsNullOrWhiteSpace($FailedEndpointFqdns)) {
    try {
        $parsedFqdns = @($FailedEndpointFqdns | ConvertFrom-Json)
        # Accept only valid RFC 1123 hostnames to prevent an adversary-crafted findings
        # file from injecting arbitrary connection targets into the retry list.
        $fqdnPattern = '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        $fqdnArray = @($parsedFqdns | Where-Object { $_ -match $fqdnPattern })
        if ($fqdnArray.Count -gt 0) {
            $scanParams['IncludeOnlyFqdns'] = [String[]]$fqdnArray
            Write-LogMessage -Type INFO -Message "Retry-failed-only mode: scanning $($fqdnArray.Count) endpoint(s): $($fqdnArray -join ', ')"
        }
    }
    catch {
        Write-LogMessage -Type WARNING -Message "Could not parse FailedEndpointFqdns JSON; running full scan instead: $($_.Exception.Message)"
    }
}

$result = Invoke-VCFPatchScanner @scanParams

# Exit with the result code
exit $result.ExitCode
