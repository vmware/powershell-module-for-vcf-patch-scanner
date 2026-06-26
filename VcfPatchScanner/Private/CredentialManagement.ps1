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

#region Credential Management

function New-SecretReferenceName {

    <#
        .SYNOPSIS
        Generate a standardized secret reference name from environment and endpoint details.

        .DESCRIPTION
        Builds a secret reference name using the format:
        {ENVIRONMENT_NAME}_{ENDPOINT_TYPE}_{INSTANCE_NUMBER}_PASSWORD

        Environment names are normalized: hyphens converted to underscores, forced uppercase.
        This ensures consistent, deterministic naming for secret lookups at runtime.

        .PARAMETER EnvironmentName
        Name of the environment (e.g., 'prod-us-west'). Normalized to uppercase with underscores.

        .PARAMETER EndpointType
        Type of endpoint (e.g., 'sddc_manager', 'vcf_ops'). Normalized to uppercase.

        .PARAMETER InstanceNumber
        Instance number if multiple endpoints of the same type exist in one environment (default: 1).
        Used only when the environment defines multiple instances; otherwise omitted.

        .EXAMPLE
        New-SecretReferenceName -EnvironmentName 'prod-us-west' -EndpointType 'sddc_manager'
        # Returns: "PROD_US_WEST_SDDC_MANAGER_1_PASSWORD"

        New-SecretReferenceName -EnvironmentName 'lab-vcf5' -EndpointType 'vrslcm' -InstanceNumber 1
        # Returns: "LAB_VCF5_VRSLCM_1_PASSWORD"

        .OUTPUTS
        [String] — the generated secret reference name.

        .NOTES
        Used internally to generate the password_secret_ref values in environments.json.
        Also used by the Python server when setting environment variables.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$EnvironmentName,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$EndpointType,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 99)] [Int]$InstanceNumber = 1
    )

    $envNormalized = ($EnvironmentName -replace '-', '_').ToUpper()
    $typeNormalized = ($EndpointType -replace '-', '_').ToUpper()
    return "${envNormalized}_${typeNormalized}_${InstanceNumber}_PASSWORD"
}
function Resolve-SecretReference {

    <#
        .SYNOPSIS
        Resolve a secret reference with graceful fallback to interactive prompt.

        .DESCRIPTION
        Attempts to retrieve a secret in this order:
        1. Microsoft.PowerShell.SecretStore (if installed)
        2. Environment variable
        3. Interactive prompt (if running interactively and terminal allows input)
        4. Error (if non-interactive and secret not found)

        Allows users to run fully operational scans without installing SecretStore,
        just by entering passwords when prompted. No setup required beyond running the script.

        .PARAMETER SecretRef
        Secret reference name (e.g., 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD').

        .PARAMETER EnvironmentName
        Environment name (used in interactive prompts for context). Example: 'prod-us-west'.

        .PARAMETER EndpointType
        Endpoint type (used in interactive prompts for context). Example: 'sddc_manager'.

        .PARAMETER AllowInteractivePrompt
        When present, allows interactive password prompts when a credential cannot be resolved
        from SecretStore or environment variables. When absent, all credentials must exist in
        SecretStore or as environment variables.

        .EXAMPLE
        # Non-interactive (CI/CD) — fails if secret not found
        $password = Resolve-SecretReference -SecretRef 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD' -AllowInteractivePrompt:$false

        # Interactive (local) — prompts if secret not found
        $password = Resolve-SecretReference -SecretRef 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD' `
            -EnvironmentName 'prod-us-west' -EndpointType 'sddc_manager'

        .OUTPUTS
        [String] — plaintext password.

        .NOTES
        Returns $null only when:
        - AllowInteractivePrompt=$false AND secret not found in SecretStore/env
        Otherwise throws an exception or prompts the user.

        Interactive prompts are only available when:
        - Running in a PowerShell console (not pwsh -NonInteractive)
        - $host.UI.PromptForCredential is available
        - Terminal allows read input
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$SecretRef,
        [Parameter(Mandatory = $false)] [String]$EnvironmentName,
        [Parameter(Mandatory = $false)] [String]$EndpointType,
        [Parameter(Mandatory = $false)] [Switch]$AllowInteractivePrompt
    )

    Write-LogMessage -Type DEBUG -Message "Resolving secret reference: '$SecretRef'"

    # Attempt 1: SecretStore (if available)
    if ((Get-Command Get-Secret -ErrorAction SilentlyContinue)) {
        try {
            $secret = Get-Secret -Name $SecretRef -AsPlainText -ErrorAction Stop -WarningAction SilentlyContinue 3>$null
            if ($secret) {
                Write-LogMessage -Type INFO -Message "Credential resolved from SecretStore: $SecretRef"
                return $secret
            }
        }
        catch {
            $errMsg = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
            Write-LogMessage -Type DEBUG -Message "SecretStore lookup failed for '$SecretRef': $errMsg"
        }
    }

    # Attempt 2: Environment variable
    $envSecret = [Environment]::GetEnvironmentVariable($SecretRef)
    if ($envSecret) {
        Write-LogMessage -Type DEBUG -Message "Credential resolved from environment variable: $SecretRef"
        return $envSecret
    }

    # Attempt 3: Interactive prompt (if allowed, running in interactive terminal, and host supports it)
    $isInteractiveTerminal = -not [System.Console]::IsInputRedirected
    if ($AllowInteractivePrompt -and $isInteractiveTerminal -and $host.UI.PromptForCredential) {
        $promptLabel = if ($EnvironmentName -and $EndpointType) {
            "$($EnvironmentName.ToUpper()) — $($EndpointType -replace '_', ' ')"
        } else {
            $SecretRef
        }

        Write-Host ""
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Host "Credential Required" -ForegroundColor Yellow
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Host "Environment: $promptLabel"
        Write-Host "Not found in: SecretStore, environment variables"
        Write-Host "Required for: Authenticating to endpoint"
        Write-Host ""

        try {
            $securePassword = Read-Host -Prompt "Enter password (or Ctrl+C to cancel)" -AsSecureString
            if (-not $securePassword -or $securePassword.Length -eq 0) {
                throw [System.InvalidOperationException]::new("Password cannot be empty.")
            }

            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($securePassword)
            )
            Write-LogMessage -Type INFO -Message "Credential provided interactively for: $promptLabel"
            Write-Host "✓ Credential accepted" -ForegroundColor Green
            Write-Host ""
            return $plainPassword
        }
        catch {
            Write-LogMessage -Type ERROR -Message "Failed to read credential: $($_.Exception.Message)"
            throw
        }
    }

    # Attempt 4: Non-interactive or no prompt support → error with helpful guidance
    $errorLines = @(
        "Credential not found: $SecretRef",
        "",
        "Lookups attempted:",
        "  1. Microsoft.PowerShell.SecretStore (if installed) — not found",
        "  2. Environment variable `$$SecretRef — not set",
        "  3. Interactive prompt — not available (non-interactive mode or no terminal)",
        "",
        "To resolve, choose ONE of these options:",
        "",
        "  OPTION A — Use environment variable (for CI/CD or automated scripts):",
        "    Set the environment variable before running the scan:",
        "    `$env:$SecretRef = 'your-password-here'",
        "    pwsh ./Invoke-VCFPatchScanner.ps1 -ConfigFile environments.json",
        "",
        "  OPTION B — Use Microsoft.PowerShell.SecretStore (for interactive local use):",
        "    Install SecretStore (one-time setup):",
        "      Install-Module -Name Microsoft.PowerShell.SecretStore -Force",
        "      Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password",
        "    Save your credential (one-time per credential):",
        "      Save-Secret -Name '$SecretRef' -SecureStringSecret (Read-Host -AsSecureString)",
        "    Then run scans — credential will be resolved automatically from SecretStore.",
        "",
        "  OPTION C — Run interactively (for one-time scans):",
        "    pwsh (not pwsh -NonInteractive)",
        "    ./Invoke-VCFPatchScanner.ps1 -ConfigFile environments.json",
        "    You will be prompted for any missing credentials.",
        ""
    )

    $fullError = $errorLines -join [Environment]::NewLine
    Write-LogMessage -Type ERROR -Message $fullError
    throw [System.InvalidOperationException]::new($fullError)
}
function Import-EnvironmentsFromConfig {

    <#
        .SYNOPSIS
        Import multi-endpoint configuration from JSON and resolve all credential references.

        .DESCRIPTION
        Reads environments.json, validates schema, resolves all secret references to plaintext,
        and returns an object suitable for iteration and scan invocation.

        Each environment's endpoint credentials are resolved via Resolve-SecretReference.
        If any required secret cannot be resolved, throws immediately (fail-fast).

        .PARAMETER ConfigPath
        Path to environments.json. File must exist and contain valid JSON.

        .PARAMETER AllowInteractivePrompt
        When present, allows interactive password prompts for missing credentials.
        When absent, all credentials must exist in SecretStore or environment variables.

        .EXAMPLE
        $envs = Import-EnvironmentsFromConfig -ConfigPath './environments.json'
        foreach ($env in $envs.environments) {
            Write-LogMessage -Type INFO -Message "Scanning environment: $($env.name)"
            Invoke-VCFPatchScanner @(ConvertTo-ScanParameters -Environment $env)
        }

        .OUTPUTS
        [PSCustomObject] with properties:
        - environments: array of [PSCustomObject] with fully resolved passwords
        - scan_options: global scan options from config (if present)

        .NOTES
        All secret references are resolved at load time. Failures are immediate.
        Does not modify the config file; resolved passwords are only in memory.
        Passwords are NOT logged; only secret reference names appear in logs.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ConfigPath,
        [Parameter(Mandatory = $false)] [Switch]$AllowInteractivePrompt
    )

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        $err = "Configuration file not found: '$ConfigPath'"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.IO.FileNotFoundException]::new($err)
    }

    Write-LogMessage -Type DEBUG -Message "Loading environment configuration from: '$ConfigPath'"

    try {
        $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        $err = "Failed to parse JSON configuration '$ConfigPath': $($_.Exception.Message)"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    if (-not $config.environments) {
        $err = "Configuration file '$ConfigPath' missing required 'environments' array"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    Write-LogMessage -Type DEBUG -Message "Found $($config.environments.Count) environment(s) in configuration"

    $resolvedCount = 0

    # Resolve all credential references
    foreach ($env in $config.environments) {
        if (-not $env.name) {
            $err = "Configuration file '$ConfigPath' contains an environment with no 'name' field"
            Write-LogMessage -Type ERROR -Message $err
            throw [System.InvalidOperationException]::new($err)
        }

        Write-LogMessage -Type DEBUG -Message "Resolving credentials for environment: '$($env.name)'"

        if (-not $env.endpoints) {
            Write-LogMessage -Type WARNING -Message "Environment '$($env.name)' has no endpoints (skipping)"
            continue
        }

        foreach ($endpointType in @('sddc_manager', 'vcf_ops', 'vcf_fm', 'nsx_manager', 'vcenter', 'vrslcm')) {
            $endpoint = $env.endpoints.$endpointType
            if (-not $endpoint) { continue }

            Write-LogMessage -Type DEBUG -Message "  $endpointType ($($endpoint.server)): resolving '$($endpoint.password_secret_ref)'"

            if (-not $endpoint.password_secret_ref) {
                $err = "Endpoint '$endpointType' in environment '$($env.name)' missing required 'password_secret_ref'"
                Write-LogMessage -Type ERROR -Message $err
                throw [System.InvalidOperationException]::new($err)
            }

            # Resolve the secret reference to plaintext (required)
            try {
                $plaintext = Resolve-SecretReference `
                    -SecretRef $endpoint.password_secret_ref `
                    -EnvironmentName $env.name `
                    -EndpointType $endpointType `
                    -AllowInteractivePrompt:$AllowInteractivePrompt

                $endpoint | Add-Member -NotePropertyName password -NotePropertyValue $plaintext -Force
                $resolvedCount++
            }
            catch {
                Write-LogMessage -Type ERROR -Message "Failed to resolve credential for $($env.name).${endpointType}: $($_.Exception.Message)"
                throw
            }
        }
    }

    Write-LogMessage -Type INFO -Message "Credentials loaded: $resolvedCount endpoint(s) configured across $($config.environments.Count) environment(s)"
    return $config
}
function ConvertTo-ScanParameters {

    <#
        .SYNOPSIS
        Convert a loaded environment config into Invoke-VCFPatchScanner parameters.

        .DESCRIPTION
        Takes a single environment object from the loaded config and creates the parameters
        required by the module's Invoke-VCFPatchScanner function. Returns a hashtable suitable
        for splatting, with EnvironmentConfig (PSCustomObject) and EnvironmentType keys.

        .PARAMETER Environment
        Single environment object from the loaded configuration (already has resolved passwords).

        .EXAMPLE
        $config = Import-EnvironmentsFromConfig -ConfigPath './environments.json'
        foreach ($env in $config.environments) {
            $scanParams = ConvertTo-ScanParameters -Environment $env
            Invoke-VCFPatchScanner @scanParams
        }

        .OUTPUTS
        [Hashtable] with keys: EnvironmentConfig, EnvironmentType.

        .NOTES
        The EnvironmentConfig is a PSCustomObject containing name, type, and endpoints.
        Passwords must already be resolved (present in $Environment.endpoints[*].password).
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [PSCustomObject]$Environment
    )

    $sddc   = $Environment.endpoints.sddc_manager
    $vc     = $Environment.endpoints.vcenter
    $nsx    = $Environment.endpoints.nsx_manager
    $vcfFm  = $Environment.endpoints.vcf_fm
    $vcfOps = $Environment.endpoints.vcf_ops
    $vrslcm = $Environment.endpoints.vrslcm

    # Create EnvironmentConfig with both the nested endpoints (for password bridging) and the
    # flat properties consumed by ConvertTo-ScanInventory guards (sddcManagerServer, etc.).
    # endpoints.*.username maps to the legacy *User flat property name.
    $envConfig = [PSCustomObject]@{
        name              = $Environment.name
        type              = $Environment.type
        endpoints         = $Environment.endpoints
        nsxManagerServer  = [String]$nsx.server
        sddcManagerServer = [String]$sddc.server
        sddcManagerUser   = [String]$sddc.username
        vcenterServer     = [String]$vc.server
        vcenterUser       = [String]$vc.username
        vcfFMServer       = [String]$vcfFm.server
        vcfFMUser         = [String]$vcfFm.username
        vcfOpsServer      = [String]$vcfOps.server
        vcfOpsUser        = [String]$vcfOps.username
        vrslcmServer      = [String]$vrslcm.server
        vrslcmUser        = [String]$vrslcm.username
    }

    $params = @{
        EnvironmentConfig = $envConfig
        EnvironmentType   = $Environment.type
    }

    return $params
}

#endregion
