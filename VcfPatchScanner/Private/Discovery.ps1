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

#region Environment Discovery and Inventory Collection

function Get-InventoryPassword {

    <#
        .SYNOPSIS
        Retrieve a plain-text inventory credential from an environment variable.

        .DESCRIPTION
        Reads the named environment variable, logs a WARNING and returns $null when the
        variable is absent or whitespace. Placed in Discovery.ps1 (which is dot-sourced
        before Inventory.ps1) so the helper is available module-wide in dependency order.

        .PARAMETER ComponentName
        Human-readable component label used in the warning message (e.g. "SDDC Manager").

        .PARAMETER EnvVarName
        Name of the environment variable that holds the password
        (e.g. "SDDC_MANAGER_PASSWORD").

        .EXAMPLE
        $password = Get-InventoryPassword -ComponentName "SDDC Manager" -EnvVarName "SDDC_MANAGER_PASSWORD"
        if ($null -eq $password) { return $inventory }

        .NOTES
        Returns $null when the variable is absent; the caller must gate on $null and
        return early. The function does not throw.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ComponentName,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$EnvVarName
    )

    $password = [System.Environment]::GetEnvironmentVariable($EnvVarName)
    if ([String]::IsNullOrWhiteSpace($password)) {
        Write-LogMessage -Type WARNING -Message "$ComponentName password not configured (env var: $EnvVarName)"
        return $null
    }
    return $password
}
function Get-RequiredInventoryPassword {

    <#
        .SYNOPSIS
        Retrieve a required inventory credential from an environment variable.

        .DESCRIPTION
        Reads the named environment variable and throws [System.InvalidOperationException]
        when the variable is absent or whitespace. Used in functions that cannot continue
        without the credential — callers must not proceed when this throws.

        Contrast with Get-InventoryPassword, which logs a WARNING and returns $null for
        functions that can gracefully skip a component when credentials are absent.

        .PARAMETER ComponentName
        Human-readable component label used in the error message (e.g. "Fleet Manager").

        .PARAMETER EnvVarName
        Environment variable that holds the password (e.g. "VCF_FM_PASSWORD").

        .EXAMPLE
        $password = Get-RequiredInventoryPassword -ComponentName "Fleet Manager" -EnvVarName "VCF_FM_PASSWORD"

        .OUTPUTS
        [String] Plain-text password read from the environment variable.

        .NOTES
        Throws [System.InvalidOperationException] when the variable is absent or whitespace.
        Never returns $null — use Get-InventoryPassword when a $null return is acceptable.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ComponentName,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$EnvVarName
    )

    $password = [System.Environment]::GetEnvironmentVariable($EnvVarName)
    if ([String]::IsNullOrWhiteSpace($password)) {
        $err = "$ComponentName password is not set (env var: $EnvVarName)."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }
    return $password
}
function Test-EndpointTcpConnection {

    <#
        .SYNOPSIS
        Test TCP port 443 connectivity and password configuration for a single endpoint.

        .DESCRIPTION
        Performs two-stage validation:
        1. Verifies TCP/443 reachability (connectivity test)
        2. If reachable, verifies password env var is set (credential availability test)

        Separates connectivity failures from authentication failures so users can
        distinguish network issues (timeout, unreachable) from credential issues (bad password).

        .PARAMETER EndpointName
        Display name used in log messages and the returned Endpoint property.

        .PARAMETER PasswordEnvVar
        Environment variable name that must be populated for this endpoint.

        .PARAMETER Server
        FQDN or IP address of the server to test.

        .PARAMETER TimeoutSeconds
        TCP probe timeout in seconds.

        .EXAMPLE
        $result = Test-EndpointTcpConnection -EndpointName "SDDC Manager" -PasswordEnvVar "SDDC_MANAGER_PASSWORD" -Server "sddc.example.com" -TimeoutSeconds 30

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message, Password.
        Status values: "Connected" (all checks passed), "Failed" (connectivity issue), "Unauthenticated"
        (connectivity OK but password missing). Password is non-null only when Status is "Connected" so
        callers never need to re-read the env var after a successful probe.

        .NOTES
        Returns a PSCustomObject with Status 'Failed' on connectivity errors and 'Unauthenticated' when TCP succeeds but the password env var is absent. Never throws.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$EndpointName,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$PasswordEnvVar,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds
    )

    # Stage 1: Test TCP connectivity to port 443
    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        try {
            $asyncResult = $tcpClient.BeginConnect($Server, 443, $null, $null)
            $isConnected = $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
            try { $tcpClient.EndConnect($asyncResult) } catch { }

            if (-not ($isConnected -and $tcpClient.Connected)) {
                Write-LogMessage -Type WARNING -Message "$EndpointName port 443 unreachable: $Server"
                return [PSCustomObject]@{
                    Endpoint  = $EndpointName
                    Server    = $Server
                    Status    = "Failed"
                    Connected = $false
                    Message   = "Port 443 unreachable (connectivity test failed)"
                    Password  = $null
                }
            }

            Write-LogMessage -Type DEBUG -Message "$EndpointName port 443 reachable: $Server"
        }
        finally {
            $tcpClient.Dispose()
        }
    }
    catch {
        Write-LogMessage -Type WARNING -Message "$EndpointName connectivity test error: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Endpoint  = $EndpointName
            Server    = $Server
            Status    = "Failed"
            Connected = $false
            Message   = "Connectivity test failed: $($_.Exception.Message)"
            Password  = $null
        }
    }

    # Stage 2: TCP is reachable; now check if credentials are available.
    # The password is returned in the result so callers can use it directly
    # without a second GetEnvironmentVariable call.
    $password = Get-InventoryPassword -ComponentName $EndpointName -EnvVarName $PasswordEnvVar

    if ($null -eq $password) {
        return [PSCustomObject]@{
            Endpoint  = $EndpointName
            Server    = $Server
            Status    = "Unauthenticated"
            Connected = $true
            Message   = "Credentials not configured — set $PasswordEnvVar"
            Password  = $null
        }
    }

    # Both connectivity and credential env var are present.
    # Callers that perform a real REST auth probe will log their own INFO on success;
    # this function only guarantees TCP reachability and password availability.
    Write-LogMessage -Type DEBUG -Message "$EndpointName port 443 reachable and password available: $Server"
    return [PSCustomObject]@{
        Endpoint  = $EndpointName
        Server    = $Server
        Status    = "Connected"
        Connected = $true
        Message   = "Port 443 reachable and credentials available"
        Password  = $password
    }
}
function Test-FleetManagerAuthentication {

    <#
        .SYNOPSIS
        Test Fleet Manager / Fleet Lifecycle Manager connectivity and authentication via both VCF 9.1.x and 9.0.x auth paths.

        .DESCRIPTION
        Performs a three-stage validation:
        1. TCP/443 reachability (via Test-EndpointTcpConnection)
        2. VSP bearer token exchange at POST /api/v1/identity/token (VCF 9.1.x path)
        3. Basic auth probe at GET /lcm/lcops/api/v2/settings/system-details (VCF 9.0.x path)

        Returns "Connected" if either auth path succeeds, labelling the Endpoint property with
        the version-appropriate name: "Fleet Lifecycle Manager" when the VSP path succeeds (VCF 9.1.x)
        or "Fleet Manager" when the lcops path succeeds (VCF 9.0.x). For failure and TCP-error
        results the Endpoint label is "VCF Fleet".

        Note: VCF 9.1.x VSP Fleet LCM expects usernames in user@vsp.local form. If the
        configured user uses a different domain (e.g. admin@local), the bearer token path
        will fail silently and only the lcops path is attempted.

        .PARAMETER Server
        Fleet Manager or Fleet Lifecycle Manager FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300).

        .PARAMETER User
        Username for authentication.

        .PARAMETER VcfMinorVersion
        Optional minor version string (e.g. "9.1") used to label Endpoint in failure and TCP-error
        results when the auth path cannot determine the version.

        .EXAMPLE
        $result = Test-FleetManagerAuthentication -Server 'flt-fc01.example.com' -User 'admin@vsp.local' -TimeoutSeconds 30 -VcfMinorVersion '9.1'
        if ($result.Status -ne 'Connected') {
            Write-LogMessage -Type ERROR -Message "$($result.Endpoint) not reachable or not authenticated: $($result.Message)"
        }

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message.

        .NOTES
        Reads VCF_FM_PASSWORD from the environment. Returns the TCP result object directly when
        TCP fails, avoiding a second credential read. The Endpoint value is "Fleet Lifecycle Manager"
        on VSP success, "Fleet Manager" on lcops success, and "VCF Fleet" on failure or TCP error.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $false)] [String]$VcfMinorVersion
    )

    # Success paths override to the version-specific name; failure and TCP-error paths use the generic "VCF Fleet" label.
    $fallbackLabel = "VCF Fleet"

    $tcpResult = Test-EndpointTcpConnection -EndpointName $fallbackLabel -PasswordEnvVar "VCF_FM_PASSWORD" -Server $Server -TimeoutSeconds $TimeoutSeconds
    if ($tcpResult.Status -ne "Connected") {
        return $tcpResult
    }

    $password = $tcpResult.Password

    try {
        $bearerToken = Get-VspBearerToken -Server $Server -User $User -Password $password -TimeoutSeconds $TimeoutSeconds
        if (-not [String]::IsNullOrWhiteSpace($bearerToken)) {
            $sysHeaders = @{ "Authorization" = "Bearer $bearerToken"; "Accept" = "application/json" }
            $null = Invoke-RestMethod -Uri "https://$Server/fleet-lcm/v1/system" `
                -Method GET -Headers $sysHeaders -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            Write-LogMessage -Type INFO -Message "Authenticated: Fleet Lifecycle Manager — $Server"
            return [PSCustomObject]@{
                Endpoint  = "Fleet Lifecycle Manager"
                Server    = $Server
                Status    = "Connected"
                Connected = $true
                Message   = "VSP bearer token auth and fleet-lcm /v1/system probe successful (VCF 9.1.x path)"
                Password  = $null
            }
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Fleet Manager VSP auth not available on $Server — $($_.Exception.Message)"
    }

    try {
        $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${User}:${password}"))
        $headers = @{ "Authorization" = "Basic $encoded"; "Accept" = "application/json" }
        $null = Invoke-RestMethod -Uri "https://$Server/lcm/lcops/api/v2/settings/system-details" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        Write-LogMessage -Type INFO -Message "Authenticated: Fleet Manager — $Server"
            return [PSCustomObject]@{
                Endpoint  = "Fleet Manager"
                Server    = $Server
                Status    = "Connected"
                Connected = $true
                Message   = "Fleet Management auth successful (VCF 9.0.x path)"
            Password  = $null
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Fleet Manager lcops auth not available on $Server — $($_.Exception.Message)"
    }

    $authFailMsg = "Authentication failed — tried both Fleet Lifecycle (VCF 9.1) and Fleet Management (VCF 9.0) paths"
    Write-LogMessage -Type WARNING -Message "Authentication failed: $fallbackLabel — $Server"
    return [PSCustomObject]@{
        Endpoint  = $fallbackLabel
        Server    = $Server
        Status    = "Unauthenticated"
        Connected = $true
        Message   = $authFailMsg
        Password  = $null
    }
}
function Test-VrslcmAuthentication {

    <#
        .SYNOPSIS
        Validate vRSLCM connectivity and credentials via REST API probe.

        .DESCRIPTION
        Performs a two-stage validation:
        1. TCP/443 reachability and password availability (via Test-EndpointTcpConnection).
        2. Basic auth probe via GET /lcm/lcops/api/v2/settings/system-details — a 401/403
           response indicates wrong credentials; a 200 response confirms authentication.

        .PARAMETER Server
        vRSLCM appliance FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300).

        .EXAMPLE
        $result = Test-VrslcmAuthentication -Server 'vrslcm.example.com' -User 'vcfadmin@local' -TimeoutSeconds 30
        if ($result.Status -ne 'Connected') {
            Write-LogMessage -Type ERROR -Message "vRSLCM auth failed: $($result.Message)"
        }

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message.
        Status: "Connected" | "Failed" | "Unauthenticated"

        .NOTES
        Reads VRSLCM_PASSWORD from the environment via Test-EndpointTcpConnection.
        Uses GET /lcm/lcops/api/v2/settings/system-details with Basic auth as the credential probe.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds
    )

    $tcpResult = Test-EndpointTcpConnection -EndpointName "vRSLCM" -PasswordEnvVar "VRSLCM_PASSWORD" -Server $Server -TimeoutSeconds $TimeoutSeconds
    if ($tcpResult.Status -ne "Connected") {
        return $tcpResult
    }

    $password = $tcpResult.Password
    $encoded  = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${User}:${password}"))
    $headers  = @{ "Authorization" = "Basic $encoded"; "Accept" = "application/json" }

    try {
        $null = Invoke-RestMethod -Uri "https://$Server/lcm/lcops/api/v2/settings/system-details" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        Write-LogMessage -Type INFO -Message "Authenticated: vRSLCM — $Server"
        return [PSCustomObject]@{
            Endpoint  = "vRSLCM"
            Server    = $Server
            Status    = "Connected"
            Connected = $true
            Message   = "Authenticated successfully via GET /lcm/lcops/api/v2/settings/system-details"
            Password  = $null
        }
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response) {
            $statusCode = [Int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in @(401, 403)) {
            Write-LogMessage -Type WARNING -Message "Authentication failed: vRSLCM — $Server"
            return [PSCustomObject]@{
                Endpoint  = "vRSLCM"
                Server    = $Server
                Status    = "Unauthenticated"
                Connected = $true
                Message   = "Authentication failed — check password"
                Password  = $null
            }
        }
        Write-LogMessage -Type WARNING -Message "vRSLCM auth probe failed on $Server — $($_.Exception.Message)"
        return [PSCustomObject]@{
            Endpoint  = "vRSLCM"
            Server    = $Server
            Status    = "Failed"
            Connected = $false
            Message   = "Auth probe failed: $($_.Exception.Message)"
            Password  = $null
        }
    }
}
function Test-SddcManagerAuthentication {

    <#
        .SYNOPSIS
        Validate SDDC Manager connectivity and credentials via REST API probe.

        .DESCRIPTION
        Performs a two-stage validation:
        1. TCP/443 reachability (via Test-EndpointTcpConnection).
        2. Bearer token acquisition via POST /v1/tokens — a 401 response indicates wrong
           credentials; a 200 response confirms authentication. This matches the token-based
           auth model used by Connect-VcfSddcManagerServer and avoids false 401s that occur
           when Basic auth is sent directly to REST endpoints in newer VCF builds.

        .PARAMETER Server
        SDDC Manager FQDN or IP address.

        .PARAMETER User
        Username for authentication (e.g. administrator@vsphere.local).

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300).

        .EXAMPLE
        $result = Test-SddcManagerAuthentication -Server 'sddc-mgr.example.com' -User 'administrator@vsphere.local' -TimeoutSeconds 30
        if ($result.Status -ne 'Connected') {
            Write-LogMessage -Type ERROR -Message "SDDC Manager auth failed: $($result.Message)"
        }

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message.
        Status: "Connected" | "Failed" | "Unauthenticated"

        .NOTES
        Reads SDDC_MANAGER_PASSWORD from the environment. Uses POST /v1/tokens as the auth probe because GET endpoints require a pre-issued Bearer token in VCF 9.x.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds
    )

    $tcpResult = Test-EndpointTcpConnection -EndpointName "SDDC Manager" -PasswordEnvVar "SDDC_MANAGER_PASSWORD" -Server $Server -TimeoutSeconds $TimeoutSeconds
    if ($tcpResult.Status -ne "Connected") {
        return $tcpResult
    }

    $password = $tcpResult.Password

    # Use POST /v1/tokens (bearer token acquisition) as the credential probe.
    # GET /v1/sddcmanagers with -Authentication Basic returns HTTP 401 in VCF 9.x even for
    # valid credentials because the endpoint requires a pre-issued Bearer token, not Basic auth.
    $tokenBody = @{ username = $User; password = $password } | ConvertTo-Json -Compress
    try {
        $null = Invoke-RestMethod -Uri "https://$Server/v1/tokens" `
            -Method POST -Body $tokenBody -ContentType "application/json" `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        Write-LogMessage -Type INFO -Message "Authenticated: SDDC Manager — $Server"
        return [PSCustomObject]@{
            Endpoint  = "SDDC Manager"
            Server    = $Server
            Status    = "Connected"
            Connected = $true
            Message   = "Authenticated successfully via POST /v1/tokens"
            Password  = $null
        }
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response) {
            $statusCode = [Int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in @(401, 403)) {
            Write-LogMessage -Type WARNING -Message "Authentication failed: SDDC Manager — $Server"
            return [PSCustomObject]@{
                Endpoint  = "SDDC Manager"
                Server    = $Server
                Status    = "Unauthenticated"
                Connected = $true
                Message   = "Authentication failed — check password"
                Password  = $null
            }
        }
        Write-LogMessage -Type WARNING -Message "SDDC Manager auth probe failed on $Server — $($_.Exception.Message)"
        return [PSCustomObject]@{
            Endpoint  = "SDDC Manager"
            Server    = $Server
            Status    = "Failed"
            Connected = $false
            Message   = "Auth probe failed: $($_.Exception.Message)"
            Password  = $null
        }
    }
}
function Test-VcfOpsAuthentication {

    <#
        .SYNOPSIS
        Validate VCF Operations connectivity and credentials via REST token probe.

        .DESCRIPTION
        Performs a two-stage validation:
        1. TCP/443 reachability (via Test-EndpointTcpConnection).
        2. POST /suite-api/api/auth/token/acquire — distinguishes wrong credentials
           (empty token response → Unauthenticated) from network issues (TCP failure → Failed).

        .PARAMETER Server
        VCF Operations FQDN or IP address.

        .PARAMETER User
        Username (e.g. admin@local).

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300).

        .EXAMPLE
        $result = Test-VcfOpsAuthentication -Server 'vcf-ops.example.com' -User 'admin@local' -TimeoutSeconds 30
        if ($result.Status -ne 'Connected') {
            Write-LogMessage -Type WARNING -Message "VCF Operations auth failed: $($result.Message)"
        }

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message.
        Status: "Connected" | "Failed" | "Unauthenticated"

        .NOTES
        Reads VCF_OPS_PASSWORD from the environment. Uses Get-VcfOpsRestToken for the auth probe, which calls POST /suite-api/api/auth/token/acquire.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds
    )

    $tcpResult = Test-EndpointTcpConnection -EndpointName "VCF Operations" -PasswordEnvVar "VCF_OPS_PASSWORD" -Server $Server -TimeoutSeconds $TimeoutSeconds
    if ($tcpResult.Status -ne "Connected") {
        return $tcpResult
    }

    $password = $tcpResult.Password

    $token = Get-VcfOpsRestToken -Server $Server -User $User -Password $password -TimeoutSeconds $TimeoutSeconds
    if (-not [String]::IsNullOrWhiteSpace($token)) {
        Write-LogMessage -Type INFO -Message "Authenticated: VCF Operations — $Server"
        return [PSCustomObject]@{
            Endpoint  = "VCF Operations"
            Server    = $Server
            Status    = "Connected"
            Connected = $true
            Message   = "Authenticated successfully via POST /suite-api/api/auth/token/acquire"
            Password  = $null
        }
    }

    Write-LogMessage -Type WARNING -Message "Authentication failed: VCF Operations — $Server"
    return [PSCustomObject]@{
        Endpoint  = "VCF Operations"
        Server    = $Server
        Status    = "Unauthenticated"
        Connected = $true
        Message   = "Authentication failed — check username and password"
        Password  = $null
    }
}
function Test-VcenterAuthentication {

    <#
        .SYNOPSIS
        Validate vCenter connectivity and credentials via the vSphere REST session API.

        .DESCRIPTION
        Performs a two-stage validation:
        1. TCP/443 reachability (via Test-EndpointTcpConnection).
        2. POST /api/session (vSphere 7+ REST) with Basic auth — a 201 response confirms
           authentication; 401/403 indicates wrong credentials.

        Uses the REST API rather than Connect-VIServer so the probe is lightweight and
        does not require PowerCLI module load time during validation.

        .PARAMETER Server
        vCenter FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300).

        .PARAMETER User
        Username for authentication (e.g. administrator@vsphere.local).

        .EXAMPLE
        $result = Test-VcenterAuthentication -Server "vcenter.corp.example.com" -User "administrator@vsphere.local" -TimeoutSeconds 30
        if ($result.Status -ne "Connected") {
            Write-LogMessage -Type WARNING -Message "vCenter auth failed: $($result.Message)"
        }

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message.
        Status: "Connected" | "Failed" | "Unauthenticated"

        .NOTES
        Reads VCENTER_PASSWORD from the environment via Test-EndpointTcpConnection on the TCP stage. DELETE /api/session is not called after the probe — the session token is discarded immediately.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User
    )

    $tcpResult = Test-EndpointTcpConnection -EndpointName "vCenter" -PasswordEnvVar "VCENTER_PASSWORD" -Server $Server -TimeoutSeconds $TimeoutSeconds
    if ($tcpResult.Status -ne "Connected") {
        return $tcpResult
    }

    $password = $tcpResult.Password

    $basicAuth = [Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes("${User}:${password}")
    )
    try {
        $null = Invoke-RestMethod -Uri "https://$Server/api/session" `
            -Method POST -Headers @{ "Authorization" = "Basic $basicAuth" } `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        Write-LogMessage -Type INFO -Message "Authenticated: vCenter — $Server"
        return [PSCustomObject]@{
            Endpoint  = "vCenter"
            Server    = $Server
            Status    = "Connected"
            Connected = $true
            Message   = "Authenticated successfully via POST /api/session"
            Password  = $null
        }
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response) {
            $statusCode = [Int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in @(401, 403)) {
            Write-LogMessage -Type WARNING -Message "Authentication failed: vCenter — $Server"
            return [PSCustomObject]@{
                Endpoint  = "vCenter"
                Server    = $Server
                Status    = "Unauthenticated"
                Connected = $true
                Message   = "Authentication failed — check password"
                Password  = $null
            }
        }
        Write-LogMessage -Type WARNING -Message "vCenter auth probe failed on $Server — $($_.Exception.Message)"
        return [PSCustomObject]@{
            Endpoint  = "vCenter"
            Server    = $Server
            Status    = "Failed"
            Connected = $false
            Message   = "Auth probe failed: $($_.Exception.Message)"
            Password  = $null
        }
    }
}
function Test-NsxManagerAuthentication {

    <#
        .SYNOPSIS
        Validate NSX Manager connectivity and credentials via the NSX REST API.

        .DESCRIPTION
        Performs a two-stage validation:
        1. TCP/443 reachability (via Test-EndpointTcpConnection).
        2. GET /api/v1/node with Basic auth (admin:<password>) — a 200 response confirms
           authentication; 401/403 indicates wrong credentials.

        .PARAMETER Server
        NSX Manager FQDN or IP address (cluster VIP).

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300).

        .EXAMPLE
        $result = Test-NsxManagerAuthentication -Server "nsx.corp.example.com" -TimeoutSeconds 30
        if ($result.Status -ne "Connected") {
            Write-LogMessage -Type WARNING -Message "NSX Manager auth failed: $($result.Message)"
        }

        .OUTPUTS
        [PSCustomObject] with properties: Endpoint, Server, Status, Connected, Message.
        Status: "Connected" | "Failed" | "Unauthenticated"

        .NOTES
        Reads NSX_MANAGER_PASSWORD from the environment. Uses the NSX admin account (fixed username "admin"). The GET /api/v1/node endpoint is available on all NSX versions and requires only read access.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds
    )

    $tcpResult = Test-EndpointTcpConnection -EndpointName "NSX Manager" -PasswordEnvVar "NSX_MANAGER_PASSWORD" -Server $Server -TimeoutSeconds $TimeoutSeconds
    if ($tcpResult.Status -ne "Connected") {
        return $tcpResult
    }

    $password = $tcpResult.Password

    $basicAuth = [Convert]::ToBase64String(
        [System.Text.Encoding]::ASCII.GetBytes("admin:$password")
    )
    try {
        $null = Invoke-RestMethod -Uri "https://$Server/api/v1/node" `
            -Method GET -Headers @{ "Authorization" = "Basic $basicAuth"; "Accept" = "application/json" } `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        Write-LogMessage -Type INFO -Message "Authenticated: NSX Manager — $Server"
        return [PSCustomObject]@{
            Endpoint  = "NSX Manager"
            Server    = $Server
            Status    = "Connected"
            Connected = $true
            Message   = "Authenticated successfully via GET /api/v1/node"
            Password  = $null
        }
    }
    catch {
        $statusCode = $null
        if ($null -ne $_.Exception.Response) {
            $statusCode = [Int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -in @(401, 403)) {
            Write-LogMessage -Type WARNING -Message "Authentication failed: NSX Manager — $Server"
            return [PSCustomObject]@{
                Endpoint  = "NSX Manager"
                Server    = $Server
                Status    = "Unauthenticated"
                Connected = $true
                Message   = "Authentication failed — check password"
                Password  = $null
            }
        }
        Write-LogMessage -Type WARNING -Message "NSX Manager auth probe failed on $Server — $($_.Exception.Message)"
        return [PSCustomObject]@{
            Endpoint  = "NSX Manager"
            Server    = $Server
            Status    = "Failed"
            Connected = $false
            Message   = "Auth probe failed: $($_.Exception.Message)"
            Password  = $null
        }
    }
}
function Test-PatchScanConnection {

    <#
        .SYNOPSIS
        Test connectivity to all configured patch scan endpoints.

        .DESCRIPTION
        Validates credentials and network connectivity for SDDC Manager,
        VCF Operations, Fleet Manager, vRSLCM, vCenter, and/or NSX Manager based on environment type.
        Every endpoint receives a real authentication probe (not just TCP/credential presence),
        so the result distinguishes wrong credentials from network failures:
          - "Connected"       — authenticated successfully.
          - "Failed"          — TCP/443 unreachable (network, DNS, or firewall issue).
          - "Unauthenticated" — reachable but credentials rejected by the server.
          - "Skipped"         — endpoint not configured for this environment type.

        vCenter (vsphere8/vvf9): probed via POST /api/session (vSphere REST).
        NSX Manager (vsphere8/vvf9): probed via GET /api/v1/node (NSX REST).

        Credentials are retrieved from environment variables:
        - SDDC_MANAGER_PASSWORD for SDDC Manager
        - VCF_OPS_PASSWORD for VCF Operations
        - VCF_FM_PASSWORD for Fleet Manager
        - VRSLCM_PASSWORD for vRSLCM (VCF 5.x optional)
        - VCENTER_PASSWORD for vCenter
        - NSX_MANAGER_PASSWORD for NSX Manager (vsphere8/vvf9 only)

        .PARAMETER EnvironmentType
        Environment type: vcf5, vcf9, vsphere8, vvf9.

        .PARAMETER NsxManagerServer
        NSX Manager FQDN or IP (required for vvf9; optional for vsphere8).

        .PARAMETER NsxManagerUser
        NSX Manager username (required when NsxManagerServer is configured).

        .PARAMETER SddcManagerServer
        SDDC Manager FQDN or IP (required for vcf5, vcf9).

        .PARAMETER SddcManagerUser
        SDDC Manager username (required for vcf5, vcf9).

        .PARAMETER TimeoutSeconds
        Connection timeout in seconds (1-300, default 30).

        .PARAMETER VcenterServer
        vCenter FQDN or IP (vsphere8, vvf9 only).

        .PARAMETER VcenterUser
        vCenter username (vsphere8, vvf9 only).

        .PARAMETER VcfFMServer
        Fleet Manager / Fleet Lifecycle Manager FQDN or IP (VCF 9 only, optional).

        .PARAMETER VcfFMUser
        Fleet Manager / Fleet Lifecycle Manager username (VCF 9 only, optional).

        .PARAMETER VcfMinorVersion
        Optional minor version string (e.g. "9.1") used to label Fleet Manager endpoints correctly
        in error results when the auth path cannot determine the version automatically.

        .PARAMETER VcfOpsServer
        VCF Operations server FQDN or IP (VCF 9 only, optional).

        .PARAMETER VcfOpsUser
        VCF Operations username (VCF 9 only, optional).

        .PARAMETER VrslcmServer
        vRealize Suite Lifecycle Manager FQDN or IP (VCF 5.x, optional).

        .PARAMETER VrslcmUser
        vRSLCM username (VCF 5.x, optional).

        .EXAMPLE
        $result = Test-PatchScanConnection -EnvironmentType vsphere8 `
            -VcenterServer "vcenter.example.com" -VcenterUser "administrator@vsphere.local" `
            -NsxManagerServer "nsx.example.com" -NsxManagerUser "admin" `
            -TimeoutSeconds 30

        .EXAMPLE
        $result = Test-PatchScanConnection -EnvironmentType vcf9 `
            -SddcManagerServer "sddc.example.com" `
            -SddcManagerUser "administrator@vsphere.local" `
            -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" `
            -VcfFMServer "flt-fc01.example.com" -VcfFMUser "admin@vsp.local" `
            -TimeoutSeconds 30

        .OUTPUTS
        [PSCustomObject] with properties: EnvironmentType, EndpointTests (array), Success (bool), Summary (string)

        .NOTES
        Credentials are passed via environment variables (SDDC_MANAGER_PASSWORD, etc.)
        and are never visible on the command line or in logs.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateSet('vcf5', 'vcf9', 'vsphere8', 'vvf9')] [String]$EnvironmentType,
        [Parameter(Mandatory = $false)] [String]$NsxManagerServer,
        [Parameter(Mandatory = $false)] [String]$NsxManagerUser,
        [Parameter(Mandatory = $false)] [String]$SddcManagerServer,
        [Parameter(Mandatory = $false)] [String]$SddcManagerUser,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $false)] [String]$VcenterServer,
        [Parameter(Mandatory = $false)] [String]$VcenterUser,
        [Parameter(Mandatory = $false)] [String]$VcfFMServer,
        [Parameter(Mandatory = $false)] [String]$VcfFMUser,
        [Parameter(Mandatory = $false)] [String]$VcfMinorVersion,
        [Parameter(Mandatory = $false)] [String]$VcfOpsServer,
        [Parameter(Mandatory = $false)] [String]$VcfOpsUser,
        [Parameter(Mandatory = $false)] [String]$VrslcmServer,
        [Parameter(Mandatory = $false)] [String]$VrslcmUser
    )

    $envDisplayName = switch ($EnvironmentType) {
        'vcf5'     { 'VCF 5' }
        'vcf9'     { 'VCF 9' }
        'vsphere8' { 'vSphere 8' }
        'vvf9'     { 'VVF 9' }
        default    { $EnvironmentType }
    }
    Write-LogMessage -Type INFO -Message "Checking credentials for $envDisplayName (timeout: $TimeoutSeconds seconds)"

    $testResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSuccess = $true

    try {
        # Test SDDC Manager (VCF 5, VCF 9) — real REST auth probe.
        if (@('vcf5', 'vcf9') -contains $EnvironmentType) {
            if ([String]::IsNullOrWhiteSpace($SddcManagerServer)) {
                $testResults.Add([PSCustomObject]@{
                    Endpoint  = "SDDC Manager"
                    Server    = "NOT_CONFIGURED"
                    Status    = "Skipped"
                    Connected = $null
                    Message   = "Server not configured"
                })
            }
            else {
                $sddcUser = if ([String]::IsNullOrWhiteSpace($SddcManagerUser)) { "administrator@vsphere.local" } else { $SddcManagerUser }
                $result = Test-SddcManagerAuthentication -Server $SddcManagerServer -User $sddcUser -TimeoutSeconds $TimeoutSeconds
                $testResults.Add($result)
                if ($result.Status -ne "Connected") { $allSuccess = $false }
            }
        }

        # Test vRSLCM (VCF 5.x, optional) — real Basic auth REST probe.
        if ($EnvironmentType -eq 'vcf5' -and -not [String]::IsNullOrWhiteSpace($VrslcmServer)) {
            $vrslcmUser = if ([String]::IsNullOrWhiteSpace($VrslcmUser)) { "vcfadmin@local" } else { $VrslcmUser }
            $result = Test-VrslcmAuthentication -Server $VrslcmServer -User $vrslcmUser -TimeoutSeconds $TimeoutSeconds
            $testResults.Add($result)
            if ($result.Status -ne "Connected") { $allSuccess = $false }
        }

        # Test VCF Operations (VCF 9 only) — real REST token probe.
        if (@('vcf9', 'vvf9') -contains $EnvironmentType) {
            if ([String]::IsNullOrWhiteSpace($VcfOpsServer)) {
                $testResults.Add([PSCustomObject]@{
                    Endpoint  = "VCF Operations"
                    Server    = "NOT_CONFIGURED"
                    Status    = "Skipped"
                    Connected = $null
                    Message   = "Server not configured"
                })
            }
            else {
                $opsUser = if ([String]::IsNullOrWhiteSpace($VcfOpsUser)) { "admin@local" } else { $VcfOpsUser }
                $result = Test-VcfOpsAuthentication -Server $VcfOpsServer -User $opsUser -TimeoutSeconds $TimeoutSeconds
                $testResults.Add($result)
                if ($result.Status -ne "Connected") { $allSuccess = $false }
            }
        }

        # Test Fleet Manager / Fleet Lifecycle Manager (VCF 9, VVF 9.1) — real VSP bearer + lcops Basic auth probe.
        # VVF 9.0 skips naturally when vcfFMServer is not configured.
        if (@('vcf9', 'vvf9') -contains $EnvironmentType) {
            $fmLabel = if ($VcfMinorVersion -eq '9.1') { "Fleet Lifecycle Manager" } else { "Fleet Manager" }
            if ([String]::IsNullOrWhiteSpace($VcfFMServer)) {
                $testResults.Add([PSCustomObject]@{
                    Endpoint  = $fmLabel
                    Server    = "NOT_CONFIGURED"
                    Status    = "Skipped"
                    Connected = $null
                    Message   = "Server not configured"
                })
            }
            else {
                $fmUser = if ([String]::IsNullOrWhiteSpace($VcfFMUser)) { "admin@local" } else { $VcfFMUser }
                $result = Test-FleetManagerAuthentication -Server $VcfFMServer -User $fmUser -TimeoutSeconds $TimeoutSeconds -VcfMinorVersion $VcfMinorVersion
                $testResults.Add($result)
                if ($result.Status -ne "Connected") { $allSuccess = $false }
            }
        }

        # Test vCenter (vsphere8, vvf9) — real REST session probe via POST /api/session.
        if (@('vsphere8', 'vvf9') -contains $EnvironmentType) {
            if ([String]::IsNullOrWhiteSpace($VcenterServer)) {
                $testResults.Add([PSCustomObject]@{
                    Endpoint  = "vCenter"
                    Server    = "NOT_CONFIGURED"
                    Status    = "Skipped"
                    Connected = $null
                    Message   = "Server not configured"
                })
            }
            else {
                $vcUser = if ([String]::IsNullOrWhiteSpace($VcenterUser)) { "administrator@vsphere.local" } else { $VcenterUser }
                $result = Test-VcenterAuthentication -Server $VcenterServer -User $vcUser -TimeoutSeconds $TimeoutSeconds
                $testResults.Add($result)
                if ($result.Status -ne "Connected") { $allSuccess = $false }
            }
        }

        # Test NSX Manager (vsphere8/vvf9 only) — real REST probe via GET /api/v1/node.
        # NSX is optional for vsphere8 and required for vvf9; validation already guards the latter.
        if (@('vsphere8', 'vvf9') -contains $EnvironmentType) {
            if ([String]::IsNullOrWhiteSpace($NsxManagerServer)) {
                $testResults.Add([PSCustomObject]@{
                    Endpoint  = "NSX Manager"
                    Server    = "NOT_CONFIGURED"
                    Status    = "Skipped"
                    Connected = $null
                    Message   = "Server not configured"
                })
            }
            else {
                $result = Test-NsxManagerAuthentication -Server $NsxManagerServer -TimeoutSeconds $TimeoutSeconds
                $testResults.Add($result)
                if ($result.Status -ne "Connected") { $allSuccess = $false }
            }
        }

        $summary = if ($allSuccess) { "All configured endpoints verified" } else { "One or more endpoints failed" }

        return [PSCustomObject]@{
            EnvironmentType = $EnvironmentType
            EndpointTests   = $testResults.ToArray()
            Success         = $allSuccess
            Summary         = $summary
        }
    }
    catch {
        Write-LogMessage -Type ERROR -Message "Connection test error: $($_.Exception.Message)"
        throw
    }
}
function Get-SddcManagerListFromVcfOps {

    <#
        .SYNOPSIS
        Discover SDDC Manager FQDNs and registered usernames from VCF Operations.

        .DESCRIPTION
        Connects to VCF Operations via PowerCLI, enumerates VcfAdapter instances to
        extract registered SDDC Manager FQDNs, and resolves the username that VCF
        Operations used to register each SDDC Manager by following the adapter's
        CredentialInstanceId to the credential object and extracting the "username"
        field from its Fields list.

        Returns one result per discovered SDDC Manager with Fqdn, InstanceName, and
        SddcUsername (empty string when the credential cannot be resolved).

        The auth source is derived from the username: if the username contains an "@"
        the portion after "@" is used as the auth source (e.g. "admin@local" → "Local",
        "user@CORP-AD" → "CORP-AD"). A bare username with no "@" defaults to "Local".

        .PARAMETER VcfOpsServer
        VCF Operations server FQDN or IP.

        .PARAMETER VcfOpsUser
        VCF Operations username. May include auth source suffix (e.g. "admin@local",
        "user@CORP-AD"). Bare usernames default to auth source "Local".

        .PARAMETER TimeoutSeconds
        Connection timeout in seconds.

        .OUTPUTS
        [PSCustomObject] with properties:
          Instances     — array of objects with Fqdn, InstanceName, and SddcUsername.
          OpsVersion    — VCF Operations product version string (e.g. "VCF Operations 9.1.0.0"),
                         or empty string when the version cannot be determined.
          VcenterFqdns  — array of standalone vCenter FQDNs registered with VCF Operations via
                         the VMWARE adapter; empty array when none are registered.

        .NOTES
        Credentials are retrieved from environment variable VCF_OPS_PASSWORD.
        SddcUsername is the username stored in the VCF Adapter credential — it is
        returned as-is and the caller should treat it as a suggestion; the user may
        substitute any username that holds SDDC Manager ADMIN rights.

        VCF PowerCLI 9 SDK bugs avoided:
        1. Invoke-VcfOpsGetCredential / Invoke-VcfOpsGetAdapterInstancesUsingCredential:
           accept -Id as System.Guid but the SDK URL-builder serialises it as
           "Variant,11,Version,4" instead of a UUID string, causing HTTP 400.
        2. Invoke-VcfOpsGetCredentials with -AdapterKind: the SDK wraps the response in a
           C# class whose list property is renamed '_CredentialInstances' by the OpenAPI
           Generator (class/property name collision), and the server-side adapterKind
           filter returns 0 results on VCF Ops 9.0.
        This function calls GET /suite-api/api/credentials directly via Invoke-RestMethod,
        parses the raw JSON 'credentialInstances' array, and filters by adapterKindKey
        client-side — no SDK type coercion, no naming ambiguity.

        .EXAMPLE
        $discovery = Get-SddcManagerListFromVcfOps -VcfOpsServer 'vcf-ops.example.com' -VcfOpsUser 'admin@local' -TimeoutSeconds 60
        foreach ($sddcMgr in $discovery.Instances) {
            Write-LogMessage -Type INFO -Message "Found SDDC Manager: $($sddcMgr.Fqdn)"
        }
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$VcfOpsServer,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$VcfOpsUser,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    $conn = $null
    try {
        $plainTextPassword = Get-RequiredInventoryPassword -ComponentName "VCF Operations" -EnvVarName "VCF_OPS_PASSWORD"

        # Connect-VcfOpsServer has no timeout parameter. Pre-check TCP/443 reachability
        # so we fail fast with a clear message rather than hanging indefinitely.
        $tcpCheck = Test-EndpointTcpConnection -EndpointName "VCF Operations" -PasswordEnvVar "VCF_OPS_PASSWORD" -Server $VcfOpsServer -TimeoutSeconds $TimeoutSeconds
        if ($tcpCheck.Status -eq "Failed") {
            $err = "VCF Operations $VcfOpsServer is not reachable (port 443): $($tcpCheck.Message)"
            Write-LogMessage -Type ERROR -Message $err
            throw [System.Net.WebException]::new($err)
        }

        $authParts = ConvertTo-VcfOpsAuthParts -User $VcfOpsUser
        Write-LogMessage -Type DEBUG -Message "Connecting to VCF Operations: $VcfOpsServer (authSource: $($authParts.AuthSource))"
        # -IgnoreInvalidCertificate: VCF Operations uses a self-signed certificate; without
        # this flag the cmdlet rejects the cert and returns an HTML error page instead of JSON.
        $conn = Connect-VcfOpsServer -Server $VcfOpsServer -User $authParts.BareUser -Password $plainTextPassword -AuthSource $authParts.AuthSource -IgnoreInvalidCertificate -ErrorAction Stop

        Write-LogMessage -Type DEBUG -Message "Querying VcfAdapter instances"
        $adapters = Invoke-VcfOpsEnumerateAdapterInstances -AdapterKindKey "VcfAdapter" -ErrorAction Stop

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Load all VcfAdapter credentials once up-front via a direct REST call.
        #
        # Why not use Invoke-VcfOpsGetCredential / Invoke-VcfOpsGetAdapterInstancesUsingCredential:
        #   Both accept -Id as System.Guid but the SDK URL-builder serialises Guid as
        #   "Variant,11,Version,4" instead of a UUID string — a confirmed VCF PowerCLI 9 bug.
        #
        # Why not use Invoke-VcfOpsGetCredentials (plural) with -AdapterKind filter:
        #   The PowerCLI SDK wraps the response in a C# class named 'CredentialInstances' whose
        #   list property is renamed to '_CredentialInstances' by the OpenAPI Generator to avoid
        #   the class/property naming collision.  In practice the filter also returns 0 results
        #   on VCF Ops 9.0 regardless of the adapterKind value.
        #
        # Solution: call GET /suite-api/api/credentials directly via Invoke-RestMethod using the
        # already-acquired REST token, parse the raw JSON, and filter by credentialKindKey
        # "VcfCredentials" (canonical VCF type; present in 9.0 and 9.1) or adapterKindKey
        # "VcfAdapter" (legacy fallback) client-side.
        $vcfAdapterCredentials = @()
        $restToken = Get-VcfOpsRestToken -Password $plainTextPassword -Server $VcfOpsServer `
            -TimeoutSeconds $TimeoutSeconds -User $VcfOpsUser -ErrorAction SilentlyContinue
        if (-not [String]::IsNullOrWhiteSpace($restToken)) {
            try {
                $credHeaders = @{
                    "Authorization" = "vRealizeOpsToken $restToken"
                    "Accept"        = "application/json"
                }
                $credResp = Invoke-RestMethod -Uri "https://$VcfOpsServer/suite-api/api/credentials" `
                    -Method GET -Headers $credHeaders -SkipCertificateCheck `
                    -TimeoutSec $TimeoutSeconds -ErrorAction Stop
                $allCreds = @($credResp.credentialInstances | Where-Object { $null -ne $_ })
                # Match VCF Adapter credentials by credentialKindKey or adapterKindKey.
                # VCF Operations 9.0: credential is stored with adapterKindKey="VcfAdapter",
                #   credentialKindKey="VcfCredentials" and is visible here.
                # VCF Operations 9.1: the VCF integration uses a cloud-account architecture.
                #   The SDDC Manager credential is managed internally and does NOT appear in
                #   GET /api/credentials — only platform service credentials are returned.
                #   Username resolution is not possible on 9.1; the UI will prompt the user.
                $vcfAdapterCredentials = @($allCreds | Where-Object {
                    $_.credentialKindKey -ieq "VcfCredentials" -or $_.adapterKindKey -ieq "VcfAdapter"
                })
                $allKinds = ($allCreds | ForEach-Object { "$($_.adapterKindKey)/$($_.credentialKindKey)" }) -join ", "
                Write-LogMessage -Type DEBUG -Message "Credential lookup: $($vcfAdapterCredentials.Count) VCF credential(s) found (of $($allCreds.Count) total; kinds: $allKinds)"
            }
            catch {
                Write-LogMessage -Type DEBUG -Message "Could not enumerate VcfAdapter credentials via REST — username resolution will be skipped: $($_.Exception.Message)"
            }
        } else {
            Write-LogMessage -Type DEBUG -Message "Could not acquire REST token for credential enumeration — username resolution will be skipped"
        }

        foreach ($dto in @($adapters.AdapterInstancesInfoDto)) {
            if ($null -eq $dto) { continue }
            $instanceName = [String]$dto.ResourceKey.Name
            $sddcFqdn = ($dto.ResourceKey.ResourceIdentifiers |
                Where-Object { $_.IdentifierType.Name -eq "SDDCManager_Hostname" }).Value

            if ([String]::IsNullOrWhiteSpace($sddcFqdn)) { continue }

            $sddcFqdn = [String]$sddcFqdn.Trim()

            # Resolve the SDDC Manager username from the pre-loaded credential list.
            # Strategy A: the adapter DTO carries a credentialInstanceId — match the enumerated
            #   credential whose Id string equals it (case-insensitive).
            # Strategy B: no ID on the DTO, or no match found — use the sole credential when
            #   there is exactly one (unambiguous), otherwise leave username empty.
            #
            # The DTO's CredentialInstanceId is a System.Guid in the SDK model but VCF Ops 9.0
            # may return "Variant,11,Version,4" (Guid variant/version metadata) for cloud-account
            # adapters.  Converting to String before comparing handles both forms.
            # The credential list from Invoke-RestMethod uses plain string IDs, so comparison
            # is a simple case-insensitive string equality check.
            $sddcUsername = ""
            $credIdStr = if ($null -ne $dto.CredentialInstanceId) { [String]$dto.CredentialInstanceId } else { "" }

            if ($vcfAdapterCredentials.Count -gt 0) {
                $matchedCred = $null

                if ($credIdStr) {
                    # Strategy A: direct ID match by string comparison — immune to the Guid URL bug.
                    $matchedCred = $vcfAdapterCredentials |
                        Where-Object { [String]$_.Id -ieq $credIdStr } |
                        Select-Object -First 1
                    if ($null -eq $matchedCred) {
                        Write-LogMessage -Type DEBUG -Message "credentialInstanceId '$credIdStr' not found in enumerated credentials for $sddcFqdn"
                    }
                }

                if ($null -eq $matchedCred -and $vcfAdapterCredentials.Count -eq 1) {
                    # Strategy B: single credential — unambiguously belongs to this adapter.
                    $matchedCred = $vcfAdapterCredentials[0]
                    Write-LogMessage -Type DEBUG -Message "Single VcfAdapter credential — assigning to $sddcFqdn"
                }

                if ($null -ne $matchedCred) {
                    $availableFields = ($matchedCred.Fields | ForEach-Object { $_.Name }) -join ", "
                    $userField = $matchedCred.Fields |
                        Where-Object { $_.Name -ieq "user" -or $_.Name -ieq "username" } |
                        Select-Object -First 1
                    if ($null -ne $userField -and -not [String]::IsNullOrWhiteSpace($userField.Value)) {
                        $sddcUsername = [String]$userField.Value.Trim()
                        Write-LogMessage -Type DEBUG -Message "Resolved username '$sddcUsername' for $sddcFqdn"
                    } else {
                        Write-LogMessage -Type DEBUG -Message "No 'USER'/'username' field in matched credential for $sddcFqdn (available: $availableFields)"
                    }
                } else {
                    Write-LogMessage -Type DEBUG -Message "Could not match a credential to $sddcFqdn ($($vcfAdapterCredentials.Count) credentials available, credentialInstanceId='$credIdStr')"
                }
            }

            Write-LogMessage -Type INFO -Message "Found SDDC Manager: $sddcFqdn (instance: $instanceName)"
            $results.Add([PSCustomObject]@{
                Fqdn          = $sddcFqdn
                InstanceName  = $instanceName
                SddcUsername  = $sddcUsername
            })
        }

        if ($results.Count -eq 0) {
            Write-LogMessage -Type DEBUG -Message "No SDDC Manager instances found via VcfAdapter."
        } else {
            Write-LogMessage -Type INFO -Message "Found $($results.Count) SDDC Manager(s)"
        }

        # Query the product version while the Connect-VcfOpsServer session is still active.
        # Callers can include this in their JSON output without a second round-trip.
        $opsVersion = ""
        try {
            $versionInfo = Invoke-VcfOpsGetCurrentVersionOfServer -ErrorAction Stop
            $opsVersion = [String]($versionInfo.ReleaseName ?? $versionInfo.releaseName)
            Write-LogMessage -Type DEBUG -Message "VCF Operations version: $opsVersion"
        }
        catch {
            Write-LogMessage -Type DEBUG -Message "Could not retrieve VCF Operations version: $($_.Exception.Message)"
        }

        # Enumerate standalone vCenters from the VMWARE adapter while the session is
        # still active — no extra connection needed.  Used by VVF9 environments where
        # SDDC Manager is absent but standalone vCenters are registered with VCF Operations.
        $vcenterFqdns = [System.Collections.Generic.List[String]]::new()
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
                $vcenterFqdns.Add([String]$vcUrl.Trim())
            }
            if ($vcenterFqdns.Count -gt 0) {
                Write-LogMessage -Type INFO -Message "Discovered $($vcenterFqdns.Count) standalone vCenter(s) from VCF Operations: $(($vcenterFqdns | Sort-Object) -join ', ')"
            } else {
                Write-LogMessage -Type INFO -Message "Discovered 0 standalone vCenter(s) from VCF Operations."
            }
        }
        catch {
            Write-LogMessage -Type DEBUG -Message "Standalone vCenter enumeration failed: $($_.Exception.Message)"
        }

        return [PSCustomObject]@{
            Instances     = $results.ToArray()
            OpsVersion    = $opsVersion.Trim()
            VcenterFqdns  = $vcenterFqdns.ToArray()
        }
    }
    catch [System.InvalidOperationException] { throw }
    catch {
        $err = "Discovery failed: $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $VcfOpsServer -Context 'VCF Operations')"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }
    finally {
        if ($null -ne $conn) { Disconnect-VcfOpsServer -Server $conn -Force -ErrorAction SilentlyContinue | Out-Null }
    }
}
function Get-SddcCredentialFromFleetManager {

    <#
        .SYNOPSIS
        Retrieve the SDDC Manager service-account username and password from the Fleet Manager locker.

        .DESCRIPTION
        Used for VCF 9.0 environments where the LCops Fleet Manager stores SDDC Manager credentials
        in its locker. Performs two REST calls against the Fleet Manager appliance:

        Step 1 — GET /lcm/lcops/api/sddc-managers (Basic auth: admin@local / FmPassword)
          Returns SddcManagerDTO objects with:
            sddcManagerServiceAccountUsername — plaintext
            sddcManagerServiceAccountPassword — locker reference "locker:password:<vmid>:<alias>"

        Step 2 — POST /lcm/locker/api/v2/passwords/{vmid}/decrypted
          Body: { "rootPassword": "<locker_reference_from_step_1>" }
          The Fleet Manager accepts the locker reference itself as the authorization proof —
          no separate appliance root password is required.
          Returns: { "password": "<plaintext>" }

        Outputs JSON to stdout: { "sddcUsername": "...", "sddcPassword": "...", "error": null }

        .PARAMETER FmServer
        Fleet Manager FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Per-request timeout in seconds.

        .EXAMPLE
        $env:VCF_FM_PASSWORD = 'secret'
        Get-SddcCredentialFromFleetManager -FmServer "flt-lcm01.sfo.rainpole.io"

        .NOTES
        Password is read from the VCF_FM_PASSWORD environment variable.
        Only applicable to VCF 9.0 (LCops-based Fleet Manager). VCF 9.1 uses a different
        architecture and does not expose credentials via this API.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$FmServer,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    $fmPassword = Get-RequiredInventoryPassword -ComponentName "Fleet Manager" -EnvVarName "VCF_FM_PASSWORD"

    $credentials = [System.Convert]::ToBase64String(
        [System.Text.Encoding]::UTF8.GetBytes("admin@local:$fmPassword")
    )
    $headers = @{
        "Authorization" = "Basic $credentials"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }
    Write-LogMessage -Type DEBUG -Message "Querying SDDC Manager list from Fleet Manager: $FmServer"
    try {
        $sddcResponse = Invoke-RestMethod -Uri "https://$FmServer/lcm/lcops/api/sddc-managers" `
            -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
    }
    catch {
        $statusCode = $_.Exception.Response?.StatusCode?.value__
        if ($statusCode -eq 401) {
            $err = "Fleet Manager authentication failed for $FmServer — verify the admin@local password."
            Write-LogMessage -Type ERROR -Message $err
            throw [System.InvalidOperationException]::new($err)
        }
        $err = "Fleet Manager SDDC Manager query failed on $FmServer — $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $FmServer -Context 'Fleet Manager')"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    # Response may be a direct array or wrapped in a property.
    $sddcList = if ($sddcResponse -is [System.Collections.IEnumerable] -and $sddcResponse -isnot [String]) {
        @($sddcResponse)
    } elseif ($null -ne $sddcResponse.content) {
        @($sddcResponse.content)
    } elseif ($null -ne $sddcResponse.sddcManagers) {
        @($sddcResponse.sddcManagers)
    } else {
        @($sddcResponse)
    }

    if ($sddcList.Count -eq 0) {
        $err = "No SDDC Manager entries found in Fleet Manager locker on $FmServer"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    # Prefer the primary entry; fall back to first.
    $entry = $sddcList | Where-Object { $_.primary -eq $true } | Select-Object -First 1
    if ($null -eq $entry) { $entry = $sddcList[0] }

    $sddcUsername = [String]($entry.sddcManagerServiceAccountUsername ?? "").Trim()
    $lockerRef    = [String]($entry.sddcManagerServiceAccountPassword ?? "").Trim()

    if ([String]::IsNullOrWhiteSpace($sddcUsername)) {
        $err = "SDDC Manager username not found in Fleet Manager response from $FmServer"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    Write-LogMessage -Type DEBUG -Message "Found SDDC Manager service account: $sddcUsername"

    if ([String]::IsNullOrWhiteSpace($lockerRef) -or -not $lockerRef.StartsWith("locker:password:")) {
        # Password returned directly (not a locker reference) — older deployments.
        Write-LogMessage -Type DEBUG -Message "SDDC Manager password returned as plaintext (no locker reference)"
        return [PSCustomObject]@{ SddcUsername = $sddcUsername; SddcPassword = $lockerRef; Error = $null }
    }

    # Parse vmid from "locker:password:<vmid>:<alias>"
    $parts = $lockerRef.Split(":")
    if ($parts.Count -lt 3) {
        $err = "Unexpected locker reference format: '$lockerRef'."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }
    $vmid = $parts[2]
    if ($vmid -notmatch '^[\w-]+$') {
        $err = "Unexpected vmid format in locker reference — path manipulation blocked: '$lockerRef'."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    Write-LogMessage -Type DEBUG -Message "Decrypting SDDC Manager password via locker vmid $vmid"
    try {
        $decryptBody = [PSCustomObject]@{ rootPassword = $lockerRef } | ConvertTo-Json -Compress
        $decryptResponse = Invoke-RestMethod -Uri "https://$FmServer/lcm/locker/api/v2/passwords/$vmid/decrypted" `
            -Method POST -Headers $headers -Body $decryptBody `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
    }
    catch {
        $err = "Fleet Manager locker decrypt failed for vmid $vmid on $FmServer — $(Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message -Server $FmServer -Context 'Fleet Manager')"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    $plaintext = [String]($decryptResponse.password ?? "").Trim()
    if ([String]::IsNullOrWhiteSpace($plaintext)) {
        $err = "Decrypted password field was empty for vmid $vmid on $FmServer"
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    Write-LogMessage -Type INFO -Message "Successfully retrieved SDDC Manager credential from Fleet Manager locker"
    return [PSCustomObject]@{ SddcUsername = $sddcUsername; SddcPassword = $plaintext; Error = $null }
}
function Get-VrslcmFromSddcManager {

    <#
        .SYNOPSIS
        Discover the vRSLCM FQDN registered with SDDC Manager via GET /v1/vrslcms.

        .DESCRIPTION
        Authenticates against SDDC Manager using Connect-VcfSddcManagerServer (the same
        mechanism used by Get-SddcManagerInventory), extracts the session token, then queries
        GET /v1/vrslcms to retrieve vRealize Suite Lifecycle Manager instances. Supported in
        VCF 5.x only — the endpoint does not exist in VCF 9.x.

        Returns a structured result with VrslcmFqdn, VrslcmVersion, and Error. VrslcmFqdn is
        null when no instance is registered (Error is also null) or when discovery fails (Error
        contains the reason). This function never throws — failures are returned as an error
        string so the caller can treat auto-discovery as a best-effort step.

        .PARAMETER Server
        SDDC Manager FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300, default 30).

        .PARAMETER User
        SDDC Manager username (e.g. administrator@vsphere.local).

        .EXAMPLE
        $env:SDDC_MANAGER_PASSWORD = (Read-Host -Prompt 'SDDC Manager password')
        $result = Get-VrslcmFromSddcManager -Server 'sddc.sfo.example.com' -User 'administrator@vsphere.local'
        if ($result.VrslcmFqdn) { Write-LogMessage -Type INFO -Message "vRSLCM: $($result.VrslcmFqdn) v$($result.VrslcmVersion)" }

        .OUTPUTS
        [PSCustomObject] with properties: VrslcmFqdn (String or null), VrslcmVersion (String), Error (String or null).

        .NOTES
        Password is read from the SDDC_MANAGER_PASSWORD environment variable.
        Uses Connect-VcfSddcManagerServer for auth so SSO/vIDM-integrated SDDC Managers are
        handled correctly — direct POST /v1/tokens calls return 401 on those environments.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$User
    )

    $password = Get-InventoryPassword -ComponentName "SDDC Manager" -EnvVarName "SDDC_MANAGER_PASSWORD"
    if ($null -eq $password) {
        $err = "SDDC_MANAGER_PASSWORD environment variable is not set."
        return [PSCustomObject]@{ VrslcmFqdn = $null; VrslcmVersion = ""; Error = $err }
    }

    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
    $password = $null  # SecureString holds the credential from here; clear the plain-text reference.
    $conn = $null

    try {
        # -IgnoreInvalidCertificate: SDDC Manager uses a self-signed certificate in most deployments.
        # Use -User/-Password directly rather than -Credential: the PSCredential parameter path
        # triggers an IDENTITY_UNAUTHORIZED_ENTITY error from some SDDC Manager builds.
        $conn = Connect-VcfSddcManagerServer -Server $Server -User $User -Password $securePassword `
            -IgnoreInvalidCertificate -ErrorAction Stop
        $securePassword.Dispose()
        $securePassword = $null  # Session established; credential no longer needed in memory.

        $accessToken = [String]($conn.SessionSecret ?? "").Trim()
        if ([String]::IsNullOrWhiteSpace($accessToken)) {
            $err = "vRSLCM discovery: SDDC Manager $Server did not return an access token."
            Write-LogMessage -Type DEBUG -Message $err
            return [PSCustomObject]@{ VrslcmFqdn = $null; VrslcmVersion = ""; Error = $err }
        }

        $headers = @{ "Authorization" = "Bearer $accessToken"; "Accept" = "application/json" }
        $accessToken = $null  # Token is now only in the Authorization header value.
        $response = Invoke-RestMethod -Uri "https://$Server/v1/vrslcms" `
            -Method GET -Headers $headers `
            -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $elements = @($response.elements | Where-Object { $null -ne $_ })
        if ($elements.Count -eq 0) {
            Write-LogMessage -Type INFO -Message "No vRSLCM instances registered with SDDC Manager: $Server"
            return [PSCustomObject]@{ VrslcmFqdn = $null; VrslcmVersion = ""; Error = $null }
        }

        $vrslcm  = $elements[0]
        $fqdn    = [String]($vrslcm.fqdn ?? "").Trim()
        $version = [String]($vrslcm.version ?? "").Trim()

        if ([String]::IsNullOrWhiteSpace($fqdn)) {
            $err = "vRSLCM element found in SDDC Manager $Server response but the FQDN field is empty."
            Write-LogMessage -Type WARNING -Message $err
            return [PSCustomObject]@{ VrslcmFqdn = $null; VrslcmVersion = ""; Error = $err }
        }

        Write-LogMessage -Type INFO -Message "Discovered vRSLCM via SDDC Manager: $fqdn (v$version)"
        return [PSCustomObject]@{ VrslcmFqdn = $fqdn; VrslcmVersion = $version; Error = $null }
    }
    catch {
        $err = "vRSLCM discovery failed for $Server — $($_.Exception.Message)"
        Write-LogMessage -Type DEBUG -Message $err
        return [PSCustomObject]@{ VrslcmFqdn = $null; VrslcmVersion = ""; Error = $err }
    }
    finally {
        # Dispose the SecureString if Connect-VcfSddcManagerServer threw before the try body could.
        if ($null -ne $securePassword) {
            $securePassword.Dispose()
        }
        if ($null -ne $conn) {
            Disconnect-VcfSddcManagerServer -Server $conn -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
function Get-VcfOpsVersion {

    <#
        .SYNOPSIS
        Return the product version string of a connected VCF Operations server.

        .DESCRIPTION
        Calls GET /api/versions/current via Invoke-VcfOpsGetCurrentVersionOfServer and
        extracts the releaseName field (e.g. "VCF Operations 9.0.2.0").  The caller must
        already be connected via Connect-VcfOpsServer.

        .PARAMETER VcfOpsServer
        VCF Operations server FQDN or IP address.

        .EXAMPLE
        $ver = Get-VcfOpsVersion -VcfOpsServer "ops.example.com"
        Write-LogMessage -Type INFO -Message "VCF Operations version: $ver"

        .OUTPUTS
        [String] The releaseName string (e.g. "VCF Operations 9.1.0.0"), or an empty
        string if the version cannot be determined.

        .NOTES
        Caller must already be connected via Connect-VcfOpsServer. Returns empty string rather than throwing when the version cannot be determined.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$VcfOpsServer
    )

    try {
        $versionInfo = Invoke-VcfOpsGetCurrentVersionOfServer -ErrorAction Stop
        $releaseName = [String]($versionInfo.ReleaseName ?? $versionInfo.releaseName)
        if (-not [String]::IsNullOrWhiteSpace($releaseName)) {
            Write-LogMessage -Type DEBUG -Message "VCF Operations version: $releaseName"
            return $releaseName.Trim()
        }
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Could not retrieve VCF Operations version from $VcfOpsServer — $($_.Exception.Message)"
    }

    return ""
}
function Get-FleetManagerFromVcfOps {

    <#
        .SYNOPSIS
        Discover the VCF Fleet Manager FQDN from VCF Operations (9.0 and 9.1).

        .DESCRIPTION
        Dispatches to the version-appropriate API based on VcfOpsVersion:

        VCF Operations 9.1+:
          GET /suite-api/internal/components?componentType=VSP (Bearer vRealizeOpsToken).
          The response carries a "components" array; each entry may have properties.fleetFqdn.

        VCF Operations 9.0:
          GET /casa/capabilities (Basic auth with VCF Operations admin credentials).
          The CASA service requires Basic auth — it does not accept Suite API tokens.
          Finds the entry whose "key" equals "ops-lcm" and extracts the Fleet Manager
          FQDN from nodes[].addresses[type="Fqdn"].value or the legacy baseUrl field.

        When VcfOpsVersion is empty or unparseable, both strategies are attempted in
        order (Suite API first, then CASA) so discovery is still possible when version
        information has not yet been obtained.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300, default 30).

        .PARAMETER VcfOpsServer
        VCF Operations server FQDN or IP address.

        .PARAMETER VcfOpsUser
        VCF Operations username (e.g. admin@local).

        .PARAMETER VcfOpsVersion
        VCF Operations version string as reported by the server (e.g. "VCF Operations 9.1.0.0").
        Used to select the correct discovery strategy. When omitted both strategies are tried.

        .EXAMPLE
        $result = Get-FleetManagerFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" -VcfOpsVersion "VCF Operations 9.1.0.0"
        Write-LogMessage -Type INFO -Message "Fleet Manager: $($result.FleetFqdn) — user: $($result.VcfFMUser)"

        .NOTES
        Credentials are retrieved from the VCF_OPS_PASSWORD environment variable.
        Mutates nothing; purely a read-only REST discovery call.

        .OUTPUTS
        [PSCustomObject] with properties: FleetFqdn (String) and VcfFMUser (String).
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$VcfOpsServer,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$VcfOpsUser,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$VcfOpsVersion = ''
    )

    $password = Get-RequiredInventoryPassword -ComponentName "VCF Operations" -EnvVarName "VCF_OPS_PASSWORD"

    # Parse the major.minor version from the supplied version string so the correct
    # discovery strategy is chosen without string-matching the raw version label.
    # Examples: "VCF Operations 9.1.0.0" → 901; "9.0.0.0" → 900; "" → 0 (unknown).
    $opsMajorMinor = 0
    if (-not [String]::IsNullOrWhiteSpace($VcfOpsVersion) -and $VcfOpsVersion -match '(\d+)\.(\d+)') {
        $opsMajorMinor = [Int]$Matches[1] * 100 + [Int]$Matches[2]
    }

    # Strategy selection:
    #   9.1+    → Suite API only (CASA returns 404 on these builds)
    #   9.0.x   → CASA only (Suite API /internal/components endpoint does not exist on 9.0)
    #   unknown → try Suite API first, then CASA (safe default when version is not yet known)
    $tryVsp  = ($opsMajorMinor -eq 0 -or $opsMajorMinor -ge 901)
    $tryCasa = ($opsMajorMinor -eq 0 -or ($opsMajorMinor -ge 900 -and $opsMajorMinor -lt 901))
    Write-LogMessage -Type DEBUG -Message "Fleet Manager discovery strategy: version=$VcfOpsVersion (parsed=$opsMajorMinor) tryVsp=$tryVsp tryCasa=$tryCasa"

    $fleetFqdn = $null
    $vcfFMUser = $null

    # ── Strategy 1: Suite API internal components (VCF 9.1+) ─────────────────
    # GET /suite-api/internal/components?componentType=VSP
    # Response: { "components": [ { "properties": { "fleetFqdn": "...", ... } } ] }
    # Requires vRealizeOpsToken (Bearer); Basic auth is not accepted by the Suite API.
    if ($tryVsp -and [String]::IsNullOrWhiteSpace($fleetFqdn)) {
        $vspToken = Get-VcfOpsRestToken -Password $password -Server $VcfOpsServer -TimeoutSeconds $TimeoutSeconds -User $VcfOpsUser
        $headersInternal = @{
            "Authorization"                     = "vRealizeOpsToken $vspToken"
            "X-vRealizeOps-API-use-unsupported" = "true"
            "Accept"                            = "application/json"
        }
        Write-LogMessage -Type DEBUG -Message "Querying VSP components from $VcfOpsServer (Suite API)"
        try {
            $vspResponse = Invoke-RestMethod -Uri "https://$VcfOpsServer/suite-api/internal/components?componentType=VSP" `
                -Method GET -Headers $headersInternal -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

            # The Suite API wraps the array under a "components" key (9.1+). Historic builds
            # used "component" (singular) or "componentList". Try each in order, then fall
            # back to treating the response itself as the array (bare-array response).
            $components = if ($null -ne $vspResponse.components) {
                @($vspResponse.components)
            } elseif ($null -ne $vspResponse.component) {
                @($vspResponse.component)
            } elseif ($null -ne $vspResponse.componentList) {
                @($vspResponse.componentList)
            } elseif ($vspResponse -is [System.Collections.IEnumerable] -and $vspResponse -isnot [String]) {
                @($vspResponse)
            } else {
                @()
            }
            Write-LogMessage -Type DEBUG -Message "Suite API returned $($components.Count) VSP component(s)"

            foreach ($component in $components) {
                $candidate = [String]($component.properties.fleetFqdn ?? "")
                if (-not [String]::IsNullOrWhiteSpace($candidate)) {
                    $fleetFqdn = $candidate.Trim()
                    $vcfFMUser = "admin@vsp.local"
                    Write-LogMessage -Type DEBUG -Message "Discovered Fleet Manager via Suite API VSP components: $fleetFqdn"
                    break
                }
            }
            if ([String]::IsNullOrWhiteSpace($fleetFqdn)) {
                Write-LogMessage -Type DEBUG -Message "Suite API VSP components returned $($components.Count) item(s) but none contained fleetFqdn"
            }
        }
        catch {
            Write-LogMessage -Type DEBUG -Message "Suite API VSP component query failed on $VcfOpsServer — $($_.Exception.Message)"
        }
    }

    # ── Strategy 2: CASA capabilities API (VCF 9.0) ───────────────────────────
    # GET /casa/capabilities (9.0). Requires Basic auth — Suite API tokens are not accepted.
    # Two credential formats are tried: bare username (e.g. "admin") and full UPN ("admin@local").
    if ($tryCasa -and [String]::IsNullOrWhiteSpace($fleetFqdn)) {
        $bareUser = $VcfOpsUser -replace '@.*$', ''
        $basicBareCredential = [System.Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes("${bareUser}:${password}")
        )
        $basicFullCredential = [System.Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes("${VcfOpsUser}:${password}")
        )
        if ($bareUser -eq $VcfOpsUser) {
            $casaHeaderSets = @(
                @{ "Authorization" = "Basic $basicBareCredential"; "Accept" = "application/json" }
            )
        } else {
            $casaHeaderSets = @(
                @{ "Authorization" = "Basic $basicBareCredential"; "Accept" = "application/json" },
                @{ "Authorization" = "Basic $basicFullCredential"; "Accept" = "application/json" }
            )
        }

        foreach ($casaPath in @("/casa/capabilities")) {
            if (-not [String]::IsNullOrWhiteSpace($fleetFqdn)) { break }
            foreach ($headers in $casaHeaderSets) {
                if (-not [String]::IsNullOrWhiteSpace($fleetFqdn)) { break }
                $authLabel = "Basic($bareUser)"
                Write-LogMessage -Type DEBUG -Message "Querying capabilities from $VcfOpsServer at $casaPath (auth: $authLabel)"
                try {
                    $capsResponse = Invoke-RestMethod -Uri "https://$VcfOpsServer$casaPath" `
                        -Method GET -Headers $headers -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop
                    $capsList = if ($capsResponse -is [System.Collections.IEnumerable] -and $capsResponse -isnot [String]) {
                        @($capsResponse)
                    } elseif ($null -ne $capsResponse.capabilities) {
                        @($capsResponse.capabilities)
                    } else {
                        @($capsResponse)
                    }

                    $lcmEntry = $capsList | Where-Object { $_.key -eq "ops-lcm" } | Select-Object -First 1
                    if ($null -ne $lcmEntry) {
                        # Canonical FQDN location: nodes[].addresses[type="Fqdn"].value.
                        # Some versions also expose a legacy baseUrl field — check both.
                        $fqdnAddress = $null
                        foreach ($node in @($lcmEntry.nodes)) {
                            if ($null -eq $node) { continue }
                            $fqdnAddress = @($node.addresses) | Where-Object { $_.type -ieq "Fqdn" } | Select-Object -First 1
                            if ($null -ne $fqdnAddress) { break }
                        }
                        if ($null -ne $fqdnAddress -and -not [String]::IsNullOrWhiteSpace($fqdnAddress.value)) {
                            $fleetFqdn = [String]$fqdnAddress.value.Trim()
                        } elseif (-not [String]::IsNullOrWhiteSpace($lcmEntry.baseUrl)) {
                            $fleetFqdn = [String]$lcmEntry.baseUrl.TrimEnd('/') -replace '^https?://', ''
                        }
                        if (-not [String]::IsNullOrWhiteSpace($fleetFqdn)) {
                            $vcfFMUser = "admin@local"
                            Write-LogMessage -Type DEBUG -Message "Discovered Fleet Manager via CASA $casaPath : $fleetFqdn (user: $vcfFMUser)"
                        } else {
                            Write-LogMessage -Type DEBUG -Message "ops-lcm entry found at $casaPath but no Fqdn address or baseUrl present"
                        }
                    } else {
                        Write-LogMessage -Type DEBUG -Message "ops-lcm entry not found at $casaPath"
                    }
                }
                catch {
                    Write-LogMessage -Type DEBUG -Message "CASA query at $casaPath failed ($($_.Exception.Message))"
                }
            }
        }
    }

    if ([String]::IsNullOrWhiteSpace($fleetFqdn)) {
        $err = "Fleet Manager FQDN not found in VCF Operations $VcfOpsServer — verify that a Fleet Manager is registered."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    Write-LogMessage -Type INFO -Message "Discovered Fleet Manager: $fleetFqdn"
    return [PSCustomObject]@{
        FleetFqdn = $fleetFqdn
        VcfFMUser = $vcfFMUser
    }
}
function ConvertTo-VcfAdvisoryVersion {

    <#
        .SYNOPSIS
        Derive the advisory-comparable form of a 5-part VCF 9.x build version string.

        .DESCRIPTION
        VCF 9.x APIs return 5-part version strings such as "9.1.0.0100.25435105" (Update 1
        builds) or "9.1.0.0.25370367" (base-release builds). The 4th segment is an update-level
        indicator; the 5th segment is the unique per-build number that advisory fixedVersion
        fields are authored against. This function extracts segments 1, 2, 3, and 5, producing
        the 4-part comparison form used in advisories: "9.1.0.25435105" and "9.1.0.25370367".
        Strings with fewer than 5 segments are returned unchanged.

        .PARAMETER Version
        Raw version string from a VCF API (e.g. "9.1.0.0100.25435105" or "9.0.2.0200").

        .EXAMPLE
        ConvertTo-VcfAdvisoryVersion -Version '9.1.0.0100.25435105'
        # returns "9.1.0.25435105"

        ConvertTo-VcfAdvisoryVersion -Version '9.1.0.0.25346025'
        # returns "9.1.0.25346025"

        ConvertTo-VcfAdvisoryVersion -Version '9.0.2.0200'
        # returns "9.0.2.0200" (already 4-part — unchanged)

        .OUTPUTS
        [String] Advisory-comparable 4-part version, or the original string when fewer than
        5 segments are present.

        .NOTES
        Pure string transformation. Does not validate the version format beyond segment count.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [ValidateNotNull()] [String]$Version
    )

    $parts = $Version.Split('.')
    if ($parts.Length -ge 5) {
        # Use segments 1,2,3,5 — the per-build number becomes the 4th comparison segment,
        # matching the form used in advisory fixedVersion fields.
        return "$($parts[0]).$($parts[1]).$($parts[2]).$($parts[4])"
    }
    return $Version
}
function Get-FleetManagerReleaseVersions {

    <#
        .SYNOPSIS
        Retrieve the Fleet Manager release version catalog.

        .DESCRIPTION
        Paginates through GET /fleet-lcm/v1/release-versions and returns every known VCF
        release version paired with the per-component build numbers it contains.

        Requires a VSP bearer token — despite earlier OpenAPI spec claims, the endpoint
        returns HTTP 401 on VCF 9.1+ Fleet Controllers unless an Authorization header is
        supplied. Pass the token obtained from Get-VspBearerToken via BearerToken.

        Only available on VCF 9.1+ Fleet Controllers (VSP fleet-lcm path).
        Returns an empty array if the endpoint is unreachable or unavailable.

        .PARAMETER BearerToken
        VSP bearer token from POST /api/v1/identity/token. When empty, the request is sent
        without an Authorization header (fails on most installations).

        .PARAMETER Server
        Fleet Controller FQDN or IP address.

        .PARAMETER TimeoutSeconds
        Request timeout in seconds (1-300, default 30).

        .EXAMPLE
        $token  = Get-VspBearerToken -Server 'flt-fc01.sfo.rainpole.io' -User 'admin@vsp.local' -Password $pw
        $catalog = Get-FleetManagerReleaseVersions -Server 'flt-fc01.sfo.rainpole.io' -BearerToken $token
        $catalog | Select-Object VcfRelease, ComponentName, BuildNumbers

        .OUTPUTS
        [PSCustomObject[]] One object per component per release:
          VcfRelease    — VCF release version string (e.g. "9.1.0.0")
          ComponentType — API type key (e.g. "OPS", "FLEET_LCM")
          ComponentName — Display name (e.g. "VCF Operations")
          BuildNumbers  — String[] of build numbers for this component in this release
                          (e.g. @("9.1.0.0100.25435105", "9.1.0.0.25346025"))

        .NOTES
        Returns an empty array when the endpoint is unavailable or the token is invalid.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [ValidateNotNull()] [String]$BearerToken = "",
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 300)] [Int]$TimeoutSeconds = 30
    )

    $results    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $pageNumber = 1
    $totalPages = 1
    $authHeaders = if (-not [String]::IsNullOrWhiteSpace($BearerToken)) {
        @{ "Authorization" = "Bearer $BearerToken"; "Accept" = "application/json" }
    } else {
        @{ "Accept" = "application/json" }
    }

    try {
        while ($pageNumber -le $totalPages) {
            $uri      = "https://$Server/fleet-lcm/v1/release-versions?pageNumber=$pageNumber&pageSize=100"
            $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $authHeaders `
                -SkipCertificateCheck -TimeoutSec $TimeoutSeconds -ErrorAction Stop

            if ($null -ne $response.pageMetadata -and $null -ne $response.pageMetadata.totalPages) {
                $totalPages = [Int]$response.pageMetadata.totalPages
            }

            foreach ($release in $response.elements) {
                $vcfRelease = [String]$release.version
                foreach ($comp in $release.components) {
                    $buildNumbers = @($comp.versions | Where-Object { -not [String]::IsNullOrWhiteSpace($_) })
                    $results.Add([PSCustomObject]@{
                        VcfRelease    = $vcfRelease
                        ComponentType = [String]$comp.type
                        ComponentName = [String]$comp.publicName
                        BuildNumbers  = $buildNumbers
                    })
                }
            }

            $pageNumber++
        }

        Write-LogMessage -Type DEBUG -Message "Fleet version catalog: $($results.Count) component-release entries from $Server"
    }
    catch {
        Write-LogMessage -Type DEBUG -Message "Fleet release-versions endpoint not available on $Server — $($_.Exception.Message)"
    }

    # Comma operator preserves the array even when empty; PowerShell discards an empty
    # collection returned without it, delivering $null to the caller instead of @().
    , $results.ToArray()
}
function ConvertTo-FleetBuildNumberMap {

    <#
        .SYNOPSIS
        Build a reverse lookup from component build number to VCF release version string.

        .DESCRIPTION
        Inverts the catalog returned by Get-FleetManagerReleaseVersions into a hashtable
        keyed by individual build number strings. Each value is the VCF release version
        (e.g. "9.0.2.0200") that the build belongs to. When a build number appears in more
        than one release entry the first association wins.

        Used by EntryPoint to normalize Fleet-reported build numbers (e.g. "9.0.2.25370929")
        to the advisory-compatible release version before patching the inventory, ensuring
        the "Current Version" column matches the format used in advisory fixed-version fields.

        .PARAMETER Catalog
        Array returned by Get-FleetManagerReleaseVersions.

        .EXAMPLE
        $catalog = Get-FleetManagerReleaseVersions -Server 'flt-fc01.sfo.rainpole.io'
        $map     = ConvertTo-FleetBuildNumberMap -Catalog $catalog
        $release = $map['9.1.0.0100.25435105']   # returns "9.1.0.25435105"

        .OUTPUTS
        [Hashtable] Keys are build number strings; values are VCF release version strings.

        .NOTES
        Pure transformation function. Does not mutate any module-scope variables. When a build number appears in more than one release, the first association wins.
    #>

    [CmdletBinding()]
    [OutputType([Hashtable])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [ValidateNotNull()] [Object[]]$Catalog
    )

    $map = @{}
    foreach ($entry in $Catalog) {
        foreach ($build in $entry.BuildNumbers) {
            $buildStr = [String]$build
            if (-not [String]::IsNullOrWhiteSpace($buildStr) -and -not $map.ContainsKey($buildStr)) {
                # Derive the advisory-comparable version: segments 1,2,3,5 (build number as 4th).
                # "9.1.0.0100.25435105" → "9.1.0.25435105"; "9.1.0.0.25346025" → "9.1.0.25346025".
                $map[$buildStr] = ConvertTo-VcfAdvisoryVersion -Version $buildStr
            }
        }
    }
    return $map
}

#endregion
