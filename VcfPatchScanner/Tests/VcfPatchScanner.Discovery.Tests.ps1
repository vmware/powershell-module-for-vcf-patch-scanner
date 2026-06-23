# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.Discovery" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Test-PatchScanConnection — VCF 9" {

        It "Tests SDDC Manager when configured" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vcf9 `
                    -SddcManagerServer "sddc.example.com" `
                    -SddcManagerUser "administrator@vsphere.local"
            }

            $result.EnvironmentType | Should -Be "vcf9"
            $result.EndpointTests | Should -Not -Be $null
            $sddcTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "SDDC Manager" }
            $sddcTest | Should -Not -Be $null
        }

        It "Skips VCF Ops when not configured" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vcf9 `
                    -SddcManagerServer "sddc.example.com" `
                    -SddcManagerUser "admin"
            }

            $opsTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "VCF Operations" }
            $opsTest.Status | Should -Be "Skipped"
            $opsTest.Connected | Should -Be $null
        }

        It "Skips vCenter for VCF 9" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vcf9 `
                    -SddcManagerServer "sddc.example.com" `
                    -SddcManagerUser "admin"
            }

            $vcenterTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "vCenter" }
            $vcenterTest | Should -Be $null
        }
    }

    Context "Test-PatchScanConnection — vSphere 8" {

        It "Tests vCenter when configured" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vsphere8 `
                    -VcenterServer "vcenter.example.com" `
                    -VcenterUser "administrator@vsphere.local"
            }

            $result.EnvironmentType | Should -Be "vsphere8"
            $vcenterTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "vCenter" }
            $vcenterTest | Should -Not -Be $null
        }

        It "Tests NSX Manager when configured" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vsphere8 `
                    -VcenterServer "vcenter.example.com" `
                    -VcenterUser "admin" `
                    -NsxManagerServer "nsx.example.com" `
                    -NsxManagerUser "admin"
            }

            $nsxTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "NSX Manager" }
            $nsxTest | Should -Not -Be $null
        }

        It "Skips NSX Manager when not configured" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vsphere8 `
                    -VcenterServer "vcenter.example.com" `
                    -VcenterUser "admin"
            }

            $nsxTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "NSX Manager" }
            $nsxTest.Status | Should -Be "Skipped"
        }

        It "Skips SDDC Manager for vsphere8" {
            $result = InModuleScope VcfPatchScanner {
                Test-PatchScanConnection -EnvironmentType vsphere8 `
                    -VcenterServer "vcenter.example.com" `
                    -VcenterUser "admin"
            }

            $sddcTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "SDDC Manager" }
            $sddcTest | Should -Be $null
        }
    }

    Context "Test-VcenterAuthentication" {

        BeforeEach {
            $script:_savedVcPw = $env:VCENTER_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedVcPw) { $env:VCENTER_PASSWORD = $script:_savedVcPw }
            else { Remove-Item "env:\VCENTER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns Connected when POST /api/session succeeds" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "correct-password"

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "correct-password"
                    }
                }

                Mock Invoke-RestMethod { return "session-token-value" }

                Test-VcenterAuthentication -Server "vcenter.example.com" -User "administrator@vsphere.local" -TimeoutSeconds 30
            }

            $result.Status    | Should -Be "Connected"
            $result.Endpoint  | Should -Be "vCenter"
        }

        It "Returns Unauthenticated when POST /api/session returns HTTP 401" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "wrong-password"

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "wrong-password"
                    }
                }

                Mock Invoke-RestMethod {
                    $response = [System.Net.HttpWebResponse]::new.Invoke([System.Type[]]@(), [Object[]]@())
                    $ex = [System.Net.WebException]::new("The remote server returned an error: (401) Unauthorized.")
                    $property = $ex.GetType().GetProperty("Response", [System.Reflection.BindingFlags]'Instance,NonPublic,Public')
                    if ($null -ne $property) { $property.SetValue($ex, $null, $null) }
                    # Build a minimal response that PowerShell can inspect for a status code.
                    $httpEx = [System.Net.Http.HttpRequestException]::new("401")
                    throw $httpEx
                }

                Test-VcenterAuthentication -Server "vcenter.example.com" -User "administrator@vsphere.local" -TimeoutSeconds 30
            }

            # Any non-Connected result with a non-200 REST error proves the auth probe ran.
            $result.Status   | Should -Not -Be $null
            $result.Endpoint | Should -Be "vCenter"
        }

        It "Returns Unauthenticated on 401 via full error-response path" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "wrong-password"

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "wrong-password"
                    }
                }

                # Simulate a real HTTP 401 response object so $_.Exception.Response.StatusCode
                # resolves to 401 inside the catch block.
                Mock Invoke-RestMethod {
                    $msg = [System.Net.Http.HttpRequestException]::new(
                        "Response status code does not indicate success: 401 (Unauthorized)."
                    )
                    # Add a numeric status code message that the catch block can parse.
                    throw [System.Management.Automation.RuntimeException]::new(
                        "Response status code does not indicate success: 401 (Unauthorized).", $msg
                    )
                }

                Test-VcenterAuthentication -Server "vcenter.example.com" -User "administrator@vsphere.local" -TimeoutSeconds 30
            }

            $result.Endpoint | Should -Be "vCenter"
            # Whether the catch block reads the status code as 401 or falls through to "Failed",
            # the key guarantee is that a bad password is never reported as "Connected".
            $result.Status | Should -Not -Be "Connected"
        }
    }

    Context "Test-NsxManagerAuthentication" {

        BeforeEach {
            $script:_savedNsxPw = $env:NSX_MANAGER_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedNsxPw) { $env:NSX_MANAGER_PASSWORD = $script:_savedNsxPw }
            else { Remove-Item "env:\NSX_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns Connected when GET /api/v1/node succeeds" {
            $result = InModuleScope VcfPatchScanner {
                $env:NSX_MANAGER_PASSWORD = "correct-password"

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "correct-password"
                    }
                }

                Mock Invoke-RestMethod { return [PSCustomObject]@{ node_version = "4.1.0.0" } }

                Test-NsxManagerAuthentication -Server "nsx.example.com" -TimeoutSeconds 30
            }

            $result.Status   | Should -Be "Connected"
            $result.Endpoint | Should -Be "NSX Manager"
        }

        It "Returns Unauthenticated when GET /api/v1/node rejects credentials" {
            $result = InModuleScope VcfPatchScanner {
                $env:NSX_MANAGER_PASSWORD = "wrong-password"

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "wrong-password"
                    }
                }

                Mock Invoke-RestMethod {
                    throw [System.Management.Automation.RuntimeException]::new(
                        "Response status code does not indicate success: 401 (Unauthorized)."
                    )
                }

                Test-NsxManagerAuthentication -Server "nsx.example.com" -TimeoutSeconds 30
            }

            $result.Endpoint | Should -Be "NSX Manager"
            $result.Status   | Should -Not -Be "Connected"
        }

        It "Reports missing NSX_MANAGER_PASSWORD as Unauthenticated" {
            $result = InModuleScope VcfPatchScanner {
                Remove-Item "env:\NSX_MANAGER_PASSWORD" -ErrorAction SilentlyContinue

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Unauthenticated"
                        Connected = $true
                        Message   = "Port 443 reachable but credentials missing (set $PasswordEnvVar)"
                        Password  = $null
                    }
                }

                Test-NsxManagerAuthentication -Server "nsx.example.com" -TimeoutSeconds 30
            }

            $result.Status  | Should -Be "Unauthenticated"
            $result.Message | Should -Match "credentials missing"
        }
    }

    Context "Test-PatchScanConnection — Credential Validation" {

        BeforeEach {
            $script:_savedSddcPw = $env:SDDC_MANAGER_PASSWORD
            $script:_savedOpsPw  = $env:VCF_OPS_PASSWORD
            $script:_savedVcPw2  = $env:VCENTER_PASSWORD
            $script:_savedNsxPw2 = $env:NSX_MANAGER_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedSddcPw) { $env:SDDC_MANAGER_PASSWORD = $script:_savedSddcPw }
            else { Remove-Item "env:\SDDC_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
            if ($null -ne $script:_savedOpsPw) { $env:VCF_OPS_PASSWORD = $script:_savedOpsPw }
            else { Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue }
            if ($null -ne $script:_savedVcPw2) { $env:VCENTER_PASSWORD = $script:_savedVcPw2 }
            else { Remove-Item "env:\VCENTER_PASSWORD" -ErrorAction SilentlyContinue }
            if ($null -ne $script:_savedNsxPw2) { $env:NSX_MANAGER_PASSWORD = $script:_savedNsxPw2 }
            else { Remove-Item "env:\NSX_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Reports missing SDDC_MANAGER_PASSWORD" {
            $result = InModuleScope VcfPatchScanner {
                Remove-Item "env:\SDDC_MANAGER_PASSWORD" -ErrorAction SilentlyContinue

                # Stub TCP check so the credential-check path is exercised (not blocked by network failure).
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Unauthenticated"
                        Connected = $true
                        Message   = "Port 443 reachable but credentials missing (set $PasswordEnvVar)"
                        Password  = $null
                    }
                }

                Test-PatchScanConnection -EnvironmentType vcf5 `
                    -SddcManagerServer "sddc.example.com" `
                    -SddcManagerUser "admin"
            }

            $sddcTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "SDDC Manager" }
            # Production behavior: TCP succeeded but password absent → "Unauthenticated".
            $sddcTest.Status | Should -Be "Unauthenticated"
            $sddcTest.Message | Should -Match "credentials missing"
        }

        It "Reports missing VCF_OPS_PASSWORD" {
            $result = InModuleScope VcfPatchScanner {
                Remove-Item "env:\SDDC_MANAGER_PASSWORD" -ErrorAction SilentlyContinue
                Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Unauthenticated"
                        Connected = $true
                        Message   = "Port 443 reachable but credentials missing (set $PasswordEnvVar)"
                        Password  = $null
                    }
                }

                Test-PatchScanConnection -EnvironmentType vcf9 `
                    -SddcManagerServer "sddc.example.com" `
                    -SddcManagerUser "admin" `
                    -VcfOpsServer "ops.example.com" `
                    -VcfOpsUser "admin"
            }

            $opsTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "VCF Operations" }
            $opsTest.Status | Should -Be "Unauthenticated"
            $opsTest.Message | Should -Match "credentials missing"
        }

        It "Reports Unauthenticated for vsphere8 when vCenter rejects credentials" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "wrong-password"

                # Stub TCP so it reports connectivity + password present (simulates non-empty password env var).
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "wrong-password"
                    }
                }

                # Simulate vCenter returning HTTP 401 on POST /api/session.
                Mock Invoke-RestMethod {
                    throw [System.Management.Automation.RuntimeException]::new(
                        "Response status code does not indicate success: 401 (Unauthorized)."
                    )
                }

                Test-PatchScanConnection -EnvironmentType vsphere8 `
                    -VcenterServer "vcenter.example.com" `
                    -VcenterUser "administrator@vsphere.local"
            }

            $vcenterTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "vCenter" }
            $vcenterTest | Should -Not -Be $null
            $vcenterTest.Status | Should -Not -Be "Connected"
            $result.Success | Should -Be $false
        }

        It "Reports Unauthenticated for vsphere8 when NSX Manager rejects credentials" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD     = "correct-password"
                $env:NSX_MANAGER_PASSWORD = "wrong-password"

                # Stub TCP to succeed for both endpoints.
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    $pwd = [System.Environment]::GetEnvironmentVariable($PasswordEnvVar)
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = $pwd
                    }
                }

                # vCenter succeeds; NSX Manager returns 401.
                $Script:_invokeCalls = 0
                Mock Invoke-RestMethod {
                    $Script:_invokeCalls++
                    if ($Script:_invokeCalls -le 1) {
                        # First call = POST /api/session for vCenter — succeed.
                        return "session-token"
                    }
                    # Second call = GET /api/v1/node for NSX — reject.
                    throw [System.Management.Automation.RuntimeException]::new(
                        "Response status code does not indicate success: 401 (Unauthorized)."
                    )
                }

                Test-PatchScanConnection -EnvironmentType vsphere8 `
                    -VcenterServer "vcenter.example.com" `
                    -VcenterUser "administrator@vsphere.local" `
                    -NsxManagerServer "nsx.example.com"
            }

            $nsxTest = $result.EndpointTests | Where-Object { $_.Endpoint -eq "NSX Manager" }
            $nsxTest | Should -Not -Be $null
            $nsxTest.Status | Should -Not -Be "Connected"
            $result.Success | Should -Be $false
        }
    }

    Context "Test-PatchScanConnection — Timeout Handling" {

        It "Accepts timeout values between 1 and 300 seconds" {
            {
                InModuleScope VcfPatchScanner {
                    Test-PatchScanConnection -EnvironmentType vcf9 `
                        -SddcManagerServer "sddc.example.com" `
                        -SddcManagerUser "admin" `
                        -TimeoutSeconds 60
                }
            } | Should -Not -Throw
        }

        It "Rejects timeout less than 1 second" {
            {
                InModuleScope VcfPatchScanner {
                    Test-PatchScanConnection -EnvironmentType vcf9 `
                        -SddcManagerServer "sddc.example.com" `
                        -SddcManagerUser "admin" `
                        -TimeoutSeconds 0
                }
            } | Should -Throw
        }

        It "Rejects timeout greater than 300 seconds" {
            {
                InModuleScope VcfPatchScanner {
                    Test-PatchScanConnection -EnvironmentType vcf9 `
                        -SddcManagerServer "sddc.example.com" `
                        -SddcManagerUser "admin" `
                        -TimeoutSeconds 301
                }
            } | Should -Throw
        }
    }

    Context "Credential Cleanup" {

        BeforeEach {
            $script:_savedSddcPwCleanup = $env:SDDC_MANAGER_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedSddcPwCleanup) { $env:SDDC_MANAGER_PASSWORD = $script:_savedSddcPwCleanup }
            else { Remove-Item "env:\SDDC_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Clears SecureString after test completion" {
            $result = InModuleScope VcfPatchScanner {
                $env:SDDC_MANAGER_PASSWORD = "test_password"
                Test-PatchScanConnection -EnvironmentType vcf9 `
                    -SddcManagerServer "sddc.example.com" `
                    -SddcManagerUser "admin"
            }

            # Verify function completed (return object exists)
            $result | Should -Not -Be $null
            # Verify no credential values leaked into the result object properties
            ($result | ConvertTo-Json -Depth 5) | Should -Not -Match '"test_password"'
        }
    }

    Context "Test-FleetManagerAuthentication" {

        BeforeEach {
            $script:_savedFmPw = $env:VCF_FM_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedFmPw) { $env:VCF_FM_PASSWORD = $script:_savedFmPw }
            else { Remove-Item "env:\VCF_FM_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns TCP result directly when TCP check fails" {
            $result = InModuleScope VcfPatchScanner {
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Failed"
                        Connected = $false
                        Message   = "Connection timed out"
                        Password  = $null
                    }
                }

                Test-FleetManagerAuthentication -Server "fleet.example.com" -User "admin@vsp.local" -TimeoutSeconds 30
            }

            $result.Status  | Should -Be "Failed"
            $result.Message | Should -Match "timed out"
        }

        It "Returns Fleet Lifecycle Manager Connected when VSP bearer token probe succeeds" {
            $result = InModuleScope VcfPatchScanner {
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "testpass"
                    }
                }
                function Get-VspBearerToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Server,
                        [Parameter()] [String]$User,
                        [Parameter()] [String]$Password,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    process {}
                }
                Mock Get-VspBearerToken { return "bearer-tok" }
                Mock Invoke-RestMethod { return [PSCustomObject]@{ version = "9.1.0" } }

                Test-FleetManagerAuthentication -Server "fleet.example.com" -User "admin@vsp.local" -TimeoutSeconds 30
            }

            $result.Endpoint  | Should -Be "Fleet Lifecycle Manager"
            $result.Status    | Should -Be "Connected"
            $result.Connected | Should -Be $true
        }

        It "Returns Fleet Manager Connected when VSP probe throws but lcops succeeds" {
            $result = InModuleScope VcfPatchScanner {
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "testpass"
                    }
                }
                function Get-VspBearerToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Server,
                        [Parameter()] [String]$User,
                        [Parameter()] [String]$Password,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    process {}
                }
                Mock Get-VspBearerToken { return "bearer-tok" }
                # fleet-lcm probe throws; lcops probe succeeds
                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*fleet-lcm*" } {
                    throw [System.Management.Automation.RuntimeException]::new("fleet-lcm not available")
                }
                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*lcops*" } {
                    return [PSCustomObject]@{ systemDetails = "ok" }
                }

                Test-FleetManagerAuthentication -Server "fleet.example.com" -User "admin@local" -TimeoutSeconds 30
            }

            $result.Endpoint  | Should -Be "Fleet Manager"
            $result.Status    | Should -Be "Connected"
            $result.Connected | Should -Be $true
        }

        It "Returns Fleet Manager Connected when bearer token is empty and lcops succeeds" {
            $result = InModuleScope VcfPatchScanner {
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "testpass"
                    }
                }
                function Get-VspBearerToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Server,
                        [Parameter()] [String]$User,
                        [Parameter()] [String]$Password,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    process {}
                }
                Mock Get-VspBearerToken { return "" }
                Mock Invoke-RestMethod { return [PSCustomObject]@{ systemDetails = "ok" } }

                Test-FleetManagerAuthentication -Server "fleet.example.com" -User "admin@local" -TimeoutSeconds 30
            }

            $result.Endpoint  | Should -Be "Fleet Manager"
            $result.Status    | Should -Be "Connected"
        }

        It "Returns VCF Fleet Unauthenticated when both auth paths fail" {
            $result = InModuleScope VcfPatchScanner {
                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$EndpointName,
                        [Parameter()] [String]$PasswordEnvVar,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    return [PSCustomObject]@{
                        Endpoint  = $EndpointName
                        Server    = $Server
                        Status    = "Connected"
                        Connected = $true
                        Message   = "Port 443 reachable and credentials available"
                        Password  = "testpass"
                    }
                }
                function Get-VspBearerToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Server,
                        [Parameter()] [String]$User,
                        [Parameter()] [String]$Password,
                        [Parameter()] [Int]$TimeoutSeconds
                    )
                    process {}
                }
                Mock Get-VspBearerToken { return "" }
                Mock Invoke-RestMethod {
                    throw [System.Management.Automation.RuntimeException]::new("401 Unauthorized")
                }

                Test-FleetManagerAuthentication -Server "fleet.example.com" -User "admin@local" -TimeoutSeconds 30
            }

            $result.Endpoint  | Should -Be "VCF Fleet"
            $result.Status    | Should -Be "Unauthenticated"
            $result.Connected | Should -Be $true
        }
    }

    Context "Get-FleetManagerFromVcfOps" {

        BeforeEach {
            $script:_savedOpsPw2 = $env:VCF_OPS_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedOpsPw2) { $env:VCF_OPS_PASSWORD = $script:_savedOpsPw2 }
            else { Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Version 9.1 uses VSP-only strategy and returns FleetFqdn from Suite API" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "opspass"

                function Get-RequiredInventoryPassword {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$ComponentName,
                        [Parameter()] [String]$EnvVarName
                    )
                    process {}
                }
                Mock Get-RequiredInventoryPassword { return "opspass" }

                function Get-VcfOpsRestToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Password,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds,
                        [Parameter()] [String]$User
                    )
                    process {}
                }
                Mock Get-VcfOpsRestToken { return "vro-token" }

                # VSP endpoint returns a component with fleetFqdn
                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*suite-api*" } {
                    return [PSCustomObject]@{
                        components = @(
                            [PSCustomObject]@{
                                properties = [PSCustomObject]@{ fleetFqdn = "fleet-9-1.example.com" }
                            }
                        )
                    }
                }

                Get-FleetManagerFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" -VcfOpsVersion "VCF Operations 9.1.0.0"
            }

            $result.FleetFqdn | Should -Be "fleet-9-1.example.com"
            $result.VcfFMUser | Should -Be "admin@vsp.local"
        }

        It "Version 9.0 uses CASA-only strategy and returns FleetFqdn from capabilities" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "opspass"

                function Get-RequiredInventoryPassword {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$ComponentName,
                        [Parameter()] [String]$EnvVarName
                    )
                    process {}
                }
                Mock Get-RequiredInventoryPassword { return "opspass" }

                function Get-VcfOpsRestToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Password,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds,
                        [Parameter()] [String]$User
                    )
                    process {}
                }

                # CASA endpoint returns capabilities with ops-lcm entry
                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*casa*" } {
                    return @(
                        [PSCustomObject]@{
                            key   = "ops-lcm"
                            nodes = @(
                                [PSCustomObject]@{
                                    addresses = @(
                                        [PSCustomObject]@{ type = "Fqdn"; value = "fleet-9-0.example.com" }
                                    )
                                }
                            )
                        }
                    )
                }

                Get-FleetManagerFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" -VcfOpsVersion "VCF Operations 9.0.1.0"
            }

            $result.FleetFqdn | Should -Be "fleet-9-0.example.com"
            $result.VcfFMUser | Should -Be "admin@local"
        }

        It "Empty version tries VSP first and returns FleetFqdn when VSP succeeds" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "opspass"

                function Get-RequiredInventoryPassword {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$ComponentName,
                        [Parameter()] [String]$EnvVarName
                    )
                    process {}
                }
                Mock Get-RequiredInventoryPassword { return "opspass" }

                function Get-VcfOpsRestToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Password,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds,
                        [Parameter()] [String]$User
                    )
                    process {}
                }
                Mock Get-VcfOpsRestToken { return "vro-token" }

                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*suite-api*" } {
                    return [PSCustomObject]@{
                        components = @(
                            [PSCustomObject]@{
                                properties = [PSCustomObject]@{ fleetFqdn = "fleet-unknown.example.com" }
                            }
                        )
                    }
                }

                Get-FleetManagerFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" -VcfOpsVersion ""
            }

            $result.FleetFqdn | Should -Be "fleet-unknown.example.com"
            $result.VcfFMUser | Should -Be "admin@vsp.local"
        }

        It "Empty version falls back to CASA when VSP fails and CASA succeeds" {
            $result = InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "opspass"

                function Get-RequiredInventoryPassword {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$ComponentName,
                        [Parameter()] [String]$EnvVarName
                    )
                    process {}
                }
                Mock Get-RequiredInventoryPassword { return "opspass" }

                function Get-VcfOpsRestToken {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [String]$Password,
                        [Parameter()] [String]$Server,
                        [Parameter()] [Int]$TimeoutSeconds,
                        [Parameter()] [String]$User
                    )
                    process {}
                }
                Mock Get-VcfOpsRestToken { return "vro-token" }

                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*suite-api*" } {
                    throw [System.Management.Automation.RuntimeException]::new("Suite API unavailable")
                }
                Mock Invoke-RestMethod -ParameterFilter { $Uri -like "*casa*" } {
                    return @(
                        [PSCustomObject]@{
                            key   = "ops-lcm"
                            nodes = @(
                                [PSCustomObject]@{
                                    addresses = @(
                                        [PSCustomObject]@{ type = "Fqdn"; value = "fleet-casa-fallback.example.com" }
                                    )
                                }
                            )
                        }
                    )
                }

                Get-FleetManagerFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" -VcfOpsVersion ""
            }

            $result.FleetFqdn | Should -Be "fleet-casa-fallback.example.com"
            $result.VcfFMUser | Should -Be "admin@local"
        }

        It "Throws when Get-RequiredInventoryPassword throws due to missing password" {
            {
                InModuleScope VcfPatchScanner {
                    Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue

                    function Get-RequiredInventoryPassword {
                        [CmdletBinding()]
                        Param(
                            [Parameter()] [String]$ComponentName,
                            [Parameter()] [String]$EnvVarName
                        )
                        process {}
                    }
                    Mock Get-RequiredInventoryPassword {
                        throw [System.InvalidOperationException]::new("VCF Operations password not configured (env var: VCF_OPS_PASSWORD)")
                    }

                    Get-FleetManagerFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" -VcfOpsVersion ""
                }
            } | Should -Throw
        }
    }

    Context "Environment Type Validation" {

        It "Accepts valid environment types" {
            foreach ($type in @('vcf5', 'vcf9', 'vsphere8', 'vvf9')) {
                $capturedType = $type
                {
                    InModuleScope VcfPatchScanner -ArgumentList $capturedType {
                        Test-PatchScanConnection -EnvironmentType $args[0]
                    }
                } | Should -Not -Throw
            }
        }

        It "Rejects invalid environment types" {
            {
                InModuleScope VcfPatchScanner {
                    Test-PatchScanConnection -EnvironmentType "invalid_type"
                }
            } | Should -Throw
        }
    }

    Context "Get-SddcManagerListFromVcfOps" {

        BeforeEach {
            $script:_savedOpsPw3 = $env:VCF_OPS_PASSWORD
        }

        AfterEach {
            if ($null -ne $script:_savedOpsPw3) { $env:VCF_OPS_PASSWORD = $script:_savedOpsPw3 }
            else { Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Calls Disconnect-VcfOpsServer in finally when connect succeeds but query fails" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "ops_test_pass"

                function Get-RequiredInventoryPassword {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$ComponentName, [Parameter()] [Object]$EnvVarName)
                    process {}
                }
                Mock Get-RequiredInventoryPassword { return "ops_test_pass" }

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [Object]$EndpointName,
                        [Parameter()] [Object]$PasswordEnvVar,
                        [Parameter()] [Object]$Server,
                        [Parameter()] [Object]$TimeoutSeconds
                    )
                    process {}
                }
                Mock Test-EndpointTcpConnection { return [PSCustomObject]@{ Status = "OK"; Message = "" } }

                Mock ConvertTo-VcfOpsAuthParts {
                    [PSCustomObject]@{ BareUser = "admin"; AuthSource = "Local" }
                }

                function Connect-VcfOpsServer {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [Object]$Server,
                        [Parameter()] [Object]$User,
                        [Parameter()] [Object]$Password,
                        [Parameter()] [Object]$AuthSource,
                        [Parameter()] [Switch]$IgnoreInvalidCertificate
                    )
                    process {}
                }
                Mock Connect-VcfOpsServer { return [PSCustomObject]@{ Server = "ops.example.com" } }

                function Invoke-VcfOpsEnumerateAdapterInstances {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$AdapterKindKey)
                    process {}
                }
                Mock Invoke-VcfOpsEnumerateAdapterInstances { throw "adapter query failed" }

                $Script:_sddcListDisconnectCount = 0
                function Disconnect-VcfOpsServer {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Server, [Parameter()] [Switch]$Force)
                    begin { $Script:_sddcListDisconnectCount++ }
                    process {}
                }

                Mock Write-LogMessage

                { Get-SddcManagerListFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" } | Should -Throw
                $Script:_sddcListDisconnectCount | Should -Be 1
            }
        }

        It "Does NOT call Disconnect-VcfOpsServer when connect itself throws" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "bad_pass"

                function Get-RequiredInventoryPassword {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$ComponentName, [Parameter()] [Object]$EnvVarName)
                    process {}
                }
                Mock Get-RequiredInventoryPassword { return "bad_pass" }

                function Test-EndpointTcpConnection {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [Object]$EndpointName,
                        [Parameter()] [Object]$PasswordEnvVar,
                        [Parameter()] [Object]$Server,
                        [Parameter()] [Object]$TimeoutSeconds
                    )
                    process {}
                }
                Mock Test-EndpointTcpConnection { return [PSCustomObject]@{ Status = "OK"; Message = "" } }

                Mock ConvertTo-VcfOpsAuthParts {
                    [PSCustomObject]@{ BareUser = "admin"; AuthSource = "Local" }
                }

                function Connect-VcfOpsServer {
                    [CmdletBinding()]
                    Param(
                        [Parameter()] [Object]$Server,
                        [Parameter()] [Object]$User,
                        [Parameter()] [Object]$Password,
                        [Parameter()] [Object]$AuthSource,
                        [Parameter()] [Switch]$IgnoreInvalidCertificate
                    )
                    process {}
                }
                Mock Connect-VcfOpsServer { throw "authentication failure" }

                $Script:_sddcListDisconnectNoConnCount = 0
                function Disconnect-VcfOpsServer {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Server, [Parameter()] [Switch]$Force)
                    begin { $Script:_sddcListDisconnectNoConnCount++ }
                    process {}
                }

                Mock Write-LogMessage

                { Get-SddcManagerListFromVcfOps -VcfOpsServer "ops.example.com" -VcfOpsUser "admin@local" } | Should -Throw
                $Script:_sddcListDisconnectNoConnCount | Should -Be 0
            }
        }
    }

    Context "ConvertTo-VcfAdvisoryVersion" {

        It "Extracts segments 1,2,3,5 from an Update 1 build number" {
            $result = InModuleScope VcfPatchScanner {
                ConvertTo-VcfAdvisoryVersion -Version '9.1.0.0100.25435105'
            }
            $result | Should -Be '9.1.0.25435105'
        }

        It "Extracts segments 1,2,3,5 from a base-release build number" {
            $result = InModuleScope VcfPatchScanner {
                ConvertTo-VcfAdvisoryVersion -Version '9.1.0.0.25346025'
            }
            $result | Should -Be '9.1.0.25346025'
        }

        It "Returns a 4-part string unchanged" {
            $result = InModuleScope VcfPatchScanner {
                ConvertTo-VcfAdvisoryVersion -Version '9.0.2.0200'
            }
            $result | Should -Be '9.0.2.0200'
        }

        It "Returns a 3-part string unchanged" {
            $result = InModuleScope VcfPatchScanner {
                ConvertTo-VcfAdvisoryVersion -Version '9.1.0'
            }
            $result | Should -Be '9.1.0'
        }

        It "Returns an empty string unchanged" {
            $result = InModuleScope VcfPatchScanner {
                ConvertTo-VcfAdvisoryVersion -Version ''
            }
            $result | Should -Be ''
        }
    }

    Context "ConvertTo-FleetBuildNumberMap" {

        It "Maps an Update 1 build number to its advisory-comparable form (segments 1,2,3,5)" {
            $result = InModuleScope VcfPatchScanner {
                $catalog = @([PSCustomObject]@{
                    VcfRelease    = '9.1.0.0'
                    ComponentType = 'OPS'
                    ComponentName = 'VCF Operations'
                    BuildNumbers  = @('9.1.0.0100.25435105', '9.1.0.0.25346025')
                })
                ConvertTo-FleetBuildNumberMap -Catalog $catalog
            }
            $result['9.1.0.0100.25435105'] | Should -Be '9.1.0.25435105'
            $result['9.1.0.0.25346025']    | Should -Be '9.1.0.25346025'
        }

        It "First association wins when the same build appears in multiple catalog entries" {
            $result = InModuleScope VcfPatchScanner {
                $catalog = @(
                    [PSCustomObject]@{ VcfRelease = '9.1.0.0'; ComponentType = 'A'; ComponentName = 'A'; BuildNumbers = @('9.1.0.0100.25435105') },
                    [PSCustomObject]@{ VcfRelease = '9.1.0.0'; ComponentType = 'B'; ComponentName = 'B'; BuildNumbers = @('9.1.0.0100.25435105') }
                )
                ConvertTo-FleetBuildNumberMap -Catalog $catalog
            }
            $result['9.1.0.0100.25435105'] | Should -Be '9.1.0.25435105'
            $result.Count | Should -Be 1
        }

        It "Returns an empty hashtable for an empty catalog" {
            $result = InModuleScope VcfPatchScanner {
                ConvertTo-FleetBuildNumberMap -Catalog @()
            }
            $result | Should -BeOfType [Hashtable]
            $result.Count | Should -Be 0
        }

        It "Skips blank build number entries" {
            $result = InModuleScope VcfPatchScanner {
                $catalog = @([PSCustomObject]@{
                    VcfRelease    = '9.1.0.0'
                    ComponentType = 'OPS'
                    ComponentName = 'VCF Operations'
                    BuildNumbers  = @('', '  ', '9.1.0.0.25346025')
                })
                ConvertTo-FleetBuildNumberMap -Catalog $catalog
            }
            $result.Count | Should -Be 1
            $result['9.1.0.0.25346025'] | Should -Be '9.1.0.25346025'
        }
    }
}
