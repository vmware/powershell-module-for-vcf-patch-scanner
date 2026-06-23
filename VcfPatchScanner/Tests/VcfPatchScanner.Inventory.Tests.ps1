# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.Inventory" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Get-SddcManagerInventory — Happy Path" {

        BeforeEach {
            $script:_savedSddcPassword = $env:SDDC_MANAGER_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedSddcPassword) { $env:SDDC_MANAGER_PASSWORD = $script:_savedSddcPassword }
            else { Remove-Item "env:\SDDC_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns empty hashtable when password env var not configured" {
            InModuleScope VcfPatchScanner {
                $env:SDDC_MANAGER_PASSWORD = $null

                Mock Write-LogMessage

                $inventory = Get-SddcManagerInventory -Server "sddc.example.com" -User "admin"

                $inventory.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "password not configured" }
            }
        }

    }

    Context "Get-VcenterInventory — Happy Path" {

        BeforeEach {
            $script:_savedVcenterPassword = $env:VCENTER_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedVcenterPassword) { $env:VCENTER_PASSWORD = $script:_savedVcenterPassword }
            else { Remove-Item "env:\VCENTER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns empty hashtable when password env var not configured" {
            InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = $null
                Mock Write-LogMessage

                $inventory = Get-VcenterInventory -Server "vcenter.example.com" -User "admin"

                $inventory.Count | Should -Be 0
            }
        }

        It "Sets BuildVersion on ESXi hosts from VMHost.Build property" {
            InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "test_pass"

                $fakeHost = [PSCustomObject]@{
                    Name            = "esxi01.example.com"
                    Version         = "8.0.3"
                    Build           = "24022510"
                    ConnectionState = "Connected"
                }
                $fakeVi = [PSCustomObject]@{
                    Version = "8.0.3"
                    Build   = "25413364"
                    Name    = "vcenter.example.com"
                }

                function Connect-VIServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User,
                        [Parameter()] [Object]$Password, [Parameter()] [Switch]$Force)
                    return $fakeVi
                }
                function Disconnect-VIServer {
                    [CmdletBinding(SupportsShouldProcess = $true)] Param([Parameter()] [Object]$Server,
                        [Parameter()] [Switch]$Force)
                    begin {}; process {}
                }
                function Get-VMHost {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$Location)
                    if ($Location) { return @($fakeHost) }
                    return @($fakeHost)
                }
                function Get-Cluster {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server)
                    return @()
                }
                Mock Write-LogMessage

                $inventory = Get-VcenterInventory -Server "vcenter.example.com" -User "admin"

                $esxiHosts = $inventory["ESXi"]
                $esxiHosts | Should -Not -BeNullOrEmpty
                $esxiHosts[0].Version      | Should -Be "8.0.3"
                $esxiHosts[0].BuildVersion | Should -Be "8.0.3.24022510"
            }
        }

        It "Does not set BuildVersion when VMHost.Build is absent or non-numeric" {
            InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "test_pass"

                $fakeHostNoBuild = [PSCustomObject]@{
                    Name            = "esxi02.example.com"
                    Version         = "7.0.3"
                    Build           = $null
                    ConnectionState = "Connected"
                }
                $fakeVi2 = [PSCustomObject]@{
                    Version = "7.0.3"
                    Build   = $null
                    Name    = "vcenter.example.com"
                }

                function Connect-VIServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User,
                        [Parameter()] [Object]$Password, [Parameter()] [Switch]$Force)
                    return $fakeVi2
                }
                function Disconnect-VIServer {
                    [CmdletBinding(SupportsShouldProcess = $true)] Param([Parameter()] [Object]$Server,
                        [Parameter()] [Switch]$Force)
                    begin {}; process {}
                }
                function Get-VMHost {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$Location)
                    if ($Location) { return @($fakeHostNoBuild) }
                    return @($fakeHostNoBuild)
                }
                function Get-Cluster {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server)
                    return @()
                }
                Mock Write-LogMessage

                $inventory = Get-VcenterInventory -Server "vcenter.example.com" -User "admin"

                $esxiHosts = $inventory["ESXi"]
                $esxiHosts | Should -Not -BeNullOrEmpty
                $esxiHosts[0].Version             | Should -Be "7.0.3"
                $esxiHosts[0].PSObject.Properties.Name | Should -Not -Contain "BuildVersion"
            }
        }
    }

    Context "Get-FleetManagerInventory — Happy Path" {

        BeforeEach {
            $script:_savedFmPassword = $env:VCF_FM_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedFmPassword) { $env:VCF_FM_PASSWORD = $script:_savedFmPassword }
            else { Remove-Item "env:\VCF_FM_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns empty hashtable when password env var not configured" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = $null
                Mock Write-LogMessage

                $inventory = Get-FleetManagerInventory -Server "fleet.example.com" -User "admin"

                $inventory.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }
    }

    Context "Get-VspFleetLcmInventory — Component Collection" {

        BeforeEach {
            $script:_savedFmPasswordVsp = $env:VCF_FM_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedFmPasswordVsp) { $env:VCF_FM_PASSWORD = $script:_savedFmPasswordVsp }
            else { Remove-Item "env:\VCF_FM_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Collects fleet components from /fleet-lcm/v1/components using advisory name mapping" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = "test_pass"

                Mock Invoke-RestMethod {
                    if ($Uri -match '/api/v1/identity/token') {
                        return [PSCustomObject]@{ access_token = "mock-bearer-token" }
                    }
                    if ($Uri -match '/fleet-lcm/v1/system') {
                        return [PSCustomObject]@{ currentVersion = "9.1.0.0" }
                    }
                    if ($Uri -match '/fleet-lcm/v1/components') {
                        return [PSCustomObject]@{
                            components = @(
                                [PSCustomObject]@{ componentType = "VRA";  fqdn = "vra.example.com";  version = "8.18.1"; nodes = @() }
                                [PSCustomObject]@{ componentType = "VIDB"; fqdn = "vidb.example.com"; version = "9.1.0.0"; nodes = @() }
                                # "OPS" and "VCF_FLEET_LCM" must be skipped — natively collected
                                [PSCustomObject]@{ componentType = "OPS";          fqdn = "ops.example.com";   version = "9.1.0.0"; nodes = @() }
                                [PSCustomObject]@{ componentType = "VCF_FLEET_LCM"; fqdn = "fleet.example.com"; version = "9.1.0.0"; nodes = @() }
                            )
                            pageMetadata = [PSCustomObject]@{ totalPages = 1 }
                        }
                    }
                    return $null
                }
                Mock Write-LogMessage

                $inventory = Get-VspFleetLcmInventory -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                # Fleet controller from /v1/system
                $inventory["Fleet Lifecycle"] | Should -Not -BeNullOrEmpty
                $inventory["Fleet Lifecycle"][0].DomainName | Should -Be "VCF Fleet"
                # VRA → "VCF Automation" via VSP_FLEET_LCM_COMPONENT_TYPE_TO_ADVISORY_NAME
                $inventory.Keys | Should -Not -Contain "VCF Operations"
                $inventory.Keys | Should -Not -Contain "Fleet Lifecycle (duplicate)"
            }
        }

        It "Skips fleet components with no FQDN" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = "test_pass"

                Mock Invoke-RestMethod {
                    if ($Uri -match '/api/v1/identity/token') { return [PSCustomObject]@{ access_token = "tok" } }
                    if ($Uri -match '/fleet-lcm/v1/system')   { return [PSCustomObject]@{ currentVersion = "9.1.0.0" } }
                    if ($Uri -match '/fleet-lcm/v1/components') {
                        return [PSCustomObject]@{
                            components = @(
                                [PSCustomObject]@{ componentType = "VIDB"; fqdn = ""; version = "9.1.0.0"; nodes = @() }
                            )
                            pageMetadata = [PSCustomObject]@{ totalPages = 1 }
                        }
                    }
                    return $null
                }
                Mock Write-LogMessage

                $inventory = Get-VspFleetLcmInventory -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                # Fleet Lifecycle from /v1/system is still collected
                $inventory["Fleet Lifecycle"] | Should -Not -BeNullOrEmpty
                # VIDB with no FQDN must be skipped, not added with an empty FQDN
                $inventory.Keys | Should -Not -Contain "Identity Broker"
                Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "no FQDN" }
            }
        }

        It "Sets DomainName = 'VCF Fleet' on all collected fleet components" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = "test_pass"

                Mock Invoke-RestMethod {
                    if ($Uri -match '/api/v1/identity/token') { return [PSCustomObject]@{ access_token = "tok" } }
                    if ($Uri -match '/fleet-lcm/v1/system')   { return [PSCustomObject]@{ currentVersion = "9.1.0.0" } }
                    if ($Uri -match '/fleet-lcm/v1/components') {
                        return [PSCustomObject]@{
                            components = @(
                                [PSCustomObject]@{ componentType = "SALT"; fqdn = "salt.example.com"; version = "3006.0"; nodes = @() }
                            )
                            pageMetadata = [PSCustomObject]@{ totalPages = 1 }
                        }
                    }
                    return $null
                }
                Mock Write-LogMessage

                $inventory = Get-VspFleetLcmInventory -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                # Salt maps to "Salt Master" in VSP_FLEET_LCM_COMPONENT_TYPE_TO_ADVISORY_NAME
                $saltEntry = $inventory["Salt Master"]
                $saltEntry | Should -Not -BeNullOrEmpty
                $saltEntry[0].DomainName | Should -Be "VCF Fleet"
                $saltEntry[0].Fqdn      | Should -Be "salt.example.com"
                $saltEntry[0].Version   | Should -Be "3006.0"
            }
        }
    }

    Context "Get-LcopsFleetManagerInventory — Component Collection" {

        It "Collects 9.0 fleet products from /lcm/lcops/api/v2/environments" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod {
                    if ($Uri -match '/lcm/lcops/api/v2/settings/system-details') {
                        return [PSCustomObject]@{ version = "9.0.1" }
                    }
                    if ($Uri -match '/lcm/lcops/api/v2/environments') {
                        return @(
                            [PSCustomObject]@{
                                products = @(
                                    [PSCustomObject]@{
                                        id      = "vra"
                                        version = "8.17.0"
                                        nodes   = @(
                                            [PSCustomObject]@{ properties = [PSCustomObject]@{ hostName = "vra.example.com" } }
                                        )
                                        clusterVIP = $null
                                    }
                                )
                            }
                        )
                    }
                    return $null
                }
                Mock Write-LogMessage

                $inventory = Get-LcopsFleetManagerInventory -Server "fleet.example.com" -User "admin@local" -Password "pass"

                $inventory["Fleet Lifecycle"] | Should -Not -BeNullOrEmpty
                $inventory["Fleet Lifecycle"][0].Version | Should -Be "9.0.1"
                # vra → "VCF Automation" in VCF_FLEET_MANAGER_COMPONENT_TYPE_TO_ADVISORY_NAME
                $inventory["VCF Automation"] | Should -Not -BeNullOrEmpty
                $inventory["VCF Automation"][0].Fqdn      | Should -Be "vra.example.com"
                $inventory["VCF Automation"][0].Version   | Should -Be "8.17.0"
                $inventory["VCF Automation"][0].DomainName | Should -Be "VCF Fleet"
            }
        }

        It "Skips 9.0 products with natively-collected types (vrops, vrslcm)" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod {
                    if ($Uri -match '/lcm/lcops/api/v2/settings/system-details') {
                        return [PSCustomObject]@{ version = "9.0.1" }
                    }
                    if ($Uri -match '/lcm/lcops/api/v2/environments') {
                        return @(
                            [PSCustomObject]@{
                                products = @(
                                    [PSCustomObject]@{
                                        id      = "vrops"
                                        version = "9.0.0"
                                        nodes   = @([PSCustomObject]@{ properties = [PSCustomObject]@{ hostName = "ops.example.com" } })
                                        clusterVIP = $null
                                    }
                                    [PSCustomObject]@{
                                        id      = "vrslcm"
                                        version = "9.0.1"
                                        nodes   = @([PSCustomObject]@{ properties = [PSCustomObject]@{ hostName = "fleet.example.com" } })
                                        clusterVIP = $null
                                    }
                                )
                            }
                        )
                    }
                    return $null
                }
                Mock Write-LogMessage

                $inventory = Get-LcopsFleetManagerInventory -Server "fleet.example.com" -User "admin@local" -Password "pass"

                $inventory.Keys | Should -Not -Contain "VCF Operations"
                $inventory.Keys | Should -Not -Contain "Fleet Management"
            }
        }
    }

    Context "Get-NsxEdgeInventory — Edge Node Collection" {

        BeforeEach {
            $script:_savedNsxPass = $env:NSX_MANAGER_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedNsxPass) { $env:NSX_MANAGER_PASSWORD = $script:_savedNsxPass }
            else { Remove-Item "env:\NSX_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns empty array when NSX_MANAGER_PASSWORD is not configured" {
            InModuleScope VcfPatchScanner {
                $env:NSX_MANAGER_PASSWORD = $null
                Mock Write-LogMessage

                $edges = Get-NsxEdgeInventory -NsxManagerFqdn "nsx.example.com"

                $edges.Count | Should -Be 0
                Should -Not -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }

        It "Returns one entry per edge node with normalised version and hostname" {
            InModuleScope VcfPatchScanner {
                $env:NSX_MANAGER_PASSWORD = "test_pass"

                Mock Invoke-RestMethod {
                    if ($Uri -match '/transport-nodes\?') {
                        return [PSCustomObject]@{
                            results = @(
                                [PSCustomObject]@{
                                    node_id              = "edge-uuid-1"
                                    display_name         = "edge-01"
                                    node_deployment_info = [PSCustomObject]@{
                                        node_settings = [PSCustomObject]@{ hostname = "edge-01.example.com" }
                                    }
                                }
                            )
                        }
                    }
                    if ($Uri -match '/status') {
                        return [PSCustomObject]@{
                            node_status = [PSCustomObject]@{ software_version = "4.2.0.0.0.24105824" }
                        }
                    }
                    return $null
                }
                Mock Write-LogMessage

                $edges = Get-NsxEdgeInventory -NsxManagerFqdn "nsx.example.com" -DomainName "mgmt"

                $edges.Count        | Should -Be 1
                $edges[0].Fqdn      | Should -Be "edge-01.example.com"
                $edges[0].DomainName | Should -Be "mgmt"
                # Build suffix normalised: "4.2.0.0.0.24105824" → "4.2.0.0.0-24105824"
                $edges[0].Version   | Should -Match "4\.2\.0\.0\.0-24105824"
            }
        }

        It "Falls back to display_name when node_settings.hostname is empty" {
            InModuleScope VcfPatchScanner {
                $env:NSX_MANAGER_PASSWORD = "test_pass"

                Mock Invoke-RestMethod {
                    if ($Uri -match '/transport-nodes\?') {
                        return [PSCustomObject]@{
                            results = @(
                                [PSCustomObject]@{
                                    node_id              = "edge-uuid-2"
                                    display_name         = "edge-node-display"
                                    node_deployment_info = [PSCustomObject]@{
                                        node_settings = [PSCustomObject]@{ hostname = "" }
                                    }
                                }
                            )
                        }
                    }
                    if ($Uri -match '/status') {
                        return [PSCustomObject]@{ node_status = [PSCustomObject]@{ software_version = "4.1.0" } }
                    }
                    return $null
                }
                Mock Write-LogMessage

                $edges = Get-NsxEdgeInventory -NsxManagerFqdn "nsx.example.com"

                $edges.Count   | Should -Be 1
                $edges[0].Fqdn | Should -Be "edge-node-display"
            }
        }

        It "Returns empty array and logs DEBUG when transport-nodes API call fails" {
            InModuleScope VcfPatchScanner {
                $env:NSX_MANAGER_PASSWORD = "test_pass"

                Mock Invoke-RestMethod { throw "connection refused" }
                Mock Write-LogMessage

                $edges = Get-NsxEdgeInventory -NsxManagerFqdn "nsx.example.com"

                $edges.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "DEBUG" -and $Message -match "failed" }
            }
        }
    }

    Context "Get-SddcManagerInventory — Negative Path" {

        BeforeEach {
            $script:_savedSddcNeg = $env:SDDC_MANAGER_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedSddcNeg) { $env:SDDC_MANAGER_PASSWORD = $script:_savedSddcNeg }
            else { Remove-Item "env:\SDDC_MANAGER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Logs WARNING and returns empty hashtable when Connect-VcfSddcManagerServer throws" {
            InModuleScope VcfPatchScanner {
                $env:SDDC_MANAGER_PASSWORD = "bad_pass"

                function Connect-VcfSddcManagerServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$Credential, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfSddcManagerServer { throw "Authentication failed: invalid credentials" }
                Mock Write-LogMessage

                $inventory = Get-SddcManagerInventory -Server "sddc.example.com" -User "admin@vsphere.local"

                $inventory.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }

        It "Calls Disconnect-VcfSddcManagerServer in finally when connect succeeds but inventory collection fails" {
            InModuleScope VcfPatchScanner {
                $env:SDDC_MANAGER_PASSWORD = "test_pass"

                function Connect-VcfSddcManagerServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$Credential, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfSddcManagerServer { return [PSCustomObject]@{ Server = "sddc.example.com" } }

                function Get-NsxAdminPasswordFromSddc {
                    [CmdletBinding()] Param()
                    process {}
                }
                Mock Get-NsxAdminPasswordFromSddc { return $null }

                function Invoke-VcfGetSddcManagers {
                    [CmdletBinding()] Param()
                    process {}
                }
                Mock Invoke-VcfGetSddcManagers { throw "API unavailable" }

                # Counter in function body writes to module scope (Pester Rule 3).
                $Script:_sddcDisconnectCount = 0
                function Disconnect-VcfSddcManagerServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Switch]$Force)
                    begin { $Script:_sddcDisconnectCount++ }
                    process {}
                }

                Mock Write-LogMessage

                $inventory = Get-SddcManagerInventory -Server "sddc.example.com" -User "admin@vsphere.local"

                $inventory.Count | Should -Be 0
                $Script:_sddcDisconnectCount | Should -Be 1
            }
        }

        It "Does NOT call Disconnect-VcfSddcManagerServer when connect itself throws" {
            InModuleScope VcfPatchScanner {
                $env:SDDC_MANAGER_PASSWORD = "bad_pass"

                function Connect-VcfSddcManagerServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$Credential, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfSddcManagerServer { throw "authentication failure" }

                # Throw inside this stub to catch any accidental disconnect call.
                function Disconnect-VcfSddcManagerServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Switch]$Force)
                    begin { throw "Disconnect-VcfSddcManagerServer must not be called when connect failed" }
                    process {}
                }

                Mock Write-LogMessage

                $inventory = Get-SddcManagerInventory -Server "sddc.example.com" -User "admin@vsphere.local"

                $inventory.Count | Should -Be 0
            }
        }
    }

    Context "Get-VcfOpsInventory — Happy Path" {

        BeforeEach {
            $script:_savedOpsHappy = $env:VCF_OPS_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedOpsHappy) { $env:VCF_OPS_PASSWORD = $script:_savedOpsHappy }
            else { Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns VCF Operations entry with parsed version and _StandaloneVcenterFqdns populated from VCURL adapter" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "good_pass"

                Mock ConvertTo-VcfOpsAuthParts { [PSCustomObject]@{ BareUser = "admin"; AuthSource = "local" } }

                function Connect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User,
                        [Parameter()] [Object]$Password, [Parameter()] [Object]$AuthSource,
                        [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfOpsServer { return $null }

                function Invoke-VcfOpsGetCurrentVersionOfServer {
                    [CmdletBinding()] Param()
                    process {}
                }
                Mock Invoke-VcfOpsGetCurrentVersionOfServer {
                    [PSCustomObject]@{ Version = "VCF Operations 9.1.0.0" }
                }

                function Invoke-VcfOpsEnumerateAdapterInstances {
                    [CmdletBinding()] Param([Parameter()] [Object]$AdapterKindKey)
                    process {}
                }
                Mock Invoke-VcfOpsEnumerateAdapterInstances {
                    [PSCustomObject]@{
                        AdapterInstancesInfoDto = @(
                            [PSCustomObject]@{
                                ResourceKey = [PSCustomObject]@{
                                    Name = "VMWARE Adapter"
                                    ResourceIdentifiers = @(
                                        [PSCustomObject]@{
                                            IdentifierType = [PSCustomObject]@{ Name = "VCURL" }
                                            Value          = "vc.example.com"
                                        }
                                    )
                                }
                            }
                        )
                    }
                }
                Mock Write-LogMessage

                $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

                $inventory.ContainsKey("VCF Operations") | Should -Be $true
                $inventory["VCF Operations"][0].Version  | Should -Be "9.1.0.0"
                $inventory["VCF Operations"][0].Fqdn     | Should -Be "ops.example.com"
                $inventory.ContainsKey("_StandaloneVcenterFqdns") | Should -Be $true
                @($inventory["_StandaloneVcenterFqdns"]).Count | Should -Be 1
                $inventory["_StandaloneVcenterFqdns"][0] | Should -Be "vc.example.com"
            }
        }

        It "Returns 'Unknown' version when Invoke-VcfOpsGetCurrentVersionOfServer returns null" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "good_pass"

                Mock ConvertTo-VcfOpsAuthParts { [PSCustomObject]@{ BareUser = "admin"; AuthSource = "local" } }

                function Connect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User,
                        [Parameter()] [Object]$Password, [Parameter()] [Object]$AuthSource,
                        [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfOpsServer { return $null }

                function Invoke-VcfOpsGetCurrentVersionOfServer {
                    [CmdletBinding()] Param()
                    process {}
                }
                Mock Invoke-VcfOpsGetCurrentVersionOfServer { return $null }

                function Invoke-VcfOpsEnumerateAdapterInstances {
                    [CmdletBinding()] Param([Parameter()] [Object]$AdapterKindKey)
                    process {}
                }
                Mock Invoke-VcfOpsEnumerateAdapterInstances {
                    [PSCustomObject]@{ AdapterInstancesInfoDto = @() }
                }
                Mock Write-LogMessage

                $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

                $inventory["VCF Operations"][0].Version | Should -Be "Unknown"
            }
        }
    }

    Context "Get-VcfOpsInventory — Negative Path" {

        BeforeEach {
            $script:_savedOpsNeg = $env:VCF_OPS_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedOpsNeg) { $env:VCF_OPS_PASSWORD = $script:_savedOpsNeg }
            else { Remove-Item "env:\VCF_OPS_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns empty hashtable with no _StandaloneVcenterFqdns key when Connect-VcfOpsServer throws" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "bad_pass"

                Mock ConvertTo-VcfOpsAuthParts { [PSCustomObject]@{ BareUser = "admin"; AuthSource = "local" } }

                function Connect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User, [Parameter()] [Object]$Password, [Parameter()] [Object]$AuthSource, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfOpsServer { throw "Authentication failure: wrong credentials" }
                Mock Write-LogMessage

                $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

                $inventory.Count | Should -Be 0
                $inventory.ContainsKey("_StandaloneVcenterFqdns") | Should -Be $false
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }

        It "Preserves VCF Operations entry and adds empty _StandaloneVcenterFqdns when adapter enumeration fails" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "good_pass"

                Mock ConvertTo-VcfOpsAuthParts { [PSCustomObject]@{ BareUser = "admin"; AuthSource = "local" } }

                function Connect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User, [Parameter()] [Object]$Password, [Parameter()] [Object]$AuthSource, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfOpsServer { return $null }

                function Invoke-VcfOpsGetCurrentVersionOfServer {
                    [CmdletBinding()] Param()
                    process {}
                }
                Mock Invoke-VcfOpsGetCurrentVersionOfServer { [PSCustomObject]@{ Version = "9.1.0" } }

                function Invoke-VcfOpsEnumerateAdapterInstances {
                    [CmdletBinding()] Param([Parameter()] [Object]$AdapterKindKey)
                    process {}
                }
                Mock Invoke-VcfOpsEnumerateAdapterInstances { throw "Adapter enumeration unavailable" }

                Mock Write-LogMessage

                $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

                $inventory.ContainsKey("VCF Operations") | Should -Be $true
                $inventory.ContainsKey("_StandaloneVcenterFqdns") | Should -Be $true
                @($inventory["_StandaloneVcenterFqdns"]).Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "DEBUG" -and $Message -match "enumeration" }
            }
        }

        It "Calls Disconnect-VcfOpsServer in finally when connect succeeds but version collection fails" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "test_pass"

                Mock ConvertTo-VcfOpsAuthParts { [PSCustomObject]@{ BareUser = "admin"; AuthSource = "local" } }

                function Connect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User, [Parameter()] [Object]$Password, [Parameter()] [Object]$AuthSource, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfOpsServer { return [PSCustomObject]@{ Server = "ops.example.com" } }

                function Invoke-VcfOpsGetCurrentVersionOfServer {
                    [CmdletBinding()] Param()
                    process {}
                }
                Mock Invoke-VcfOpsGetCurrentVersionOfServer { throw "version endpoint unavailable" }

                # Counter in function body writes to module scope (Pester Rule 3).
                $Script:_opsDisconnectCount = 0
                function Disconnect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Switch]$Force)
                    begin { $Script:_opsDisconnectCount++ }
                    process {}
                }

                Mock Write-LogMessage

                $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

                $inventory.Count | Should -Be 0
                $Script:_opsDisconnectCount | Should -Be 1
            }
        }

        It "Does NOT call Disconnect-VcfOpsServer when connect itself throws" {
            InModuleScope VcfPatchScanner {
                $env:VCF_OPS_PASSWORD = "bad_pass"

                Mock ConvertTo-VcfOpsAuthParts { [PSCustomObject]@{ BareUser = "admin"; AuthSource = "local" } }

                function Connect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User, [Parameter()] [Object]$Password, [Parameter()] [Object]$AuthSource, [Parameter()] [Switch]$IgnoreInvalidCertificate)
                    process {}
                }
                Mock Connect-VcfOpsServer { throw "authentication failure" }

                # Throw inside this stub to catch any accidental disconnect call.
                function Disconnect-VcfOpsServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Switch]$Force)
                    begin { throw "Disconnect-VcfOpsServer must not be called when connect failed" }
                    process {}
                }

                Mock Write-LogMessage

                $inventory = Get-VcfOpsInventory -Server "ops.example.com" -User "admin@local"

                $inventory.Count | Should -Be 0
            }
        }
    }

    Context "Get-FleetManagerInventory — Negative Path" {

        BeforeEach {
            $script:_savedFmNeg = $env:VCF_FM_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedFmNeg) { $env:VCF_FM_PASSWORD = $script:_savedFmNeg }
            else { Remove-Item "env:\VCF_FM_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Returns empty hashtable when password env var is not configured" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = $null
                Mock Write-LogMessage

                $inventory = Get-FleetManagerInventory -Server "fm.example.com" -User "admin@local"

                $inventory.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "password not configured" }
            }
        }

        It "Logs WARNING and returns empty hashtable when all VSP and lcops paths fail" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = "bad_pass"

                Mock Get-VspFleetLcmInventory { return @{} }
                Mock Get-LcopsFleetManagerInventory { return @{} }
                Mock Write-LogMessage

                $inventory = Get-FleetManagerInventory -Server "fm.example.com" -User "admin@local" -AllowVspUserFallback

                $inventory.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" -and $Message -match "neither" }
            }
        }

        It "Tries admin@vsp.local as fallback when AllowVspUserFallback is set and initial user is not admin@vsp.local" {
            InModuleScope VcfPatchScanner {
                $env:VCF_FM_PASSWORD = "test_pass"

                $Script:_vspCallUsers = [System.Collections.Generic.List[String]]::new()
                function Get-VspFleetLcmInventory {
                    [CmdletBinding()]
                    Param([Parameter()] [String]$Server, [Parameter()] [String]$User, [Parameter()] [String]$Password, [Parameter()] [Int]$TimeoutSeconds)
                    begin { $Script:_vspCallUsers.Add($User) }
                    process {}
                }
                Mock Get-LcopsFleetManagerInventory { return @{} }
                Mock Write-LogMessage

                Get-FleetManagerInventory -Server "fm.example.com" -User "admin@local" -AllowVspUserFallback | Out-Null

                $Script:_vspCallUsers.Count | Should -BeGreaterOrEqual 2
                $Script:_vspCallUsers | Should -Contain "admin@vsp.local"
            }
        }
    }

    Context "Get-VspBearerToken" {

        It "Returns access_token when response has access_token property" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ access_token = "tok-abc" } }
                Mock Write-LogMessage

                $token = Get-VspBearerToken -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                $token | Should -Be "tok-abc"
                Should -Not -Invoke Write-LogMessage -ParameterFilter { $Type -eq "DEBUG" }
            }
        }

        It "Returns AccessToken (fallback) when only AccessToken property is present" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ AccessToken = "tok-abc" } }
                Mock Write-LogMessage

                $token = Get-VspBearerToken -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                $token | Should -Be "tok-abc"
            }
        }

        It "Returns token (third fallback) when only token property is present" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ token = "tok-abc" } }
                Mock Write-LogMessage

                $token = Get-VspBearerToken -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                $token | Should -Be "tok-abc"
            }
        }

        It "Returns empty string when response has no recognisable token property" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ someOtherProp = "x" } }
                Mock Write-LogMessage

                $token = Get-VspBearerToken -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                $token | Should -Be ""
            }
        }

        It "Returns empty string when access_token is empty string (falls through all three properties)" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ access_token = ""; AccessToken = ""; token = "" } }
                Mock Write-LogMessage

                $token = Get-VspBearerToken -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                $token | Should -Be ""
            }
        }

        It "Returns empty string and logs DEBUG when Invoke-RestMethod throws" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { throw "Connection refused" }
                Mock Write-LogMessage

                $token = Get-VspBearerToken -Server "fleet.example.com" -User "admin@vsp.local" -Password "pass"

                $token | Should -Be ""
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "DEBUG" }
            }
        }
    }

    Context "Get-VcfOpsRestToken" {

        It "Returns token when response has a non-empty token property" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ token = "vrops-token-xyz" } }
                Mock Write-LogMessage

                $token = Get-VcfOpsRestToken -Server "ops.example.com" -User "admin@local" -Password "pass"

                $token | Should -Be "vrops-token-xyz"
                Should -Not -Invoke Write-LogMessage -ParameterFilter { $Type -eq "DEBUG" }
            }
        }

        It "Returns empty string when token property is empty string" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ token = "" } }
                Mock Write-LogMessage

                $token = Get-VcfOpsRestToken -Server "ops.example.com" -User "admin@local" -Password "pass"

                $token | Should -Be ""
            }
        }

        It "Returns empty string when token property is null" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { [PSCustomObject]@{ token = $null } }
                Mock Write-LogMessage

                $token = Get-VcfOpsRestToken -Server "ops.example.com" -User "admin@local" -Password "pass"

                $token | Should -Be ""
            }
        }

        It "Returns empty string and logs DEBUG when Invoke-RestMethod throws" {
            InModuleScope VcfPatchScanner {
                Mock Invoke-RestMethod { throw "Connection refused" }
                Mock Write-LogMessage

                $token = Get-VcfOpsRestToken -Server "ops.example.com" -User "admin@local" -Password "pass"

                $token | Should -Be ""
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "DEBUG" }
            }
        }

        It "Passes authSource from ConvertTo-VcfOpsAuthParts in the JSON body sent to Invoke-RestMethod" {
            InModuleScope VcfPatchScanner {
                $Script:_capturedBody = $null
                Mock Invoke-RestMethod {
                    $Script:_capturedBody = $Body
                    return [PSCustomObject]@{ token = "tok" }
                }
                Mock Write-LogMessage

                Get-VcfOpsRestToken -Server "ops.example.com" -User "admin@local" -Password "pass" | Out-Null

                $Script:_capturedBody | Should -Not -BeNullOrEmpty
                $Script:_capturedBody | Should -Match '"authSource"'
            }
        }
    }

    Context "Get-VcenterInventory — Negative Path" {

        BeforeEach {
            $script:_savedVcNeg = $env:VCENTER_PASSWORD
        }
        AfterEach {
            if ($null -ne $script:_savedVcNeg) { $env:VCENTER_PASSWORD = $script:_savedVcNeg }
            else { Remove-Item "env:\VCENTER_PASSWORD" -ErrorAction SilentlyContinue }
        }

        It "Logs WARNING and returns empty hashtable when Connect-VIServer throws" {
            InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "bad_pass"

                function Connect-VIServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User, [Parameter()] [Object]$Password, [Parameter()] [Switch]$Force)
                    process {}
                }
                Mock Connect-VIServer { throw "Cannot connect to vCenter: name or service not known" }

                function Disconnect-VIServer {
                    [CmdletBinding(SupportsShouldProcess = $true)] Param([Parameter()] [Object]$Server)
                    process {}
                }
                Mock Disconnect-VIServer
                Mock Write-LogMessage

                $inventory = Get-VcenterInventory -Server "vcenter.example.com" -User "admin@vsphere.local"

                $inventory.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }

        It "Returns vCenter entry with no ESXi key when zero hosts report as Connected" {
            InModuleScope VcfPatchScanner {
                $env:VCENTER_PASSWORD = "test_pass"

                $fakeConnection = [PSCustomObject]@{ Version = "8.0.3"; Build = $null }

                function Connect-VIServer {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$User, [Parameter()] [Object]$Password, [Parameter()] [Switch]$Force)
                    process {}
                }
                Mock Connect-VIServer { return $fakeConnection }

                function Get-VMHost {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server, [Parameter()] [Object]$Location)
                    process {}
                }
                Mock Get-VMHost { return @() }

                function Get-Cluster {
                    [CmdletBinding()] Param([Parameter()] [Object]$Server)
                    process {}
                }
                Mock Get-Cluster { return @() }

                function Disconnect-VIServer {
                    [CmdletBinding(SupportsShouldProcess = $true)] Param([Parameter()] [Object]$Server)
                    process {}
                }
                Mock Disconnect-VIServer
                Mock Write-LogMessage

                $inventory = Get-VcenterInventory -Server "vcenter.example.com" -User "admin@vsphere.local"

                $inventory.ContainsKey("vCenter") | Should -Be $true
                $inventory.ContainsKey("ESXi") | Should -Be $false
                $inventory["vCenter"][0].Fqdn | Should -Be "vcenter.example.com"
            }
        }
    }

    Context "Resolve-HtmlAwareErrorMessage" {

        It "Returns a plain exception message unchanged" {
            InModuleScope VcfPatchScanner {
                $result = Resolve-HtmlAwareErrorMessage -ExceptionMessage "Connection timeout" -Server "sddc.example.com" -Context "SDDC Manager"
                $result | Should -Be "Connection timeout"
            }
        }

        It "Returns HTML guidance when message contains an HTML parse marker" {
            InModuleScope VcfPatchScanner {
                $result = Resolve-HtmlAwareErrorMessage `
                    -ExceptionMessage "Unexpected character encountered while parsing value: <" `
                    -Server "ops.example.com" -Context "VCF Operations"
                $result | Should -Match "HTML page"
                $result | Should -Match "ops\.example\.com"
            }
        }

        It "Strips the PowerShell error decoration prefix leaving only the actionable message" {
            InModuleScope VcfPatchScanner {
                $decorated = "6/22/2026 17:14:05    Connect-VcfSddcManagerServer        Object reference not set to an instance of an object."
                $result = Resolve-HtmlAwareErrorMessage -ExceptionMessage $decorated -Server "sddc.example.com" -Context "SDDC Manager"
                $result | Should -Be "Object reference not set to an instance of an object."
            }
        }

        It "Strips decoration when month and hour are single digits" {
            InModuleScope VcfPatchScanner {
                $decorated = "1/5/2026 9:03:12    Invoke-VcfGetSddcManagers        API endpoint not found."
                $result = Resolve-HtmlAwareErrorMessage -ExceptionMessage $decorated -Server "sddc.example.com" -Context "SDDC Manager"
                $result | Should -Be "API endpoint not found."
            }
        }
    }

}
