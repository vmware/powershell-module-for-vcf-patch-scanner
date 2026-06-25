# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.EntryPoint" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Invoke-VCFPatchScanner — Happy Path" {

        It "Completes scan successfully with VCF 9 environment" {
            InModuleScope VcfPatchScanner {
                $testAdvisoryFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "advisory_$([System.Guid]::NewGuid()).json"
                $testFindingsFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_$([System.Guid]::NewGuid()).json"

                try {
                    $advisoryDoc = [PSCustomObject]@{
                        schemaVersion = "2.0"
                        updatedAt     = "2026-06-17T00:00:00Z"
                        advisories    = @(
                            [PSCustomObject]@{
                                vmsaId = "VMSA-2026-0001"
                                severity = "Critical"
                                impactedComponents = @(
                                    [PSCustomObject]@{
                                        component = "SDDC Manager"
                                        minimumVersions = @("9.0")
                                        fixedVersions = @("9.1")
                                        severity = "Critical"
                                        cves = @("CVE-2025-12345")
                                        fixedVersionUrl = "https://example.com"
                                    }
                                )
                            }
                        )
                    } | ConvertTo-Json -Depth 10

                    Set-Content -LiteralPath $testAdvisoryFile -Value $advisoryDoc

                    $env:VCF_OPS_PASSWORD = $null
                    $env:VCF_FM_PASSWORD = $null

                    $config = [PSCustomObject]@{
                        EnvironmentId = "test-env-1"
                        Name = "Lab"
                        EnvironmentType = "vcf9"
                        Servers = @{
                            SddcManager = "sddc.example.com"
                            Nsx = $null
                            Vcenter = $null
                            VcfOps = $null
                            FleetManager = $null
                        }
                        Users = @{
                            SddcManager = "administrator@vsphere.local"
                            Nsx = $null
                            Vcenter = $null
                            VcfOps = $null
                            FleetManager = $null
                        }
                        UseSinglePassword = $false
                    }

                    $result = Invoke-VCFPatchScanner -AdvisoryPath $testAdvisoryFile `
                        -FindingsOutputPath $testFindingsFile `
                        -EnvironmentType vcf9 `
                        -EnvironmentConfig $config

                    $result.Status | Should -Be "Success"
                    $result.ExitCode | Should -Be 0
                    $result.AdvisoriesLoaded | Should -Be 1
                    $result.AdvisoriesFiltered | Should -Be 1
                    Test-Path -LiteralPath $testFindingsFile | Should -Be $true
                }
                finally {
                    if (Test-Path -LiteralPath $testAdvisoryFile) { Remove-Item -LiteralPath $testAdvisoryFile -Force }
                    if (Test-Path -LiteralPath $testFindingsFile) { Remove-Item -LiteralPath $testFindingsFile -Force }
                }
            }
        }

        It "Exports CSV when specified" {
            InModuleScope VcfPatchScanner {
                $testAdvisoryFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "adv_csv_$([System.Guid]::NewGuid()).json"
                $testJsonFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "find_csv_$([System.Guid]::NewGuid()).json"
                $testCsvFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "find_csv_$([System.Guid]::NewGuid()).csv"

                try {
                    $advisoryDoc = [PSCustomObject]@{
                        schemaVersion = "2.0"
                        updatedAt     = "2026-06-17T00:00:00Z"
                        advisories    = @(
                            [PSCustomObject]@{
                                vmsaId = "VMSA-2026-0001"
                                severity = "High"
                                impactedComponents = @(
                                    [PSCustomObject]@{
                                        component = "vCenter"
                                        minimumVersions = @("8.0")
                                        fixedVersions = @("8.0.1")
                                        severity = "High"
                                        cves = @("CVE-TEST")
                                        fixedVersionUrl = "https://..."
                                    }
                                )
                            }
                        )
                    } | ConvertTo-Json -Depth 10

                    Set-Content -LiteralPath $testAdvisoryFile -Value $advisoryDoc

                    $config = [PSCustomObject]@{
                        EnvironmentId = "test-env-2"
                        Name = "Lab"
                        EnvironmentType = "vsphere8"
                        Servers = @{ Vcenter = "vcenter.example.com" }
                        Users = @{ Vcenter = "admin@vsphere.local" }
                        UseSinglePassword = $false
                    }

                    $result = Invoke-VCFPatchScanner -AdvisoryPath $testAdvisoryFile `
                        -FindingsOutputPath $testJsonFile `
                        -EnvironmentType vsphere8 `
                        -EnvironmentConfig $config `
                        -ExportCsv $testCsvFile

                    Test-Path -LiteralPath $testJsonFile | Should -Be $true
                    Test-Path -LiteralPath $testCsvFile | Should -Be $true
                }
                finally {
                    if (Test-Path -LiteralPath $testAdvisoryFile) { Remove-Item -LiteralPath $testAdvisoryFile -Force }
                    if (Test-Path -LiteralPath $testJsonFile) { Remove-Item -LiteralPath $testJsonFile -Force }
                    if (Test-Path -LiteralPath $testCsvFile) { Remove-Item -LiteralPath $testCsvFile -Force }
                }
            }
        }
    }

    Context "Invoke-VCFPatchScanner — Edge Cases" {

        It "Returns success when no applicable advisories" {
            InModuleScope VcfPatchScanner {
                $testAdvisoryFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "noapp_$([System.Guid]::NewGuid()).json"
                $testFindingsFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "noapp_$([System.Guid]::NewGuid()).json"

                try {
                    $advisoryDoc = [PSCustomObject]@{
                        schemaVersion = "2.0"
                        updatedAt     = "2026-06-17T00:00:00Z"
                        advisories    = @(
                            [PSCustomObject]@{
                                vmsaId = "VMSA-2026-0001"
                                severity = "Critical"
                                impactedComponents = @(
                                    [PSCustomObject]@{
                                        component = "VCF Operations"
                                        minimumVersions = @("9.0")
                                        fixedVersions = @("9.1")
                                        severity = "Critical"
                                        cves = @("CVE-2025-12345")
                                        fixedVersionUrl = "https://..."
                                    }
                                )
                            }
                        )
                    } | ConvertTo-Json -Depth 10

                    Set-Content -LiteralPath $testAdvisoryFile -Value $advisoryDoc

                    $config = [PSCustomObject]@{
                        EnvironmentId = "test-env-3"
                        Name = "Lab"
                        EnvironmentType = "vsphere8"
                        Servers = @{ Vcenter = "vcenter.example.com" }
                        Users = @{ Vcenter = "admin" }
                        UseSinglePassword = $false
                    }

                    $result = Invoke-VCFPatchScanner -AdvisoryPath $testAdvisoryFile `
                        -FindingsOutputPath $testFindingsFile `
                        -EnvironmentType vsphere8 `
                        -EnvironmentConfig $config

                    $result.Status | Should -Be "Success"
                    $result.ExitCode | Should -Be 0
                    $result.AdvisoriesLoaded | Should -Be 1
                    $result.AdvisoriesFiltered | Should -Be 0
                    $result.FindingsCount | Should -Be 0
                }
                finally {
                    if (Test-Path -LiteralPath $testAdvisoryFile) { Remove-Item -LiteralPath $testAdvisoryFile -Force }
                    if (Test-Path -LiteralPath $testFindingsFile) { Remove-Item -LiteralPath $testFindingsFile -Force }
                }
            }
        }

        It "Returns error when advisory file not found" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    EnvironmentId = "test"
                    Name = "Lab"
                    EnvironmentType = "vcf9"
                    Servers = @{}
                    Users = @{}
                    UseSinglePassword = $false
                }

                $result = Invoke-VCFPatchScanner -AdvisoryPath "/nonexistent/advisory.json" `
                    -FindingsOutputPath "findings.json" `
                    -EnvironmentType vcf9 `
                    -EnvironmentConfig $config

                $result.Status | Should -Be "Failed"
                $result.ExitCode | Should -Be 1
            }
        }

        It "Returns error when advisory JSON is invalid" {
            InModuleScope VcfPatchScanner {
                $testAdvisoryFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "invalid_$([System.Guid]::NewGuid()).json"
                $testFindingsFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "invalid_$([System.Guid]::NewGuid()).json"

                try {
                    Set-Content -LiteralPath $testAdvisoryFile -Value "{ invalid json }"

                    $config = [PSCustomObject]@{
                        EnvironmentId = "test"
                        Name = "Lab"
                        EnvironmentType = "vcf9"
                        Servers = @{}
                        Users = @{}
                        UseSinglePassword = $false
                    }

                    $result = Invoke-VCFPatchScanner -AdvisoryPath $testAdvisoryFile `
                        -FindingsOutputPath $testFindingsFile `
                        -EnvironmentType vcf9 `
                        -EnvironmentConfig $config

                    $result.Status | Should -Be "Failed"
                    $result.ExitCode | Should -Be 1
                }
                finally {
                    if (Test-Path -LiteralPath $testAdvisoryFile) { Remove-Item -LiteralPath $testAdvisoryFile -Force }
                    if (Test-Path -LiteralPath $testFindingsFile) { Remove-Item -LiteralPath $testFindingsFile -Force }
                }
            }
        }
    }

    Context "Invoke-VCFPatchScanner — Return Value Structure" {

        It "Returns result with all required properties" {
            InModuleScope VcfPatchScanner {
                $testAdvisoryFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "struct_$([System.Guid]::NewGuid()).json"
                $testFindingsFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "struct_$([System.Guid]::NewGuid()).json"

                try {
                    Set-Content -LiteralPath $testAdvisoryFile -Value "[]"

                    $config = [PSCustomObject]@{
                        EnvironmentId = "test"
                        Name = "Lab"
                        EnvironmentType = "vcf5"
                        Servers = @{ SddcManager = "sddc.example.com" }
                        Users = @{ SddcManager = "admin" }
                        UseSinglePassword = $false
                    }

                    $result = Invoke-VCFPatchScanner -AdvisoryPath $testAdvisoryFile `
                        -FindingsOutputPath $testFindingsFile `
                        -EnvironmentType vcf5 `
                        -EnvironmentConfig $config

                    $result | Should -Not -Be $null
                    $result.Status | Should -Not -Be $null
                    $result.ScanStartedAt | Should -Not -Be $null
                    $result.ScanCompletedAt | Should -Not -Be $null
                    $result.DurationSeconds | Should -Not -Be $null
                    $result.AdvisoriesLoaded | Should -Not -Be $null
                    $result.AdvisoriesFiltered | Should -Not -Be $null
                    $result.FindingsCount | Should -Not -Be $null
                    $result.FindingsPath | Should -Not -Be $null
                    $result.ExitCode | Should -Not -Be $null
                }
                finally {
                    if (Test-Path -LiteralPath $testAdvisoryFile) { Remove-Item -LiteralPath $testAdvisoryFile -Force }
                    if (Test-Path -LiteralPath $testFindingsFile) { Remove-Item -LiteralPath $testFindingsFile -Force }
                }
            }
        }
    }

    Context "ConvertTo-ScanInventory" {

        It "Creates correct inventory for VCF 5" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    sddcManagerServer = "sddc.example.com"
                    vcenterServer = "vcenter.example.com"
                }

                # ConvertTo-ScanInventory returns [PSCustomObject]@{ Inventory = $hashtable; ... }
                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vcf5

                $result.Inventory.Keys | Should -Contain "SDDC Manager"
                $result.Inventory.Keys | Should -Contain "vCenter"
                $result.Inventory['SDDC Manager'][0].Fqdn | Should -Be "sddc.example.com"
            }
        }

        It "Creates correct inventory for VCF 9" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    sddcManagerServer = "sddc.example.com"
                    vcfOpsServer = "ops.example.com"
                    vcfFMServer = "fleet.example.com"
                }

                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vcf9

                $result.Inventory.Keys | Should -Contain "SDDC Manager"
                $result.Inventory.Keys | Should -Contain "VCF Operations"
                $result.Inventory.Keys | Should -Contain "Fleet Lifecycle"
                # SDDC Manager belongs to the management domain — unknown without a live API call.
                $result.Inventory['SDDC Manager'][0].DomainName | Should -Be ''
                # Fleet-tier components are tagged at collection time.
                $result.Inventory['VCF Operations'][0].DomainName | Should -Be 'VCF Fleet'
                $result.Inventory['Fleet Lifecycle'][0].DomainName | Should -Be 'VCF Fleet'
            }
        }

        It "Creates correct inventory for vSphere 8" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    vcenterServer = "vcenter.example.com"
                    sddcManagerServer = "sddc.example.com"
                }

                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vsphere8

                $result.Inventory.Keys | Should -Contain "vCenter"
                $result.Inventory.Keys | Should -Not -Contain "SDDC Manager"
            }
        }

        It "Skips null servers" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    sddcManagerServer = $null
                    vcenterServer = "vcenter.example.com"
                }

                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vcf5

                $result.Inventory.Keys | Should -Not -Contain "SDDC Manager"
                $result.Inventory.Keys | Should -Contain "vCenter"
            }
        }
    }

    Context "ConvertTo-InventoryStatus" {

        It "Emits ServerFqdn (not Endpoint) for safe components" {
            InModuleScope VcfPatchScanner {
                $inventory = @{
                    'ESXi' = @(
                        [PSCustomObject]@{ Fqdn = 'esx01.example.com'; Version = '9.1.0.0' },
                        [PSCustomObject]@{ Fqdn = 'esx02.example.com'; Version = '9.1.0.0' }
                    )
                }

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings @()

                $status.Count | Should -Be 2
                $fqdns = @($status | Select-Object -ExpandProperty ServerFqdn)
                $fqdns | Should -Contain 'esx01.example.com'
                $fqdns | Should -Contain 'esx02.example.com'
                $status[0].PSObject.Properties.Name | Should -Not -Contain 'Endpoint'
            }
        }

        It "Carries per-item DomainName from inventory items through to status entries" {
            InModuleScope VcfPatchScanner {
                # Fleet-tier components carry "VCF Fleet"; SDDC-managed components carry
                # their workload domain name. Both should flow through unchanged.
                $inventory = @{
                    'Fleet Lifecycle' = @(
                        [PSCustomObject]@{ Fqdn = 'flt-fc01.example.com'; Version = '9.1.0.0'; DomainName = 'VCF Fleet' }
                    )
                    'ESXi' = @(
                        [PSCustomObject]@{ Fqdn = 'esx01.example.com'; Version = '9.1.0.0'; DomainName = 'sfo-m01' }
                    )
                }

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings @()

                $fleetEntry = $status | Where-Object { $_.component -eq 'Fleet Lifecycle' }
                $esxiEntry  = $status | Where-Object { $_.component -eq 'ESXi' }
                $fleetEntry.DomainName | Should -Be 'VCF Fleet'
                $esxiEntry.DomainName  | Should -Be 'sfo-m01'
            }
        }

        It "Produces empty DomainName when inventory item has no DomainName property" {
            InModuleScope VcfPatchScanner {
                $inventory = @{
                    'vCenter' = @([PSCustomObject]@{ Fqdn = 'vc.example.com'; Version = '8.0' })
                }

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings @()

                $status[0].DomainName | Should -Be ''
            }
        }

        It "Excludes endpoints that already have vulnerability findings" {
            InModuleScope VcfPatchScanner {
                $inventory = @{
                    'ESXi' = @(
                        [PSCustomObject]@{ Fqdn = 'esx01.example.com'; Version = '9.1.0.0' },
                        [PSCustomObject]@{ Fqdn = 'esx02.example.com'; Version = '9.1.0.0' }
                    )
                }
                $findings = @(
                    [PSCustomObject]@{ component = 'ESXi'; ServerFqdn = 'esx01.example.com'; vmsaId = 'VMSA-2026-0001'; Severity = 'Critical'; cves = @('CVE-1') }
                )

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings $findings

                # esx01 already has a finding so it should not appear in inventory status
                $status.Count | Should -Be 1
                $status[0].ServerFqdn | Should -Be 'esx02.example.com'
                $status[0].Status | Should -Be 'Safe'
            }
        }

        It "Produces one row per unique FQDN (no duplicates)" {
            InModuleScope VcfPatchScanner {
                $inventory = @{
                    'ESXi' = @(
                        [PSCustomObject]@{ Fqdn = 'esx01.example.com'; Version = '9.1.0.0' },
                        [PSCustomObject]@{ Fqdn = 'esx02.example.com'; Version = '9.1.0.0' },
                        [PSCustomObject]@{ Fqdn = 'esx03.example.com'; Version = '9.1.0.0' },
                        [PSCustomObject]@{ Fqdn = 'esx04.example.com'; Version = '9.1.0.0' }
                    )
                }

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings @()

                $status.Count | Should -Be 4
                ($status | Select-Object -ExpandProperty ServerFqdn | Select-Object -Unique).Count | Should -Be 4
            }
        }

        It "Suppresses Safe row when finding uses an advisory alias name for the same inventory key" {
            InModuleScope VcfPatchScanner {
                # vRSLCM reports vrops as "VCF Operations" (inventory key).
                # Advisories list the same product as "VMware Aria Operations" (advisory name).
                # The finding's component field uses the advisory name; the inventory key is the
                # canonical alias target. Without alias resolution in the dedup set, both a
                # "VMware Aria Operations" vulnerability finding AND a "VCF Operations" Safe row
                # would appear for the same server — a contradictory result.
                $inventory = @{
                    'VCF Operations' = @(
                        [PSCustomObject]@{ Fqdn = 'ops01.example.com'; Version = '8.18.0' }
                    )
                }
                $findings = @(
                    [PSCustomObject]@{
                        component   = 'VMware Aria Operations'
                        serverFqdn  = 'ops01.example.com'
                        vmsaId      = 'VMSA-2026-0004'
                        severity    = 'Critical'
                        cves        = @('CVE-2026-0001')
                    }
                )

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings $findings

                $status.Count | Should -Be 0 -Because "ops01.example.com already has a vulnerability finding via its advisory alias name; emitting a Safe row for the same server under its inventory key is a false negative"
            }
        }
        It "Produces one row per component even when multiple Fleet components share the same FQDN" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                # Salt Master, Salt RaaS, and Fleet Lifecycle can all run on the same host.
                $sharedFqdn = 'flt-fc01.example.com'
                $inventory = @{
                    'Fleet Lifecycle' = @([PSCustomObject]@{ Fqdn = $sharedFqdn; Version = '9.1.0.0100' })
                    'Salt Master'     = @([PSCustomObject]@{ Fqdn = $sharedFqdn; Version = '3006.0' })
                    'Salt RaaS'       = @([PSCustomObject]@{ Fqdn = $sharedFqdn; Version = '8.32.0' })
                }

                $status = ConvertTo-InventoryStatus -Inventory $inventory -Findings @()

                $status.Count | Should -Be 3
                $status | Where-Object { $_.component -eq 'Fleet Lifecycle' } | Should -Not -BeNullOrEmpty
                $status | Where-Object { $_.component -eq 'Salt Master' }     | Should -Not -BeNullOrEmpty
                $status | Where-Object { $_.component -eq 'Salt RaaS' }       | Should -Not -BeNullOrEmpty
                Should -Not -Invoke Write-LogMessage -ParameterFilter { $Type -eq 'ERROR' }
            }
        }
    }

    Context "Phase Integration" {

        It "Successfully orchestrates all phases: Discovery → Advisory → Scanning → Findings" {
            InModuleScope VcfPatchScanner {
                $testAdvisoryFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "integration_$([System.Guid]::NewGuid()).json"
                $testFindingsFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "integration_$([System.Guid]::NewGuid()).json"

                try {
                    # Advisory for SDDC Manager 5.0 → 5.1 so mock inventory (version 5.0) produces a vulnerability.
                    $advisoryDoc = [PSCustomObject]@{
                        schemaVersion = "2.0"
                        updatedAt     = "2026-06-17T00:00:00Z"
                        advisories    = @(
                            [PSCustomObject]@{
                                vmsaId = "VMSA-2026-0001"
                                VmsaUrl = ""
                                severity = "Critical"
                                impactedComponents = @(
                                    [PSCustomObject]@{
                                        component = "SDDC Manager"
                                        minimumVersions = @("5.0")
                                        fixedVersions = @("5.1")
                                        severity = "Critical"
                                        cves = @("CVE-2025-12345")
                                        fixedVersionUrl = "https://example.com"
                                    }
                                )
                            }
                        )
                    } | ConvertTo-Json -Depth 10

                    Set-Content -LiteralPath $testAdvisoryFile -Value $advisoryDoc

                    $config = [PSCustomObject]@{
                        sddcManagerServer = "sddc.example.com"
                        sddcManagerUser   = "administrator@vsphere.local"
                    }

                    # Return version 5.0 so the SDDC Manager advisory (5.0 → 5.1) produces a finding.
                    Mock Get-SddcManagerInventory {
                        @{
                            "SDDC Manager" = @([PSCustomObject]@{ Fqdn = "sddc.example.com"; Version = "5.0.0"; DomainName = "" })
                        }
                    }

                    $result = Invoke-VCFPatchScanner -AdvisoryPath $testAdvisoryFile `
                        -FindingsOutputPath $testFindingsFile `
                        -EnvironmentType vcf5 `
                        -EnvironmentConfig $config `
                        -UseLiveInventory

                    $result.Status | Should -Be "Success"
                    $result.ExitCode | Should -Be 0
                    $result.AdvisoriesLoaded | Should -Be 1
                    $result.AdvisoriesFiltered | Should -Be 1

                    Test-Path -LiteralPath $testFindingsFile | Should -Be $true
                    # Findings file is { findings: [...], failedEndpoints: [...], ... }
                    $output = Get-Content -LiteralPath $testFindingsFile -Raw | ConvertFrom-Json
                    $output.findings | Should -Not -Be $null
                    @($output.findings).Count | Should -Be 1
                    $output.findings[0].component | Should -Be "SDDC Manager"
                    $output.findings[0].vmsaId | Should -Be "VMSA-2026-0001"
                }
                finally {
                    if (Test-Path -LiteralPath $testAdvisoryFile) { Remove-Item -LiteralPath $testAdvisoryFile -Force }
                    if (Test-Path -LiteralPath $testFindingsFile) { Remove-Item -LiteralPath $testFindingsFile -Force }
                }
            }
        }
    }

    Context "ConvertTo-ScanInventory — Negative Path" {

        It "Populates FailedEndpoints when SDDC Manager inventory call throws during live collection" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    sddcManagerServer = "sddc.example.com"
                    sddcManagerUser   = "admin@vsphere.local"
                    vcenterServer     = "vcenter.example.com"
                    vcenterUser       = "admin@vsphere.local"
                }

                Mock Get-SddcManagerInventory { throw "Connection refused: sddc.example.com port 443" }
                Mock Get-VcenterBuildMap { @{ VersionToBuild = @{}; BuildToVersion = @{} } }
                Mock Get-VcenterInventory {
                    @{ "vCenter" = @([PSCustomObject]@{ Fqdn = "vcenter.example.com"; Version = "8.0.3"; DomainName = "" }) }
                }
                Mock Write-LogMessage

                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vcf5 -UseLiveInventory

                $result.FailedEndpoints.Count | Should -BeGreaterOrEqual 1
                $result.FailedEndpoints[0].Component | Should -Be "SDDC Manager"
                $result.Inventory.ContainsKey("vCenter") | Should -Be $true
            }
        }

        It "Falls back to mock inventory when all live collection returns empty data" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    sddcManagerServer = "sddc.example.com"
                    sddcManagerUser   = "admin@vsphere.local"
                    vcenterServer     = "vcenter.example.com"
                    vcenterUser       = "admin@vsphere.local"
                }

                Mock Get-VcenterBuildMap { @{ VersionToBuild = @{}; BuildToVersion = @{} } }
                Mock Get-SddcManagerInventory { return @{} }
                Mock Get-VcenterInventory { return @{} }
                Mock Write-LogMessage

                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vcf5 -UseLiveInventory

                # When all live collection returns empty the function falls back to mock inventory.
                # Mock inventory always reports Version = "Unknown" for every configured server.
                $result.Inventory.ContainsKey("SDDC Manager") | Should -Be $true
                $result.Inventory["SDDC Manager"][0].Version | Should -Be "Unknown"
            }
        }

        It "VVF9 scan with no adapter FQDNs discovered still produces valid fleet inventory" {
            InModuleScope VcfPatchScanner {
                $config = [PSCustomObject]@{
                    vcfOpsServer = "ops.example.com"
                    vcfOpsUser   = "admin@local"
                    vcfFMServer  = "fm.example.com"
                    vcfFMUser    = "admin@local"
                    vcenterUser  = "admin@vsphere.local"
                }

                Mock Get-VcenterBuildMap { @{ VersionToBuild = @{}; BuildToVersion = @{} } }
                Mock Get-FleetManagerInventory {
                    @{
                        '_FleetApiPath'       = 'vsp'
                        "Fleet Lifecycle"     = @([PSCustomObject]@{ Fqdn = "fm.example.com"; Version = "9.1.0"; DomainName = "VCF Fleet" })
                    }
                }
                Mock Get-FleetManagerReleaseVersions { return @() }
                Mock ConvertTo-FleetBuildNumberMap { return @{} }
                Mock Get-VcfOpsInventory {
                    @{
                        "VCF Operations"          = @([PSCustomObject]@{ Fqdn = "ops.example.com"; Version = "9.1.0"; DomainName = "VCF Fleet" })
                        "_StandaloneVcenterFqdns" = @()
                    }
                }
                Mock Write-LogMessage

                $result = ConvertTo-ScanInventory -EnvironmentConfig $config -EnvironmentType vvf9 -UseLiveInventory

                $result.Inventory.ContainsKey("Fleet Lifecycle") | Should -Be $true
                $result.Inventory.ContainsKey("VCF Operations") | Should -Be $true
                $result.FailedEndpoints.Count | Should -Be 0
            }
        }
    }
}
