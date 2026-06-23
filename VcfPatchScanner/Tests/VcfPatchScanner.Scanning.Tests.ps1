# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.Scanning" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Test-VersionVulnerable" {

        It "Returns false when current version is below minimum version" {
            InModuleScope VcfPatchScanner {
                $vulnerable = Test-VersionVulnerable -CurrentVersion "7.0.0" -MinimumVersion "7.0.1" -FixedVersions @("7.0.3")
                $vulnerable | Should -Be $false
            }
        }

        It "Returns true when current version is between minimum and fixed version" {
            InModuleScope VcfPatchScanner {
                $vulnerable = Test-VersionVulnerable -CurrentVersion "7.0.1" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3")
                $vulnerable | Should -Be $true
            }
        }

        It "Returns false when current version equals fixed version" {
            InModuleScope VcfPatchScanner {
                $vulnerable = Test-VersionVulnerable -CurrentVersion "7.0.3" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3")
                $vulnerable | Should -Be $false
            }
        }

        It "Returns false when current version is above fixed version" {
            InModuleScope VcfPatchScanner {
                $vulnerable = Test-VersionVulnerable -CurrentVersion "7.0.4" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3")
                $vulnerable | Should -Be $false
            }
        }

        It "Handles multiple fixed versions" {
            InModuleScope VcfPatchScanner {
                $vulnerable1 = Test-VersionVulnerable -CurrentVersion "7.0.1" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3", "7.0.5")
                $vulnerable1 | Should -Be $true

                $vulnerable2 = Test-VersionVulnerable -CurrentVersion "7.0.3" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3", "7.0.5")
                $vulnerable2 | Should -Be $false

                $vulnerable3 = Test-VersionVulnerable -CurrentVersion "7.0.5" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3", "7.0.5")
                $vulnerable3 | Should -Be $false
            }
        }

        It "Returns false for invalid current version format" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $vulnerable = Test-VersionVulnerable -CurrentVersion "invalid" -MinimumVersion "7.0.0" -FixedVersions @("7.0.3")
                $vulnerable | Should -Be $false
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }

        It "Returns false for invalid minimum version format" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $vulnerable = Test-VersionVulnerable -CurrentVersion "7.0.1" -MinimumVersion "invalid" -FixedVersions @("7.0.3")
                $vulnerable | Should -Be $false
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }

        It "Handles invalid fixed version gracefully and continues" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $vulnerable = Test-VersionVulnerable -CurrentVersion "7.0.2" -MinimumVersion "7.0.0" -FixedVersions @("invalid", "7.0.3")
                $vulnerable | Should -Be $true
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }
    }

    Context "Invoke-VulnerabilityScan" {

        It "Returns empty array when no advisories provided" {
            InModuleScope VcfPatchScanner {
                $inventory = @{ "ESXi" = @([PSCustomObject]@{ Fqdn = "host1.example.com"; Version = "7.0.1" }) }
                $findings = Invoke-VulnerabilityScan -Advisories @() -Inventory $inventory
                $findings.Count | Should -Be 0
            }
        }

        It "Returns empty array when inventory is empty" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = @("7.0")
                                fixedVersions = @("7.0.3")
                                severity = "Critical"
                                cves = @("CVE-2025-12345")
                                fixedVersionUrl = "https://..."
                            }
                        )
                    }
                )

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory @{}
                $findings.Count | Should -Be 0
            }
        }

        It "Detects vulnerable component" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = @("8.0")
                                fixedVersions = @("8.0.3")
                                severity = "Critical"
                                cves = @("CVE-2025-12345")
                                fixedVersionUrl = "https://example.com/fix"
                            }
                        )
                    }
                )

                $inventory = @{ "ESXi" = @([PSCustomObject]@{ Fqdn = "host1.example.com"; Version = "8.0.1" }) }
                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 1
                $findings[0].component | Should -Be "ESXi"
                $findings[0].currentVersion | Should -Be "8.0.1"
                $findings[0].vmsaId | Should -Be "VMSA-2026-0001"
                $findings[0].serverFqdn | Should -Be "host1.example.com"
            }
        }

        It "Populates instanceName from inventory item when present" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
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

                # InstanceName maps to the VCF 9 friendly name (e.g. the SDDC Manager instance name).
                $inventory = @{
                    "SDDC Manager" = @(
                        [PSCustomObject]@{ Fqdn = "sddc.example.com"; Version = "9.0.0"; InstanceName = "San Francisco" }
                    )
                }

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 1
                $findings[0].instanceName | Should -Be "San Francisco"
            }
        }

        It "Sets instanceName to empty string when inventory item has no InstanceName" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "High"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = @("8.0")
                                fixedVersions = @("8.0.3")
                                severity = "High"
                                cves = @("CVE-TEST")
                                fixedVersionUrl = "https://example.com"
                            }
                        )
                    }
                )

                $inventory = @{
                    "ESXi" = @([PSCustomObject]@{ Fqdn = "esx01.example.com"; Version = "8.0.1" })
                }

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 1
                $findings[0].instanceName | Should -Be ''
            }
        }

        It "Handles multiple vulnerable servers for same component" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "High"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = @("8.0")
                                fixedVersions = @("8.0.3")
                                severity = "High"
                                cves = @("CVE-2025-12345")
                                fixedVersionUrl = "https://example.com/fix"
                            }
                        )
                    }
                )

                $inventory = @{
                    "ESXi" = @(
                        [PSCustomObject]@{ Fqdn = "host1.example.com"; Version = "8.0.1" },
                        [PSCustomObject]@{ Fqdn = "host2.example.com"; Version = "8.0.2" },
                        [PSCustomObject]@{ Fqdn = "host3.example.com"; Version = "8.0.3" }
                    )
                }

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 2
                $findings | Where-Object { $_.ServerFqdn -eq "host1.example.com" } | Should -Not -Be $null
                $findings | Where-Object { $_.ServerFqdn -eq "host2.example.com" } | Should -Not -Be $null
                $findings | Where-Object { $_.ServerFqdn -eq "host3.example.com" } | Should -Be $null
            }
        }

        It "Handles multiple components in single advisory" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = @("8.0")
                                fixedVersions = @("8.0.3")
                                severity = "Critical"
                                cves = @("CVE-2025-12345")
                                fixedVersionUrl = "https://..."
                            },
                            [PSCustomObject]@{
                                component = "vCenter"
                                minimumVersions = @("8.0")
                                fixedVersions = @("8.0.4")
                                severity = "Critical"
                                cves = @("CVE-2025-12345")
                                fixedVersionUrl = "https://..."
                            }
                        )
                    }
                )

                $inventory = @{
                    "ESXi" = @([PSCustomObject]@{ Fqdn = "host1.example.com"; Version = "8.0.1" })
                    "vCenter" = @([PSCustomObject]@{ Fqdn = "vcenter.example.com"; Version = "8.0.2" })
                }

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 2
                $findings | Where-Object { $_.Component -eq "ESXi" } | Should -Not -Be $null
                $findings | Where-Object { $_.Component -eq "vCenter" } | Should -Not -Be $null
            }
        }

        It "Skips advisories without vmsaId" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $advisories = @(
                    [PSCustomObject]@{
                        severity = "Critical"
                        impactedComponents = @()
                    }
                )

                $inventory = @{}
                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 0
                Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "VMSA ID" }
            }
        }

        It "Skips disallowed advisory components" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "VMware Fusion"
                                minimumVersions = @("12")
                                fixedVersions = @("13")
                                severity = "Critical"
                                cves = @("CVE-2025-99999")
                                fixedVersionUrl = "https://..."
                            }
                        )
                    }
                )

                $inventory = @{ "VMware Fusion" = @([PSCustomObject]@{ Fqdn = "workstation.local"; Version = "12.1" }) }
                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 0
            }
        }

        It "Scans NSX Edge nodes when NSX advisory is present and 'NSX Edge' inventory key exists" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0010"
                        severity = "Critical"
                        advisoryUrl = "https://example.com/vmsa-2026-0010"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component       = "NSX"
                                minimumVersions = @("4.1")
                                fixedVersions   = @("4.2.2")
                                severity        = "Critical"
                                cves            = @("CVE-2026-99999")
                                fixedVersionUrl = "https://example.com/fix"
                            }
                        )
                    }
                )

                $inventory = @{
                    "NSX"      = @([PSCustomObject]@{ Fqdn = "nsx-mgr.example.com";   Version = "4.2.0"; DomainName = "" })
                    "NSX Edge" = @(
                        [PSCustomObject]@{ Fqdn = "edge-01.example.com"; Version = "4.2.0"; DomainName = "" }
                        [PSCustomObject]@{ Fqdn = "edge-02.example.com"; Version = "4.2.1"; DomainName = "" }
                    )
                }

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                # All three nodes are vulnerable (below 4.2.2): NSX Manager + 2 Edge nodes.
                $findings.Count | Should -Be 3
                $findings | Where-Object { $_.serverFqdn -eq "nsx-mgr.example.com"  } | Should -Not -BeNullOrEmpty
                $findings | Where-Object { $_.serverFqdn -eq "edge-01.example.com" } | Should -Not -BeNullOrEmpty
                $findings | Where-Object { $_.serverFqdn -eq "edge-02.example.com" } | Should -Not -BeNullOrEmpty
                # component is "NSX" for all (advisory component name); endpointSubType distinguishes Manager from Edge.
                $findings | ForEach-Object { $_.component | Should -Be "NSX" }
                ($findings | Where-Object { $_.serverFqdn -eq "nsx-mgr.example.com" }).endpointSubType | Should -Be "NSX Manager"
                ($findings | Where-Object { $_.serverFqdn -eq "edge-01.example.com" }).endpointSubType | Should -Be "NSX Edge"
                ($findings | Where-Object { $_.serverFqdn -eq "edge-02.example.com" }).endpointSubType | Should -Be "NSX Edge"
            }
        }

        It "Scans NSX Edge nodes even when no NSX Manager entry exists in inventory" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0011"
                        severity = "High"
                        advisoryUrl = "https://example.com/vmsa-2026-0011"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component       = "NSX"
                                minimumVersions = @("4.0")
                                fixedVersions   = @("4.2.1")
                                severity        = "High"
                                cves            = @("CVE-2026-11111")
                                fixedVersionUrl = "https://example.com/fix"
                            }
                        )
                    }
                )

                # Inventory has only edge nodes (e.g. NSX Manager inventory failed but edges succeeded).
                $inventory = @{
                    "NSX Edge" = @([PSCustomObject]@{ Fqdn = "edge-01.example.com"; Version = "4.1.0"; DomainName = "" })
                }

                $findings = Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                $findings.Count | Should -Be 1
                $findings[0].serverFqdn      | Should -Be "edge-01.example.com"
                $findings[0].component       | Should -Be "NSX"
                $findings[0].endpointSubType | Should -Be "NSX Edge"
            }
        }

        It "Logs scan progress and completion" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Low"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = @("7.0")
                                fixedVersions = @("7.0.3")
                                severity = "Low"
                                cves = @("CVE-2025-12345")
                                fixedVersionUrl = "https://..."
                            }
                        )
                    }
                )

                $inventory = @{ "ESXi" = @([PSCustomObject]@{ Fqdn = "host1.example.com"; Version = "7.0.1" }) }
                Invoke-VulnerabilityScan -Advisories $advisories -Inventory $inventory

                Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "Starting vulnerability scan" }
                Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "complete" }
            }
        }
    }

    Context "New-FindingsSummary" {

        It "Returns correct counts for empty findings" {
            InModuleScope VcfPatchScanner {
                $summary = New-FindingsSummary -Findings @()

                $summary.TotalFindings | Should -Be 0
                $summary.UniqueComponents | Should -Be 0
                $summary.CriticalCount | Should -Be 0
                $summary.HighCount | Should -Be 0
            }
        }

        It "Counts findings by severity" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{ component = "ESXi"; severity = "Critical"; cves = @("CVE-1", "CVE-2") },
                    [PSCustomObject]@{ component = "vCenter"; severity = "Critical"; cves = @("CVE-1") },
                    [PSCustomObject]@{ component = "ESXi"; severity = "High"; cves = @("CVE-3") },
                    [PSCustomObject]@{ component = "NSX"; severity = "Medium"; cves = @("CVE-4") }
                )

                $summary = New-FindingsSummary -Findings $findings

                $summary.TotalFindings | Should -Be 4
                $summary.CriticalCount | Should -Be 2
                $summary.HighCount | Should -Be 1
                $summary.MediumCount | Should -Be 1
            }
        }

        It "Counts unique components and CVEs" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{ component = "ESXi"; severity = "Critical"; cves = @("CVE-1", "CVE-2") },
                    [PSCustomObject]@{ component = "ESXi"; severity = "High"; cves = @("CVE-3") },
                    [PSCustomObject]@{ component = "vCenter"; severity = "Medium"; cves = @("CVE-1") }
                )

                $summary = New-FindingsSummary -Findings $findings

                $summary.UniqueComponents | Should -Be 2
                $summary.UniqueCVEs | Should -BeGreaterOrEqual 3
            }
        }
    }

    Context "Merge-FindingsByComponent" {

        It "Aggregates findings by component" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{ component = "ESXi"; serverFqdn = "host1"; cves = @("CVE-1"); severity = "Critical" },
                    [PSCustomObject]@{ component = "ESXi"; serverFqdn = "host2"; cves = @("CVE-1"); severity = "High" },
                    [PSCustomObject]@{ component = "vCenter"; serverFqdn = "vcenter1"; cves = @("CVE-2"); severity = "Medium" }
                )

                $merged = Merge-FindingsByComponent -Findings $findings

                $merged.Count | Should -Be 2
                $merged | Where-Object { $_.Component -eq "ESXi" } | ForEach-Object {
                    $_.VulnerabilityCount | Should -Be 2
                    $_.InstanceCount | Should -Be 2
                }
            }
        }

        It "Preserves original findings in merged result" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{ component = "ESXi"; serverFqdn = "host1"; cves = @("CVE-1"); severity = "Critical" },
                    [PSCustomObject]@{ component = "ESXi"; serverFqdn = "host2"; cves = @("CVE-1"); severity = "Critical" }
                )

                $merged = Merge-FindingsByComponent -Findings $findings

                $merged[0].Findings.Count | Should -Be 2
            }
        }
    }

    Context "ConvertTo-NormalizedVersion" {

        It "Parses a standard four-part version string" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "8.0.3.0"
                $v.Major    | Should -Be 8
                $v.Minor    | Should -Be 0
                $v.Build    | Should -Be 3
                $v.Revision | Should -Be 0
            }
        }

        It "Parses a second standard four-part version string" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "9.1.0.0"
                $v.Major    | Should -Be 9
                $v.Minor    | Should -Be 1
                $v.Build    | Should -Be 0
                $v.Revision | Should -Be 0
            }
        }

        It "Parses a three-part version string — Revision is -1" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "4.2.1"
                $v.Major    | Should -Be 4
                $v.Minor    | Should -Be 2
                $v.Build    | Should -Be 1
                $v.Revision | Should -Be -1
            }
        }

        It "Promotes ESXi-style three-part dash-build to fourth segment" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "8.0.3-24022510"
                $v.Major    | Should -Be 8
                $v.Minor    | Should -Be 0
                $v.Build    | Should -Be 3
                $v.Revision | Should -Be 24022510
            }
        }

        It "Promotes NSX-style three-part dash-build to fourth segment" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "7.0.3-25413364"
                $v.Major    | Should -Be 7
                $v.Minor    | Should -Be 0
                $v.Build    | Should -Be 3
                $v.Revision | Should -Be 25413364
            }
        }

        It "Strips dash suffix from four-part vCenter-style version string" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "8.0.3.00100-24091160"
                $v.Major    | Should -Be 8
                $v.Minor    | Should -Be 0
                $v.Build    | Should -Be 3
                $v.Revision | Should -Be 100
            }
        }

        It "Strips dash suffix from four-part SDDC Manager version string without promoting" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "9.0.0.25370929-25370929"
                $v.Major    | Should -Be 9
                $v.Minor    | Should -Be 0
                $v.Build    | Should -Be 0
                $v.Revision | Should -Be 25370929
            }
        }

        It "Strips trailing EP edition token before parsing" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "8.0.3.00900 EP1"
                $v.Revision | Should -Be 900
            }
        }

        It "Strips trailing HF hotfix token before parsing" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "9.1.0.0 HF"
                $v.Major    | Should -Be 9
                $v.Minor    | Should -Be 1
                $v.Build    | Should -Be 0
                $v.Revision | Should -Be 0
            }
        }

        It "5-part with zero update-level yields build number as Revision" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "9.1.0.0.25370933"
                $v.Major    | Should -Be 9
                $v.Minor    | Should -Be 1
                $v.Build    | Should -Be 0
                $v.Revision | Should -Be 25370933
            }
        }

        It "5-part Update 1 build drops update-level and uses build number as Revision" {
            InModuleScope VcfPatchScanner {
                $v = ConvertTo-NormalizedVersion -VersionString "9.1.0.0100.25428926"
                $v.Major    | Should -Be 9
                $v.Minor    | Should -Be 1
                $v.Build    | Should -Be 0
                $v.Revision | Should -Be 25428926
            }
        }

        It "5-part Update 1 and base-release builds for the same component order correctly" {
            InModuleScope VcfPatchScanner {
                $base   = ConvertTo-NormalizedVersion -VersionString "9.1.0.0.25370933"
                $update = ConvertTo-NormalizedVersion -VersionString "9.1.0.0100.25428926"
                ($base -lt $update) | Should -Be $true
            }
        }

        It "Throws on a non-numeric version string" {
            { InModuleScope VcfPatchScanner { ConvertTo-NormalizedVersion -VersionString "not-a-version" } } | Should -Throw
        }

        It "Throws on the string Unknown" {
            { InModuleScope VcfPatchScanner { ConvertTo-NormalizedVersion -VersionString "Unknown" } } | Should -Throw
        }

        It "Throws when only an edition token remains after stripping" {
            { InModuleScope VcfPatchScanner { ConvertTo-NormalizedVersion -VersionString "EP1" } } | Should -Throw
        }

        It "Dash-promoted form is equivalent to the four-part advisory form" {
            InModuleScope VcfPatchScanner {
                $dashForm  = ConvertTo-NormalizedVersion -VersionString "8.0.3-24022510"
                $dotForm   = ConvertTo-NormalizedVersion -VersionString "8.0.3.24022510"
                $dashForm.CompareTo($dotForm) | Should -Be 0
            }
        }

        It "Dash-promoted earlier build is correctly less than a later build" {
            InModuleScope VcfPatchScanner {
                $earlier = ConvertTo-NormalizedVersion -VersionString "8.0.3-24022510"
                $later   = ConvertTo-NormalizedVersion -VersionString "8.0.3.24103953"
                ($earlier -lt $later) | Should -Be $true
            }
        }
    }
}
