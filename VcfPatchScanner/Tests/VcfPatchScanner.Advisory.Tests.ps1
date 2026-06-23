# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.Advisory" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "ConvertFrom-AdvisoryDocument" {

        It "Accepts valid advisory with required fields" {
            InModuleScope VcfPatchScanner {
                $advisory = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @(@{
                        component = "ESXi"
                        minimumVersions = "7.0"
                        fixedVersions = @("7.0.3")
                    })
                }

                $result = ConvertFrom-AdvisoryDocument -Advisory $advisory
                $result.vmsaId | Should -Be "VMSA-2026-0001"
                $result.severity | Should -Be "Critical"
            }
        }

        It "Throws on missing vmsaId" {
            InModuleScope VcfPatchScanner {
                $advisory = [PSCustomObject]@{
                    severity = "Medium"
                    impactedComponents = @()
                }

                { ConvertFrom-AdvisoryDocument -Advisory $advisory } | Should -Throw
            }
        }

        It "Throws on missing Severity" {
            InModuleScope VcfPatchScanner {
                $advisory = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    impactedComponents = @()
                }

                # -ExpectedMessage performs a fuzzy match against Exception.Message (not FullyQualifiedErrorId).
                { ConvertFrom-AdvisoryDocument -Advisory $advisory } | Should -Throw -ExpectedMessage "*severity*"
            }
        }

        It "Warns when impactedComponents is empty" {
            InModuleScope VcfPatchScanner {
                $advisory = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Medium"
                    impactedComponents = @()
                }

                Mock Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }

                ConvertFrom-AdvisoryDocument -Advisory $advisory
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq "WARNING" }
            }
        }
    }

    Context "Get-AdvisoryComponentMatches" {

        It "Returns advisories matching a component" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = "7.0"
                                fixedVersions = @("7.0.3")
                                cves = @("CVE-2025-12345")
                            }
                        )
                    }
                )

                $matches = Get-AdvisoryComponentMatches -Advisories $advisories -ComponentName "ESXi"
                $matches.Count | Should -Be 1
                $matches[0].vmsaId | Should -Be "VMSA-2026-0001"
                $matches[0].ComponentName | Should -Be "ESXi"
            }
        }

        It "Returns empty array when no matches found" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{
                                component = "ESXi"
                                minimumVersions = "7.0"
                                fixedVersions = @("7.0.3")
                            }
                        )
                    }
                )

                $matches = Get-AdvisoryComponentMatches -Advisories $advisories -ComponentName "vCenter"
                $matches.Count | Should -Be 0
            }
        }

        It "Handles multiple impacted components per advisory" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Medium"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "ESXi"; minimumVersions = "7.0"; fixedVersions = @("7.0.3") },
                            [PSCustomObject]@{ component = "vCenter"; minimumVersions = "7.0"; fixedVersions = @("7.0.4") },
                            [PSCustomObject]@{ component = "NSX"; minimumVersions = "3.0"; fixedVersions = @("3.2.1") }
                        )
                    }
                )

                $esxiMatches = Get-AdvisoryComponentMatches -Advisories $advisories -ComponentName "ESXi"
                $nsxMatches = Get-AdvisoryComponentMatches -Advisories $advisories -ComponentName "NSX"

                $esxiMatches.Count | Should -Be 1
                $nsxMatches.Count | Should -Be 1
                $esxiMatches[0].vmsaId | Should -Be "VMSA-2026-0001"
                $nsxMatches[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Skips invalid advisories and continues" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{ severity = "Critical" },  # Missing vmsaId — invalid
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "ESXi"; minimumVersions = "7.0"; fixedVersions = @("7.0.3") }
                        )
                    }
                )

                Mock Write-LogMessage

                $matches = Get-AdvisoryComponentMatches -Advisories $advisories -ComponentName "ESXi"
                $matches.Count | Should -Be 1
                $matches[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }
    }

    Context "Select-AdvisoryByEnvironmentType" {

        It "Returns VCF 5 applicable advisories" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "ESXi"; minimumVersions = "6.7"; fixedVersions = @("7.0") }
                        )
                    },
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0002"
                        severity = "Medium"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "VMware Fusion"; minimumVersions = "12"; fixedVersions = @("13") }
                        )
                    }
                )

                $filtered = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType vcf5
                $filtered.Count | Should -Be 1
                $filtered[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Returns VCF 9 applicable advisories (includes VCF Operations components)" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "VCF Operations"; minimumVersions = "1.0"; fixedVersions = @("1.1") }
                        )
                    }
                )

                $filtered = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType vcf9
                $filtered.Count | Should -Be 1
            }
        }

        It "Returns vSphere 8 applicable advisories (ESXi, vCenter, NSX; excludes SDDC Manager)" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Medium"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "vCenter"; minimumVersions = "8.0"; fixedVersions = @("8.0.1") }
                        )
                    },
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0002"
                        severity = "Critical"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "NSX"; minimumVersions = "4.0"; fixedVersions = @("4.1") }
                        )
                    },
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0003"
                        severity = "High"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "SDDC Manager"; minimumVersions = "5.0"; fixedVersions = @("5.1") }
                        )
                    }
                )

                $filtered = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType vsphere8
                $filtered.Count | Should -Be 2
                ($filtered | Where-Object { $_.vmsaId -eq "VMSA-2026-0001" }) | Should -Not -BeNullOrEmpty
                ($filtered | Where-Object { $_.vmsaId -eq "VMSA-2026-0002" }) | Should -Not -BeNullOrEmpty
                ($filtered | Where-Object { $_.vmsaId -eq "VMSA-2026-0003" }) | Should -BeNullOrEmpty
            }
        }

        It "Filters return empty when no applicable components" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Medium"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "VMware Fusion"; minimumVersions = "12"; fixedVersions = @("13") }
                        )
                    }
                )

                $filtered = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType vcf9
                $filtered.Count | Should -Be 0
            }
        }

        It "Handles invalid advisories gracefully" {
            InModuleScope VcfPatchScanner {
                $advisories = @(
                    [PSCustomObject]@{ severity = "Critical" },  # Invalid
                    [PSCustomObject]@{
                        vmsaId = "VMSA-2026-0001"
                        severity = "Medium"
                        impactedComponents = @(
                            [PSCustomObject]@{ component = "ESXi"; minimumVersions = "7.0"; fixedVersions = @("7.0.3") }
                        )
                    }
                )

                Mock Write-LogMessage

                $filtered = Select-AdvisoryByEnvironmentType -Advisories $advisories -EnvironmentType vcf5
                $filtered.Count | Should -Be 1
                $filtered[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }
    }

    Context "Get-SecurityAdvisory — File Loading" {

        It "Loads advisory from valid JSON file" {
            InModuleScope VcfPatchScanner {
                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "test_advisory_$([System.Guid]::NewGuid()).json"

                try {
                    $testAdvisory = @(
                        [PSCustomObject]@{
                            vmsaId = "VMSA-2026-0001"
                            severity = "Critical"
                            impactedComponents = @()
                        }
                    ) | ConvertTo-Json -Depth 10

                    Set-Content -LiteralPath $testFile -Value $testAdvisory

                    $result = Get-SecurityAdvisory -FilePath $testFile
                    $result.Count | Should -Be 1
                    $result[0].vmsaId | Should -Be "VMSA-2026-0001"
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Throws when file not found" {
            InModuleScope VcfPatchScanner {
                { Get-SecurityAdvisory -FilePath "/nonexistent/advisory.json" } | Should -Throw
            }
        }

        It "Throws on invalid JSON" {
            InModuleScope VcfPatchScanner {
                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "invalid_json_$([System.Guid]::NewGuid()).json"

                try {
                    Set-Content -LiteralPath $testFile -Value "{ invalid json }"
                    { Get-SecurityAdvisory -FilePath $testFile } | Should -Throw
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }
    }

    Context "Select-AdvisoryByComponent" {

        It "Returns only the ESXi advisory when filtering by single component" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $vcenterAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0002"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "vCenter"; minimumVersions = "8.0"; fixedVersions = @("8.0.2") })
                }
                $nsxAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0003"
                    severity = "Medium"
                    impactedComponents = @([PSCustomObject]@{ component = "NSX"; minimumVersions = "4.0"; fixedVersions = @("4.1.0") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByComponent -Advisories @($esxiAdv, $vcenterAdv, $nsxAdv) -Component 'ESXi'
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Returns ESXi and vCenter advisories when filtering by multiple components" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $vcenterAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0002"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "vCenter"; minimumVersions = "8.0"; fixedVersions = @("8.0.2") })
                }
                $nsxAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0003"
                    severity = "Medium"
                    impactedComponents = @([PSCustomObject]@{ component = "NSX"; minimumVersions = "4.0"; fixedVersions = @("4.1.0") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByComponent -Advisories @($esxiAdv, $vcenterAdv, $nsxAdv) -Component 'ESXi', 'vCenter'
                $result.Count | Should -Be 2
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0001" }) | Should -Not -BeNullOrEmpty
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0002" }) | Should -Not -BeNullOrEmpty
            }
        }

        It "Returns zero matches when no advisory matches the component" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }

                Mock Write-LogMessage

                $result = @(Select-AdvisoryByComponent -Advisories @($esxiAdv) -Component 'SDDC Manager')
                $result.Count | Should -Be 0
            }
        }

        It "Returns advisory when any one of its multiple components matches the filter" {
            InModuleScope VcfPatchScanner {
                $multiCompAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0004"
                    severity = "Critical"
                    impactedComponents = @(
                        [PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") },
                        [PSCustomObject]@{ component = "NSX"; minimumVersions = "4.0"; fixedVersions = @("4.1.0") }
                    )
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByComponent -Advisories @($multiCompAdv) -Component 'NSX'
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0004"
            }
        }

        It "Matches component name case-insensitively (PowerShell -contains operator)" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }

                Mock Write-LogMessage

                # PowerShell's -contains operator is case-insensitive; 'esxi' matches advisory with component 'ESXi'.
                $result = Select-AdvisoryByComponent -Advisories @($esxiAdv) -Component 'esxi'
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Logs WARNING and skips invalid advisory while returning valid ones" {
            InModuleScope VcfPatchScanner {
                $invalidAdv = [PSCustomObject]@{
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $validAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByComponent -Advisories @($invalidAdv, $validAdv) -Component 'ESXi'
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq 'WARNING' }
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Rejects empty Advisories array at parameter binding (ValidateNotNull on Object[])" {
            InModuleScope VcfPatchScanner {
                # [ValidateNotNull()] on [Object[]] without [AllowEmptyCollection()] rejects empty arrays.
                { Select-AdvisoryByComponent -Advisories @() -Component 'ESXi' } | Should -Throw
            }
        }

        It "Filters correctly when called with pipeline input" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $vcenterAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0002"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "vCenter"; minimumVersions = "8.0"; fixedVersions = @("8.0.2") })
                }

                Mock Write-LogMessage

                $result = @($esxiAdv, $vcenterAdv) | Select-AdvisoryByComponent -Component 'ESXi'
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }
    }

    Context "Select-AdvisoryByProductFamily" {

        It "Returns ESXi advisory for VCF product family" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByProductFamily -Advisories @($esxiAdv) -ProductFamily VCF
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Returns VCF Automation advisory for VCF family but not for vSphere family" {
            InModuleScope VcfPatchScanner {
                $vcfAutomationAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0010"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "VCF Automation"; minimumVersions = "8.0"; fixedVersions = @("8.18") })
                }

                Mock Write-LogMessage

                $vcfResult = Select-AdvisoryByProductFamily -Advisories @($vcfAutomationAdv) -ProductFamily VCF
                $vcfResult.Count | Should -Be 1

                $vsphereResult = Select-AdvisoryByProductFamily -Advisories @($vcfAutomationAdv) -ProductFamily vSphere
                $vsphereResult.Count | Should -Be 0
            }
        }

        It "Excludes VCF Automation advisory from vSphere product family" {
            InModuleScope VcfPatchScanner {
                $vcfAutomationAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0010"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "VCF Automation"; minimumVersions = "8.0"; fixedVersions = @("8.18") })
                }
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByProductFamily -Advisories @($vcfAutomationAdv, $esxiAdv) -ProductFamily vSphere
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Returns ESXi and VCF Operations for VVF family and excludes SDDC Manager" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $vcfOpsAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0005"
                    severity = "Medium"
                    impactedComponents = @([PSCustomObject]@{ component = "VCF Operations"; minimumVersions = "8.0"; fixedVersions = @("8.18") })
                }
                $sddcAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0006"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "SDDC Manager"; minimumVersions = "5.0"; fixedVersions = @("5.2") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByProductFamily -Advisories @($esxiAdv, $vcfOpsAdv, $sddcAdv) -ProductFamily VVF
                $result.Count | Should -Be 2
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0001" }) | Should -Not -BeNullOrEmpty
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0005" }) | Should -Not -BeNullOrEmpty
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0006" }) | Should -BeNullOrEmpty
            }
        }

        It "Logs WARNING and skips invalid advisory while returning valid ones" {
            InModuleScope VcfPatchScanner {
                $invalidAdv = [PSCustomObject]@{
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $validAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }

                Mock Write-LogMessage

                $result = Select-AdvisoryByProductFamily -Advisories @($invalidAdv, $validAdv) -ProductFamily VCF
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq 'WARNING' }
                $result.Count | Should -Be 1
                $result[0].vmsaId | Should -Be "VMSA-2026-0001"
            }
        }

        It "Rejects empty Advisories array at parameter binding (ValidateNotNull on Object[])" {
            InModuleScope VcfPatchScanner {
                # [ValidateNotNull()] on [Object[]] without [AllowEmptyCollection()] rejects empty arrays.
                { Select-AdvisoryByProductFamily -Advisories @() -ProductFamily VCF } | Should -Throw
            }
        }

        It "Filters correctly when called with pipeline input" {
            InModuleScope VcfPatchScanner {
                $esxiAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0001"
                    severity = "Critical"
                    impactedComponents = @([PSCustomObject]@{ component = "ESXi"; minimumVersions = "8.0"; fixedVersions = @("8.0.3") })
                }
                $vcfAutomationAdv = [PSCustomObject]@{
                    vmsaId = "VMSA-2026-0010"
                    severity = "High"
                    impactedComponents = @([PSCustomObject]@{ component = "VCF Automation"; minimumVersions = "8.0"; fixedVersions = @("8.18") })
                }

                Mock Write-LogMessage

                $result = @($esxiAdv, $vcfAutomationAdv) | Select-AdvisoryByProductFamily -ProductFamily VCF
                $result.Count | Should -Be 2
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0001" }) | Should -Not -BeNullOrEmpty
                ($result | Where-Object { $_.vmsaId -eq "VMSA-2026-0010" }) | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context "Invoke-AdvisoryDownloadIfChanged" {

        BeforeEach {
            $script:_advTestDir  = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "adv_test_$([System.Guid]::NewGuid())"
            New-Item -ItemType Directory -Path $script:_advTestDir -Force | Out-Null
            $script:_advDestPath = Join-Path -Path $script:_advTestDir -ChildPath "securityAdvisory.json"
        }

        AfterEach {
            if (Test-Path -LiteralPath $script:_advTestDir) {
                Remove-Item -LiteralPath $script:_advTestDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It "Returns Skipped=true and does not write the file when ETags match" {
            $destPath = $script:_advDestPath
            $etagPath = "$destPath.etag"
            # The function strips surrounding quotes from ETag headers before writing the
            # sidecar, so the file contains the bare hash without quotes.
            [System.IO.File]::WriteAllText($etagPath, 'abc123', [System.Text.Encoding]::UTF8)
            [System.IO.File]::WriteAllText($destPath, '{"updatedAt":"2026-01-01T00:00:00Z"}', [System.Text.Encoding]::UTF8)
            $originalMtime = (Get-Item -LiteralPath $destPath).LastWriteTimeUtc

            InModuleScope VcfPatchScanner -ArgumentList $destPath {
                $destPath = $args[0]
                function Invoke-WebRequest {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Uri, [Parameter()] [Object]$Method, [Parameter()] [Object]$TimeoutSec)
                    # Return the ETag with surrounding quotes as GitHub does; function strips them.
                    process { [PSCustomObject]@{ Headers = @{ ETag = '"abc123"' }; Content = "" } }
                }
                $result = Invoke-AdvisoryDownloadIfChanged -DestinationPath $destPath
                $result.Skipped      | Should -Be $true
                $result.Downloaded   | Should -Be $false
                $result.ErrorMessage | Should -BeNullOrEmpty
            }
            # File timestamp must not have changed.
            (Get-Item -LiteralPath $destPath).LastWriteTimeUtc | Should -Be $originalMtime
        }

        It "Returns Downloaded=true and overwrites the file when ETags differ" {
            $destPath = $script:_advDestPath
            $etagPath = "$destPath.etag"
            $advisoryJson = '{"schemaVersion":"2.0","updatedAt":"2026-06-01T00:00:00Z","advisories":[{"vmsaId":"VMSA-2026-0001"}]}'

            InModuleScope VcfPatchScanner -ArgumentList $destPath, $advisoryJson {
                $destPath     = $args[0]
                $advisoryJson = $args[1]
                function Invoke-WebRequest {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Uri, [Parameter()] [Object]$Method, [Parameter()] [Object]$TimeoutSec)
                    process {
                        if ($Method -ieq 'Head') { return [PSCustomObject]@{ Headers = @{ ETag = '"newetag"' }; Content = "" } }
                        return [PSCustomObject]@{ Headers = @{ ETag = '"newetag"' }; Content = $advisoryJson }
                    }
                }
                $result = Invoke-AdvisoryDownloadIfChanged -DestinationPath $destPath
                $result.Downloaded   | Should -Be $true
                $result.Skipped      | Should -Be $false
                $result.ErrorMessage | Should -BeNullOrEmpty
            }
            Test-Path -LiteralPath $destPath -PathType Leaf | Should -Be $true
            Test-Path -LiteralPath $etagPath -PathType Leaf | Should -Be $true
            (Get-Content -LiteralPath $etagPath -Raw).Trim() | Should -Be 'newetag'
        }

        It "Returns an error and does not touch the file when the HEAD request fails" {
            $destPath = $script:_advDestPath

            InModuleScope VcfPatchScanner -ArgumentList $destPath {
                $destPath = $args[0]
                function Invoke-WebRequest {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Uri, [Parameter()] [Object]$Method, [Parameter()] [Object]$TimeoutSec)
                    process { throw "Connection refused." }
                }
                $result = Invoke-AdvisoryDownloadIfChanged -DestinationPath $destPath
                $result.Downloaded   | Should -Be $false
                $result.Skipped      | Should -Be $false
                $result.ErrorMessage | Should -Match "HEAD request failed"
            }
            Test-Path -LiteralPath $destPath -PathType Leaf | Should -Be $false
        }

        It "Returns an error when the upstream file has an incompatible schema version" {
            $destPath = $script:_advDestPath
            $badJson  = '{"schemaVersion":"1.0","advisories":[{"vmsaId":"VMSA-2026-0001"}]}'

            InModuleScope VcfPatchScanner -ArgumentList $destPath, $badJson {
                $destPath = $args[0]
                $badJson  = $args[1]
                function Invoke-WebRequest {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Uri, [Parameter()] [Object]$Method, [Parameter()] [Object]$TimeoutSec)
                    process {
                        if ($Method -ieq 'Head') { return [PSCustomObject]@{ Headers = @{ ETag = '"v1etag"' }; Content = "" } }
                        return [PSCustomObject]@{ Headers = @{ ETag = '"v1etag"' }; Content = $badJson }
                    }
                }
                $result = Invoke-AdvisoryDownloadIfChanged -DestinationPath $destPath
                $result.Downloaded   | Should -Be $false
                $result.ErrorMessage | Should -Match "incompatible"
            }
            Test-Path -LiteralPath $destPath -PathType Leaf | Should -Be $false
        }

        It "Returns an error when the upstream file contains no advisories" {
            $destPath  = $script:_advDestPath
            $emptyJson = '{"schemaVersion":"2.0","advisories":[]}'

            InModuleScope VcfPatchScanner -ArgumentList $destPath, $emptyJson {
                $destPath  = $args[0]
                $emptyJson = $args[1]
                function Invoke-WebRequest {
                    [CmdletBinding()]
                    Param([Parameter()] [Object]$Uri, [Parameter()] [Object]$Method, [Parameter()] [Object]$TimeoutSec)
                    process {
                        if ($Method -ieq 'Head') { return [PSCustomObject]@{ Headers = @{ ETag = '"empty"' }; Content = "" } }
                        return [PSCustomObject]@{ Headers = @{ ETag = '"empty"' }; Content = $emptyJson }
                    }
                }
                $result = Invoke-AdvisoryDownloadIfChanged -DestinationPath $destPath
                $result.Downloaded   | Should -Be $false
                $result.ErrorMessage | Should -Match "no advisories"
            }
        }
    }
}
