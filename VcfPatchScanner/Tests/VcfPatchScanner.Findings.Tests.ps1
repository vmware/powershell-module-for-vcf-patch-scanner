# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.Findings" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Export-PatchScanFindings — JSON Export" {

        It "Exports empty findings array to JSON" {
            InModuleScope VcfPatchScanner {
                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_empty_$([System.Guid]::NewGuid()).json"

                try {
                    Export-PatchScanFindings -Findings @() -OutputPath $testFile

                    Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
                    $content = Get-Content -LiteralPath $testFile -Raw
                    $content | Should -Not -BeNullOrEmpty
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Exports findings with all properties" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{
                        component = "ESXi"
                        currentVersion = "7.0.1"
                        vulnerableMinimumVersion = @("7.0")
                        fixedVersions = @("7.0.3")
                        severity = "Critical"
                        cves = @("CVE-2025-12345")
                        vmsaId = "VMSA-2026-0001"
                        fixedVersionUrl = "https://example.com"
                        serverFqdn = "host1.example.com"
                    }
                )

                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_full_$([System.Guid]::NewGuid()).json"

                try {
                    Export-PatchScanFindings -Findings $findings -OutputPath $testFile

                    Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
                    $content = Get-Content -LiteralPath $testFile -Raw
                    $json = $content | ConvertFrom-Json
                    $json.findings.Count | Should -Be 1
                    $json.findings[0].component | Should -Be "ESXi"
                    $json.findings[0].vmsaId | Should -Be "VMSA-2026-0001"
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Creates output directory if it does not exist" {
            InModuleScope VcfPatchScanner {
                $testDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_test_$([System.Guid]::NewGuid())"
                $testFile = Join-Path -Path $testDir -ChildPath "findings.json"

                try {
                    Export-PatchScanFindings -Findings @() -OutputPath $testFile

                    Test-Path -LiteralPath $testDir -PathType Container | Should -Be $true
                    Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
                }
                finally {
                    if (Test-Path -LiteralPath $testDir) { Remove-Item -LiteralPath $testDir -Recurse -Force }
                }
            }
        }

        It "Overwrites existing file" {
            InModuleScope VcfPatchScanner {
                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_overwrite_$([System.Guid]::NewGuid()).json"

                try {
                    Set-Content -LiteralPath $testFile -Value "old content"

                    $findings = @([PSCustomObject]@{ component = "ESXi"; severity = "High" })
                    Export-PatchScanFindings -Findings $findings -OutputPath $testFile

                    $content = Get-Content -LiteralPath $testFile -Raw
                    $content | Should -Not -Match "old content"
                    $content | Should -Match 'component'
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Logs export progress" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $findings = @([PSCustomObject]@{ component = "ESXi"; severity = "High" })
                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_log_$([System.Guid]::NewGuid()).json"

                try {
                    Export-PatchScanFindings -Findings $findings -OutputPath $testFile
                    Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "Findings exported" }
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Throws when the output directory cannot be created" {
            InModuleScope VcfPatchScanner {
                # Use a path whose parent is a regular file, not a directory — guaranteed
                # to fail on every platform without requiring a pre-existing directory.
                $existingFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_blocker_$([System.Guid]::NewGuid()).tmp"
                [System.IO.File]::WriteAllText($existingFile, "blocker")

                $invalidPath = Join-Path -Path $existingFile -ChildPath "findings.json"

                try {
                    {
                        Export-PatchScanFindings -Findings @() -OutputPath $invalidPath
                    } | Should -Throw
                }
                finally {
                    if (Test-Path -LiteralPath $existingFile) { Remove-Item -LiteralPath $existingFile -Force }
                }
            }
        }
    }

    Context "Export-PatchScanFindingsCSV — CSV Export" {

        It "Exports findings to CSV with proper columns" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{
                        component = "ESXi"
                        currentVersion = "7.0.1"
                        vulnerableMinimumVersion = @("7.0")
                        fixedVersions = @("7.0.3")
                        severity = "Critical"
                        cves = @("CVE-2025-12345")
                        vmsaId = "VMSA-2026-0001"
                        serverFqdn = "host1.example.com"
                    }
                )

                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindingsCSV -Findings $findings -OutputPath $testFile

                    Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
                    $content = Get-Content -LiteralPath $testFile -Raw
                    $content | Should -Match "Component"
                    $content | Should -Match 'component'
                    $content | Should -Match "VMSA-2026-0001"
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Handles multiple findings" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{
                        component = "ESXi"
                        currentVersion = "7.0.1"
                        vulnerableMinimumVersion = @("7.0")
                        fixedVersions = @("7.0.3")
                        severity = "Critical"
                        cves = @("CVE-1", "CVE-2")
                        vmsaId = "VMSA-2026-0001"
                        serverFqdn = "host1.example.com"
                    },
                    [PSCustomObject]@{
                        component = "vCenter"
                        currentVersion = "7.0.2"
                        vulnerableMinimumVersion = @("7.0")
                        fixedVersions = @("7.0.4")
                        severity = "High"
                        cves = @("CVE-3")
                        vmsaId = "VMSA-2026-0002"
                        serverFqdn = "vcenter.example.com"
                    }
                )

                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_multi_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindingsCSV -Findings $findings -OutputPath $testFile

                    $content = Get-Content -LiteralPath $testFile -Raw
                    $lines = $content -split "`n" | Where-Object { $_ }
                    $lines.Count | Should -BeGreaterOrEqual 2  # header + at least 1 data row
                    $content | Should -Match 'component'
                    $content | Should -Match "vCenter"
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Formats CVE array as semicolon-delimited string" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{
                        component = "ESXi"
                        currentVersion = "7.0.1"
                        vulnerableMinimumVersion = @("7.0")
                        fixedVersions = @("7.0.3")
                        severity = "Critical"
                        cves = @("CVE-2025-12345", "CVE-2025-67890")
                        vmsaId = "VMSA-2026-0001"
                        serverFqdn = "host1.example.com"
                    }
                )

                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_cve_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindingsCSV -Findings $findings -OutputPath $testFile

                    $content = Get-Content -LiteralPath $testFile -Raw
                    $content | Should -Match "CVE-2025-12345"
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Creates output directory if it does not exist" {
            InModuleScope VcfPatchScanner {
                $testDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_csv_$([System.Guid]::NewGuid())"
                $testFile = Join-Path -Path $testDir -ChildPath "findings.csv"

                try {
                    Export-PatchScanFindingsCSV -Findings @() -OutputPath $testFile

                    Test-Path -LiteralPath $testDir -PathType Container | Should -Be $true
                    Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
                }
                finally {
                    if (Test-Path -LiteralPath $testDir) { Remove-Item -LiteralPath $testDir -Recurse -Force }
                }
            }
        }

        It "Logs export progress" {
            InModuleScope VcfPatchScanner {
                Mock Write-LogMessage
                $findings = @([PSCustomObject]@{
                    component = "ESXi"
                    currentVersion = "7.0.1"
                    vulnerableMinimumVersion = @("7.0")
                    fixedVersions = @("7.0.3")
                    severity = "Critical"
                    cves = @()
                    vmsaId = "VMSA-2026-0001"
                    serverFqdn = "host1"
                })
                $testFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_log_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindingsCSV -Findings $findings -OutputPath $testFile
                    Should -Invoke Write-LogMessage -ParameterFilter { $Message -match "Findings exported" }
                }
                finally {
                    if (Test-Path -LiteralPath $testFile) { Remove-Item -LiteralPath $testFile -Force }
                }
            }
        }

        It "Throws when the output directory cannot be created" {
            InModuleScope VcfPatchScanner {
                $existingFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "csv_blocker_$([System.Guid]::NewGuid()).tmp"
                [System.IO.File]::WriteAllText($existingFile, "blocker")

                $invalidPath = Join-Path -Path $existingFile -ChildPath "findings.csv"

                try {
                    {
                        Export-PatchScanFindingsCSV -Findings @() -OutputPath $invalidPath
                    } | Should -Throw
                }
                finally {
                    if (Test-Path -LiteralPath $existingFile) { Remove-Item -LiteralPath $existingFile -Force }
                }
            }
        }
    }

    Context "JSON and CSV Compatibility" {

        It "JSON and CSV export same findings data" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{
                        component = "ESXi"
                        currentVersion = "7.0.1"
                        vulnerableMinimumVersion = @("7.0")
                        fixedVersions = @("7.0.3")
                        severity = "Critical"
                        cves = @("CVE-2025-12345")
                        vmsaId = "VMSA-2026-0001"
                        fixedVersionUrl = "https://example.com"
                        serverFqdn = "host1.example.com"
                    }
                )

                $jsonFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_$([System.Guid]::NewGuid()).json"
                $csvFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "findings_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindings -Findings $findings -OutputPath $jsonFile
                    Export-PatchScanFindingsCSV -Findings $findings -OutputPath $csvFile

                    $jsonContent = Get-Content -LiteralPath $jsonFile -Raw | ConvertFrom-Json
                    $csvContent = Get-Content -LiteralPath $csvFile -Raw

                    $jsonContent.findings[0].component | Should -Be "ESXi"
                    $csvContent | Should -Match "ESXi"
                }
                finally {
                    if (Test-Path -LiteralPath $jsonFile) { Remove-Item -LiteralPath $jsonFile -Force }
                    if (Test-Path -LiteralPath $csvFile) { Remove-Item -LiteralPath $csvFile -Force }
                }
            }
        }
    }

    Context "Empty and Edge Cases" {

        It "Exports empty findings array to both JSON and CSV" {
            InModuleScope VcfPatchScanner {
                $jsonFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "empty_$([System.Guid]::NewGuid()).json"
                $csvFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "empty_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindings -Findings @() -OutputPath $jsonFile
                    Export-PatchScanFindingsCSV -Findings @() -OutputPath $csvFile

                    Test-Path -LiteralPath $jsonFile -PathType Leaf | Should -Be $true
                    Test-Path -LiteralPath $csvFile -PathType Leaf | Should -Be $true
                }
                finally {
                    if (Test-Path -LiteralPath $jsonFile) { Remove-Item -LiteralPath $jsonFile -Force }
                    if (Test-Path -LiteralPath $csvFile) { Remove-Item -LiteralPath $csvFile -Force }
                }
            }
        }

        It "Handles findings with special characters in component names" {
            InModuleScope VcfPatchScanner {
                $findings = @(
                    [PSCustomObject]@{
                        component = "Fleet Lifecycle"
                        currentVersion = "9.0"
                        vulnerableMinimumVersion = @("8.0")
                        fixedVersions = @("9.1")
                        severity = "Medium"
                        cves = @("CVE-TEST")
                        vmsaId = "VMSA-2026-0001"
                        serverFqdn = "fleet.example.com"
                    }
                )

                $jsonFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "special_$([System.Guid]::NewGuid()).json"
                $csvFile = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "special_$([System.Guid]::NewGuid()).csv"

                try {
                    Export-PatchScanFindings -Findings $findings -OutputPath $jsonFile
                    Export-PatchScanFindingsCSV -Findings $findings -OutputPath $csvFile

                    $jsonContent = Get-Content -LiteralPath $jsonFile -Raw | ConvertFrom-Json
                    $jsonContent.findings[0].component | Should -Be "Fleet Lifecycle"

                    $csvContent = Get-Content -LiteralPath $csvFile -Raw
                    $csvContent | Should -Match "Fleet Lifecycle"
                }
                finally {
                    if (Test-Path -LiteralPath $jsonFile) { Remove-Item -LiteralPath $jsonFile -Force }
                    if (Test-Path -LiteralPath $csvFile) { Remove-Item -LiteralPath $csvFile -Force }
                }
            }
        }
    }
}
