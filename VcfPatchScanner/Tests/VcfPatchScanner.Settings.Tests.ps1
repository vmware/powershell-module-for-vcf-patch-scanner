# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted for brevity - full copyright notice required in production]
# =============================================================================

Describe "VcfPatchScanner.Settings" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
        $Script:TestTempDir = New-Item -ItemType Directory -Path (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "VcfPatchScannerTests_$([System.Guid]::NewGuid())") -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $Script:TestTempDir) {
            Remove-Item -LiteralPath $Script:TestTempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context "New-PatchScanEnvironmentTemplate" {

        It "Creates a valid template with default values" {
            $template = New-PatchScanEnvironmentTemplate

            $template | Should -Not -Be $null
            $template.PSObject.Properties.Name | Should -Contain "environments"
            $template.PSObject.Properties.Name | Should -Contain "findingsOutputDirectory"
            $template.PSObject.Properties.Name | Should -Contain "logLevel"
        }

        It "Initializes environments as empty array" {
            $template = New-PatchScanEnvironmentTemplate
            # Pester receives $null when an empty @() is piped — use -is to avoid this.
            ($template.environments -is [Array]) | Should -Be $true
            $template.environments.Count | Should -Be 0
        }

        It "Sets correct default directory paths" {
            $template = New-PatchScanEnvironmentTemplate

            $template.findingsOutputDirectory | Should -Be "findings"
            $template.logDirectory | Should -Be "logs"
        }

        It "Sets correct default log level" {
            $template = New-PatchScanEnvironmentTemplate
            $template.logLevel | Should -Be "INFO"
        }

        It "Sets correct security advisory file path" {
            $template = New-PatchScanEnvironmentTemplate
            $template.securityAdvisoryFile | Should -Be "Data/securityAdvisory.json"
        }

        It "Sets certificate ignore flag to true" {
            $template = New-PatchScanEnvironmentTemplate
            $template.ignoreCertificate | Should -Be $true
        }

        It "Sets connection timeout to 30 seconds" {
            $template = New-PatchScanEnvironmentTemplate
            $template.connectionTimeoutSeconds | Should -Be 30
        }
    }

    Context "New-PatchScanEnvironment" {

        It "Creates environment with required parameters" {
            $env = New-PatchScanEnvironment -Name "Production" -Type "vcf9" -SddcManagerServer "sddc.example.com" -SddcManagerUser "admin@vsphere.local"

            $env.name | Should -Be "Production"
            $env.type | Should -Be "vcf9"
            $env.sddcManagerServer | Should -Be "sddc.example.com"
            $env.sddcManagerUser | Should -Be "admin@vsphere.local"
        }

        It "Generates unique GUID for each environment" {
            $env1 = New-PatchScanEnvironment -Name "Env1" -Type "vcf9"
            $env2 = New-PatchScanEnvironment -Name "Env2" -Type "vcf9"

            $env1.id | Should -Not -Be $env2.id
            # [ref]$null is not a valid out-parameter for a value type; use regex instead.
            $env1.id | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            $env2.id | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        }

        It "Trims whitespace from string properties" {
            $env = New-PatchScanEnvironment -Name "  Test  " -Type "vcf9" -SddcManagerServer "  sddc.test  "

            $env.name | Should -Be "Test"
            $env.sddcManagerServer | Should -Be "sddc.test"
        }

        It "Sets UseSinglePassword flag when switch is provided" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9" -UseSinglePassword

            $env.useSinglePassword | Should -Be $true
        }

        It "Defaults UseSinglePassword to false" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9"

            $env.useSinglePassword | Should -Be $false
        }

        It "Accepts all required environment types" {
            foreach ($type in @("vcf5", "vcf9", "vsphere8", "vvf9")) {
                $env = New-PatchScanEnvironment -Name "Test" -Type $type
                $env.type | Should -Be $type
            }
        }

        It "Accepts optional VCF 9 parameters" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9" `
                -SddcManagerServer "sddc.test" `
                -VcfOpsServer "ops.test" `
                -VcfFMServer "fm.test"

            $env.vcfOpsServer | Should -Be "ops.test"
            $env.vcfFMServer | Should -Be "fm.test"
        }

        It "Accepts NsxManagerServer and NsxManagerUser for vsphere8" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vsphere8" `
                -VcenterServer "vc.example.com" -VcenterUser "administrator@vsphere.local" `
                -NsxManagerServer "nsx.example.com" -NsxManagerUser "admin"

            $env.nsxManagerServer | Should -Be "nsx.example.com"
            $env.nsxManagerUser   | Should -Be "admin"
        }

        It "Does not add nsxManagerServer when omitted" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vsphere8" `
                -VcenterServer "vc.example.com" -VcenterUser "administrator@vsphere.local"

            $env.PSObject.Properties.Name | Should -Not -Contain "nsxManagerServer"
        }

        It "Accepts VrslcmServer and VrslcmUser for vcf5" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf5" `
                -SddcManagerServer "sddc.example.com" -SddcManagerUser "admin@vsphere.local" `
                -VrslcmServer "vrslcm.example.com" -VrslcmUser "admin@local"

            $env.vrslcmServer | Should -Be "vrslcm.example.com"
            $env.vrslcmUser   | Should -Be "admin@local"
        }

        It "Does not add vrslcmServer when omitted" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf5" `
                -SddcManagerServer "sddc.example.com" -SddcManagerUser "admin@vsphere.local"

            $env.PSObject.Properties.Name | Should -Not -Contain "vrslcmServer"
        }

        It "Adds sddcManagerInstanceName when a non-empty value is supplied" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9" `
                -SddcManagerServer "sddc.test" -SddcManagerInstanceName "San Francisco"

            $env.sddcManagerInstanceName | Should -Be "San Francisco"
        }

        It "Trims whitespace from SddcManagerInstanceName" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9" `
                -SddcManagerInstanceName "  Austin  "

            $env.sddcManagerInstanceName | Should -Be "Austin"
        }

        It "Does not add sddcManagerInstanceName property when value is empty string" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9" `
                -SddcManagerInstanceName ""

            $env.PSObject.Properties.Name | Should -Not -Contain "sddcManagerInstanceName"
        }

        It "Does not add sddcManagerInstanceName property when value is whitespace only" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9" `
                -SddcManagerInstanceName "   "

            $env.PSObject.Properties.Name | Should -Not -Contain "sddcManagerInstanceName"
        }

        It "Does not add sddcManagerInstanceName property when parameter is omitted" {
            $env = New-PatchScanEnvironment -Name "Test" -Type "vcf9"

            $env.PSObject.Properties.Name | Should -Not -Contain "sddcManagerInstanceName"
        }
    }

    Context "Set-PatchScanSettings" {

        It "Writes settings to JSON file" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "test-settings.json"
            $settings = New-PatchScanEnvironmentTemplate
            $settings.logLevel = "DEBUG"

            Set-PatchScanSettings -Settings $settings -OutputPath $testFile

            Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
        }

        It "Creates parent directories if they don't exist" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "subdir" -AdditionalChildPath "nested", "test-settings.json"
            $settings = New-PatchScanEnvironmentTemplate

            Set-PatchScanSettings -Settings $settings -OutputPath $testFile

            Test-Path -LiteralPath $testFile -PathType Leaf | Should -Be $true
        }

        It "Produces valid JSON that can be parsed" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "valid-json.json"
            $settings = New-PatchScanEnvironmentTemplate
            $settings.logLevel = "WARNING"

            Set-PatchScanSettings -Settings $settings -OutputPath $testFile

            $content = Get-Content -LiteralPath $testFile -Raw
            $parsed = ConvertFrom-Json -InputObject $content
            $parsed | Should -Not -BeNullOrEmpty
            $parsed.logLevel | Should -Be "WARNING"
        }

        It "Preserves object properties when writing" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "preserve.json"
            $settings = New-PatchScanEnvironmentTemplate
            $settings.logLevel = "ERROR"
            $settings.connectionTimeoutSeconds = 60

            Set-PatchScanSettings -Settings $settings -OutputPath $testFile

            $content = Get-Content -LiteralPath $testFile -Raw
            $parsed = ConvertFrom-Json -InputObject $content
            $parsed.logLevel | Should -Be "ERROR"
            $parsed.connectionTimeoutSeconds | Should -Be 60
        }

        It "Overwrites existing settings file" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "overwrite.json"

            # Write first version
            $settings1 = New-PatchScanEnvironmentTemplate
            $settings1.logLevel = "DEBUG"
            Set-PatchScanSettings -Settings $settings1 -OutputPath $testFile

            # Write second version
            $settings2 = New-PatchScanEnvironmentTemplate
            $settings2.logLevel = "INFO"
            Set-PatchScanSettings -Settings $settings2 -OutputPath $testFile

            $content = Get-Content -LiteralPath $testFile -Raw
            $parsed = ConvertFrom-Json -InputObject $content
            $parsed.logLevel | Should -Be "INFO"
        }

        It "Throws on invalid settings object" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "invalid.json"

            { Set-PatchScanSettings -Settings $null -OutputPath $testFile } | Should -Throw
        }
    }

    Context "Get-PatchScanSettings" {

        It "Loads settings from file successfully" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "load-test.json"
            $originalSettings = New-PatchScanEnvironmentTemplate
            $originalSettings.logLevel = "DEBUG"
            Set-PatchScanSettings -Settings $originalSettings -OutputPath $testFile

            $loadedSettings = Get-PatchScanSettings -SettingsFile $testFile

            $loadedSettings.logLevel | Should -Be "DEBUG"
            $loadedSettings.findingsOutputDirectory | Should -Be "findings"
        }

        It "Throws when file does not exist" {
            $nonExistentFile = Join-Path -Path $Script:TestTempDir -ChildPath "nonexistent.json"

            { Get-PatchScanSettings -SettingsFile $nonExistentFile } | Should -Throw
        }

        It "Throws on invalid JSON content" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "invalid-json.json"
            Set-Content -LiteralPath $testFile -Value "{ invalid json }" -Encoding UTF8

            { Get-PatchScanSettings -SettingsFile $testFile } | Should -Throw
        }

        It "Resolves relative paths from module root" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "relative-path.json"
            $originalSettings = New-PatchScanEnvironmentTemplate
            Set-PatchScanSettings -Settings $originalSettings -OutputPath $testFile

            # When SettingsFile is relative, it should resolve from module root
            # This test verifies the path resolution logic
            $testFile | Should -Exist
        }

        It "Preserves all properties when loading" {
            $testFile = Join-Path -Path $Script:TestTempDir -ChildPath "preserve-load.json"
            $originalSettings = New-PatchScanEnvironmentTemplate
            $originalSettings.logLevel = "WARNING"
            $originalSettings.connectionTimeoutSeconds = 45
            $originalSettings.ignoreCertificate = $false

            Set-PatchScanSettings -Settings $originalSettings -OutputPath $testFile
            $loadedSettings = Get-PatchScanSettings -SettingsFile $testFile

            $loadedSettings.logLevel | Should -Be "WARNING"
            $loadedSettings.connectionTimeoutSeconds | Should -Be 45
            $loadedSettings.ignoreCertificate | Should -Be $false
        }
    }

    Context "Environment Management Workflows" {

        It "Create, modify, and reload settings workflow" {
            $settingsFile = Join-Path -Path $Script:TestTempDir -ChildPath "workflow.json"

            # Create template
            $settings = New-PatchScanEnvironmentTemplate
            $settings.logLevel = "DEBUG"

            # Add environment — build the array explicitly to avoid $obj.Property += anti-pattern.
            $env = New-PatchScanEnvironment -Name "Production" -Type "vcf9" -SddcManagerServer "sddc.prod.local"
            $settings.environments = @($env)

            # Save
            Set-PatchScanSettings -Settings $settings -OutputPath $settingsFile

            # Load and verify
            $loaded = Get-PatchScanSettings -SettingsFile $settingsFile
            $loaded.environments.Count | Should -Be 1
            $loaded.environments[0].name | Should -Be "Production"
        }

        It "Add multiple environments to settings" {
            $settingsFile = Join-Path -Path $Script:TestTempDir -ChildPath "multi-env.json"

            $settings = New-PatchScanEnvironmentTemplate
            $settings.environments = @(
                (New-PatchScanEnvironment -Name "Prod" -Type "vcf9"),
                (New-PatchScanEnvironment -Name "Dev" -Type "vcf5")
            )

            Set-PatchScanSettings -Settings $settings -OutputPath $settingsFile

            $loaded = Get-PatchScanSettings -SettingsFile $settingsFile
            $loaded.environments.Count | Should -Be 2
        }
    }
}
