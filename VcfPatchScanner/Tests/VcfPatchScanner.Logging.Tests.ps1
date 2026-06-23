# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted - see module for full header]
# =============================================================================

Describe "VcfPatchScanner.Logging" {

    BeforeAll {
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Resolve-PatchScanBaseDirectory" {

        BeforeEach {
            $script:_savedEnv = $env:VcfPatchScannerBaseDirectory
            $env:VcfPatchScannerBaseDirectory = $null
        }

        AfterEach {
            if ($null -ne $script:_savedEnv) {
                $env:VcfPatchScannerBaseDirectory = $script:_savedEnv
            } else {
                Remove-Item -Path Env:\VcfPatchScannerBaseDirectory -ErrorAction SilentlyContinue
            }
        }

        It "Returns default path when Read-Host returns empty string" {
            InModuleScope VcfPatchScanner {
                Mock Read-Host { return "" }
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcf"
                $result | Should -Not -BeNullOrEmpty
                $result | Should -Be ([System.IO.Path]::GetFullPath("$HOME/TestVcf"))
            }
        }

        It "Returns resolved path within home when user types a relative path" {
            InModuleScope VcfPatchScanner {
                Mock Read-Host { return "VcfPatchScannerTest" }
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcf"
                $result | Should -Not -BeNullOrEmpty
                $result | Should -Be ([System.IO.Path]::GetFullPath((Join-Path -Path $HOME -ChildPath "VcfPatchScannerTest")))
            }
        }

        It "Returns null and logs ERROR when path is outside home directory" {
            InModuleScope VcfPatchScanner {
                Mock Read-Host { return "/tmp/outside" }
                Mock Write-LogMessage
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcf"
                $result | Should -BeNullOrEmpty
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq 'ERROR' -and $Message -match "home" }
            }
        }

        It "Returns existing env var path when user answers n to re-initialize" {
            InModuleScope VcfPatchScanner {
                $env:VcfPatchScannerBaseDirectory = $TestDrive
                Mock Read-Host { return "n" }
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcf"
                $result | Should -Not -BeNullOrEmpty
                $result | Should -Be (Resolve-Path -LiteralPath $TestDrive).Path
            }
        }

        It "Falls through to the prompt when user answers c to change the directory" {
            InModuleScope VcfPatchScanner {
                $env:VcfPatchScannerBaseDirectory = $TestDrive
                $script:_readHostCallCount = 0
                Mock Read-Host {
                    $script:_readHostCallCount++
                    # First call: the Keep/Change prompt — answer "c" to select Change.
                    if ($script:_readHostCallCount -eq 1) { return "c" }
                    # Second call: the directory path prompt — press Enter to accept default.
                    return ""
                }
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcfFallthrough"
                $result | Should -Not -BeNullOrEmpty
                $result | Should -Be ([System.IO.Path]::GetFullPath("$HOME/TestVcfFallthrough"))
            }
        }

        It "Clears stale env var and returns default when env path does not exist" {
            InModuleScope VcfPatchScanner {
                $stale = "/nonexistent/path/$(New-Guid)"
                $env:VcfPatchScannerBaseDirectory = $stale
                Mock Read-Host { return "" }
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcf"
                $env:VcfPatchScannerBaseDirectory | Should -BeNullOrEmpty
                $result | Should -Not -BeNullOrEmpty
                $result | Should -Be ([System.IO.Path]::GetFullPath("$HOME/TestVcf"))
            }
        }

        It "Returns null and logs ERROR when Read-Host throws (non-interactive session)" {
            InModuleScope VcfPatchScanner {
                Mock Read-Host { throw [System.InvalidOperationException]::new("Host does not support prompting.") }
                Mock Write-LogMessage
                $result = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/TestVcf"
                $result | Should -BeNullOrEmpty
                Should -Invoke Write-LogMessage -ParameterFilter { $Type -eq 'ERROR' }
            }
        }
    }

    Context "Test-VcfPatchScannerDependencies" {

        # Resolve the real python3 path once so per-test mocks can forward actual calls.
        # The function runs "& $pythonCmd.Source --version" to confirm Python 3; feeding the
        # real binary path through the Get-Command mock avoids a network hit while keeping
        # the version-string check live.
        BeforeAll {
            $Script:_realPython3 = (Get-Command -Name python3 -ErrorAction SilentlyContinue)?.Source
        }

        It "Returns true when all dependencies are present" {
            if ($null -eq $Script:_realPython3) {
                Set-ItResult -Skipped -Because "python3 is not available in this test environment."
            }
            InModuleScope VcfPatchScanner -ArgumentList $Script:_realPython3 {
                param($Python3Source)
                Mock Get-Module {
                    param($Name)
                    if ($Name -eq 'VCF.PowerCLI') {
                        return [PSCustomObject]@{ Name = 'VCF.PowerCLI'; Version = [Version]'9.0.0' }
                    }
                    return $null
                }
                Mock Get-Command {
                    param($Name)
                    switch ($Name) {
                        'python3' { return [PSCustomObject]@{ Name = $Name; Source = $Python3Source } }
                        'python'  { return $null }
                        'pwsh'    { return [PSCustomObject]@{ Name = $Name; Source = '/usr/local/bin/pwsh' } }
                        default   { return $null }
                    }
                }
                $result = Test-VcfPatchScannerDependencies
                $result | Should -Be $true
            }
        }

        It "Returns false when Python 3 is not found on PATH" {
            InModuleScope VcfPatchScanner {
                Mock Get-Module {
                    param($Name)
                    if ($Name -eq 'VCF.PowerCLI') {
                        return [PSCustomObject]@{ Name = 'VCF.PowerCLI'; Version = [Version]'9.0.0' }
                    }
                    return $null
                }
                Mock Get-Command {
                    param($Name)
                    switch ($Name) {
                        'python3' { return $null }
                        'python'  { return $null }
                        'pwsh'    { return [PSCustomObject]@{ Name = $Name; Source = '/usr/local/bin/pwsh' } }
                        default   { return $null }
                    }
                }
                $result = Test-VcfPatchScannerDependencies
                $result | Should -Be $false
            }
        }

        It "Returns false when VCF PowerCLI is not installed" {
            InModuleScope VcfPatchScanner {
                # Module not found at all — the failure message must say "not installed".
                Mock Get-Module { param($Name); return $null }
                Mock Write-Host
                Mock Get-Command {
                    param($Name)
                    switch ($Name) {
                        'python3' { return $null }
                        'python'  { return $null }
                        'pwsh'    { return [PSCustomObject]@{ Name = $Name; Source = '/usr/local/bin/pwsh' } }
                        default   { return $null }
                    }
                }
                $result = Test-VcfPatchScannerDependencies
                $result | Should -Be $false
                Should -Invoke Write-Host -ParameterFilter { $Object -match 'not installed' } -Times 1
            }
        }

        It "Returns false when VCF PowerCLI version is below 9.0" {
            InModuleScope VcfPatchScanner {
                # Module installed but too old.
                Mock Get-Module {
                    param($Name)
                    if ($Name -eq 'VCF.PowerCLI') {
                        return [PSCustomObject]@{ Name = 'VCF.PowerCLI'; Version = [Version]'8.0.0' }
                    }
                    return $null
                }
                Mock Write-Host
                Mock Get-Command {
                    param($Name)
                    switch ($Name) {
                        'python3' { return $null }
                        'python'  { return $null }
                        'pwsh'    { return [PSCustomObject]@{ Name = $Name; Source = '/usr/local/bin/pwsh' } }
                        default   { return $null }
                    }
                }
                $result = Test-VcfPatchScannerDependencies
                $result | Should -Be $false
                Should -Invoke Write-Host -ParameterFilter { $Object -match '8\.0\.0.*required' } -Times 1
            }
        }

        It "Returns false when pwsh is not on PATH" {
            InModuleScope VcfPatchScanner {
                Mock Get-Module {
                    param($Name)
                    if ($Name -eq 'VCF.PowerCLI') {
                        return [PSCustomObject]@{ Name = 'VCF.PowerCLI'; Version = [Version]'9.0.0' }
                    }
                    return $null
                }
                Mock Get-Command {
                    param($Name)
                    switch ($Name) {
                        'python3' { return $null }
                        'python'  { return $null }
                        'pwsh'    { return $null }
                        default   { return $null }
                    }
                }
                $result = Test-VcfPatchScannerDependencies
                $result | Should -Be $false
            }
        }

        It "Returns false when current PowerShell version is below 7.4" {
            InModuleScope VcfPatchScanner {
                # $PSVersionTable is read-only; the too-old path cannot be exercised in the
                # same session as Pester (which requires >= 7.4). Skip when the requirement
                # is already satisfied, which is always the case in a functioning test run.
                $currentVersion = $PSVersionTable.PSVersion
                $minRequired = [Version]"7.4"
                if ($currentVersion -ge $minRequired) {
                    Set-ItResult -Skipped -Because "Cannot mock PSVersionTable; current PS $currentVersion satisfies 7.4 — the too-old path cannot be exercised here."
                }
            }
        }
    }

    Context "Copy-PatchScanAdvisoryDataFromModule" {

        # Tests use the real module Data/ directory as the source (the bundled advisory stub has
        # updatedAt "2026-06-01T00:00:00Z").  Only the destination directory is a temp path.

        BeforeEach {
            $script:_dstDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "VcfPatchScannerTest_$(New-Guid)"
            New-Item -ItemType Directory -Path $script:_dstDir -Force | Out-Null
        }

        AfterEach {
            Remove-Item -LiteralPath $script:_dstDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        It "Creates the advisory file on first install (destination absent)" {
            $dstFile = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json'
            $result = InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir
            $result | Should -Be $true
            (Test-Path -LiteralPath $dstFile) | Should -Be $true
        }

        It "Returns true and keeps existing file when it has a newer updatedAt than the bundled copy" {
            # Write a far-future date — always newer than the bundled stub (2026-06-01).
            $dstFile = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json'
            @{ schemaVersion = "2.0"; advisories = @(); updatedAt = "2099-01-01T00:00:00Z" } |
                ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $dstFile -Encoding UTF8
            $contentBefore = Get-Content -LiteralPath $dstFile -Raw
            $result = InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir
            $result | Should -Be $true
            (Get-Content -LiteralPath $dstFile -Raw) | Should -Be $contentBefore
        }

        It "Keeps existing file when it has the same updatedAt as the bundled copy" {
            # Read the bundled advisory's updatedAt so the test stays correct if the stub changes.
            $bundledDate = InModuleScope VcfPatchScanner {
                $p = [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'Data', 'securityAdvisory.json'))
                if (Test-Path -LiteralPath $p) { (Get-Content -LiteralPath $p -Raw | ConvertFrom-Json).updatedAt } else { "2026-06-01T00:00:00Z" }
            }
            $dstFile = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json'
            @{ schemaVersion = "2.0"; advisories = @(); updatedAt = $bundledDate } |
                ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $dstFile -Encoding UTF8
            $contentBefore = Get-Content -LiteralPath $dstFile -Raw
            $result = InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir
            $result | Should -Be $true
            (Get-Content -LiteralPath $dstFile -Raw) | Should -Be $contentBefore
        }

        It "Replaces a corrupt (unparseable) existing file with the bundled copy" {
            $dstFile = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json'
            Set-Content -LiteralPath $dstFile -Value 'NOT VALID JSON {{{' -Encoding UTF8
            $result = InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir
            $result | Should -Be $true
            { Get-Content -LiteralPath $dstFile -Raw | ConvertFrom-Json } | Should -Not -Throw
        }

        It "Deletes the ETag sidecar when the bundled advisory is written (first install)" {
            # Simulate a stale ETag file left from a prior download — the server must not
            # use it to claim the newly-written file is already up to date.
            $dstEtag = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json.etag'
            Set-Content -LiteralPath $dstEtag -Value 'stale-etag-value' -Encoding UTF8
            $result = InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir
            $result | Should -Be $true
            (Test-Path -LiteralPath $dstEtag) | Should -Be $false
        }

        It "Deletes the ETag sidecar when a stale ETag exists alongside an older advisory being replaced" {
            # Write a far-past advisory so the bundled copy (2026-06-01) is strictly newer.
            $dstFile = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json'
            $dstEtag = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json.etag'
            @{ schemaVersion = "2.0"; advisories = @(); updatedAt = "2000-01-01T00:00:00Z" } |
                ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $dstFile -Encoding UTF8
            Set-Content -LiteralPath $dstEtag -Value 'stale-etag-from-old-download' -Encoding UTF8
            $result = InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir
            $result | Should -Be $true
            (Test-Path -LiteralPath $dstEtag) | Should -Be $false
        }

        It "Preserves the ETag sidecar when the existing advisory is kept unchanged" {
            # When the destination is current (>= bundled) the ETag must NOT be touched
            # — deleting it would cause a spurious update prompt on the next server start.
            $dstFile = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json'
            $dstEtag = Join-Path -Path $script:_dstDir -ChildPath 'securityAdvisory.json.etag'
            @{ schemaVersion = "2.0"; advisories = @(); updatedAt = "2099-01-01T00:00:00Z" } |
                ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $dstFile -Encoding UTF8
            Set-Content -LiteralPath $dstEtag -Value 'valid-current-etag' -Encoding UTF8
            InModuleScope VcfPatchScanner -Parameters @{ Dst = $script:_dstDir } {
                Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $args[0]
            } -ArgumentList $script:_dstDir | Out-Null
            (Test-Path -LiteralPath $dstEtag) | Should -Be $true
            (Get-Content -LiteralPath $dstEtag -Raw).Trim() | Should -Be 'valid-current-etag'
        }
    }

    Context "Invoke-PersistPatchScanBaseDirectory — profile entry management" {

        BeforeEach {
            $script:_savedEnv     = $env:VcfPatchScannerBaseDirectory
            $script:_savedProfile = $global:PROFILE
            $script:_tmpProfile   = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "VcfPatchScanTestProfile_$([System.Guid]::NewGuid()).ps1"
        }

        AfterEach {
            $global:PROFILE = $script:_savedProfile
            if ($null -ne $script:_savedEnv) {
                $env:VcfPatchScannerBaseDirectory = $script:_savedEnv
            } else {
                Remove-Item -Path Env:\VcfPatchScannerBaseDirectory -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $script:_tmpProfile -ErrorAction SilentlyContinue
        }

        It "Writes a new entry when the profile has no scan base directory assignment" {
            Set-Content -LiteralPath $script:_tmpProfile -Value "# existing profile content" -Encoding UTF8
            $global:PROFILE = $script:_tmpProfile
            InModuleScope VcfPatchScanner {
                Mock Write-Host {}
                Invoke-PersistPatchScanBaseDirectory `
                    -BaseDirectoryWasCreated $false `
                    -ResolvedBaseDirectory   "/Users/test/VcfPatchScanner" `
                    -SubdirectoriesCreated   ([System.Collections.Generic.List[String]]::new()) `
                    -FilesCopied             ([System.Collections.Generic.List[String]]::new())
            }
            $content = Get-Content -LiteralPath $script:_tmpProfile -Raw
            $content | Should -Match '\$env:VcfPatchScannerBaseDirectory\s*=\s*"/Users/test/VcfPatchScanner"'
        }

        It "Replaces a stale VcfPatchScanBaseDirectory entry from the pre-rename module" {
            $oldLine = '$env:VcfPatchScanBaseDirectory = "/Users/nthaler/VcfPatchScan"'
            Set-Content -LiteralPath $script:_tmpProfile -Value "# header`n$oldLine" -Encoding UTF8
            $global:PROFILE = $script:_tmpProfile
            InModuleScope VcfPatchScanner {
                Mock Write-Host {}
                Invoke-PersistPatchScanBaseDirectory `
                    -BaseDirectoryWasCreated $false `
                    -ResolvedBaseDirectory   "/Users/nthaler/VcfPatchScanner" `
                    -SubdirectoriesCreated   ([System.Collections.Generic.List[String]]::new()) `
                    -FilesCopied             ([System.Collections.Generic.List[String]]::new())
            }
            $content = Get-Content -LiteralPath $script:_tmpProfile -Raw
            $content | Should -Match '\$env:VcfPatchScannerBaseDirectory\s*=\s*"/Users/nthaler/VcfPatchScanner"'
            $content | Should -Not -Match '\$env:VcfPatchScanBaseDirectory\s*='
        }

        It "Updates the entry when the path has changed" {
            $oldLine = '$env:VcfPatchScannerBaseDirectory = "/Users/nthaler/OldPath"'
            Set-Content -LiteralPath $script:_tmpProfile -Value $oldLine -Encoding UTF8
            $global:PROFILE = $script:_tmpProfile
            InModuleScope VcfPatchScanner {
                Mock Write-Host {}
                Invoke-PersistPatchScanBaseDirectory `
                    -BaseDirectoryWasCreated $false `
                    -ResolvedBaseDirectory   "/Users/nthaler/NewPath" `
                    -SubdirectoriesCreated   ([System.Collections.Generic.List[String]]::new()) `
                    -FilesCopied             ([System.Collections.Generic.List[String]]::new())
            }
            $content = Get-Content -LiteralPath $script:_tmpProfile -Raw
            $content | Should -Match '\$env:VcfPatchScannerBaseDirectory\s*=\s*"/Users/nthaler/NewPath"'
            $content | Should -Not -Match 'OldPath'
        }

        It "Leaves the profile unchanged when the exact entry is already present" {
            $exactLine = '$env:VcfPatchScannerBaseDirectory = "/Users/nthaler/VcfPatchScanner"'
            Set-Content -LiteralPath $script:_tmpProfile -Value "# header`n$exactLine" -Encoding UTF8
            $global:PROFILE = $script:_tmpProfile
            $contentBefore = Get-Content -LiteralPath $script:_tmpProfile -Raw
            InModuleScope VcfPatchScanner {
                Mock Write-Host {}
                Invoke-PersistPatchScanBaseDirectory `
                    -BaseDirectoryWasCreated $false `
                    -ResolvedBaseDirectory   "/Users/nthaler/VcfPatchScanner" `
                    -SubdirectoriesCreated   ([System.Collections.Generic.List[String]]::new()) `
                    -FilesCopied             ([System.Collections.Generic.List[String]]::new())
            }
            $contentAfter = Get-Content -LiteralPath $script:_tmpProfile -Raw
            $contentAfter | Should -Be $contentBefore
        }
    }
}
