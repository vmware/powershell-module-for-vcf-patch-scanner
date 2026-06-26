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

@{
    RootModule           = 'VcfPatchScanner.psm1'
    ModuleVersion        = '1.0.0.1005'
    GUID                 = '1f2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d'
    Author               = 'Broadcom'
    CompanyName          = 'Broadcom'
    Description          = 'VCF Patch Scanner Module'
    PowerShellVersion    = '7.4'
    RequiredModules      = @()

    FunctionsToExport    = @(
        'Invoke-VCFPatchScanner'
        'Get-PatchScanSettings'
        'Set-PatchScanSettings'
        'New-PatchScanEnvironmentTemplate'
        'New-PatchScanEnvironment'
        'Test-PatchScanConnection'
        'Get-SecurityAdvisory'
        'Invoke-AdvisoryDownloadIfChanged'
        'Test-AdvisorySchemaValidity'
        'Select-AdvisoryByEnvironmentType'
        'Select-AdvisoryByProductFamily'
        'Select-AdvisoryByComponent'
        'Get-AdvisoryComponentMatches'
        'Get-SddcManagerInventory'
        'Get-SddcManagerListFromVcfOps'
        'Get-FleetManagerFromVcfOps'
        'Get-SddcCredentialFromFleetManager'
        'Get-VrslcmFromSddcManager'
        'Get-VcenterInventory'
        'Get-FleetManagerInventory'
        'Initialize-VcfPatchScanner'
        'Invoke-VcfPatchScannerCollectLogs'
        'Initialize-PatchScanLogging'
        'Get-PatchScanLogDirectory'
        'Invoke-VulnerabilityScan'
        'Export-PatchScanFindings'
        'Export-PatchScanFindingsCSV'
        'Write-LogMessage'
        'Start-VCFPatchScannerServer'
        'Stop-VCFPatchScannerServer'
        'Get-VCFPatchScannerServerStatus'
        'Restart-VCFPatchScannerServer'
        'Get-VcfPatchScannerToolsPath'
        'New-SecretReferenceName'
        'Resolve-SecretReference'
        'Import-EnvironmentsFromConfig'
        'ConvertTo-ScanParameters'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    FileList             = @(
        'VcfPatchScanner.psm1'
        'VcfPatchScanner.psd1'
        'Private\Logging.ps1'
        'Private\Mapping.ps1'
        'Private\Settings.ps1'
        'Private\Advisory.ps1'
        'Private\CredentialManagement.ps1'
        'Private\Discovery.ps1'
        'Private\Inventory.ps1'
        'Private\Scanning.ps1'
        'Private\Findings.ps1'
        'Private\EntryPoint.ps1'
        'Private\Tools.ps1'
        'Tools\Invoke-VCFPatchScanner.ps1'
        'Tools\Manage-VCFPatchScannerServer.py'
        'Tools\Start-VCFPatchScannerServer.py'
        'Tools\vcp-patch-ui.html'
    )

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # PSEdition_Core, Windows, Linux, MacOS populate the Gallery's left-side filter panes.
        Tags = @(
            'VMware', 'VCF', 'vSphere', 'Patch', 'Scanner',
            'Automation','PSEdition_Core', 'Windows', 'Linux', 'MacOS'
        )

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/vmware/powershell-module-for-vcf-patch-scanner/blob/main/LICENSE.md'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/vmware/powershell-module-for-vcf-patch-scanner'

        # A URL to an icon representing this module.
        IconUri = 'https://raw.githubusercontent.com/vmware/powershell-module-for-vcf-patch-scanner/main/.github/icon-85px.svg'

        # Release notes displayed on the PowerShell Gallery package page.
        ReleaseNotes = 'https://github.com/vmware/ppowershell-module-for-vcf-patch-scanner/blob/main/CHANGELOG.md'

    } # End of PSData hashtable

} # End of PrivateData hashtable

}
