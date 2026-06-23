# Copyright (c) 2026 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
# SOFTWARE LICENSE AGREEMENT
# [License omitted for brevity - full copyright notice required in production]
# =============================================================================

Describe "VcfPatchScanner.Mapping" {

    BeforeAll {
        # Import module in isolated scope
        Import-Module -Name (Join-Path -Path (Split-Path -Parent -Path $PSScriptRoot) -ChildPath 'VcfPatchScanner.psd1') -Force
    }

    AfterAll {
        Remove-Module -Name VcfPatchScanner -Force -ErrorAction SilentlyContinue
    }

    Context "Component Type Mappings" {

        It "Maps VCF Fleet Manager component types to advisory names" {
            InModuleScope VcfPatchScanner {
                $mapping = $Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_TO_ADVISORY_NAME

                $mapping["vra"] | Should -Be "VCF Automation"
                $mapping["vrops"] | Should -Be "VCF Operations"
                $mapping["vidb"] | Should -Be "VCF Identity"
                $mapping["vrslcm"] | Should -Be "Fleet Lifecycle"
            }
        }

        It "Maps VSP Fleet LCM component types to advisory names" {
            InModuleScope VcfPatchScanner {
                $mapping = $Script:VSP_FLEET_LCM_COMPONENT_TYPE_TO_ADVISORY_NAME

                $mapping["ops"] | Should -Be "VCF Operations"
                $mapping["vcfa"] | Should -Be "VCF Automation"
                $mapping["vidb"] | Should -Be "Identity Broker"
                $mapping["telemetry_acceptor"] | Should -Be "Telemetry"
                $mapping["vcf_fleet_lcm"] | Should -Be "Fleet Lifecycle"
                $mapping["vsp"] | Should -Be "VCF Services Runtime"
            }
        }

        It "Maps advisory components to SDDC Manager bundle types" {
            InModuleScope VcfPatchScanner {
                $mapping = $Script:ADVISORY_COMPONENT_TO_BUNDLE_TYPE

                $mapping["ESXi"] | Should -Be "ESX"
                $mapping["NSX"] | Should -Be "NSX_T_MANAGER"
                $mapping["vCenter"] | Should -Be "VCENTER"
                $mapping["SDDC Manager"] | Should -Be "SDDC_MANAGER"
                $mapping["VCF Operations"] | Should -Be "VCF_OPERATIONS"
            }
        }

        It "Maps advisory components to product types" {
            InModuleScope VcfPatchScanner {
                $mapping = $Script:ADVISORY_COMPONENT_TO_TARGET_PRODUCT_TYPE

                $mapping["ESXi"] | Should -Be "ESX"
                $mapping["NSX"] | Should -Be "NSX_T_MANAGER"
                $mapping["vCenter"] | Should -Be "VCENTER"
            }
        }

        It "Maintains sync between bundle type and product type mappings" {
            InModuleScope VcfPatchScanner {
                $bundleMapping = $Script:ADVISORY_COMPONENT_TO_BUNDLE_TYPE
                $productMapping = $Script:ADVISORY_COMPONENT_TO_TARGET_PRODUCT_TYPE

                # Sort before comparing — KeyCollection iteration order is non-deterministic.
                ($bundleMapping.Keys | Sort-Object) | Should -BeExactly ($productMapping.Keys | Sort-Object)
            }
        }
    }

    Context "Disallow List" {

        It "Contains products not managed by VCF" {
            InModuleScope VcfPatchScanner {
                $disallowList = $Script:ADVISORY_COMPONENT_DISALLOW_LIST

                $disallowList.Contains("VMware Fusion") | Should -Be $true
                $disallowList.Contains("VMware Workstation") | Should -Be $true
                $disallowList.Contains("VMware Cloud Director") | Should -Be $true
            }
        }

        It "Performs case-insensitive matching" {
            InModuleScope VcfPatchScanner {
                $disallowList = $Script:ADVISORY_COMPONENT_DISALLOW_LIST

                # HashSet comparison should be case-insensitive
                $disallowList.Contains("vmware fusion") | Should -Be $true
                $disallowList.Contains("VMWARE WORKSTATION") | Should -Be $true
            }
        }
    }

    Context "Friendly Name Mappings" {

        It "Maps Fleet Manager component types to friendly names" {
            InModuleScope VcfPatchScanner {
                $friendly = $Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_FRIENDLY

                $friendly["vra"] | Should -Be "VCF Automation"
                $friendly["vrslcm"] | Should -Be "Fleet Lifecycle"
            }
        }

        It "Maps VSP Fleet LCM component types to friendly names" {
            InModuleScope VcfPatchScanner {
                $friendly = $Script:VSP_FLEET_LCM_COMPONENT_TYPE_FRIENDLY

                $friendly["vcf_fleet_lcm"] | Should -Be "Fleet Lifecycle"
                $friendly["vcf_sddc_lcm"] | Should -Be "SDDC Lifecycle"
            }
        }
    }

    Context "Configuration Constants" {

        It "Defines VCF Fleet Manager configuration values" {
            InModuleScope VcfPatchScanner {
                $Script:VCF_FLEET_MANAGER_DEFAULT_USER_DOMAIN | Should -Be "local"
                $Script:VCF_FLEET_MANAGER_INVENTORY_PAGE_SIZE | Should -Be 50
                $Script:VCF_FLEET_MANAGER_REQUEST_TIMEOUT_SECONDS | Should -Be 60
            }
        }

        It "Defines VSP Fleet LCM configuration values" {
            InModuleScope VcfPatchScanner {
                $Script:VSP_FLEET_LCM_DEFAULT_USER_DOMAIN | Should -Be "vsp.local"
                $Script:VSP_FLEET_LCM_INVENTORY_PAGE_SIZE | Should -Be 100
                $Script:VSP_FLEET_LCM_BASE_PATH | Should -Be "/fleet-lcm"
            }
        }

        It "Defines JSON serialization depth constants" {
            InModuleScope VcfPatchScanner {
                $Script:JSON_SERIALIZE_DEPTH | Should -Be 10
                $Script:JSON_PARSE_MAX_DEPTH | Should -Be 100
            }
        }
    }

    Context "Get-ComponentMapping Function" {

        It "Returns bundle type mapping for component" {
            InModuleScope VcfPatchScanner {
                $result = Get-ComponentMapping -ComponentName "ESXi" -MappingType BundleType
                $result | Should -Be "ESX"
            }
        }

        It "Returns product type mapping for component" {
            InModuleScope VcfPatchScanner {
                $result = Get-ComponentMapping -ComponentName "vCenter" -MappingType ProductType
                $result | Should -Be "VCENTER"
            }
        }

        It "Returns null for unmapped component" {
            InModuleScope VcfPatchScanner {
                $result = Get-ComponentMapping -ComponentName "NonExistentComponent" -MappingType BundleType
                $result | Should -Be $null
            }
        }

        It "Defaults to BundleType mapping" {
            InModuleScope VcfPatchScanner {
                $resultDefault = Get-ComponentMapping -ComponentName "NSX"
                $resultExplicit = Get-ComponentMapping -ComponentName "NSX" -MappingType BundleType
                $resultDefault | Should -Be $resultExplicit
            }
        }
    }

    Context "Test-ValidAdvisoryComponent Function" {

        It "Returns true for allowed components" {
            InModuleScope VcfPatchScanner {
                $result = Test-ValidAdvisoryComponent -ComponentName "ESXi"
                $result | Should -Be $true
            }
        }

        It "Returns false for disallowed components" {
            InModuleScope VcfPatchScanner {
                $result = Test-ValidAdvisoryComponent -ComponentName "VMware Fusion"
                $result | Should -Be $false
            }
        }

        It "Handles case-insensitive matching" {
            InModuleScope VcfPatchScanner {
                $result = Test-ValidAdvisoryComponent -ComponentName "vmware fusion"
                $result | Should -Be $false
            }
        }

        It "Trims whitespace before checking" {
            InModuleScope VcfPatchScanner {
                $result = Test-ValidAdvisoryComponent -ComponentName "  VMware Fusion  "
                $result | Should -Be $false
            }
        }
    }
}
