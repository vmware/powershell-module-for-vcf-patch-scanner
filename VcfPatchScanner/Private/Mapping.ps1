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

#region Component Name Mappings

# VCF Fleet Manager (VCF 9.0) component type friendly names
$Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_FRIENDLY = @{
    "vra"    = "VCF Automation"
    "vrops"  = "VCF Operations"
    "vrli"   = "VCF Operations for Logs"
    "vrni"   = "VCF Operations for Networks"
    "vidb"   = "Identity Broker"
    "vrslcm" = "Fleet Lifecycle"
}

# Maps Fleet Manager componentType IDs to advisory Component names
# NOTE: Keep in sync with ADVISORY_COMPONENT_TO_BUNDLE_TYPE
$Script:VCF_FLEET_MANAGER_COMPONENT_TYPE_TO_ADVISORY_NAME = @{
    "vra"    = "VCF Automation"
    "vrops"  = "VCF Operations"
    "vrli"   = "VCF Operations for Logs"
    "vrni"   = "VCF Operations for Networks"
    "vidb"   = "VCF Identity"
    "vrslcm" = "Fleet Lifecycle"
}

# VSP Fleet LCM (VCF 9.1) component type friendly names
$Script:VSP_FLEET_LCM_COMPONENT_TYPE_FRIENDLY = @{
    "ops"                = "VCF Operations"
    "salt"               = "Salt Master"
    "salt_raas"          = "Salt RaaS"
    "telemetry_acceptor" = "Telemetry"
    "vcfa"               = "VCF Automation"
    "vcf_fleet_depot"    = "Software Depot"
    "vcf_fleet_lcm"      = "Fleet Lifecycle"
    "vcf_sddc_lcm"       = "SDDC Lifecycle"
    "vidb"               = "Identity Broker"
    "vsp"                = "VCF Services Runtime"
}

# Maps VSP Fleet LCM componentType IDs to inventory/advisory component names.
# These strings become the inventory hashtable keys and appear in the scan results
# Component column. They use the same names shown in the Broadcom Fleet Manager UI.
# NOTE: Keep in sync with ADVISORY_COMPONENT_TO_BUNDLE_TYPE
$Script:VSP_FLEET_LCM_COMPONENT_TYPE_TO_ADVISORY_NAME = @{
    "ops"                = "VCF Operations"
    "salt"               = "Salt Master"
    "salt_raas"          = "Salt RaaS"
    "telemetry_acceptor" = "Telemetry"
    "vcfa"               = "VCF Automation"
    "vcf_fleet_depot"    = "Software Depot"
    "vcf_fleet_lcm"      = "Fleet Lifecycle"
    "vcf_sddc_lcm"       = "SDDC Lifecycle"
    "vidb"               = "Identity Broker"
    "vsp"                = "VCF Services Runtime"
}

# Maps advisory component names to SDDC Manager bundle types.
# Both the current Broadcom UI names and legacy "VCF XXX" names are included
# so existing advisory database entries continue to resolve correctly.
# NOTE: Keep in sync with ADVISORY_COMPONENT_TO_TARGET_PRODUCT_TYPE
$Script:ADVISORY_COMPONENT_TO_BUNDLE_TYPE = @{
    "ESXi"                        = "ESX"
    "NSX"                         = "NSX_T_MANAGER"
    "SDDC Manager"                = "SDDC_MANAGER"
    "vCenter"                     = "VCENTER"
    "Fleet Lifecycle"             = "VCF_FLEET_MANAGEMENT"
    "Identity Broker"             = "VCF_IDENTITY_BROKER"
    "Salt Master"                 = "VCF_SALT_MASTER"
    "Salt RaaS"                   = "VCF_SALT_RAAS"
    "SDDC Lifecycle"              = "VCF_SDDC_LIFECYCLE"
    "Software Depot"              = "VCF_SOFTWARE_DEPOT"
    "Telemetry"                   = "VCF_TELEMETRY"
    "VCF Automation"              = "VCF_AUTOMATION"
    "VCF Fleet Management"        = "VCF_FLEET_MANAGEMENT"
    "VCF Identity"                = "VCF_IDENTITY_BROKER"
    "VCF Identity Broker"         = "VCF_IDENTITY_BROKER"
    "VCF Operations"              = "VCF_OPERATIONS"
    "VCF Operations for Logs"     = "VCF_LOG_INSIGHT"
    "VCF Operations for Networks" = "VCF_NI"
    "VCF Salt Master"             = "VCF_SALT_MASTER"
    "VCF Salt RaaS"               = "VCF_SALT_RAAS"
    "VCF SDDC Lifecycle"          = "VCF_SDDC_LIFECYCLE"
    "VCF Services Runtime"        = "VCF_SERVICES_RUNTIME"
    "VCF Software Depot"          = "VCF_SOFTWARE_DEPOT"
    "VCF Telemetry"               = "VCF_TELEMETRY"
}

# Maps advisory component names to VCF Lifecycle product type strings.
# NOTE: Keep in sync with ADVISORY_COMPONENT_TO_BUNDLE_TYPE
$Script:ADVISORY_COMPONENT_TO_TARGET_PRODUCT_TYPE = @{
    "ESXi"                        = "ESX"
    "NSX"                         = "NSX_T_MANAGER"
    "SDDC Manager"                = "SDDC_MANAGER"
    "vCenter"                     = "VCENTER"
    "Fleet Lifecycle"             = "VCF_FLEET_MANAGEMENT"
    "Identity Broker"             = "VCF_IDENTITY_BROKER"
    "Salt Master"                 = "VCF_SALT_MASTER"
    "Salt RaaS"                   = "VCF_SALT_RAAS"
    "SDDC Lifecycle"              = "VCF_SDDC_LIFECYCLE"
    "Software Depot"              = "VCF_SOFTWARE_DEPOT"
    "Telemetry"                   = "VCF_TELEMETRY"
    "VCF Automation"              = "VCF_AUTOMATION"
    "VCF Fleet Management"        = "VCF_FLEET_MANAGEMENT"
    "VCF Identity"                = "VCF_IDENTITY_BROKER"
    "VCF Identity Broker"         = "VCF_IDENTITY_BROKER"
    "VCF Operations"              = "VCF_OPERATIONS"
    "VCF Operations for Logs"     = "VCF_LOG_INSIGHT"
    "VCF Operations for Networks" = "VCF_NI"
    "VCF Salt Master"             = "VCF_SALT_MASTER"
    "VCF Salt RaaS"               = "VCF_SALT_RAAS"
    "VCF SDDC Lifecycle"          = "VCF_SDDC_LIFECYCLE"
    "VCF Services Runtime"        = "VCF_SERVICES_RUNTIME"
    "VCF Software Depot"          = "VCF_SOFTWARE_DEPOT"
    "VCF Telemetry"               = "VCF_TELEMETRY"
}

# Maps every historical Broadcom advisory component name variant to the current inventory key.
# Advisory pages have used different names for the same product across publication eras:
#   vRealize era (pre-2023): "VMware vRealize Operations", "VMware vRealize Automation", etc.
#   Aria era (2023-2024):    "VMware Aria Operations", "VMware Aria Automation", etc.
#   VCF 9.0 era (2024-2025): "VCF Fleet Management", "VCF Identity Broker", "VCF Telemetry", etc.
#   VCF 9.1 era (2025+):     "Fleet Lifecycle", "Identity Broker", "Telemetry", etc. (Broadcom UI names)
# Inventory keys always use the current names from the Broadcom Fleet Manager UI.
# Infrastructure components (ESXi, NSX, vCenter, SDDC Manager) are normalized at scrape time
# and do not need entries here.
$Script:ADVISORY_COMPONENT_ALIASES = @{
    # vRealize / Aria era names
    "VMware vRealize Operations Manager"    = "VCF Operations"
    "VMware vRealize Operations"            = "VCF Operations"
    "VMware Aria Operations"                = "VCF Operations"
    "VMware vRealize Automation"            = "VCF Automation"
    "VMware vRealize Orchestrator"          = "VCF Automation"
    "VMware Aria Automation"                = "VCF Automation"
    "VMware vRealize Log Insight"           = "VCF Operations for Logs"
    "VMware Aria Operations for Logs"       = "VCF Operations for Logs"
    "VMware vRealize Network Insight"       = "VCF Operations for Networks"
    "VMware Aria Operations for Networks"   = "VCF Operations for Networks"
    "VMware Identity Manager"               = "VCF Identity"
    "VMware Workspace ONE Access"           = "VCF Identity"
    "VMware Aria Identity Manager"          = "VCF Identity"
    "VMware Workspace ONE Access Connector" = "Identity Broker"
    "VMware Identity Manager Connector"     = "Identity Broker"
    # VCF 9.0 advisory names → VCF 9.1 inventory keys
    "VCF Fleet Management"                  = "Fleet Lifecycle"
    "Lifecycle Manager"                     = "Fleet Lifecycle"
    "VCF Identity Broker"                   = "Identity Broker"
    "VCF Telemetry"                         = "Telemetry"
    "VCF Salt Master"                       = "Salt Master"
    "VCF Salt RaaS"                         = "Salt RaaS"
    "VCF Software Depot"                    = "Software Depot"
    "VCF SDDC Lifecycle"                    = "SDDC Lifecycle"
    "VCF Services Runtime"                  = "VCF Services Runtime"
}

# Advisory component names that should be filtered out (not patchable via VCF)
$Script:ADVISORY_COMPONENT_DISALLOW_LIST = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        "NSX Data Center for vSphere",
        "VMware Cloud Director",
        "VMware Cloud Director Appliance",
        "VMware Cloud Director Availability",
        "VMware Cloud Director Object Storage Extension",
        "VMware Cloud Foundation (NSX-V)",
        "VMware Enhanced Authentication Plug-in",
        "VMware Fusion",
        "VMware Tools for macOS",
        "VMware Tools for Windows",
        "VMware Workstation",
        "VMware Workstation Pro/Player"
    ),
    [System.StringComparer]::OrdinalIgnoreCase
)

# Fleet Manager and VSP configuration constants
$Script:VCF_FLEET_MANAGER_DEFAULT_USER_DOMAIN = "local"
$Script:VCF_FLEET_MANAGER_INVENTORY_PAGE_SIZE = 50
$Script:VCF_FLEET_MANAGER_INVENTORY_MAX_PAGES = 40
$Script:VCF_FLEET_MANAGER_REQUEST_TIMEOUT_SECONDS = 60
$Script:VCF_FLEET_MANAGER_LCM_VCF_VERSION = "9.0"

$Script:VSP_FLEET_LCM_DEFAULT_USER_DOMAIN = "vsp.local"
$Script:VSP_FLEET_LCM_IDENTITY_PATH = "/api/v1/identity/token"
$Script:VSP_FLEET_LCM_BASE_PATH = "/fleet-lcm"
$Script:VSP_FLEET_LCM_REQUEST_TIMEOUT_SECONDS = 60
$Script:VSP_FLEET_LCM_INVENTORY_PAGE_SIZE = 100
$Script:VSP_FLEET_LCM_INVENTORY_MAX_PAGES = 20

# JSON serialization depth
$Script:JSON_SERIALIZE_DEPTH = 10
$Script:JSON_PARSE_MAX_DEPTH = 100

# FQDN / hostname key names used by Fleet Manager 9.0.x additionalProperties bags.
# Probed in order; the first non-blank value wins.
$Script:FQDN_PROBE_KEYS = @('hostName', 'hostname', 'fqdn', 'FQDN', 'host', 'loadBalancerFqdn')

#endregion

#region Helper Functions

function Get-ComponentMapping {

    <#
        .SYNOPSIS
        Look up the bundle type or product type for an advisory component name.

        .DESCRIPTION
        Returns the SDDC Manager bundle type or VCF Lifecycle product type string for the given
        advisory component name, using the maps defined in $Script:ADVISORY_COMPONENT_TO_BUNDLE_TYPE
        and $Script:ADVISORY_COMPONENT_TO_TARGET_PRODUCT_TYPE. Returns $null when no mapping exists
        for the component name.

        .PARAMETER ComponentName
        Advisory component name to look up (e.g. "ESXi", "NSX", "vCenter").

        .PARAMETER MappingType
        Type of mapping: BundleType (default) or ProductType.

        .EXAMPLE
        $bundleType = Get-ComponentMapping -ComponentName 'ESXi' -MappingType BundleType
        # Returns "ESX"

        .NOTES
        Returns the global component mapping hashtable. Callers must not mutate the returned object — it is shared across all scanning operations in the session.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ComponentName,
        [Parameter(Mandatory = $false)] [ValidateSet('BundleType', 'ProductType')] [String]$MappingType = 'BundleType'
    )

    # Resolve any historical advisory name to the current VCF 9.x key before looking up the map.
    $resolvedName = if ($Script:ADVISORY_COMPONENT_ALIASES.ContainsKey($ComponentName)) {
        $Script:ADVISORY_COMPONENT_ALIASES[$ComponentName]
    } else {
        $ComponentName
    }
    if ($MappingType -eq 'BundleType') {
        return $Script:ADVISORY_COMPONENT_TO_BUNDLE_TYPE[$resolvedName]
    } else {
        return $Script:ADVISORY_COMPONENT_TO_TARGET_PRODUCT_TYPE[$resolvedName]
    }
}

function Test-ValidAdvisoryComponent {

    <#
        .SYNOPSIS
        Check whether a component name is eligible for scanning.

        .DESCRIPTION
        Returns $true when the component name is not in the advisory disallow list
        ($Script:ADVISORY_COMPONENT_DISALLOW_LIST). Components on the disallow list are third-party
        or non-VCF products that appear in Broadcom advisories but cannot be patched via VCF tooling.
        Comparison is case-insensitive (OrdinalIgnoreCase).

        .PARAMETER ComponentName
        Component name to check against the disallow list.

        .EXAMPLE
        if (-not (Test-ValidAdvisoryComponent -ComponentName $componentName)) { continue }

        .NOTES
        Pure predicate function. Does not mutate any module-scope variables.
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ComponentName
    )

    return -not $Script:ADVISORY_COMPONENT_DISALLOW_LIST.Contains($ComponentName.Trim())
}

#endregion
