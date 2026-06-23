# API graph - VcfPatchScanner.psm1

Generated on **2026-06-23 08:26:04 -04:00**.

Sources analyzed:

- `VcfPatchScanner/VcfPatchScanner.psm1`

Auto-discovered via dot-source:

- `Private/Mapping.ps1`
- `Private/Logging.ps1`
- `Private/Settings.ps1`
- `Private/Advisory.ps1`
- `Private/Discovery.ps1`
- `Private/Inventory.ps1`
- `Private/Scanning.ps1`
- `Private/Findings.ps1`
- `Private/EntryPoint.ps1`
- `Private/Tools.ps1`
- `Tools/Invoke-VCFPatchScanner.ps1`

## Legend

- A node labeled `METHOD /path` is an HTTP endpoint. The second line of the label is `<Public|Internal> . <via SDK|via REST>`.
- A third label line (for example `VCF 9.0.x only`, `VCF 9.0–9.0.x`, `VCF 9.1+`) is rendered only when the API map declares the endpoint is *version-gated* (i.e. has a `MaxVcfVersion`). Endpoints that are simply available from the script's minimum VCF release upward skip the third line to keep the overview flowchart readable; their applicability is still surfaced in the **VCF release** column of the endpoints table below.
- SDK cmdlets are translated to their underlying HTTP endpoint; the specific cmdlet name appears on the edge into that endpoint, so two SDK cmdlets that call the same endpoint are both visible as separate edges.
- REST calls (project wrappers over `Invoke-RestMethod`) use the URL observed at the call site; the wrapper name appears on the edge.
- Local cmdlets (for example `Initialize-*` payload builders, client-side `Disconnect-*`) do not issue HTTP requests and are not rendered in the graph.

## Summary

| Metric | Count |
|---|---:|
| Call sites analyzed | 54 |
| Call sites mapped to an endpoint | 42 |
| Distinct endpoints | 31 |
| VCF-version-gated endpoints (max release set) | 2 |
| SDK cmdlet calls | 17 |
| REST calls | 25 |
| Public-endpoint calls | 19 |
| Internal-endpoint calls | 2 |
| Local (no HTTP) cmdlet calls | 12 |

### By target system

| Target system | Call sites | Distinct endpoints |
|---|---:|---:|
| Fleet Manager | 2 | 2 |
| NSX-T | 2 | 2 |
| Other | 21 | 16 |
| SDDC Manager | 9 | 8 |
| VCF Operations | 8 | 3 |

## Overview

```mermaid
flowchart LR
    sc1("VcfPatchScanner.psm1")
    ts1[("Fleet Manager")]
    sc1 --> ts1
    ep1(["GET /lcm/lcops/api/sddc-managers<br/>Internal . via REST<br/>VCF up to 9.0.x"])
    ts1 --> ep1
    ep2(["POST /lcm/locker/api/v2/passwords/$vmid/decrypted<br/>Internal . via REST<br/>VCF up to 9.0.x"])
    ts1 --> ep2
    ts2[("NSX-T")]
    sc1 --> ts2
    ep3(["GET /api/v1/transport-nodes?node_types=EdgeNode&page_size=100<br/>Public . via REST"])
    ts2 --> ep3
    ep4(["GET /api/v1/transport-nodes/$nodeId/status<br/>Public . via REST"])
    ts2 --> ep4
    ts3[("Other")]
    sc1 --> ts3
    ep5(["GET /api/v1/node<br/>Unknown . via REST"])
    ts3 --> ep5
    ep6(["GET /casa/capabilities<br/>Unknown . via REST"])
    ts3 --> ep6
    ep7(["GET /fleet-lcm/v1/components?pageNumber=$pageNumber&pageSize=$Script:VSP_FLEET_LCM_INVENTORY_PAGE_SIZE<br/>Unknown . via REST"])
    ts3 --> ep7
    ep8(["GET /fleet-lcm/v1/release-versions?pageNumber=$pageNumber&pageSize=100<br/>Unknown . via REST"])
    ts3 --> ep8
    ep9(["GET /fleet-lcm/v1/system<br/>Unknown . via REST"])
    ts3 --> ep9
    ep10(["GET /lcm/lcops/api/v2/environments<br/>Unknown . via REST"])
    ts3 --> ep10
    ep11(["GET /lcm/lcops/api/v2/settings/system-details<br/>Unknown . via REST"])
    ts3 --> ep11
    ep12(["GET /suite-api/api/credentials<br/>Unknown . via REST"])
    ts3 --> ep12
    ep13(["GET /suite-api/internal/components?componentType=VSP<br/>Unknown . via REST"])
    ts3 --> ep13
    ep14(["GET /v1/vrslcms<br/>Unknown . via REST"])
    ts3 --> ep14
    ep15(["GET /vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json<br/>Unknown . via REST"])
    ts3 --> ep15
    ep16(["HEAD /vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json<br/>Unknown . via REST"])
    ts3 --> ep16
    ep17(["POST /api/session<br/>Unknown . via REST"])
    ts3 --> ep17
    ep18(["POST /api/v1/identity/token<br/>Unknown . via REST"])
    ts3 --> ep18
    ep19(["POST /suite-api/api/auth/token/acquire<br/>Unknown . via REST"])
    ts3 --> ep19
    ep20(["POST /v1/tokens<br/>Unknown . via REST"])
    ts3 --> ep20
    ts4[("SDDC Manager")]
    sc1 --> ts4
    ep21(["GET /v1/clusters<br/>Public . via SDK"])
    ts4 --> ep21
    ep22(["GET /v1/credentials<br/>Public . via SDK"])
    ts4 --> ep22
    ep23(["GET /v1/domains<br/>Public . via SDK"])
    ts4 --> ep23
    ep24(["GET /v1/hosts<br/>Public . via SDK"])
    ts4 --> ep24
    ep25(["GET /v1/nsx-clusters<br/>Public . via SDK"])
    ts4 --> ep25
    ep26(["GET /v1/sddc-managers<br/>Public . via SDK"])
    ts4 --> ep26
    ep27(["GET /v1/vcenters<br/>Public . via SDK"])
    ts4 --> ep27
    ep28(["POST /v1/tokens<br/>Public . via SDK"])
    ts4 --> ep28
    ts5[("VCF Operations")]
    sc1 --> ts5
    ep29(["GET /suite-api/api/adapters<br/>Public . via SDK"])
    ts5 --> ep29
    ep30(["GET /suite-api/api/versions/current<br/>Public . via SDK"])
    ts5 --> ep30
    ep31(["POST /suite-api/api/auth/token/acquire<br/>Public . via SDK"])
    ts5 --> ep31
```

## Per target system

### Fleet Manager

```mermaid
flowchart TB
    subgraph FleetManagerSub ["Fleet Manager"]
      direction TB
      ep1(["GET /lcm/lcops/api/sddc-managers<br/>Internal . via REST<br/>VCF up to 9.0.x"])
      ep2(["POST /lcm/locker/api/v2/passwords/$vmid/decrypted<br/>Internal . via REST<br/>VCF up to 9.0.x"])
      fn1("Get-SddcCredentialFromFleetManager") -->|"Invoke-RestMethod"| ep1
      fn1("Get-SddcCredentialFromFleetManager") -->|"Invoke-RestMethod"| ep2
    end
```

### NSX-T

```mermaid
flowchart TB
    subgraph NsxSub ["NSX-T"]
      direction TB
      ep1(["GET /api/v1/transport-nodes?node_types=EdgeNode&page_size=100<br/>Public . via REST"])
      ep2(["GET /api/v1/transport-nodes/$nodeId/status<br/>Public . via REST"])
      fn1("Get-NsxEdgeInventory") -->|"Invoke-RestMethod"| ep1
      fn1("Get-NsxEdgeInventory") -->|"Invoke-RestMethod"| ep2
    end
```

### Other

```mermaid
flowchart TB
    subgraph OtherSub ["Other"]
      direction TB
      ep1(["GET /api/v1/node<br/>Unknown . via REST"])
      ep2(["GET /casa/capabilities<br/>Unknown . via REST"])
      ep3(["GET /fleet-lcm/v1/components?pageNumber=$pageNumber&pageSize=$Script:VSP_FLEET_LCM_INVENTORY_PAGE_SIZE<br/>Unknown . via REST"])
      ep4(["GET /fleet-lcm/v1/release-versions?pageNumber=$pageNumber&pageSize=100<br/>Unknown . via REST"])
      ep5(["GET /fleet-lcm/v1/system<br/>Unknown . via REST"])
      ep6(["GET /lcm/lcops/api/v2/environments<br/>Unknown . via REST"])
      ep7(["GET /lcm/lcops/api/v2/settings/system-details<br/>Unknown . via REST"])
      ep8(["GET /suite-api/api/credentials<br/>Unknown . via REST"])
      ep9(["GET /suite-api/internal/components?componentType=VSP<br/>Unknown . via REST"])
      ep10(["GET /v1/vrslcms<br/>Unknown . via REST"])
      ep11(["GET /vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json<br/>Unknown . via REST"])
      ep12(["HEAD /vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json<br/>Unknown . via REST"])
      ep13(["POST /api/session<br/>Unknown . via REST"])
      ep14(["POST /api/v1/identity/token<br/>Unknown . via REST"])
      ep15(["POST /suite-api/api/auth/token/acquire<br/>Unknown . via REST"])
      ep16(["POST /v1/tokens<br/>Unknown . via REST"])
      fn1("Invoke-AdvisoryDownloadIfChanged") -->|"Invoke-WebRequest"| ep12
      fn1("Invoke-AdvisoryDownloadIfChanged") -->|"Invoke-WebRequest"| ep11
      fn2("Test-FleetManagerAuthentication") -->|"Invoke-RestMethod"| ep5
      fn2("Test-FleetManagerAuthentication") -->|"Invoke-RestMethod"| ep7
      fn3("Test-SddcManagerAuthentication") -->|"Invoke-RestMethod"| ep16
      fn4("Test-VcenterAuthentication") -->|"Invoke-RestMethod"| ep13
      fn5("Test-NsxManagerAuthentication") -->|"Invoke-RestMethod"| ep1
      fn6("Get-SddcManagerListFromVcfOps") -->|"Invoke-RestMethod"| ep8
      fn7("Get-VrslcmFromSddcManager") -->|"Invoke-RestMethod"| ep10
      fn8("Get-FleetManagerFromVcfOps") -->|"Invoke-RestMethod"| ep9
      fn8("Get-FleetManagerFromVcfOps") -->|"Invoke-RestMethod"| ep2
      fn9("Get-FleetManagerReleaseVersions") -->|"Invoke-RestMethod"| ep4
      fn10("Get-StandaloneNsxManagerInventory") -->|"Invoke-RestMethod"| ep1
      fn11("Get-VspBearerToken") -->|"Invoke-RestMethod"| ep14
      fn12("Get-VcfOpsRestToken") -->|"Invoke-RestMethod"| ep15
      fn13("Get-VspFleetLcmInventory") -->|"Invoke-RestMethod"| ep5
      fn13("Get-VspFleetLcmInventory") -->|"Invoke-RestMethod"| ep3
      fn14("Get-LcopsFleetManagerInventory") -->|"Invoke-RestMethod"| ep7
      fn14("Get-LcopsFleetManagerInventory") -->|"Invoke-RestMethod"| ep6
      fn15("Get-VrslcmInventory") -->|"Invoke-RestMethod"| ep7
      fn15("Get-VrslcmInventory") -->|"Invoke-RestMethod"| ep6
    end
```

### SDDC Manager

```mermaid
flowchart TB
    subgraph SddcManagerSub ["SDDC Manager"]
      direction TB
      ep1(["GET /v1/clusters<br/>Public . via SDK"])
      ep2(["GET /v1/credentials<br/>Public . via SDK"])
      ep3(["GET /v1/domains<br/>Public . via SDK"])
      ep4(["GET /v1/hosts<br/>Public . via SDK"])
      ep5(["GET /v1/nsx-clusters<br/>Public . via SDK"])
      ep6(["GET /v1/sddc-managers<br/>Public . via SDK"])
      ep7(["GET /v1/vcenters<br/>Public . via SDK"])
      ep8(["POST /v1/tokens<br/>Public . via SDK"])
      fn1("Get-VrslcmFromSddcManager") -->|"Connect-VcfSddcManagerServer"| ep8
      fn2("Get-NsxAdminPasswordFromSddc") -->|"Invoke-VcfGetCredentials"| ep2
      fn3("Get-SddcManagerInventory") -->|"Connect-VcfSddcManagerServer"| ep8
      fn3("Get-SddcManagerInventory") -->|"Invoke-VcfGetSddcManagers"| ep6
      fn3("Get-SddcManagerInventory") -->|"Invoke-VcfGetDomains"| ep3
      fn3("Get-SddcManagerInventory") -->|"Invoke-VcfGetClusters"| ep1
      fn3("Get-SddcManagerInventory") -->|"Invoke-VcfGetVcenters"| ep7
      fn3("Get-SddcManagerInventory") -->|"Invoke-VcfGetNsxClusters"| ep5
      fn3("Get-SddcManagerInventory") -->|"Invoke-VcfGetHosts"| ep4
    end
```

### VCF Operations

```mermaid
flowchart TB
    subgraph VcfOperationsSub ["VCF Operations"]
      direction TB
      ep1(["GET /suite-api/api/adapters<br/>Public . via SDK"])
      ep2(["GET /suite-api/api/versions/current<br/>Public . via SDK"])
      ep3(["POST /suite-api/api/auth/token/acquire<br/>Public . via SDK"])
      fn1("Get-SddcManagerListFromVcfOps") -->|"Connect-VcfOpsServer"| ep3
      fn1("Get-SddcManagerListFromVcfOps") -->|"Invoke-VcfOpsEnumerateAdapterInstances"| ep1
      fn1("Get-SddcManagerListFromVcfOps") -->|"Invoke-VcfOpsGetCurrentVersionOfServer"| ep2
      fn2("Get-VcfOpsVersion") -->|"Invoke-VcfOpsGetCurrentVersionOfServer"| ep2
      fn3("Get-VcfOpsInventory") -->|"Connect-VcfOpsServer"| ep3
      fn3("Get-VcfOpsInventory") -->|"Invoke-VcfOpsGetCurrentVersionOfServer"| ep2
      fn3("Get-VcfOpsInventory") -->|"Invoke-VcfOpsEnumerateAdapterInstances"| ep1
    end
```

## Endpoints

| Target system | Method | Path | Visibility | Implementation | VCF release | Cmdlets | Call sites |
|---|---|---|---|---|---|---|---:|
| Fleet Manager | GET | `/lcm/lcops/api/sddc-managers` | Internal | via REST | VCF up to 9.0.x | `Invoke-RestMethod` | 1 |
| Fleet Manager | POST | `/lcm/locker/api/v2/passwords/$vmid/decrypted` | Internal | via REST | VCF up to 9.0.x | `Invoke-RestMethod` | 1 |
| NSX-T | GET | `/api/v1/transport-nodes?node_types=EdgeNode&page_size=100` | Public | via REST | - | `Invoke-RestMethod` | 1 |
| NSX-T | GET | `/api/v1/transport-nodes/$nodeId/status` | Public | via REST | - | `Invoke-RestMethod` | 1 |
| Other | POST | `/api/session` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | POST | `/api/v1/identity/token` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/api/v1/node` | Unknown | via REST | - | `Invoke-RestMethod` | 2 |
| Other | GET | `/casa/capabilities` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/fleet-lcm/v1/components?pageNumber=$pageNumber&pageSize=$Script:VSP_FLEET_LCM_INVENTORY_PAGE_SIZE` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/fleet-lcm/v1/release-versions?pageNumber=$pageNumber&pageSize=100` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/fleet-lcm/v1/system` | Unknown | via REST | - | `Invoke-RestMethod` | 2 |
| Other | GET | `/lcm/lcops/api/v2/environments` | Unknown | via REST | - | `Invoke-RestMethod` | 2 |
| Other | GET | `/lcm/lcops/api/v2/settings/system-details` | Unknown | via REST | - | `Invoke-RestMethod` | 3 |
| Other | POST | `/suite-api/api/auth/token/acquire` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/suite-api/api/credentials` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/suite-api/internal/components?componentType=VSP` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | POST | `/v1/tokens` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/v1/vrslcms` | Unknown | via REST | - | `Invoke-RestMethod` | 1 |
| Other | GET | `/vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json` | Unknown | via REST | - | `Invoke-WebRequest` | 1 |
| Other | HEAD | `/vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json` | Unknown | via REST | - | `Invoke-WebRequest` | 1 |
| SDDC Manager | GET | `/v1/clusters` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetClusters` | 1 |
| SDDC Manager | GET | `/v1/credentials` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetCredentials` | 1 |
| SDDC Manager | GET | `/v1/domains` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetDomains` | 1 |
| SDDC Manager | GET | `/v1/hosts` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetHosts` | 1 |
| SDDC Manager | GET | `/v1/nsx-clusters` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetNsxClusters` | 1 |
| SDDC Manager | GET | `/v1/sddc-managers` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetSddcManagers` | 1 |
| SDDC Manager | POST | `/v1/tokens` | Public | via SDK | VCF 9.0+ | `Connect-VcfSddcManagerServer` | 2 |
| SDDC Manager | GET | `/v1/vcenters` | Public | via SDK | VCF 9.0+ | `Invoke-VcfGetVcenters` | 1 |
| VCF Operations | GET | `/suite-api/api/adapters` | Public | via SDK | VCF 9.0+ | `Invoke-VcfOpsEnumerateAdapterInstances` | 3 |
| VCF Operations | POST | `/suite-api/api/auth/token/acquire` | Public | via SDK | VCF 9.0+ | `Connect-VcfOpsServer` | 2 |
| VCF Operations | GET | `/suite-api/api/versions/current` | Public | via SDK | VCF 9.0+ | `Invoke-VcfOpsGetCurrentVersionOfServer` | 3 |

## VCF version applicability

The following endpoints are **version-gated** — the API map declares a `MaxVcfVersion`, meaning they are only delivered on specific VCF releases. The consuming script must check the live VCF release and skip these calls on later trains (for example, `Invoke-VCFPatchPlan.ps1` gates Fleet Manager on `Test-PatchPlanIsVcfOpsVersion9Dot0x` and skips it on VCF 9.1+).

| Target system | Method | Path | Visibility | VCF release | Cmdlets |
|---|---|---|---|---|---|
| Fleet Manager | GET | `/lcm/lcops/api/sddc-managers` | Internal | VCF up to 9.0.x | `Invoke-RestMethod` |
| Fleet Manager | POST | `/lcm/locker/api/v2/passwords/$vmid/decrypted` | Internal | VCF up to 9.0.x | `Invoke-RestMethod` |

