[![PowerShell](https://img.shields.io/badge/PowerShell-7.4%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-Broadcom-green.svg)](LICENSE.md)
[![GitHub Clones](https://img.shields.io/badge/dynamic/json?color=success&label=Clone&query=count&url=https://gist.githubusercontent.com/nathanthaler/37dc26bf4836fb92693f016ea6065f8e/raw/clone.json&logo=github)](https://gist.githubusercontent.com/nathanthaler/37dc26bf4836fb92693f016ea6065f8e/raw/clone.json)
[![PS Version](https://img.shields.io/powershellgallery/v/VcfPatchScanner?label=Version)](https://www.powershellgallery.com/packages/VcfPatchScanner)
[![PS Downloads](https://img.shields.io/powershellgallery/dt/VcfPatchScanner?label=PS%20Gallery%20Downloads)](https://www.powershellgallery.com/packages/VcfPatchScanner)
[![Downloads](https://img.shields.io/github/downloads/vmware/powershell-module-for-vcf-patch-scanner/total?label=Github%20Release%20Downloads)](https://github.com/vmware/powershell-module-for-vcf-patch-scanner/releases)

# VCF Patch Scanner

A PowerShell module and browser-based UI for scanning VMware Cloud Foundation (VCF), VMware vSphere Foundation (VVF), and vSphere environments against Broadcom security advisories. Connects to your endpoints, collects installed component versions, and reports which components require patching.

## Table of contents

- [Supported environments](#supported-environments)
- [Supported components](#supported-components)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Option 1 — PowerShell Gallery (recommended)](#option-1--powershell-gallery-recommended)
  - [Option 2 — Manual install from GitHub](#option-2--manual-install-from-github)
- [Uninstallation](#uninstallation)
  - [PowerShell Gallery install](#powershell-gallery-install)
  - [Manual install](#manual-install)
  - [Removing the working directory (optional)](#removing-the-working-directory-optional)
  - [Removing the profile entry](#removing-the-profile-entry)
- [First-run setup (one time)](#first-run-setup-one-time)
- [Using the web UI](#using-the-web-ui)
  - [Running as a background process](#running-as-a-background-process)
  - [Advisory database status](#advisory-database-status)
  - [Workflow](#workflow)
  - [Retry failed endpoints](#retry-failed-endpoints)
- [Advisory database](#advisory-database)
  - [Schema version](#schema-version)
  - [Included advisories](#included-advisories)
- [Network access requirements](#network-access-requirements)
  - [VCF 9.x](#vcf-9x)
  - [VVF 9.x](#vvf-9x)
  - [VCF 5.x](#vcf-5x)
  - [vSphere 8](#vsphere-8)
- [Required credentials and privileges](#required-credentials-and-privileges)
  - [VCF 9.x](#vcf-9x-1)
  - [VVF 9.x](#vvf-9x-1)
  - [VCF 5.x](#vcf-5x-1)
  - [vSphere 8](#vsphere-8-1)
- [Collecting logs](#collecting-logs)
- [PowerShell cmdlets (advanced)](#powershell-cmdlets-advanced)
  - [Programmatic advisory update](#programmatic-advisory-update)
- [Security](#security)

## Supported environments

| Product | Versions |
| --- | --- |
| VMware Cloud Foundation (VCF) | 5.x, 9.x |
| VMware vSphere Foundation (VVF) | 9.x |
| vSphere | 8.x |

## Supported components

These components, which have versions under general support, can be scanned.

| Component | Min. version | Product |
| --- | --- | --- |
| Aria Automation (vRealize Automation) | 8.0 | VCF 5.x (via vRSLCM) |
| Aria Operations (vRealize Operations) | 8.0 | VCF 5.x (via vRSLCM) |
| Aria Operations for Logs (vRealize Log Insight) | 8.0 | VCF 5.x (via vRSLCM) |
| Aria Operations for Networks (vRealize Network Insight) | 8.0 | VCF 5.x (via vRSLCM) |
| ESX | 8.0 | VCF, VVF, vSphere |
| Identity Broker | 9.0 | VCF 9.x, VVF 9.x |
| Identity Manager (Workspace ONE Access) | 3.3 | VCF 5.x (via vRSLCM) |
| NSX | 4.0 | VCF, vSphere |
| vCenter | 8.0 | VCF, VVF, vSphere |
| VCF Automation | 9.0 | VCF 9.x |
| VCF Operations | 9.0 | VCF 9.x, VVF 9.x |

> **Note:** VVF does not include NSX. The NSX component is only scanned for VCF and standalone vSphere environments.

## Prerequisites

| Requirement | Minimum version |
| --- | --- |
| PowerShell | 7.4 |
| VCF PowerCLI | 9.0 |
| Python | 3.13 |

Both `pwsh` and `python3` (or `python`) must be on your `PATH`. VCF.PowerCLI must be imported in your PowerShell session before running the scanner.

## Installation

### Option 1 — PowerShell Gallery (recommended)

```powershell
Install-Module -Name VcfPatchScanner
```

PowerShell auto-imports the module on first use — no `Import-Module` line in your `$PROFILE` is needed.

### Option 2 — Manual install from GitHub

Clone the repository and run the installer script:

```powershell
git clone https://github.com/vmware/powershell-module-for-vcf-patch-scanner.git
cd powershell-module-for-vcf-patch-scanner
.\Install-VcfPatchScannerModule.ps1
```

The installer copies the module to your `$env:PSModulePath`, validates the manifest, and checks your `$PROFILE` for any eager-load lines that would slow shell startup.

> **Windows note — cloned or downloaded ZIP sources:** Windows marks files from the internet with a zone flag that PowerShell's default execution policy blocks. The installer runs `Unblock-File` on all copied files automatically. If you need to unblock before running the installer itself:
>
> ```powershell
> Get-ChildItem -Path .\powershell-module-for-vcf-patch-scanner -Recurse | Unblock-File
> ```

## Uninstallation

### PowerShell Gallery

```powershell
Uninstall-Module -Name VcfPatchScanner
```

### Manual

Remove the module directory that the installer copied to your module path:

```powershell
$installPath = Join-Path -Path ($env:PSModulePath -split [System.IO.Path]::PathSeparator)[0] `
    -ChildPath "VcfPatchScanner"
Remove-Item -Path $installPath -Recurse -Force
```

### Removing the working directory (optional)

`Initialize-VcfPatchScanner` creates a working directory (default: `~/VcfPatchScanner`) that holds your scan settings, advisory database, findings history, and logs. This directory is **not** removed by either uninstall method above. Delete it manually if you no longer need it:

```powershell
# Uses the path stored in the current session; substitute your actual path if unset.
Remove-Item -Path $env:VcfPatchScannerBaseDirectory -Recurse -Force
```

### Removing the profile entry

`Initialize-VcfPatchScanner` appends one line to your `$PROFILE`:

```powershell
$env:VcfPatchScannerBaseDirectory = "<your base directory>"
```

Remove it manually in your editor, or run this one-liner to strip it automatically:

```powershell
$profileContent = Get-Content -LiteralPath $PROFILE -Raw
$cleaned = $profileContent -replace '(?m)^\$env:VcfPatch[A-Za-z]*BaseDirectory\s*=\s*"[^"]*"\r?\n?', ''
Set-Content -LiteralPath $PROFILE -Value $cleaned.TrimEnd() -Encoding UTF8 -NoNewline
```

> **Windows only:** `Initialize-VcfPatchScanner` also persists the variable to the user environment registry. Remove it with:
>
> ```powershell
> [System.Environment]::SetEnvironmentVariable('VcfPatchScannerBaseDirectory', $null, 'User')
> ```

## First-run setup (one time)

After installing by either method, run:

```powershell
Initialize-VcfPatchScanner
```

`Initialize-VcfPatchScanner` checks prerequisites, prompts for a base directory (default: `~/VcfPatchScanner`), creates the directory structure, and persists `$env:VcfPatchScannerBaseDirectory` to your PowerShell profile so future sessions pick it up automatically.

The base directory layout after initialization:

```text
~/VcfPatchScanner/
  Config/      scan-settings.json            (environments and preferences)
  Data/        securityAdvisory.json         (Broadcom advisory database)
               securityAdvisory.json.etag    (ETag cache for update checks)
               securityAdvisory.json.old     (backup of previous advisory file)
               securityAdvisory.json.sha256sum  (SHA-256 checksum for download verification)
               vcenterBuildMap.json          (vCenter version → MOB build mapping)
               vcenterBuildMap.json.sha256sum   (SHA-256 checksum for build map)
  Findings/    <env-name>/                   (one subdirectory per environment)
               vcf-findings-YYYYMMDD_HHMMSS.json
  Logs/        VcfPatchScannerEngine-YYYY-MM-DD.log   (PowerShell engine)
               VcfPatchScannerServer-YYYY-MM-DD.log   (Python web server)
  Tools/       Manage-VCFPatchScannerServer.py, Start-VCFPatchScannerServer.py, vcp-patch-ui.html, Invoke-VCFPatchScanner.ps1
```

## Using the web UI

```powershell
Start-VCFPatchScannerServer
```

This starts a local web server (port 8765 by default) and opens the browser UI. The server binds to `127.0.0.1` only — it is not accessible from other machines.

### Running as a background process

Use `-Background` to start the server as a detached background process that survives terminal closure. A companion set of cmdlets manages the lifecycle:

```powershell
# Start in the background (returns immediately; browser opens automatically)
Start-VCFPatchScannerServer -Background

# Suppress the automatic browser launch (useful in scripts or CI)
Start-VCFPatchScannerServer -Background -NoBrowser

# Custom port
Start-VCFPatchScannerServer -Background -Port 9000

# Check whether the background server is running
Get-VCFPatchScannerServerStatus
# IsRunning : True
# ProcessId : 84312
# Url       : http://localhost:8765

# Stop the server (works for both background and foreground servers)
Stop-VCFPatchScannerServer

# Restart (stop + start background server in one call)
Restart-VCFPatchScannerServer

# If the port is already in use by a previous server, kill it and restart
Start-VCFPatchScannerServer -Force
Start-VCFPatchScannerServer -Background -Force
```

On macOS and Linux the background process is detached via `setsid`; on Windows it uses `DETACHED_PROCESS`. The server writes its PID to `Logs/vcfpatch-server.pid` after binding the socket. `Stop-VCFPatchScannerServer` kills any process holding the port — whether it was started with `-Background` or as a foreground server — and waits for the port to be released before returning. Background server startup output is appended to `Logs/VcfPatchScannerServer-daemon.log`.

> **Tip:** If `Start-VCFPatchScannerServer` reports that the port is already in use, run `Stop-VCFPatchScannerServer` to release it, or use `-Force` to kill the existing process and restart in one step.

### Advisory database status

At startup, the scan server performs a lightweight background check to see whether the upstream advisory database has been updated. The result appears in a status bar below the page header:

| Status | Meaning |
| --- | --- |
| Up to date | Your local database matches the published version. The last updated date is shown. |
| Update available | A newer version is available. Click **Update Now** to download it. |
| Offline | GitHub could not be reached. If this is expected (air-gapped environment), you will be prompted once to disable future checks. |
| Checks disabled | Update checks are turned off. A link lets you re-enable them. |

**Checking for updates manually:** click **🔄 Check for Updates** in the page header at any time — no restart required.

**Applying an update:** when a new advisory database is available, click **Update Now**. A confirmation dialog explains the steps:

1. The SHA-256 checksum is fetched from GitHub and verified against the downloaded file.
2. Your current `securityAdvisory.json` is backed up to `securityAdvisory.json.old`.
3. The new file is written atomically.
4. A banner prompts you to restart the scan server to load the updated database.

**Offline or air-gapped environments:** if the update check fails and you do not want to see the warning again, click **Disable Update Checks** in the one-time prompt, or toggle **Disable advisory update checks** in the Settings panel. This setting is stored in `Config/scan-settings.json` and can be changed at any time.

### Workflow

1. **Add an environment** — Click "Add Environment" and follow the guided wizard. Choose your environment type and fill in the mandatory fields. The Next button is disabled until all required fields are populated.
   - **VCF 9.x**: Enter VCF Operations details. SDDC Manager, Fleet Manager, vCenter, and NSX are auto-discovered from VCF Operations.
   - **VVF 9.x**: Enter VCF Operations details. Fleet Manager and vCenter are auto-discovered. NSX is not part of VVF.
   - **VCF 5.x**: Enter SDDC Manager credentials. vRSLCM is auto-detected from SDDC Manager — if one is registered its FQDN is pre-populated; if none is found the wizard skips the vRSLCM step entirely.
2. **Save settings** — Environments and preferences are saved to `Config/scan-settings.json`.
3. **Enter credentials** — Passwords are entered in the Run Scan panel and passed securely via environment variables. They are never stored to disk.
4. **Validate credentials** — Use "Credential Check" to confirm all endpoints are reachable and credentials are accepted before running a full scan.
5. **Run scan** — Select one or more environments and click "Run Scan". Progress is shown per endpoint in real time. The environment badge updates with the detected VCF minor version (e.g. "VMware Cloud Foundation 5.2") after each scan.
6. **Review findings** — The results table lists each vulnerable endpoint with the VMSA advisory ID, severity, current version, minimum fixed version, and CVEs.
   - **Filter bar** (always visible above the table): narrow by **minimum severity** (All / Low+ / Medium+ / High+ / Critical only) and **component type** (ESX, vCenter, NSX, NSX Edge, etc.). Both filters update the summary banner, the stat cards, and the table simultaneously. Click **Save as Default** to persist your preferred filter settings across sessions.
   - **Column filters and search**: each column has a text or select filter; the global search box searches all columns at once.
   - **Sort and group**: sort by any column header, or use the Default sort (VMSA ID descending → Severity → Endpoint) from the toolbar. Clicking the VMSA ID column header always sorts descending first (most recent advisory at the top); clicking again reverses to ascending.
   - **Cell ordering within columns**: VMSA IDs, Min. Fixed Versions, and CVE IDs are all shown newest-to-oldest within each cell. Fix versions use semantic version order (4.2.2.1 before 4.2.2 before 4.2.1); CVE IDs use reverse-alphabetical order (CVE-2025 before CVE-2024).
   - **CVE lists**: click "+N more" to expand; click "show less" to collapse.
7. **Export** — Download findings as JSON, CSV, or PDF from the toolbar.

### Retry failed endpoints

If one or more endpoints were unreachable during a scan, a "Retry N Failed Endpoint(s)" button appears after the run completes. This re-scans only the failed endpoints without re-collecting from everything that already succeeded.

---

## Advisory database

The advisory database (`securityAdvisory.json`) is a JSON file that maps VMSA advisory IDs to affected component versions and fixed versions. The file is included with the module and updated independently of the module itself.

### Schema version

The file uses schema version `2.0`. The `updatedAt` field records when the advisory content last changed (not when the file was last generated). The file is only rewritten when at least one advisory is added, removed, or modified — running the conversion script against unchanged upstream data produces no output file change.

> Product names in the advisory database reflect the name Broadcom published at the time. The same product appears under different names across eras: vRealize-branded (pre-2023), Aria-branded (2023–2024), and VCF-branded (2025+). The scraper also handles suite-wrapper labels such as `"VMware Cloud Foundation (vIDM)"` and footnote-suffixed names such as `"vRealize Automation [1]"`, normalizing all variants to their canonical form before inclusion.

---

## Network access requirements

The machine running the scanner must have outbound HTTPS (port 443) access to the following endpoints. All connections are read-only REST API calls — the scanner never modifies any configuration.

The **update check** requires outbound HTTPS access to `raw.githubusercontent.com`. If this is not possible, disable update checks in Settings.

### VCF 9.x

| Endpoint | How it is provided |
| --- | --- |
| VCF Operations (e.g. `ops.example.com`) | Entered manually in the environment wizard |
| SDDC Manager (e.g. `vcf01.example.com`) | Auto-discovered via VCF Operations |
| Fleet Manager / Fleet Lifecycle (e.g. `fm.example.com`) | Auto-discovered via VCF Operations |
| vCenter Servers | Auto-discovered from SDDC Manager workload domain inventory |
| NSX Managers | Auto-discovered from SDDC Manager workload domain inventory |
| ESXi hosts | Inventoried via vCenter (no direct ESXi connection required) |

### VVF 9.x

| Endpoint | How it is provided |
| --- | --- |
| VCF Operations (e.g. `ops.example.com`) | Entered manually in the environment wizard |
| Fleet Manager / Fleet Lifecycle | Auto-discovered via VCF Operations |
| vCenter Server | Auto-discovered via VCF Operations |
| ESXi hosts | Inventoried via vCenter (no direct ESXi connection required) |

### VCF 5.x

| Endpoint | How it is provided |
| --- | --- |
| SDDC Manager | Entered manually |
| vCenter Servers | Auto-discovered from SDDC Manager |
| NSX Managers | Auto-discovered from SDDC Manager |
| NSX Managers (Edge node API) | Same NSX Manager FQDNs |
| ESXi hosts | Inventoried via vCenter |
| vRSLCM (optional) | Auto-detected from SDDC Manager, or entered manually |

### vSphere 8

| Endpoint | How it is provided |
| --- | --- |
| vCenter Server | Entered manually |
| NSX Manager (optional) | Entered manually |
| ESXi hosts | Inventoried via vCenter |

---

## Required credentials and privileges

The scanner uses read-only API access for all endpoints. No changes are made to any system.

### VCF 9.x

| Component | Credential | Notes |
| --- | --- | --- |
| **VCF Operations** | Local admin (e.g. `admin@local`) | Used to authenticate to the VCF Operations REST API and auto-discover the SDDC Manager(s) and Fleet Manager. |
| **SDDC Manager** | SSO admin (e.g. `administrator@vsphere.local`) | Used to enumerate workload domains, vCenter FQDNs, and NSX Manager FQDNs via the SDDC Manager REST API. |
| **Fleet Manager (VCF 9.0)** | `admin@local` | Authenticates to the Fleet Manager REST API (LCops / CASA). |
| **Fleet Lifecycle (VCF 9.1+)** | `admin@vsp.local` — **VCF Services Runtime Password** | Authenticates to the Fleet Lifecycle REST API via the Suite API internal endpoint. The password is the "VCF Services Runtime Password" set during VCF deployment. |
| **vCenter** | Any SSO user with read-only permissions | Used by VCF PowerCLI to enumerate clusters, hosts, VMs, and component versions. |
| **NSX Manager** | Any user with read-only API access | Used to retrieve NSX component versions. |

### VVF 9.x

| Component | Credential | Notes |
| --- | --- | --- |
| **VCF Operations** | Local admin (e.g. `admin@local`) | Used to authenticate to the VCF Operations REST API and auto-discover the Fleet Manager and vCenter. |
| **Fleet Manager (VVF 9.0)** | `admin@local` | Authenticates to the Fleet Manager REST API. |
| **Fleet Lifecycle (VVF 9.1+)** | `admin@vsp.local` — **VCF Services Runtime Password** | Authenticates to the Fleet Lifecycle REST API. |
| **vCenter** | Any SSO user with read-only permissions | Component version inventory. |

### VCF 5.x

| Component | Credential | Notes |
| --- | --- | --- |
| **SDDC Manager** | SSO admin (e.g. `administrator@vsphere.local`) | Enumerates workload domains, vCenter FQDNs, NSX Manager FQDNs, and detects registered vRSLCM. |
| **vCenter** | Any SSO user with read-only permissions | Component version inventory. |
| **NSX Manager** | Any user with read-only API access | NSX Manager version inventory. |
| **vRSLCM** (optional) | vRSLCM admin | Enumerates lifecycle managed products. Only required when vRSLCM is registered with SDDC Manager. |

### vSphere 8

| Component | Credential | Notes |
| --- | --- | --- |
| **vCenter** | Any SSO user with read-only permissions | Component version inventory. |
| **NSX Manager** (optional) | Any user with read-only API access | NSX version inventory. Only required when NSX is deployed. |

---

## Collecting logs

To bundle all log files into a zip for troubleshooting:

```powershell
Invoke-VcfPatchScannerCollectLogs
```

The archive is written to `$HOME`. The web UI also has a "📦 Collect Logs" button in the page header.

Log files are written to `~/VcfPatchScanner/Logs/`:

| File | Contents |
| --- | --- |
| `VcfPatchScannerEngine-YYYY-MM-DD.log` | PowerShell scan engine — inventory collection, advisory matching, and error details |
| `VcfPatchScannerServer-YYYY-MM-DD.log` | Python web server — HTTP requests, discovery calls, and security events |
| `VcfPatchScannerServer-daemon.log` | Background server startup output (only present when started with `-Background`) |
| `vcfpatch-server.pid` | Background server PID file — read by `Stop-VCFPatchScannerServer` and `Get-VCFPatchScannerServerStatus` |

## PowerShell cmdlets (advanced)

The web UI is the recommended interface. For automation or scripting, the following cmdlets are available:

| Cmdlet | Purpose |
| --- | --- |
| `Initialize-VcfPatchScanner` | One-time setup |
| `Start-VCFPatchScannerServer` | Launch the web UI (foreground or `-Background` background) |
| `Stop-VCFPatchScannerServer` | Stop the background server gracefully |
| `Get-VCFPatchScannerServerStatus` | Check whether the background server is running and get its PID and URL |
| `Restart-VCFPatchScannerServer` | Stop then restart the background server in one call |
| `Invoke-VCFPatchScanner` | Run a scan programmatically |
| `Test-PatchScanConnection` | Validate credentials for all endpoints |
| `Get-PatchScanSettings` | Load settings from `Config/scan-settings.json` |
| `Set-PatchScanSettings` | Save settings |
| `New-PatchScanEnvironment` | Build an environment config object |
| `Invoke-VcfPatchScannerCollectLogs` | Bundle logs into a zip |
| `Get-SecurityAdvisory` | Load the advisory database (supports `-Uri` for ETag-aware download) |
| `Invoke-AdvisoryDownloadIfChanged` | Download the advisory database only if the upstream ETag has changed |

Get help on any cmdlet:

```powershell
Get-Help Invoke-VCFPatchScanner -Full
```

### Programmatic advisory update

```powershell
# Check whether an update is available without downloading:
$result = Invoke-AdvisoryDownloadIfChanged `
    -DestinationPath "$env:VcfPatchScannerBaseDirectory\Data\securityAdvisory.json"

if ($result.Downloaded) {
    Write-Host "Advisory database updated to $($result.UpdatedAt)"
} elseif ($result.Skipped) {
    Write-Host "Already up to date"
} else {
    Write-Warning "Update failed: $($result.ErrorMessage)"
}

# Or load advisories and download in one call:
$advisories = Get-SecurityAdvisory `
    -Uri "https://raw.githubusercontent.com/vmware/powershell-module-for-vcf-patch-scanner/main/data/securityAdvisory.json" `
    -DestinationPath "$env:VcfPatchScannerBaseDirectory\Data\securityAdvisory.json"
```

---

## Security

- The web server binds to `127.0.0.1` only; remote access is not possible.
- Credentials are passed via environment variables, never written to disk or logged.
- PowerShell subprocesses run with `-NoProfile` to prevent user profile scripts from interfering with injected credentials.
- Log files are created with mode `0600` on macOS/Linux.
- Advisory database downloads are verified against a SHA-256 checksum before the local file is replaced.
- The advisory JSON and settings file are validated before use; oversized files are rejected.
- All endpoint connections use HTTPS with configurable certificate handling.

## Credentials and Secrets Management

### Overview

VCF Patch Scanner supports three credential management approaches:

| Approach | Setup Required | Use Case | Security |
|----------|---|---|---|
| **Interactive Prompts** | None | Local one-time scans | Passwords in memory only (not written to disk) |
| **Environment Variables** | Minimal | CI/CD pipelines, automation | Secrets managed by CI/CD system (GitHub Secrets, Jenkins, etc.) |
| **SecretStore (optional)** | One-time installation | Local recurring scans | Encrypted local credential store (optionally password-protected) |

### Three Paths to Running Scans

#### Path 1: Interactive Prompts (Zero Setup)

No configuration needed. Run a scan and enter passwords when prompted:

```powershell
# Copy the example config and fill in your server details
Copy-Item VcfPatchScanner/Tools/environments.example.json ./my-environment.json
# Edit my-environment.json — set server FQDNs and usernames; keep password_secret_ref values as-is

# Run the scan and enter passwords at prompts
pwsh -File VcfPatchScanner/Tools/Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json
```

When a credential is not found in SecretStore or environment variables, the script prompts:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Credential Required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Environment: PROD_US_WEST — sddc_manager
Not found in: SecretStore, environment variables
Required for: Authenticating to endpoint

Enter password (or Ctrl+C to cancel): ••••••••
✓ Credential accepted
```

#### Path 2: Environment Variables (CI/CD Pipelines)

Set environment variables before running the scan:

```powershell
# Set credentials from your CI/CD system's secret management
$env:PROD_US_WEST_SDDC_MANAGER_1_PASSWORD = 'my-password'
$env:PROD_US_WEST_VCF_OPS_1_PASSWORD = 'my-password'
# ... etc for each credential

# Run the scan — credentials come from env vars, no prompts occur
# -NonInteractive is a pwsh host flag (not a script parameter); include it in CI/CD
# to fail fast if a credential is missing rather than hanging for user input
pwsh -NonInteractive -File Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json
```

**GitHub Actions Example:**

```yaml
- name: Run VCF Patch Scan
  env:
    PROD_US_WEST_SDDC_MANAGER_1_PASSWORD: ${{ secrets.PROD_US_WEST_SDDC_MANAGER_PASSWORD }}
    PROD_US_WEST_VCF_OPS_1_PASSWORD: ${{ secrets.PROD_US_WEST_VCF_OPS_PASSWORD }}
  run: |
    pwsh -NonInteractive -File ${{ github.workspace }}/Invoke-VCFPatchScanner.ps1 `
      -ConfigFile ${{ github.workspace }}/my-environment.json
```

#### Path 3: Microsoft.PowerShell.SecretStore (Local Recurring Scans)

Install SecretStore once and save credentials. Future scans use the credential store automatically.

**One-time setup (run once per machine):**

```powershell
# Step 1: Install both required modules
#   SecretManagement is the front-end API; SecretStore is the encrypted backend vault
Install-Module -Name Microsoft.PowerShell.SecretManagement -Force
Install-Module -Name Microsoft.PowerShell.SecretStore -Force

# Step 2: Register SecretStore as your default vault
Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

# Step 3: Configure vault security
#   -Authentication Password: vault re-locks after -PasswordTimeout seconds (recommended for shared machines)
#   -Authentication None:     vault never prompts (recommended for scheduled tasks / single-user machines)
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication None
# -- OR, for password-protected vaults --
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 28800
```

**One-time per credential (save each password):**

```powershell
Set-Secret -Name 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD' -Secret (Read-Host -AsSecureString 'SDDC Manager password')
Set-Secret -Name 'PROD_US_WEST_VCF_OPS_1_PASSWORD'      -Secret (Read-Host -AsSecureString 'VCF Operations password')
# ... one Set-Secret call per endpoint in your environments.json
```

**Future scans (no prompts, no typing passwords):**

```powershell
pwsh -File Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json
```

> **Password-protected vaults:** If you configured `-Authentication Password`, the vault re-locks after the timeout. Before running a scan you must unlock it:
> ```powershell
> Unlock-SecretStore -Password (Read-Host -AsSecureString 'Vault password')
> ```
> For fully automated scans (cron, scheduled tasks) use `-Authentication None` instead.

**Day-2: Rotating a password** (run `Set-Secret` again with the same name — it overwrites):

```powershell
Set-Secret -Name 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD' -Secret (Read-Host -AsSecureString 'New SDDC Manager password')
```

**Listing stored credentials** (useful for verifying all secrets are saved before a scan):

```powershell
Get-SecretInfo | Where-Object Name -like '*_PASSWORD' | Select-Object Name, VaultName
```

**Why SecretStore?**
- Credentials encrypted at rest on your machine
- No plain-text files on disk
- No typing passwords repeatedly for recurring scans
- Optional installation — your choice

**When to use SecretStore:**
- You scan the same environments regularly from your laptop
- You want credentials encrypted locally

**When NOT to use SecretStore:**
- You're running in a CI/CD pipeline (use env vars instead — Path 2)
- You prefer ephemeral credential entry (use interactive prompts — Path 1)

### Configuration File Format

Paths 1 and 2 (interactive prompts and environment variables) use `environments.json` when invoking the CLI directly. The web UI generates this file internally — you do not create or edit it when using the browser interface.

```json
{
  "version": "1.0",
  "environments": [
    {
      "name": "prod-us-west",
      "displayName": "Production US-West SDDC",
      "type": "vcf9",
      "endpoints": {
        "sddc_manager": {
          "server": "sddc-prod-uw.corp.local",
          "username": "administrator@vsphere.local",
          "password_secret_ref": "PROD_US_WEST_SDDC_MANAGER_1_PASSWORD"
        },
        "vcf_ops": {
          "server": "ops-prod-uw.corp.local",
          "username": "admin",
          "password_secret_ref": "PROD_US_WEST_VCF_OPS_1_PASSWORD"
        }
      }
    }
  ]
}
```

**Key rules:**
- Credentials are **never** stored in the config file
- `password_secret_ref` names follow the pattern: `{ENVIRONMENT}_{ENDPOINT}_{INSTANCE}_PASSWORD` (uppercase, underscores)
- You can define multiple environments in one config file
- Server FQDNs and usernames come from your infrastructure; only passwords are secrets

### Adding a New Environment (Day-2 Operations)

**Scenario:** Your organization deployed a new SDDC in us-east. Add it to scans without re-entering known credentials.

1. **Add the new environment to `environments.json`** (inside the existing `environments` array):

```json
{
  "version": "1.0",
  "environments": [
    {
      "name": "prod-us-west",
      "...": "existing environment — unchanged"
    },
    {
      "name": "prod-us-east",
      "displayName": "Production US-East SDDC",
      "type": "vcf9",
      "endpoints": {
        "sddc_manager": {
          "server": "sddc-prod-ue.corp.local",
          "username": "administrator@vsphere.local",
          "password_secret_ref": "PROD_US_EAST_SDDC_MANAGER_1_PASSWORD"
        }
      }
    }
  ]
}
```

2. **Save the credential (one-time per new environment):**

```powershell
# SecretStore (recommended for recurring use)
Set-Secret -Name 'PROD_US_EAST_SDDC_MANAGER_1_PASSWORD' -Secret (Read-Host -AsSecureString 'SDDC Manager password')

# OR — environment variable (CI/CD or one-time use)
$env:PROD_US_EAST_SDDC_MANAGER_1_PASSWORD = 'password-here'
```

3. **Scan both environments together:**

```powershell
# Both environments are scanned sequentially
pwsh -File Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json
```

### Batch Scanning Multiple Environments

Run all configured environments in a single scan:

```powershell
# Scan prod-us-west, prod-us-east, lab-vcf5, etc. — all in one invocation
pwsh Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json

# Findings for each environment are written to:
#   Findings/prod-us-west-findings.json
#   Findings/prod-us-east-findings.json
#   Findings/lab-vcf5-findings.json
```

### Secret Reference Name Format

Secret references are auto-generated from your config values. You don't need to calculate them, but understanding the format helps with troubleshooting:

```
{ENVIRONMENT}_{ENDPOINT_TYPE}_{INSTANCE_NUMBER}_PASSWORD

Examples:
  PROD_US_WEST_SDDC_MANAGER_1_PASSWORD    (environment "prod-us-west", endpoint type "sddc_manager", instance 1)
  PROD_US_WEST_VCF_OPS_1_PASSWORD         (environment "prod-us-west", endpoint type "vcf_ops", instance 1)
  LAB_VCF5_VRSLCM_1_PASSWORD              (environment "lab-vcf5", endpoint type "vrslcm", instance 1)
```

Transformation rules:
- Environment names: hyphens converted to underscores, forced uppercase
- Endpoint types: underscores preserved, forced uppercase
- Instance numbers: start at 1 for the first instance of each type

### Troubleshooting Credentials

**Error: "Credential reference 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD' not found"**

This means the credential lookup failed. The script tried these three places in order:

1. **Microsoft.PowerShell.SecretStore** — if installed, tried `Get-Secret`
2. **Environment variable** — tried `$env:PROD_US_WEST_SDDC_MANAGER_1_PASSWORD`
3. **Interactive prompt** — would have prompted if running in a terminal (blocked by `-NonInteractive` or no terminal)

**Fix it:** Choose ONE of:

```powershell
# Option A: Set the environment variable
$env:PROD_US_WEST_SDDC_MANAGER_1_PASSWORD = 'password-here'
pwsh -File Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json

# Option B: Save to SecretStore
Set-Secret -Name 'PROD_US_WEST_SDDC_MANAGER_1_PASSWORD' -Secret (Read-Host -AsSecureString 'SDDC Manager password')
pwsh -File Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json

# Option C: Run interactively and enter the password when prompted
pwsh -File Invoke-VCFPatchScanner.ps1 -ConfigFile my-environment.json
```

**Error: "running non-interactively"**

You're running `pwsh -NonInteractive` (or via a scheduled task) but no credentials were found in SecretStore or env vars. Note: `-NonInteractive` is a **`pwsh` host flag**, not a script parameter — the correct syntax is `pwsh -NonInteractive -File Invoke-VCFPatchScanner.ps1 ...`, not `pwsh -File Invoke-VCFPatchScanner.ps1 ... -NonInteractive`.

**Fix:** Set credentials as environment variables or save them to SecretStore first, then re-run.

### Web UI and Credentials

When using the browser UI (`Start-VCFPatchScannerServer`), the credential flow is entirely password-based:

- Passwords entered in the UI are passed directly to the PowerShell scanner as environment variables
- **Passwords are never stored to disk** — they live in memory for the duration of the scan subprocess and are discarded afterward
- The Python server has no awareness of SecretStore; it always uses env-var delivery

**SecretStore takes priority over UI passwords.** If you have SecretStore installed and a secret stored under the expected reference name (e.g. `VCF5_SDDC_MANAGER_1_PASSWORD`), the PowerShell resolver will use the SecretStore value and ignore the password entered in the UI. This is intentional for operators who have already set up SecretStore — they can leave the UI password fields empty.

**To save UI credentials to SecretStore for future scans:**
1. Determine the secret reference names the scanner generated for your environment (check the engine log at `DEBUG` level — look for lines like `sddc_manager (sddc.example.com): env var 'VCF5_SDDC_MANAGER_1_PASSWORD'`)
2. Save each credential once:
   ```powershell
   Set-Secret -Name 'VCF5_SDDC_MANAGER_1_PASSWORD' -Secret (Read-Host -AsSecureString 'SDDC Manager password')
   ```
3. Future scans will resolve credentials from SecretStore automatically; the UI password fields become optional

## SOFTWARE LICENSE AGREEMENT

Copyright (c) CA, Inc. All rights reserved.

You are hereby granted a non-exclusive, worldwide, royalty-free license under CA, Inc.'s copyrights to use, copy, modify, and distribute this software in source code or binary form for use in connection with CA, Inc. products.

This copyright notice shall be included in all copies or substantial portions of the software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**
