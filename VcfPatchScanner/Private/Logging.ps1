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

#region Logging

function Write-LogMessage {

    <#
        .SYNOPSIS
        Writes a log message to console and/or log file.

        .DESCRIPTION
        Writes a timestamped, type-prefixed message to the console and log file.
        Message types: DEBUG, INFO, WARNING, ERROR.

        Screen output is filtered by the configured log level threshold (set via
        Initialize-PatchScanLogging). Only messages at or above the configured level
        are displayed on the console.

        All messages are always written to the log file regardless of their level. This
        ensures that DEBUG context is always available in the file for troubleshooting scan
        runs, even when the screen threshold is set to INFO or higher.

        .PARAMETER Type
        Message type: DEBUG, INFO, WARNING, ERROR.

        .PARAMETER Message
        The message text.

        .EXAMPLE
        Write-LogMessage -Type INFO -Message "Scan started."

        .EXAMPLE
        Write-LogMessage -Type ERROR -Message "Connection failed: $($_.Exception.Message)"

        .NOTES
        Write-Host is the primary output mechanism in this function; all Write-Host calls are intentional interactive console output. Also appends formatted messages to the log file when logging is initialized.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')] [String]$Type,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Message
    )

    # Screen output is filtered by the configured log level — only messages at or above the
    # threshold are displayed on the console.  All messages are always written to the log file
    # regardless of level, matching VcfEdgeAtScale behaviour and ensuring DEBUG context is never
    # silently discarded when troubleshooting a scan run that produced no visible errors.
    $levelOrder = @{ 'DEBUG' = 0; 'INFO' = 1; 'WARNING' = 2; 'ERROR' = 3 }
    $configuredLevel = if ($Script:VcfPatchScannerLogLevel) { $Script:VcfPatchScannerLogLevel } else { 'INFO' }
    $aboveScreenThreshold = $levelOrder[$Type] -ge $levelOrder[$configuredLevel]

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $prefix = "[$timestamp] [$Type]"
    $formattedMessage = "$prefix $Message"

    if ($aboveScreenThreshold) {
        switch ($Type) {
            'DEBUG'   { Write-Host $formattedMessage -ForegroundColor Gray }
            'INFO'    { Write-Host $formattedMessage -ForegroundColor White }
            'WARNING' { Write-Host $formattedMessage -ForegroundColor Yellow }
            'ERROR'   { Write-Host $formattedMessage -ForegroundColor Red }
        }
    }

    if ($Script:VcfPatchScannerLogFilePath) {
        try {
            $fileExists = Test-Path -LiteralPath $Script:VcfPatchScannerLogFilePath
            Add-Content -LiteralPath $Script:VcfPatchScannerLogFilePath -Value $formattedMessage -ErrorAction Stop

            # On first write, set secure permissions (Unix-like systems only).
            if (-not $fileExists -and $PSVersionTable.Platform -ne "Win32NT") {
                & chmod 600 $Script:VcfPatchScannerLogFilePath 2>$null
            }
        }
        catch {
            Write-Host "Warning: Could not write to log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
function Get-PatchScanLogDirectory {

    <#
        .SYNOPSIS
        Get the patch scan log directory path.

        .DESCRIPTION
        Returns the directory where patch scan logs are written. If logging has been initialized,
        returns the configured directory. Otherwise returns the default VcfPatchScanner/logs
        relative to the module installation directory.

        .EXAMPLE
        $logDir = Get-PatchScanLogDirectory
        Write-LogMessage -Type INFO -Message "Log output directory: $logDir"

        .OUTPUTS
        [String] Fully qualified path to the log directory.

        .NOTES
        This function is useful for locating logs for troubleshooting or for external tools
        (like Python servers) that need to write to the same log directory.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param ()

    if ($Script:VcfPatchScannerLogDirectory) {
        return $Script:VcfPatchScannerLogDirectory
    }

    # Default to VcfPatchScanner/logs relative to module root
    return Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath "logs"
}
function Initialize-PatchScanLogging {

    <#
        .SYNOPSIS
        Initialize logging configuration.

        .DESCRIPTION
        Sets up logging infrastructure for patch scan operations.

        When LogDirectory is omitted the log directory is resolved from
        $env:VcfPatchScannerBaseDirectory (set by Initialize-VcfPatchScanner). The function
        throws if that environment variable is not set and no explicit path is provided.

        Log entries are written to VcfPatchScannerEngine-YYYY-MM-DD.log in the resolved
        directory. All severity levels are always written to the file; only messages at or
        above the configured LogLevel threshold are echoed to the console.

        .PARAMETER LogDirectory
        Absolute or relative path to the log directory. When omitted, logs are written to
        the Logs/ sub-directory of $env:VcfPatchScannerBaseDirectory. Throws if neither is set.

        .PARAMETER LogLevel
        Minimum log level to display on the console: DEBUG, INFO, WARNING, ERROR. Default: INFO.
        All levels are always written to the log file regardless of this setting.

        .OUTPUTS
        [String] Absolute path to the initialized log directory.

        .EXAMPLE
        $logDir = Initialize-PatchScanLogging
        Resolves the log directory from $env:VcfPatchScannerBaseDirectory and returns its path.

        .EXAMPLE
        Initialize-PatchScanLogging -LogLevel DEBUG
        Initializes with DEBUG-level console output (all messages visible).

        .EXAMPLE
        Initialize-PatchScanLogging -LogDirectory "/custom/log/path"
        Writes logs to an explicit directory instead of the default base-directory path.

        .NOTES
        Mutates $Script:VcfPatchScannerLogFile — sets the active log file path for the session.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [String]$LogDirectory = "",
        [Parameter(Mandatory = $false)] [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')] [String]$LogLevel = 'INFO'
    )

    $Script:VcfPatchScannerLogLevel = $LogLevel

    # Determine log directory path — priority: explicit param > base dir env var.
    if ([String]::IsNullOrWhiteSpace($LogDirectory)) {
        if ([String]::IsNullOrWhiteSpace($env:VcfPatchScannerBaseDirectory)) {
            throw [System.InvalidOperationException]::new(
                "$($Script:VCF_PATCH_SCANNER_ENV_VAR) is not set. Run Initialize-VcfPatchScanner before using the scanner."
            )
        }
        $Script:VcfPatchScannerLogDirectory = Join-Path -Path $env:VcfPatchScannerBaseDirectory.Trim() -ChildPath $Script:SCAN_LOGS_DIR_NAME
    } else {
        # Validate against path traversal
        if ($LogDirectory -match '[/\\]\.\.[/\\]' -or $LogDirectory -match '[/\\]\.\.$') {
            throw [System.InvalidOperationException]::new("Log directory path contains invalid traversal sequences: $LogDirectory")
        }

        # Use provided path (resolve to absolute if relative)
        if ([System.IO.Path]::IsPathRooted($LogDirectory)) {
            $Script:VcfPatchScannerLogDirectory = $LogDirectory
        } else {
            # Resolve relative to the module root (VcfPatchScanner directory), not cwd
            $Script:VcfPatchScannerLogDirectory = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath $LogDirectory
        }
    }

    # Create log directory if it doesn't exist, then restrict it to the current user on non-Windows.
    if (-not (Test-Path -Path $Script:VcfPatchScannerLogDirectory -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path $Script:VcfPatchScannerLogDirectory -Force | Out-Null
        }
        catch {
            Write-Host "Warning: Could not create log directory: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    if ($PSVersionTable.Platform -ne "Win32NT") {
        & chmod 700 $Script:VcfPatchScannerLogDirectory 2>$null
    }

    $fileTimestamp = (Get-Date).ToString('yyyy-MM-dd')
    $Script:VcfPatchScannerLogFilePath = Join-Path -Path $Script:VcfPatchScannerLogDirectory -ChildPath "VcfPatchScannerEngine-$fileTimestamp.log"
    $isNewLogFile = -not (Test-Path -LiteralPath $Script:VcfPatchScannerLogFilePath)

    if ($PSVersionTable.Platform -ne "Win32NT") {
        try {
            # Pre-create the log file and set 0600 before the first append so it is
            # never world-readable even briefly at session start.
            if ($isNewLogFile) {
                [System.IO.File]::WriteAllText(
                    $Script:VcfPatchScannerLogFilePath,
                    "",
                    [System.Text.UTF8Encoding]::new($false)
                )
            }
            & chmod 600 $Script:VcfPatchScannerLogFilePath 2>$null
        }
        catch {
            Write-Host "Warning: Could not set log file permissions: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-LogMessage -Type DEBUG -Message "Logging initialized: $($Script:VcfPatchScannerLogFilePath)"

    # On a new log file, record environment context — mirrors VcfEdgeAtScale New-LogFile behaviour
    # so that support bundles always contain enough context to diagnose the environment.
    if ($isNewLogFile) {
        Write-LogMessage -Type DEBUG -Message "=== Session start ==="
        Write-LogMessage -Type DEBUG -Message "PowerShell version: $($PSVersionTable.PSVersion)"
        Write-LogMessage -Type DEBUG -Message "Platform: $($PSVersionTable.Platform) / OS: $($PSVersionTable.OS)"
        Write-LogMessage -Type DEBUG -Message "Module version: $($Script:VcfPatchScannerVersion)"
        Write-LogMessage -Type DEBUG -Message "Base directory: $($env:VcfPatchScannerBaseDirectory)"
        Write-LogMessage -Type DEBUG -Message "Log level threshold (screen): $LogLevel"
        # Identify VCF PowerCLI version from the installed module manifest.
        $debugVcfMod = Get-Module -ListAvailable -Name 'VCF.PowerCLI' -ErrorAction SilentlyContinue |
            Sort-Object -Property Version -Descending | Select-Object -First 1
        if ($null -ne $debugVcfMod) {
            Write-LogMessage -Type DEBUG -Message "VCF PowerCLI: $($debugVcfMod.Version)"
        } else {
            Write-LogMessage -Type DEBUG -Message "VCF PowerCLI: not installed (VCF.PowerCLI module not found)"
        }
    }

    return $Script:VcfPatchScannerLogDirectory
}
function Test-VcfPatchScannerDependencies {

    <#
        .SYNOPSIS
        Verify that all runtime dependencies required by VcfPatchScanner are available.

        .DESCRIPTION
        Checks the following prerequisites and collects all failures before returning:
          - PowerShell 7.4 or later.
          - VCF PowerCLI 9.0 or later — detected via Get-Module -ListAvailable on the
            VCF.PowerCLI module. No per-cmdlet probing; the module version is authoritative.
          - Python 3.13 or later — runs Start-VCFPatchScannerServer.py; must be in PATH as 'python3' or 'python'.
          - pwsh — launched by the Python server for each scan subprocess; must be in PATH.

        Returns $true when all checks pass. Writes WARNING messages and returns $false
        when one or more checks fail, listing every unmet dependency in a single pass.

        .EXAMPLE
        if (-not (Test-VcfPatchScannerDependencies)) {
            Write-LogMessage -Type ERROR -Message "One or more dependencies are missing. Install them before running a scan."
            return
        }

        .OUTPUTS
        [Bool] $true when all dependencies are satisfied; $false otherwise.

        .NOTES
        Write-Host is the primary output mechanism in this function; all Write-Host calls are
        intentional interactive console output. Use Write-LogMessage for diagnostic logging.
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param ()

    $failures = [System.Collections.Generic.List[String]]::new()
    $pathHint = if ($IsWindows) { ' ($env:PATH)' } else { '' }

    $minPsVersion = [Version]"7.4"
    $currentPsVersion = $PSVersionTable.PSVersion
    if ($currentPsVersion -lt $minPsVersion) {
        $failures.Add("PowerShell $minPsVersion or later is required. Current: $currentPsVersion.")
    }

    # Check VCF.PowerCLI by module version — a single registry scan, not per-cmdlet probing.
    $minPowerCliVersion = [Version]"9.0"
    $vcfMod = Get-Module -ListAvailable -Name 'VCF.PowerCLI' -ErrorAction SilentlyContinue |
        Sort-Object -Property Version -Descending | Select-Object -First 1
    if ($null -eq $vcfMod) {
        $failures.Add("VCF PowerCLI 9 or later is not installed. Download it from Broadcom and ensure it is on the PowerShell module path.")
    } elseif ($vcfMod.Version -lt $minPowerCliVersion) {
        $failures.Add("VCF PowerCLI $($vcfMod.Version) is installed but version 9.0 or later is required. Update to VCF PowerCLI 9.")
    }

    $pythonCmd = Get-Command -Name python3 -ErrorAction SilentlyContinue
    if ($null -eq $pythonCmd) {
        $pythonCmd = Get-Command -Name python -ErrorAction SilentlyContinue
    }
    $minPythonMinor = 13
    if ($null -eq $pythonCmd) {
        $failures.Add("Python 3.13 or later was not found. Install Python 3.13+ from python.org and ensure it is in your PATH$pathHint.")
    } else {
        try {
            $versionOutput = & $pythonCmd.Source --version 2>&1
            if ($versionOutput -match '^Python (\d+)\.(\d+)') {
                $pyMajor = [Int]$Matches[1]
                $pyMinor = [Int]$Matches[2]
                if ($pyMajor -lt 3) {
                    $failures.Add("Python $($Matches[0]) was found at '$($pythonCmd.Source)' but Python 3.13 or later is required. Install Python 3.13+ and ensure it precedes older versions in your PATH$pathHint.")
                } elseif ($pyMajor -eq 3 -and $pyMinor -lt $minPythonMinor) {
                    $failures.Add("Python $($Matches[0]) was found at '$($pythonCmd.Source)' but Python 3.$minPythonMinor or later is required. Upgrade to Python 3.$minPythonMinor+.")
                }
            } else {
                $failures.Add("Could not parse the Python version from '$($pythonCmd.Source)' (output: $versionOutput).")
            }
        } catch {
            $failures.Add("Could not determine the Python version at '$($pythonCmd.Source)': $($_.Exception.Message)")
        }
    }

    $pwshCmd = Get-Command -Name pwsh -ErrorAction SilentlyContinue
    if ($null -eq $pwshCmd) {
        $failures.Add("'pwsh' was not found. Install PowerShell 7 and ensure 'pwsh' is in your PATH$pathHint.")
    }

    if ($failures.Count -eq 0) {
        Write-Host "  Dependency check: all requirements satisfied." -ForegroundColor Green
        Write-Host "    PowerShell  : $currentPsVersion (required: $minPsVersion+)" -ForegroundColor Gray
        if ($null -ne $vcfMod) {
            Write-Host "    VCF PowerCLI: $($vcfMod.Version) (required: 9.0+)" -ForegroundColor Gray
        }
        if ($null -ne $pythonCmd) {
            $pyVer = if ($versionOutput -match 'Python (\S+)') { $Matches[1] } else { [String]$versionOutput }
            Write-Host "    Python 3.13+: $pyVer" -ForegroundColor Gray
        }
        return $true
    }

    Write-Host ""
    Write-Host "  Dependency check: $($failures.Count) unmet requirement(s):" -ForegroundColor Red
    foreach ($failure in $failures) {
        Write-Host "    - $failure" -ForegroundColor Yellow
    }
    Write-Host ""

    return $false
}
function Resolve-PatchScanBaseDirectory {

    <#
        .SYNOPSIS
        Resolve the VCF Patch Scanner base directory interactively.

        .DESCRIPTION
        Handles three cases in order:
          1. VcfPatchScannerBaseDirectory is set and the path does not exist — clears the stale
             value from the session (and from the Windows user environment registry if on Windows)
             and falls through to the prompt.
          2. VcfPatchScannerBaseDirectory is set and is a valid directory — offers the operator the
             choice to keep the existing directory or pick a different one.
          3. No env var set — prompts with the default path as the proposed value.

        Returns the operator-chosen (or defaulted) absolute path, or $null when the session is
        non-interactive or the operator provides no path.

        .PARAMETER DefaultBaseDirectory
        Default directory path shown to the operator at the prompt.

        .EXAMPLE
        $baseDir = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory "$HOME/VcfPatchScanner"
        if ($null -eq $baseDir) { return }

        .OUTPUTS
        [String] Absolute resolved base directory path, or $null on failure.

        .NOTES
        Write-Host is the primary output mechanism in this function; all Write-Host calls are
        intentional interactive console output. Use Write-LogMessage for diagnostic logging.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$DefaultBaseDirectory
    )

    $envRaw = $env:VcfPatchScannerBaseDirectory

    if (-not [String]::IsNullOrWhiteSpace($envRaw)) {
        $trimmed = $envRaw.Trim()

        if (-not (Test-Path -LiteralPath $trimmed)) {
            Write-Host ""
            Write-Host "  Note: `$env:VcfPatchScannerBaseDirectory pointed at a path that does not exist:" -ForegroundColor Yellow
            Write-Host "    $trimmed" -ForegroundColor White
            $env:VcfPatchScannerBaseDirectory = $null
            if ($IsWindows) {
                try {
                    [System.Environment]::SetEnvironmentVariable($Script:VCF_PATCH_SCANNER_ENV_VAR, $null, [System.EnvironmentVariableTarget]::User)
                    Write-Host "  Stale value cleared from session and user environment. Choose a folder below." -ForegroundColor Green
                } catch {
                    Write-Host "  Stale value cleared from session. User-level clear failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  Stale value cleared from session. Choose a folder below." -ForegroundColor Green
            }
        } elseif (Test-Path -LiteralPath $trimmed -PathType Container) {
            Write-Host "  Detected: `$env:VcfPatchScannerBaseDirectory is set to $trimmed" -ForegroundColor Green
            try {
                $resp = Read-Host "  Keep this directory or set a different one? [(K)eep / (C)hange, default: K]"
            } catch {
                Write-LogMessage -Type ERROR -Message "Initialize requires an interactive session. $($_.Exception.Message)"
                return $null
            }
            if ($resp.Trim() -inotmatch '^c(hange)?$') {
                # K, Enter, or anything other than C → keep the existing directory.
                return (Resolve-Path -LiteralPath $trimmed -ErrorAction Stop).Path
            }
            # C → fall through to the path prompt so the operator can choose a new directory.
        }
    }

    Write-Host "  Default base directory: $DefaultBaseDirectory" -ForegroundColor White
    Write-Host ""
    try {
        $input = Read-Host "Press Enter to use the default, or type a full directory path"
    } catch {
        Write-LogMessage -Type ERROR -Message "Initialize requires an interactive session. $($_.Exception.Message)"
        return $null
    }

    $chosen = if ([String]::IsNullOrWhiteSpace($input)) { $DefaultBaseDirectory } else { $input.Trim() }

    if (-not [System.IO.Path]::IsPathRooted($chosen)) {
        $chosen = Join-Path -Path $HOME -ChildPath $chosen
    }
    $chosen = [System.IO.Path]::GetFullPath($chosen)

    $homeFull = [System.IO.Path]::GetFullPath($HOME)
    $sep = [System.IO.Path]::DirectorySeparatorChar
    if (-not $chosen.StartsWith($homeFull + $sep, [StringComparison]::OrdinalIgnoreCase) -and
        $chosen -ine $homeFull) {
        Write-LogMessage -Type ERROR -Message "BaseDirectory must be within the home directory. Chosen: $chosen"
        return $null
    }

    return $chosen
}
function Invoke-PersistPatchScanBaseDirectory {

    <#
        .SYNOPSIS
        Persist VcfPatchScannerBaseDirectory and print the initialize summary.

        .DESCRIPTION
        Sets VcfPatchScannerBaseDirectory in the current session. On Windows, also writes it to the
        user environment registry via [System.Environment]::SetEnvironmentVariable so that new
        sessions and Explorer-launched processes inherit it. On all platforms, writes or updates
        the assignment in $PROFILE, removing any stale entry from a previous module name or path.

        Prints the initialize summary to the console after all persistence operations.

        .PARAMETER BaseDirectoryWasCreated
        True when the base directory was freshly created by this Initialize run.

        .PARAMETER ResolvedBaseDirectory
        Fully resolved absolute path that was initialized.

        .PARAMETER SubdirectoriesCreated
        Names of subdirectories created during this run (for the summary).

        .PARAMETER FilesCopied
        Display names of files copied during this run (for the summary).

        .EXAMPLE
        Invoke-PersistPatchScanBaseDirectory -BaseDirectoryWasCreated $true -ResolvedBaseDirectory "$HOME/VcfPatchScanner" -SubdirectoriesCreated $createdDirs -FilesCopied $copiedFiles

        .NOTES
        Write-Host is the primary output mechanism in this function; all Write-Host calls are
        intentional interactive console output. Use Write-LogMessage for diagnostic logging.
        Mutates $env:VcfPatchScannerBaseDirectory — sets the scanner root for the current session.
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)] [Bool]$BaseDirectoryWasCreated,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ResolvedBaseDirectory,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [System.Collections.Generic.List[String]]$SubdirectoriesCreated,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [System.Collections.Generic.List[String]]$FilesCopied
    )

    $env:VcfPatchScannerBaseDirectory = $ResolvedBaseDirectory
    $persistedEnvSucceeded = $false

    if ($IsWindows) {
        try {
            [System.Environment]::SetEnvironmentVariable($Script:VCF_PATCH_SCANNER_ENV_VAR, $ResolvedBaseDirectory, [System.EnvironmentVariableTarget]::User)
            $verifyValue = [System.Environment]::GetEnvironmentVariable($Script:VCF_PATCH_SCANNER_ENV_VAR, [System.EnvironmentVariableTarget]::User)
            $persistedEnvSucceeded = ($verifyValue -eq $ResolvedBaseDirectory)
            if (-not $persistedEnvSucceeded) {
                Write-LogMessage -Type WARNING -Message "VcfPatchScannerBaseDirectory registry write appeared to succeed but read-back returned '$verifyValue'."
            }
        } catch {
            Write-LogMessage -Type WARNING -Message "Could not persist VcfPatchScannerBaseDirectory to user environment: $($_.Exception.Message)"
        }
    }

    $profileLine   = "`$env:$($Script:VCF_PATCH_SCANNER_ENV_VAR) = `"$ResolvedBaseDirectory`""
    $profileAction = 'none'
    try {
        $profileDir = Split-Path -Path $PROFILE -Parent
        if (-not (Test-Path -LiteralPath $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }
        if (-not (Test-Path -LiteralPath $PROFILE)) {
            New-Item -ItemType File -Path $PROFILE -Force | Out-Null
        }
        $existingContent = Get-Content -LiteralPath $PROFILE -Raw -ErrorAction SilentlyContinue
        if ($null -eq $existingContent) { $existingContent = "" }

        if ($existingContent -match [Regex]::Escape($profileLine)) {
            # Exact line already present with the correct path — nothing to change.
            $profileAction = 'current'
        } else {
            # Remove any stale scan base directory assignment. The pattern catches the current
            # variable name with a different path AND any previous module name (e.g. the old
            # VcfPatchScanBaseDirectory line written before the module was renamed to VcfPatchScanner).
            $stalePattern   = '(?m)^\$env:VcfPatch[A-Za-z]*BaseDirectory\s*=\s*"[^"]*"\r?\n?'
            $cleanedContent = $existingContent -replace $stalePattern, ''
            $profileAction  = if ($existingContent -ne $cleanedContent) { 'updated' } else { 'written' }
            Set-Content -LiteralPath $PROFILE -Value ($cleanedContent.TrimEnd() + "`n$profileLine") -Encoding UTF8 -NoNewline
        }
    } catch {
        Write-LogMessage -Type WARNING -Message "Could not update `$PROFILE ($PROFILE): $($_.Exception.Message)"
    }

    Write-Host ""
    Write-Host "=== Initialize summary ===" -ForegroundColor Yellow
    Write-Host "  Scan root: $ResolvedBaseDirectory" -ForegroundColor White
    if ($BaseDirectoryWasCreated) {
        Write-Host "  Base directory: created." -ForegroundColor Green
    } else {
        Write-Host "  Base directory: already existed; existing files kept." -ForegroundColor Gray
    }
    if ($SubdirectoriesCreated.Count -gt 0) {
        Write-Host "  Subdirectories created: $($SubdirectoriesCreated -join ', ')." -ForegroundColor Green
    } else {
        Write-Host "  Subdirectories already present." -ForegroundColor Gray
    }
    foreach ($fileName in $FilesCopied) {
        Write-Host "    Copied: $fileName" -ForegroundColor White
    }
    Write-Host ""

    if ($IsWindows) {
        if ($persistedEnvSucceeded) {
            Write-Host "  $($Script:VCF_PATCH_SCANNER_ENV_VAR) -> $ResolvedBaseDirectory (session + user environment persisted)." -ForegroundColor Green
        } else {
            Write-Host "  $($Script:VCF_PATCH_SCANNER_ENV_VAR) -> $ResolvedBaseDirectory (current session only; user-level persist failed — see warning above)." -ForegroundColor Yellow
            Write-Host "  To set manually: [System.Environment]::SetEnvironmentVariable(`"$($Script:VCF_PATCH_SCANNER_ENV_VAR)`", `"<path>`", [System.EnvironmentVariableTarget]::User)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  $($Script:VCF_PATCH_SCANNER_ENV_VAR) -> $ResolvedBaseDirectory (set for this PowerShell session)." -ForegroundColor Green
        Write-Host ""
        Write-Host "  macOS / Linux note:" -ForegroundColor Yellow
        Write-Host "  The variable is set for this PowerShell session and persisted to your" -ForegroundColor Gray
        Write-Host "  PowerShell profile (`$PROFILE). If you also need to launch the Python server" -ForegroundColor Gray
        Write-Host "  directly from bash or zsh (without going through PowerShell first), add" -ForegroundColor Gray
        Write-Host "  the following line to your shell profile (~/.zshrc, ~/.bashrc, etc.):" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    export $($Script:VCF_PATCH_SCANNER_ENV_VAR)=`"$ResolvedBaseDirectory`"" -ForegroundColor White
        Write-Host ""
        Write-Host "  The Python server will exit with a clear error if this variable is missing." -ForegroundColor Gray
    }
    Write-Host ""

    switch ($profileAction) {
        'written' {
            Write-Host "  Profile line appended to: $PROFILE" -ForegroundColor Green
            Write-Host "  New terminal sessions will inherit this variable automatically." -ForegroundColor Gray
        }
        'updated' {
            Write-Host "  Profile updated: $PROFILE (replaced old entry)." -ForegroundColor Green
            Write-Host "  New terminal sessions will inherit the updated variable." -ForegroundColor Gray
        }
        'current' {
            Write-Host "  `$PROFILE already up to date — no change made." -ForegroundColor Gray
            Write-Host "  Profile: $PROFILE" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "  Next step: Start-VCFPatchScannerServer" -ForegroundColor Yellow
    Write-Host "  Opens the browser UI at http://localhost:8765" -ForegroundColor Gray
    Write-Host ""
}
function Copy-PatchScanToolFilesFromModule {

    <#
        .SYNOPSIS
        Copy module-owned tool files to a target Tools directory.

        .DESCRIPTION
        Copies every file listed in $Script:SCAN_TOOL_FILE_NAMES from the module's Tools/
        subdirectory to TargetDirectory, overwriting any existing copies. Returns the names
        of all files that were successfully copied.

        .PARAMETER TargetDirectory
        Absolute path of the destination Tools directory.

        .OUTPUTS
        [String[]] Names of files copied from the module.

        .NOTES
        Write-Host: progress feedback; this helper is called exclusively from Initialize-VcfPatchScanner
        which is a UI-builder function. Use Write-LogMessage for any diagnostic logging.

        .EXAMPLE
        Copy-PatchScanToolFilesFromModule -TargetDirectory "$HOME/VcfPatchScanner/Tools"
    #>

    [CmdletBinding()]
    [OutputType([String[]])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$TargetDirectory
    )

    $moduleToolsPath = [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath ".." -AdditionalChildPath "Tools"))
    $copiedFiles = [System.Collections.Generic.List[String]]::new()

    Write-Host "  Tools" -ForegroundColor Yellow
    foreach ($toolFile in $Script:SCAN_TOOL_FILE_NAMES) {
        $sourceFile = Join-Path -Path $moduleToolsPath -ChildPath $toolFile
        if (Test-Path -LiteralPath $sourceFile -PathType Leaf) {
            Copy-Item -LiteralPath $sourceFile -Destination (Join-Path -Path $TargetDirectory -ChildPath $toolFile) -Force
            Write-Host "    Copied: $toolFile" -ForegroundColor White
            $copiedFiles.Add($toolFile)
        } else {
            Write-Host "    WARNING: source file not found in module: $toolFile" -ForegroundColor Yellow
        }
    }
    return [String[]]$copiedFiles.ToArray()
}
function Copy-PatchScanAdvisoryDataFromModule {

    <#
        .SYNOPSIS
        Copy the advisory reference JSON from the module Data/ directory to a target Data directory.

        .DESCRIPTION
        Copies securityAdvisory.json from the module's Data/ subdirectory to TargetDirectory.
        When a file already exists at the destination, it is only replaced when the bundled copy
        carries a strictly newer updatedAt timestamp. This prevents a module update from
        downgrading an advisory database that was refreshed via the UI update flow.
        Returns $true on success or when the existing file is already current, $false when the
        source file is not found in the module.

        .PARAMETER TargetDirectory
        Absolute path of the destination Data directory.

        .OUTPUTS
        [Bool] $true if the file was copied; $false if the source was not found in the module.

        .NOTES
        Write-Host: progress feedback; this helper is called exclusively from Initialize-VcfPatchScanner
        which is a UI-builder function. Use Write-LogMessage for any diagnostic logging.

        .EXAMPLE
        Copy-PatchScanAdvisoryDataFromModule -TargetDirectory "$HOME/VcfPatchScanner/Data"
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$TargetDirectory
    )

    $moduleDataPath = [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath ".." -AdditionalChildPath "Data"))
    $sourceAdvisory = Join-Path -Path $moduleDataPath -ChildPath $Script:SCAN_ADVISORY_FILE_NAME
    $targetAdvisory = Join-Path -Path $TargetDirectory -ChildPath $Script:SCAN_ADVISORY_FILE_NAME

    Write-Host "  Data" -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $sourceAdvisory -PathType Leaf)) {
        Write-Host "    WARNING: $($Script:SCAN_ADVISORY_FILE_NAME) not found in module Data/." -ForegroundColor Yellow
        return $false
    }

    if (Test-Path -LiteralPath $targetAdvisory -PathType Leaf) {
        # Parse updatedAt from each file independently so a corrupt destination does not
        # accidentally block a legitimate overwrite (its $dstDate stays $null).
        $srcDate = $null
        $dstDate = $null
        try { $srcDate = [DateTime]::Parse((Get-Content -LiteralPath $sourceAdvisory -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).updatedAt) } catch { }
        try { $dstDate = [DateTime]::Parse((Get-Content -LiteralPath $targetAdvisory -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop).updatedAt) } catch { }

        # Keep the existing file when it is parseable and the bundled copy is not strictly newer.
        if ($null -ne $dstDate -and ($null -eq $srcDate -or $srcDate -le $dstDate)) {
            Write-Host "    Kept:  $($Script:SCAN_ADVISORY_FILE_NAME) (existing copy is current)" -ForegroundColor Gray
            return $true
        }

        if ($null -ne $dstDate) {
            Write-Host "    Updating: $($Script:SCAN_ADVISORY_FILE_NAME) (module copy is newer)" -ForegroundColor Cyan
        } else {
            Write-Host "    Replacing: $($Script:SCAN_ADVISORY_FILE_NAME) (existing file could not be parsed)" -ForegroundColor Yellow
        }
    }

    Copy-Item -LiteralPath $sourceAdvisory -Destination $targetAdvisory -Force

    # Delete the ETag sidecar so the server does not incorrectly report the newly-written
    # file as "up to date".  The sidecar was written by the Python server after a successful
    # upstream download; it contains the ETag for whatever file was current at that time.
    # After replacing the JSON content the sidecar is stale — the server must re-check
    # upstream on next startup or manual check to learn the real state.
    $targetEtag = "$targetAdvisory.etag"
    if (Test-Path -LiteralPath $targetEtag -PathType Leaf) {
        Remove-Item -LiteralPath $targetEtag -Force -ErrorAction SilentlyContinue
    }

    Write-Host "    Copied: $($Script:SCAN_ADVISORY_FILE_NAME)" -ForegroundColor White
    return $true
}
function Initialize-VcfPatchScanner {

    <#
        .SYNOPSIS
        Initialize the VCF Patch Scanner base directory structure and persist the environment variable.

        .DESCRIPTION
        Creates the base directory structure for the VCF Patch Scanner (default: ~/VcfPatchScanner).

        Subdirectories created:
          Config/    — scan-settings.json (written on first run only, preserving configured environments)
          Data/      — securityAdvisory.json reference data
          Findings/  — scan result JSON files
          Logs/      — diagnostic log files
          Tools/     — Python server, HTML UI, PowerShell wrapper (refreshed from module on every run)

        Files copied on each run:
          Tools/Start-VCFPatchScannerServer.py   (always overwritten — tools are safe to replace)
          Tools/vcp-patch-ui.html             (always overwritten)
          Tools/Invoke-VCFPatchScanner.ps1       (always overwritten)
          Data/securityAdvisory.json          (only when the bundled copy has a newer updatedAt
                                               than the existing file — never downgrades a database
                                               refreshed via the UI update flow)

        scan-settings.json is written to Config/ only if it does not already exist there,
        preserving any environments the operator has already configured.

        Sets VcfPatchScannerBaseDirectory for the current session. On Windows, also writes it to the
        user environment registry. On all platforms, appends the assignment to $PROFILE.

        When -RefreshTools or -RefreshData is specified the function runs in partial-refresh mode:
        it skips the dependency check, the interactive base-directory prompt, and environment
        persistence, using the existing VcfPatchScannerBaseDirectory. Run partial refresh after
        installing a new version of the module to pick up updated files without repeating setup.

        .PARAMETER RefreshData
        Partial refresh: updates Data/securityAdvisory.json from the module when the bundled copy
        is newer than the existing file (same timestamp-guard as a full init). Requires
        VcfPatchScannerBaseDirectory to already be set from a prior initialization. Skips the
        dependency check, directory prompt, and environment persistence.

        .PARAMETER RefreshTools
        Partial refresh: re-copies all Tools/ files (server, UI, PowerShell wrapper) from the module
        to the existing base directory. Requires VcfPatchScannerBaseDirectory to already be set.
        Skips the dependency check, directory prompt, and environment persistence.

        .OUTPUTS
        [String] Absolute path to the initialized base directory, or $null on failure.

        .NOTES
        Mutates $env:VcfPatchScannerBaseDirectory — sets the scanner root for the current session.
        Write-Host is the primary output mechanism in this function; all Write-Host calls are
        intentional interactive console output. Use Write-LogMessage for diagnostic logging.

        .EXAMPLE
        Initialize-VcfPatchScanner
        Creates ~/VcfPatchScanner with the standard directory layout.

        .EXAMPLE
        Initialize-VcfPatchScanner -RefreshTools
        Re-copies Start-VCFPatchScannerServer.py, vcp-patch-ui.html, and Invoke-VCFPatchScanner.ps1 from
        the module to the existing base directory. Run after updating the VcfPatchScanner module.

        .EXAMPLE
        Initialize-VcfPatchScanner -RefreshData
        Re-copies securityAdvisory.json from the module to Data/. Run after updating advisory data.

        .EXAMPLE
        Initialize-VcfPatchScanner -RefreshTools -RefreshData
        Re-copies both Tools/ and Data/ from the module in one call without running full interactive setup.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $false)] [Switch]$RefreshData,
        [Parameter(Mandatory = $false)] [Switch]$RefreshTools
    )

    $isPartialRefresh = $RefreshData.IsPresent -or $RefreshTools.IsPresent

    if ($RefreshData.IsPresent -and $RefreshTools.IsPresent) {
        $modeLabel = 'tools+data — refreshing Tools/ and Data/ from module'
    } elseif ($RefreshTools.IsPresent) {
        $modeLabel = 'tools — refreshing Tools/ from module'
    } elseif ($RefreshData.IsPresent) {
        $modeLabel = 'data — refreshing Data/securityAdvisory.json from module'
    } else {
        $modeLabel = 'full — Data, Logs, Tools, advisory JSON, and settings template.'
    }

    Write-Host ""
    Write-Host "VcfPatchScanner initialize" -ForegroundColor Yellow
    Write-Host "  Mode: $modeLabel" -ForegroundColor Gray
    Write-Host ""

    if ($isPartialRefresh) {
        $trimmedBase = ([String]$env:VcfPatchScannerBaseDirectory).Trim()
        if ([String]::IsNullOrWhiteSpace($trimmedBase) -or -not (Test-Path -LiteralPath $trimmedBase -PathType Container)) {
            Write-Host "  ERROR: VcfPatchScannerBaseDirectory is not set or does not exist on disk." -ForegroundColor Red
            Write-Host "  Run Initialize-VcfPatchScanner (without switches) to perform a full setup first." -ForegroundColor Yellow
            return $null
        }

        $filesCopied = [System.Collections.Generic.List[String]]::new()

        if ($RefreshTools.IsPresent) {
            $targetToolsPath = Join-Path -Path $trimmedBase -ChildPath $Script:SCAN_TOOLS_DIR_NAME
            if (-not (Test-Path -LiteralPath $targetToolsPath -PathType Container)) {
                New-Item -ItemType Directory -Path $targetToolsPath -Force | Out-Null
            }
            foreach ($f in (Copy-PatchScanToolFilesFromModule -TargetDirectory $targetToolsPath)) {
                $filesCopied.Add($f)
            }
        }

        if ($RefreshData.IsPresent) {
            if ($RefreshTools.IsPresent) { Write-Host "" }
            $targetDataPath = Join-Path -Path $trimmedBase -ChildPath $Script:SCAN_DATA_DIR_NAME
            if (-not (Test-Path -LiteralPath $targetDataPath -PathType Container)) {
                New-Item -ItemType Directory -Path $targetDataPath -Force | Out-Null
            }
            if (Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $targetDataPath) {
                $filesCopied.Add($Script:SCAN_ADVISORY_FILE_NAME)
            }
        }

        Write-Host ""
        Write-Host "  Base directory : $trimmedBase"
        Write-Host "  Updated        : $($filesCopied.Count) file(s)"
        Write-Host ""
        return $trimmedBase
    }

    Write-Host "  Checking dependencies..." -ForegroundColor Gray
    if (-not (Test-VcfPatchScannerDependencies)) {
        Write-Host "  Resolve the dependency issues listed above, then run Initialize-VcfPatchScanner again." -ForegroundColor Red
        return $null
    }
    Write-Host ""

    $defaultDir = Join-Path -Path $HOME -ChildPath $Script:VCF_PATCH_SCANNER_DEFAULT_DIR
    $targetDir = Resolve-PatchScanBaseDirectory -DefaultBaseDirectory $defaultDir
    if ($null -eq $targetDir) {
        return $null
    }

    $baseWasCreated = -not (Test-Path -LiteralPath $targetDir -PathType Container)
    if ($baseWasCreated) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    $subdirectoriesCreated = [System.Collections.Generic.List[String]]::new()
    $filesCopied           = [System.Collections.Generic.List[String]]::new()

    foreach ($subName in @($Script:SCAN_CONFIG_DIR_NAME, $Script:SCAN_DATA_DIR_NAME, $Script:SCAN_FINDINGS_DIR_NAME, $Script:SCAN_LOGS_DIR_NAME, $Script:SCAN_TOOLS_DIR_NAME)) {
        $subPath = Join-Path -Path $targetDir -ChildPath $subName
        if (-not (Test-Path -LiteralPath $subPath -PathType Container)) {
            New-Item -ItemType Directory -Path $subPath -Force | Out-Null
            $subdirectoriesCreated.Add($subName)
        }
    }

    $targetToolsPath = Join-Path -Path $targetDir -ChildPath $Script:SCAN_TOOLS_DIR_NAME
    foreach ($f in (Copy-PatchScanToolFilesFromModule -TargetDirectory $targetToolsPath)) {
        $filesCopied.Add($f)
    }

    Write-Host ""
    $targetDataPath = Join-Path -Path $targetDir -ChildPath $Script:SCAN_DATA_DIR_NAME
    if (Copy-PatchScanAdvisoryDataFromModule -TargetDirectory $targetDataPath) {
        $filesCopied.Add($Script:SCAN_ADVISORY_FILE_NAME)
    }

    $targetConfigPath = Join-Path -Path $targetDir -ChildPath $Script:SCAN_CONFIG_DIR_NAME
    $targetSettings = Join-Path -Path $targetConfigPath -ChildPath $Script:SCAN_SETTINGS_FILE_NAME
    Write-Host ""
    Write-Host "  Config" -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $targetSettings -PathType Leaf)) {
        $defaultSettings = [PSCustomObject]@{
            environments             = @()
            findingsOutputDirectory  = "Findings"
            logDirectory             = "Logs"
            logLevel                 = "INFO"
            securityAdvisoryFile     = $Script:SCAN_ADVISORY_FILE_NAME
            ignoreCertificate        = $true
            connectionTimeoutSeconds = 30
            lightMode                = $true
            defaultSort              = "severity"
            hiddenCols               = @(9, 10, 11, 12, 13)
        }
        $defaultSettings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $targetSettings -Encoding UTF8 -Force
        Write-Host "    Wrote: $($Script:SCAN_SETTINGS_FILE_NAME) (new, no environments)" -ForegroundColor Green
        $filesCopied.Add($Script:SCAN_SETTINGS_FILE_NAME)
    } else {
        Write-Host "    Kept:  $($Script:SCAN_SETTINGS_FILE_NAME) (already exists — environments preserved)" -ForegroundColor Gray
    }

    Write-Host ""

    Invoke-PersistPatchScanBaseDirectory `
        -BaseDirectoryWasCreated $baseWasCreated `
        -ResolvedBaseDirectory   $targetDir `
        -SubdirectoriesCreated   $subdirectoriesCreated `
        -FilesCopied             $filesCopied

    return $targetDir
}
function Invoke-VcfPatchScannerCollectLogs {

    <#
        .SYNOPSIS
        Bundle the patch scanner logs directory into a timestamped zip file.

        .DESCRIPTION
        Reads the log directory from the scan-settings.json in VcfPatchScannerBaseDirectory (or the module
        Tools directory), copies all .log files into a temp staging area, compresses them into a zip, and
        saves the zip under $HOME. Designed to be called interactively or triggered by the Python UI's
        Collect Logs button.

        .OUTPUTS
        [String] Absolute path to the created zip file, or $null on failure.

        .NOTES
        Write-Host is the primary output mechanism in this function; all Write-Host calls are
        intentional interactive console output. Use Write-LogMessage for diagnostic logging.

        .EXAMPLE
        Invoke-VcfPatchScannerCollectLogs
        Zips all scan logs and writes the archive path to the console.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param ()

    if ([String]::IsNullOrWhiteSpace($env:VcfPatchScannerBaseDirectory)) {
        $err = "$($Script:VCF_PATCH_SCANNER_ENV_VAR) is not set. Run Initialize-VcfPatchScanner before collecting logs."
        Write-LogMessage -Type ERROR -Message $err
        return $null
    }

    # Prefer the active log directory set by Initialize-PatchScanLogging; fall back to the
    # base dir Logs/ subdirectory when logging has not yet been initialized in this session.
    $logsDir = if (-not [String]::IsNullOrWhiteSpace($Script:VcfPatchScannerLogDirectory)) {
        $Script:VcfPatchScannerLogDirectory
    } else {
        Join-Path -Path $env:VcfPatchScannerBaseDirectory.Trim() -ChildPath $Script:SCAN_LOGS_DIR_NAME
    }

    if (-not (Test-Path -LiteralPath $logsDir -PathType Container)) {
        Write-LogMessage -Type ERROR -Message "Log directory not found: $logsDir"
        return $null
    }

    $logFiles = @(Get-ChildItem -LiteralPath $logsDir -Filter "*.log" -ErrorAction SilentlyContinue)
    if ($logFiles.Count -eq 0) {
        Write-LogMessage -Type WARNING -Message "No .log files found in $logsDir — nothing to archive."
        return $null
    }

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $zipFileName = "VcfPatchScanner-logs-$stamp.zip"
    $zipPath = Join-Path -Path $HOME -ChildPath $zipFileName
    $stagingParent = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "VcfPatchScanner-collect-$stamp"
    $stagingRoot = Join-Path -Path $stagingParent -ChildPath "archive"

    try {
        $null = New-Item -ItemType Directory -Path $stagingRoot -Force -ErrorAction Stop

        foreach ($logFile in $logFiles) {
            $destPath = Join-Path -Path $stagingRoot -ChildPath $logFile.Name
            Copy-Item -LiteralPath $logFile.FullName -Destination $destPath -Force -ErrorAction Stop
        }

        if (Test-Path -LiteralPath $zipPath -PathType Leaf) {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop
        }

        Compress-Archive -Path "$stagingRoot\*" -DestinationPath $zipPath -Force -ErrorAction Stop

        Write-Host ""
        Write-Host "CollectLogs complete. Archive saved to:"
        Write-Host "  $zipPath"
        Write-Host ""
    }
    catch {
        Write-LogMessage -Type ERROR -Message "CollectLogs failed: $($_.Exception.Message)"
        return $null
    }
    finally {
        if (Test-Path -LiteralPath $stagingParent) {
            Remove-Item -LiteralPath $stagingParent -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return $zipPath
}
function Remove-AnsiEscapeCodes {

    <#
        .SYNOPSIS
        Remove ANSI escape codes from a string.

        .DESCRIPTION
        Strips ANSI control sequences that could be used for injection attacks.
        Removes sequences like ESC[...m (color codes), ESC[...H (cursor movement), etc.
        Safe to use on user-supplied display names and environment descriptions.

        .PARAMETER InputString
        String potentially containing ANSI escape codes.

        .EXAMPLE
        $cleanName = Remove-AnsiEscapeCodes -InputString $rawDisplayName

        .OUTPUTS
        [String] Cleaned string with ANSI codes removed.

        .NOTES
        Pure string transformation. Does not mutate any module-scope variables.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [String]$InputString
    )

    if ([String]::IsNullOrEmpty($InputString)) {
        return $InputString
    }

    # Remove ANSI escape sequences: ESC[ followed by any sequence ending with a letter
    # Covers: color codes, cursor movement, text formatting, etc.
    return $InputString -replace '\x1b\[[0-9;]*[a-zA-Z]', ''
}

#endregion
