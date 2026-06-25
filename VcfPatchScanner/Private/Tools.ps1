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

#region Tools Management

function Get-VcfPatchScannerToolsPath {

    <#
        .SYNOPSIS
        Get the path to the active VcfPatchScanner Tools directory.

        .DESCRIPTION
        Returns the full path to the Tools directory that contains the Python server,
        HTML UI, and PowerShell wrapper. When VcfPatchScannerBaseDirectory is set and the
        Tools subdirectory exists there (populated by Initialize-VcfPatchScanner), that user
        copy is returned so that updates from Initialize always take effect. Falls back to
        the module-installed Tools directory when the env var is unset or the subdir is absent.

        .EXAMPLE
        $toolsPath = Get-VcfPatchScannerToolsPath
        $serverScript = Join-Path -Path $toolsPath -ChildPath "Start-VCFPatchScannerServer.py"

        .OUTPUTS
        [String] Full path to the active Tools directory.

        .NOTES
        Returns the Tools directory path inside the module installation. Used by Initialize-VcfPatchScanner to locate files for copying.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param ()

    $baseDirEnv = $env:VcfPatchScannerBaseDirectory
    if ([String]::IsNullOrWhiteSpace($baseDirEnv)) {
        $err = "$($Script:VCF_PATCH_SCANNER_ENV_VAR) is not set. Run Initialize-VcfPatchScanner before using the scanner."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    $trimmedBase = $baseDirEnv.Trim()
    if (-not (Test-Path -LiteralPath $trimmedBase -PathType Container)) {
        $err = "$($Script:VCF_PATCH_SCANNER_ENV_VAR) points to a path that does not exist: '$trimmedBase'. Re-run Initialize-VcfPatchScanner."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    $userToolsPath = Join-Path -Path $trimmedBase -ChildPath $Script:SCAN_TOOLS_DIR_NAME
    if (-not (Test-Path -LiteralPath $userToolsPath -PathType Container)) {
        $err = "Tools directory not found under '$trimmedBase'. Re-run Initialize-VcfPatchScanner to recreate it."
        Write-LogMessage -Type ERROR -Message $err
        throw [System.InvalidOperationException]::new($err)
    }

    return (Resolve-Path -LiteralPath $userToolsPath -ErrorAction Stop).Path
}
function Get-TcpListenerProcessId {

    <#
        .SYNOPSIS
        Return the PID of the process listening on a TCP port, or $null if none.

        .DESCRIPTION
        On Windows, queries Get-NetTCPConnection. On macOS and Linux, invokes lsof.
        Returns $null when no process is listening on the port or when the required
        platform tool is unavailable.

        .PARAMETER Port
        TCP port number to query.

        .EXAMPLE
        $ownerPid = Get-TcpListenerProcessId -Port 8765
        if ($null -ne $ownerPid) {
            Write-LogMessage -Type WARNING -Message "Port 8765 is held by PID $ownerPid."
        }

        .OUTPUTS
        [Int] PID of the listening process, or $null if none is found.
    #>

    [CmdletBinding()]
    [OutputType([Int])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateRange(1, 65535)] [Int]$Port
    )

    if ($IsWindows) {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -eq $conn) { return $null }
        return [Int]$conn.OwningProcess
    }

    if ($null -eq (Get-Command -Name lsof -ErrorAction SilentlyContinue)) { return $null }

    $iFlag     = "-iTCP:$Port"
    $pidLines  = @(& lsof -nP $iFlag -sTCP:LISTEN -t 2>/dev/null)
    [Int]$ownerPid = 0
    foreach ($line in $pidLines) {
        if ([Int]::TryParse($line.Trim(), [ref]$ownerPid) -and $ownerPid -gt 0) {
            return $ownerPid
        }
    }
    return $null
}

function Start-VCFPatchScannerServer {

    <#
        .SYNOPSIS
        Start the VCF Patch Scan web server.

        .DESCRIPTION
        Starts the Python-based web server for the VCF Patch Scanner. By default the
        server runs in the foreground and blocks until Ctrl+C is pressed. When -Background is
        specified, the server is launched as a detached background process (cross-platform:
        setsid on macOS/Linux, DETACHED_PROCESS on Windows). Use Stop-VCFPatchScannerServer
        to stop a background server and Get-VCFPatchScannerServerStatus to check whether it is running.

        Credentials are collected through the web UI and never passed on the command line.

        .PARAMETER Background
        Start the server as a background process. Returns immediately after confirming startup.
        Use Stop-VCFPatchScannerServer to stop a background server.

        .PARAMETER Force
        Kill any process currently holding the port before starting. Without this switch,
        Start-VCFPatchScannerServer exits with an error when the port is already in use.

        .PARAMETER NoBrowser
        Suppress the automatic browser launch on startup. Useful when starting as a background process
        from a login script or CI pipeline.

        .PARAMETER Port
        TCP port for the web server. Default: 8765. Must be between 1 and 65535.

        .EXAMPLE
        Start-VCFPatchScannerServer

        .EXAMPLE
        Start-VCFPatchScannerServer -Port 9000

        .EXAMPLE
        Start-VCFPatchScannerServer -Force

        .EXAMPLE
        Start-VCFPatchScannerServer -Background
        Get-VCFPatchScannerServerStatus
        Stop-VCFPatchScannerServer

        .EXAMPLE
        Start-VCFPatchScannerServer -Background -NoBrowser -Port 9000

        .NOTES
        The server binds to 127.0.0.1 (localhost only), not 0.0.0.0.
        It is NOT accessible from remote networks or other machines.
        See README.md for security architecture details and required network access.
        Background mode delegates to Manage-VCFPatchScannerServer.py, which writes a PID file
        to <VcfPatchScannerBaseDirectory>/Logs/vcfpatch-server.pid.
    #>

    [CmdletBinding()]
    [OutputType([Int])]
    Param (
        [Parameter(Mandatory = $false)] [Switch]$Background,
        [Parameter(Mandatory = $false)] [Switch]$Force,
        [Parameter(Mandatory = $false)] [Switch]$NoBrowser,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 65535)] [Int]$Port = 8765
    )

    $process = $null
    try {
        $pythonPath = Get-Command -Name python3 -ErrorAction SilentlyContinue
        if ($null -eq $pythonPath) {
            $pythonPath = Get-Command -Name python -ErrorAction SilentlyContinue
            if ($null -eq $pythonPath) {
                throw [System.InvalidOperationException]::new("Python 3 was not found. Install Python 3 and ensure it is in your PATH$(if ($IsWindows) { ' ($env:PATH)' }).")
            }
        }

        $toolsPath    = Get-VcfPatchScannerToolsPath
        $serverScript = Join-Path -Path $toolsPath -ChildPath "Start-VCFPatchScannerServer.py"

        if (-not (Test-Path -LiteralPath $serverScript -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("Python server not found: $serverScript")
        }

        $moduleToolsPath = Join-Path -Path $MyInvocation.MyCommand.Module.ModuleBase -ChildPath "Tools"
        $staleFiles = [System.Collections.Generic.List[String]]::new()
        foreach ($toolFile in $Script:SCAN_TOOL_FILE_NAMES) {
            $src = Join-Path -Path $moduleToolsPath -ChildPath $toolFile
            $dst = Join-Path -Path $toolsPath       -ChildPath $toolFile
            if ((Test-Path -LiteralPath $src -PathType Leaf) -and (Test-Path -LiteralPath $dst -PathType Leaf)) {
                $srcHash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
                $dstHash = (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash
                if ($srcHash -ne $dstHash) { $staleFiles.Add($toolFile) }
            }
        }
        if ($staleFiles.Count -gt 0) {
            Write-LogMessage -Type INFO -Message "Deployed tool files are out of sync with the current module ($($staleFiles -join ', ')). Updating before starting the server..."
            foreach ($toolFile in $Script:SCAN_TOOL_FILE_NAMES) {
                $src = Join-Path -Path $moduleToolsPath -ChildPath $toolFile
                $dst = Join-Path -Path $toolsPath       -ChildPath $toolFile
                if (Test-Path -LiteralPath $src -PathType Leaf) {
                    Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue
                    Write-LogMessage -Type DEBUG -Message "Refreshed tool file: $toolFile"
                }
            }
            Write-LogMessage -Type INFO -Message "Tool files refreshed. Server will use the current module version."
        }

        $modulePsd1 = Join-Path -Path $MyInvocation.MyCommand.Module.ModuleBase -ChildPath 'VcfPatchScanner.psd1'
        if (Test-Path -LiteralPath $modulePsd1 -PathType Leaf) {
            # Set in the current session so the background manage script inherits it via $env:.
            $env:VCFPATCHSCANNER_MODULE_PSD1 = $modulePsd1
        }

        $portOwner = Get-TcpListenerProcessId -Port $Port
        if ($null -ne $portOwner) {
            if (-not $Force) {
                Write-LogMessage -Type ERROR -Message "Port $Port is already in use by PID $portOwner."
                Write-LogMessage -Type INFO  -Message "Run: Stop-VCFPatchScannerServer -Port $Port"
                Write-LogMessage -Type INFO  -Message "Or:  Start-VCFPatchScannerServer -Force to kill it and restart."
                return
            }
            Write-LogMessage -Type WARNING -Message "Port $Port is held by PID $portOwner — stopping it (-Force)."
            $null = Stop-VCFPatchScannerServer -Port $Port
        }

        if ($Background) {
            $manageScript = Join-Path -Path $toolsPath -ChildPath "Manage-VCFPatchScannerServer.py"
            if (-not (Test-Path -LiteralPath $manageScript -PathType Leaf)) {
                throw [System.IO.FileNotFoundException]::new("Management script not found: $manageScript. Re-run Initialize-VcfPatchScanner.")
            }
            Write-LogMessage -Type INFO -Message "Starting VCF Patch Scan Server in background on port $Port..."
            $manageArgs = [System.Collections.Generic.List[String]]::new()
            $manageArgs.Add("--port=$Port")
            if ($NoBrowser) { $manageArgs.Add("--no-browser") }
            & $pythonPath.Source $manageScript "start" @manageArgs
            $backgroundExitCode = $LASTEXITCODE
            if ($backgroundExitCode -eq 0) {
                Write-LogMessage -Type INFO -Message "Background server started. Use Stop-VCFPatchScannerServer to stop it."
            }
            return $backgroundExitCode
        }

        Write-LogMessage -Type INFO -Message "Starting VCF Patch Scan Server on port $Port..."
        Write-LogMessage -Type INFO -Message "Web UI will be available at http://localhost:$Port"
        Write-LogMessage -Type DEBUG -Message "Server script: $serverScript"

        $env_vars = @{}

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $pythonPath.Source
        $processInfo.Arguments = "`"$serverScript`" --port $Port$(if ($NoBrowser) { ' --no-browser' })"
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $false
        $processInfo.WorkingDirectory = $toolsPath

        if (-not [String]::IsNullOrWhiteSpace($env:VcfPatchScannerBaseDirectory)) {
            $env_vars[$Script:VCF_PATCH_SCANNER_ENV_VAR] = $env:VcfPatchScannerBaseDirectory.Trim()
        }

        if (-not [String]::IsNullOrWhiteSpace($env:VCFPATCHSCANNER_MODULE_PSD1)) {
            $env_vars['VCFPATCHSCANNER_MODULE_PSD1'] = $env:VCFPATCHSCANNER_MODULE_PSD1
        }

        foreach ($key in $env_vars.Keys) {
            $processInfo.Environment[$key] = $env_vars[$key]
        }

        $process = [System.Diagnostics.Process]::Start($processInfo)

        Write-LogMessage -Type INFO -Message "Server started (PID: $($process.Id))"
        Write-LogMessage -Type INFO -Message "Press Ctrl+C to stop the server"

        $process.WaitForExit()

        $exitCode = $process.ExitCode
        Write-LogMessage -Type INFO -Message "Server stopped (exit code: $exitCode)"

        return $exitCode
    }
    catch {
        Write-LogMessage -Type ERROR -Message "Failed to start server: $($_.Exception.Message)"
        return -1
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}
function Stop-VCFPatchScannerServer {

    <#
        .SYNOPSIS
        Stop the VCF Patch Scan Server.

        .DESCRIPTION
        Stops the server whether it was started in background mode (tracked via PID file) or
        foreground mode (no PID file). After killing the tracked process, the function also
        kills any other process holding the configured port — this handles orphaned foreground
        servers and processes started outside of Start-VCFPatchScannerServer. Waits for the
        port to be fully released before returning so that Start-VCFPatchScannerServer can
        immediately bind the port again. Stopping an already-stopped server is idempotent.

        .PARAMETER Port
        TCP port the server is running on. Default: 8765. Used to detect and kill untracked
        processes (foreground servers) holding the port.

        .EXAMPLE
        Stop-VCFPatchScannerServer

        .EXAMPLE
        Stop-VCFPatchScannerServer -Port 9000

        .EXAMPLE
        if (-not (Stop-VCFPatchScannerServer)) {
            Write-LogMessage -Type WARNING -Message "Server stop command failed."
        }

        .OUTPUTS
        [Bool] $true when the server was stopped (or was already stopped); $false on error.
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter(Mandatory = $false)] [ValidateRange(1, 65535)] [Int]$Port = 8765
    )

    $status = Get-VCFPatchScannerServerStatus -Port $Port
    if ($null -eq $status) {
        Write-LogMessage -Type ERROR -Message "Could not read server status. Ensure $($Script:VCF_PATCH_SCANNER_ENV_VAR) is set."
        return $false
    }

    if ($status.IsRunning) {
        Write-LogMessage -Type INFO -Message "Stopping VCF Patch Scan Server (PID $($status.ProcessId))..."
        Stop-Process -Id $status.ProcessId -ErrorAction SilentlyContinue

        $processDead = $false
        $deadline    = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            if ($null -eq (Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue)) {
                $processDead = $true
                break
            }
            Start-Sleep -Milliseconds 200
        }

        if (-not $processDead) {
            Write-LogMessage -Type WARNING -Message "Server did not stop within 10 seconds — sending force-stop."
            Stop-Process -Id $status.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }

    $portOwner = Get-TcpListenerProcessId -Port $Port
    if ($null -ne $portOwner) {
        $msg = if ($status.IsRunning) { "Port $Port still held by PID $portOwner after stopping tracked process — killing it." } `
                                 else { "No tracked server found but port $Port is held by PID $portOwner (untracked process) — stopping it." }
        Write-LogMessage -Type WARNING -Message $msg
        Stop-Process -Id $portOwner -ErrorAction SilentlyContinue
    }

    if (-not $status.IsRunning -and $null -eq $portOwner) {
        Write-LogMessage -Type INFO -Message "Server is not running."
        return $true
    }

    $portDeadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $portDeadline) {
        if ($null -eq (Get-TcpListenerProcessId -Port $Port)) {
            Write-LogMessage -Type INFO -Message "Server stopped."
            return $true
        }
        Start-Sleep -Milliseconds 200
    }

    Write-LogMessage -Type WARNING -Message "Port $Port was not released within 5 seconds."
    return $true
}
function Get-VCFPatchScannerServerStatus {

    <#
        .SYNOPSIS
        Report whether the VCF Patch Scan Server background process is currently running.

        .DESCRIPTION
        Reads the PID file written by the background server to
        <VcfPatchScannerBaseDirectory>/Logs/vcfpatch-server.pid and verifies that
        the process is still alive. Stale PID files (process no longer exists) are
        removed automatically. Returns a PSCustomObject describing the server state.

        .PARAMETER Port
        Port the server was started on, used to construct the Url field in the returned
        object. Defaults to 8765 (the server default). Has no effect on whether the
        server is detected as running — detection is based solely on the PID file.

        .EXAMPLE
        $status = Get-VCFPatchScannerServerStatus
        if ($status.IsRunning) {
            Write-Host "Server is running at $($status.Url) (PID $($status.ProcessId))"
        }

        .EXAMPLE
        Get-VCFPatchScannerServerStatus -Port 9000

        .OUTPUTS
        [PSCustomObject] Object with IsRunning ([Bool]), ProcessId ([Int] or $null),
        and Url ([String] or $null). Returns $null when the base directory is not configured.

        .NOTES
        Only reflects background-mode servers (started with Start-VCFPatchScannerServer -Background).
        Foreground servers do not write a PID file and will not be detected.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $false)] [ValidateRange(1, 65535)] [Int]$Port = 8765
    )

    $basePath = $env:VcfPatchScannerBaseDirectory
    if ([String]::IsNullOrWhiteSpace($basePath)) {
        Write-LogMessage -Type ERROR -Message "$($Script:VCF_PATCH_SCANNER_ENV_VAR) is not set. Run Initialize-VcfPatchScanner first."
        return $null
    }

    $pidFile = Join-Path -Path (Join-Path -Path $basePath.Trim() -ChildPath "Logs") -ChildPath "vcfpatch-server.pid"

    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) {
        return [PSCustomObject]@{ IsRunning = $false; ProcessId = $null; Url = $null }
    }

    $pidText = Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue
    [Int]$serverPid = 0
    if ([String]::IsNullOrWhiteSpace($pidText) -or -not [Int]::TryParse($pidText.Trim(), [ref]$serverPid)) {
        Write-LogMessage -Type WARNING -Message "PID file contains invalid content — removing: $pidFile"
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{ IsRunning = $false; ProcessId = $null; Url = $null }
    }

    if ($null -eq (Get-Process -Id $serverPid -ErrorAction SilentlyContinue)) {
        Write-LogMessage -Type DEBUG -Message "PID $serverPid not found — removing stale PID file."
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{ IsRunning = $false; ProcessId = $null; Url = $null }
    }

    return [PSCustomObject]@{
        IsRunning = $true
        ProcessId = $serverPid
        Url       = "http://localhost:$Port"
    }
}
function Restart-VCFPatchScannerServer {

    <#
        .SYNOPSIS
        Restart the VCF Patch Scan Server background process.

        .DESCRIPTION
        Stops the running background server (if any) and starts a new background process on the specified
        port. Equivalent to calling Stop-VCFPatchScannerServer followed by
        Start-VCFPatchScannerServer -Background. Always starts in background mode — use
        Start-VCFPatchScannerServer without -Background for a foreground server.

        .PARAMETER NoBrowser
        Suppress the automatic browser launch on startup.

        .PARAMETER Port
        TCP port for the restarted server. Default: 8765. Must be between 1 and 65535.

        .EXAMPLE
        Restart-VCFPatchScannerServer

        .EXAMPLE
        Restart-VCFPatchScannerServer -Port 9000 -NoBrowser

        .OUTPUTS
        [Int] Exit code from the background server start (0 = success, non-zero = failure).

        .NOTES
        If no server is currently running, the stop step is a no-op and the start proceeds
        normally. Stop-VCFPatchScannerServer waits for the port to be fully released before
        returning, so the new process can bind immediately.
    #>

    [CmdletBinding()]
    [OutputType([Int])]
    Param (
        [Parameter(Mandatory = $false)] [Switch]$NoBrowser,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 65535)] [Int]$Port = 8765
    )

    $null = Stop-VCFPatchScannerServer -Port $Port
    return Start-VCFPatchScannerServer -Background -Port $Port -NoBrowser:$NoBrowser.IsPresent
}
function Resolve-HtmlAwareErrorMessage {

    <#
        .SYNOPSIS
        Translate a raw exception message into a human-readable error, detecting HTML responses.

        .DESCRIPTION
        PowerCLI Connect-Vcf* cmdlets and Invoke-RestMethod both throw a JSON-parse exception
        whose message starts with "Unexpected character encountered while parsing value: <" when
        the remote server returns an HTML page (wrong address, SSO redirect, reverse-proxy error).
        This function maps that pattern to a clear, actionable message and passes all other
        exception messages through unchanged.

        .PARAMETER ExceptionMessage
        Raw exception message string from $_.Exception.Message.

        .PARAMETER Server
        Hostname or FQDN of the server that was contacted, included in the returned message.

        .PARAMETER Context
        Short product/role label inserted into the message (e.g. "VCF Operations", "SDDC Manager").

        .EXAMPLE
        catch {
            $err = Resolve-HtmlAwareErrorMessage -ExceptionMessage $_.Exception.Message `
                -Server $Server -Context "VCF Operations"
            Write-LogMessage -Type ERROR -Message $err
            throw [System.InvalidOperationException]::new($err)
        }

        .OUTPUTS
        [String] Human-readable error message.

        .NOTES
        Pure string transformation. Does not mutate any module-scope variables. Strips HTML tags when the error message appears to be an HTML response body.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$ExceptionMessage,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Server,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$Context
    )

    if ($ExceptionMessage -match 'Unexpected character.*<') {
        return "$Context server at $Server returned an HTML page instead of an API response. Verify the address points to the correct product endpoint and is not a proxy, SDDC Manager, or SSO redirect URL."
    }
    # PowerCLI Write-Error output embeds the invocation timestamp and cmdlet name before the
    # actual message: "M/d/yyyy H:mm:ss    CmdletName        actual message". Strip that prefix
    # so only the actionable text reaches the log.
    $stripped = $ExceptionMessage -replace '^\d{1,2}/\d{1,2}/\d{4} \d+:\d{2}:\d{2}\s{2,}\S+\s{2,}', ''
    if ($stripped.Length -gt 0) { return $stripped }
    return $ExceptionMessage
}

#endregion
