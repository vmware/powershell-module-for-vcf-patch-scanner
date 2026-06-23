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

        $modulePsd1 = Join-Path -Path $MyInvocation.MyCommand.Module.ModuleBase -ChildPath 'VcfPatchScanner.psd1'
        if (Test-Path -LiteralPath $modulePsd1 -PathType Leaf) {
            $env_vars['VCFPATCHSCANNER_MODULE_PSD1'] = $modulePsd1
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
        Stop a running VCF Patch Scan Server background process.

        .DESCRIPTION
        Reads the PID written by the background server to
        <VcfPatchScannerBaseDirectory>/Logs/vcfpatch-server.pid and stops the process.
        On macOS and Linux the process receives SIGTERM so the server exits cleanly.
        On Windows the process is terminated immediately.

        If the server is not running (no PID file or stale PID) the function returns
        $true without error — stopping an already-stopped server is idempotent.

        .EXAMPLE
        Stop-VCFPatchScannerServer

        .EXAMPLE
        if (-not (Stop-VCFPatchScannerServer)) {
            Write-LogMessage -Type WARNING -Message "Server stop command failed."
        }

        .OUTPUTS
        [Bool] $true when the server was stopped (or was already stopped); $false on error.

        .NOTES
        Only effective when the server was started with -Background (which writes the PID file).
        A foreground server (started without -Background) must be stopped with Ctrl+C.
    #>

    [CmdletBinding()]
    [OutputType([Bool])]
    Param ()

    $status = Get-VCFPatchScannerServerStatus
    if ($null -eq $status) {
        Write-LogMessage -Type ERROR -Message "Could not read server status. Ensure $($Script:VCF_PATCH_SCANNER_ENV_VAR) is set."
        return $false
    }

    if (-not $status.IsRunning) {
        Write-LogMessage -Type INFO -Message "Server is not running."
        return $true
    }

    Write-LogMessage -Type INFO -Message "Stopping VCF Patch Scan Server (PID $($status.ProcessId))..."
    Stop-Process -Id $status.ProcessId -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq (Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue)) {
            Write-LogMessage -Type INFO -Message "Server stopped."
            return $true
        }
        Start-Sleep -Milliseconds 200
    }

    Write-LogMessage -Type WARNING -Message "Server did not stop within 10 seconds — sending force-stop."
    Stop-Process -Id $status.ProcessId -Force -ErrorAction SilentlyContinue
    Write-LogMessage -Type INFO -Message "Server force-stopped."
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
        If no background server is currently running, the stop step is a no-op and the start
        proceeds normally. The 500 ms pause between stop and start ensures the port
        is fully released before the new process binds it.
    #>

    [CmdletBinding()]
    [OutputType([Int])]
    Param (
        [Parameter(Mandatory = $false)] [Switch]$NoBrowser,
        [Parameter(Mandatory = $false)] [ValidateRange(1, 65535)] [Int]$Port = 8765
    )

    $null = Stop-VCFPatchScannerServer
    Start-Sleep -Milliseconds 500
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
