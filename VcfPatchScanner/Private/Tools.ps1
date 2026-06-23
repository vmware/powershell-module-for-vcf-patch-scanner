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
        Starts the Python-based web server for the VCF Patch Scanner.
        The server listens on localhost and serves the web UI for patch scanning.
        Credentials are collected through the web UI and never passed on the command line.

        .PARAMETER Port
        TCP port for the web server. Default: 8765.
        Must be between 1 and 65535.

        .EXAMPLE
        Start-VCFPatchScannerServer

        .EXAMPLE
        Start-VCFPatchScannerServer -Port 9000

        .NOTES
        The server binds to 127.0.0.1 (localhost only), not 0.0.0.0.
        It is NOT accessible from remote networks or other machines.
        See README.md for security architecture details and required network access.
    #>

    [CmdletBinding()]
    [OutputType([Int])]
    Param (
        [Parameter(Mandatory = $false)] [ValidateRange(1, 65535)] [Int]$Port = 8765
    )

    $process = $null
    try {
        # Validate Python is available
        $pythonPath = Get-Command -Name python3 -ErrorAction SilentlyContinue
        if ($null -eq $pythonPath) {
            $pythonPath = Get-Command -Name python -ErrorAction SilentlyContinue
            if ($null -eq $pythonPath) {
                throw [System.InvalidOperationException]::new("Python 3 was not found. Install Python 3 and ensure it is in your PATH$(if ($IsWindows) { ' ($env:PATH)' }).")
            }
        }

        # Get Tools path
        $toolsPath = Get-VcfPatchScannerToolsPath
        $serverScript = Join-Path -Path $toolsPath -ChildPath "Start-VCFPatchScannerServer.py"

        if (-not (Test-Path -LiteralPath $serverScript -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("Python server not found: $serverScript")
        }

        # Detect a module-vs-deployed-tools version mismatch before starting. Any tool file
        # that differs from the module's copy is stale — refresh all of them so the server
        # always runs a consistent set regardless of which file changed.
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

        Write-LogMessage -Type INFO -Message "Starting VCF Patch Scan Server on port $Port..."
        Write-LogMessage -Type INFO -Message "Web UI will be available at http://localhost:$Port"
        Write-LogMessage -Type DEBUG -Message "Server script: $serverScript"

        $env_vars = @{}

        # Prepare process info
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $pythonPath.Source
        $processInfo.Arguments = "`"$serverScript`" --port $Port"
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $false
        $processInfo.WorkingDirectory = $toolsPath

        # Forward the base directory env var so the Python server resolves paths correctly.
        if (-not [String]::IsNullOrWhiteSpace($env:VcfPatchScannerBaseDirectory)) {
            $env_vars[$Script:VCF_PATCH_SCANNER_ENV_VAR] = $env:VcfPatchScannerBaseDirectory.Trim()
        }

        # Inject the module PSD1 path so Invoke-VCFPatchScanner.ps1 can load the module even when the
        # server script runs from a deployed Tools directory that does not contain the full module tree.
        # $MyInvocation.MyCommand.Module.ModuleBase is always the directory containing VcfPatchScanner.psd1,
        # regardless of whether the module was loaded from the repo or from a PSModulePath location.
        $modulePsd1 = Join-Path -Path $MyInvocation.MyCommand.Module.ModuleBase -ChildPath 'VcfPatchScanner.psd1'
        if (Test-Path -LiteralPath $modulePsd1 -PathType Leaf) {
            $env_vars['VCFPATCHSCANNER_MODULE_PSD1'] = $modulePsd1
        }

        foreach ($key in $env_vars.Keys) {
            $processInfo.Environment[$key] = $env_vars[$key]
        }

        # Start process
        $process = [System.Diagnostics.Process]::Start($processInfo)

        Write-LogMessage -Type INFO -Message "Server started (PID: $($process.Id))"
        Write-LogMessage -Type INFO -Message "Press Ctrl+C to stop the server"

        # Wait for process to exit
        $process.WaitForExit()

        $exitCode = $process.ExitCode
        Write-LogMessage -Type INFO -Message "Server stopped (exit code: $exitCode)"

        return $exitCode
    }
    catch {
        Write-LogMessage -Type ERROR -Message "Failed to start server: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }
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
