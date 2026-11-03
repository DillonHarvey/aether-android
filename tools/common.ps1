Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Both presets share executables, test fixtures and per-user Windows Shell state.
# Coordinate independent Codex/terminal sessions without a lock file or retrying
# any build/test mutation. This waits before the requested operation starts.
function Enter-AetherBuildTestLease {
    $aetherRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\').ToLowerInvariant()
    $aetherIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $aetherHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $aetherKey = $aetherRoot + '|' + $aetherIdentity.User.Value
        $aetherDigest = $aetherHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($aetherKey))
        $aetherName = 'Local\Aether.BuildTest.' + ([BitConverter]::ToString($aetherDigest)).Replace('-', '')
    } finally {
        $aetherHasher.Dispose()
        $aetherIdentity.Dispose()
    }
    $aetherLease = [Threading.Mutex]::new($false, $aetherName)
    try {
        if (-not $aetherLease.WaitOne(0)) {
            Write-Host 'Waiting for the current Aether workspace build/test operation to finish.'
            while (-not $aetherLease.WaitOne(1000)) { }
        }
        return $aetherLease
    } catch [Threading.AbandonedMutexException] {
        $aetherLease.ReleaseMutex()
        $aetherLease.Dispose()
        throw 'The previous Aether build/test coordinator exited unexpectedly. Inspect its child processes before explicitly retrying.'
    } catch {
        $aetherLease.Dispose()
        throw
    }
}

function Initialize-AetherBuildEnvironment {
    $aetherVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $aetherVswhere)) {
        throw 'Visual Studio Build Tools are not detected. Install the Desktop development with C++ workload. See docs/BUILD_WINDOWS.md.'
    }
    $aetherVsPath = & $aetherVswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $aetherVsPath) { throw 'No complete MSVC x64 toolchain found by vswhere.' }
    $aetherDevShell = Join-Path $aetherVsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    Import-Module $aetherDevShell
    Enter-VsDevShell -VsInstallPath $aetherVsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
    foreach ($name in @('cmake.exe', 'ctest.exe', 'ninja.exe', 'cl.exe')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Required build tool unavailable: $name" }
    }
}

function Invoke-AetherChecked {
    param([string]$Command, [string[]]$Arguments, [string]$LogPath = '', [string[]]$SourcePaths = @())
    # Resolve before relaxing native stderr handling; a missing command must not
    # inherit the exit code of an earlier application. Keep PowerShell's native
    # argv marshalling rather than building a second command line or shell.
    $aetherApplication = Get-Command -Name $Command -CommandType Application -ErrorAction Stop
    $aetherProjectFullPath = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
    $aetherLogFullPath = $null
    $aetherLogUtf8 = [Text.UTF8Encoding]::new($false)
    if ($PSBoundParameters.ContainsKey('LogPath')) {
        if ([string]::IsNullOrWhiteSpace($LogPath)) { throw 'Use a final build log path under out.' }
        $aetherLogCandidate = $LogPath
        if (-not [IO.Path]::IsPathRooted($aetherLogCandidate)) {
            $aetherLogCandidate = Join-Path (Get-Location).Path $aetherLogCandidate
        }
        $aetherLogFullPath = [IO.Path]::GetFullPath($aetherLogCandidate)
        $aetherOutputPrefix = [IO.Path]::GetFullPath((Join-Path $aetherProjectFullPath 'out')).TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
        if (-not $aetherLogFullPath.StartsWith($aetherOutputPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($aetherLogFullPath))) {
            throw 'Use a final build log in an existing directory under this project out directory.'
        }
        if ([IO.File]::Exists($aetherLogFullPath)) {
            # Appending UTF8 to a UTF16 Tee-Object log silently corrupts evidence.
            # Validate existing text with a strict, bounded streaming decoder.
            $aetherLogReader = [IO.StreamReader]::new($aetherLogFullPath, [Text.UTF8Encoding]::new($false, $true), $false)
            try {
                $aetherLogBuffer = [char[]]::new(4096)
                while (($aetherLogRead = $aetherLogReader.Read($aetherLogBuffer, 0, $aetherLogBuffer.Length)) -gt 0) {
                    for ($aetherLogIndex = 0; $aetherLogIndex -lt $aetherLogRead; ++$aetherLogIndex) {
                        if ($aetherLogBuffer[$aetherLogIndex] -eq [char]0) { throw 'The existing build log is not UTF8 text.' }
                    }
                }
            } finally { $aetherLogReader.Dispose() }
        }
    }
    $aetherAppendLog = {
        param([string]$Line)
        # Native warnings must be nonterminating, but failed evidence writes must
        # still stop the command path. This child scope does not change native EAP.
        $ErrorActionPreference = 'Stop'
        [IO.File]::AppendAllText($aetherLogFullPath, $Line + [Environment]::NewLine, $aetherLogUtf8)
    }

    # Optional bindings describe only explicitly supplied production inputs, not
    # a claim that every source dependency or any runtime behavior was checked.
    $aetherSourceBefore = @{}
    $aetherBoundInputs = [Collections.Generic.SortedDictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    $aetherCaptureBoundInput = {
        param([string]$RelativePath, [string]$FullPath)
        $aetherBoundItem = Get-Item -LiteralPath $FullPath -Force -ErrorAction Stop
        if ($aetherBoundItem.PSIsContainer) { throw "Aether build input is not a file: $RelativePath" }
        $aetherBoundHash = (Get-FileHash -LiteralPath $FullPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        [pscustomobject]@{ path = $RelativePath; bytes = [int64]$aetherBoundItem.Length; sha256 = $aetherBoundHash }
    }
    if ($null -ne $SourcePaths -and $SourcePaths.Count -gt 0) {
        if ($null -eq $aetherLogFullPath) { throw 'SourcePaths requires a final LogPath.' }
        $aetherSourcePrefix = $aetherProjectFullPath.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
        foreach ($aetherSourcePath in $SourcePaths) {
            if ([string]::IsNullOrWhiteSpace($aetherSourcePath)) { throw 'Aether build source path is empty.' }
            $aetherSourceCandidate = $aetherSourcePath
            if (-not [IO.Path]::IsPathRooted($aetherSourceCandidate)) { $aetherSourceCandidate = Join-Path $aetherProjectFullPath $aetherSourceCandidate }
            $aetherSourceFullPath = [IO.Path]::GetFullPath($aetherSourceCandidate)
            if (-not $aetherSourceFullPath.StartsWith($aetherSourcePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Aether build input must be inside the project: $aetherSourcePath" }
            if ($aetherSourceFullPath.Equals($aetherLogFullPath, [StringComparison]::OrdinalIgnoreCase)) { throw 'Aether build log cannot also be a bound source input.' }
            $aetherSourceRelative = $aetherSourceFullPath.Substring($aetherSourcePrefix.Length).Replace('\', '/')
            $aetherBoundInputs[$aetherSourceRelative] = $aetherSourceFullPath
        }
        foreach ($aetherSourcePair in $aetherBoundInputs.GetEnumerator()) {
            try { $aetherSourceRecord = & $aetherCaptureBoundInput $aetherSourcePair.Key $aetherSourcePair.Value }
            catch {
                & $aetherAppendLog (([ordered]@{ kind = 'source-input-binding'; phase = 'before'; path = $aetherSourcePair.Key; status = 'missing-or-unreadable' }) | ConvertTo-Json -Compress)
                throw
            }
            $aetherSourceBefore[$aetherSourcePair.Key] = $aetherSourceRecord
            & $aetherAppendLog (([ordered]@{ kind = 'source-input-binding'; phase = 'before'; path = $aetherSourceRecord.path; bytes = $aetherSourceRecord.bytes; sha256 = $aetherSourceRecord.sha256 }) | ConvertTo-Json -Compress)
        }
    }

    $aetherPreviousErrorAction = $ErrorActionPreference
    $aetherNativeExitCode = $null
    $aetherNativeFailure = $null
    $aetherSourceBindingFailure = $null
    # The native engine updates global LASTEXITCODE. Clear that actual slot, not
    # a local shadow, so a launch without an exit code cannot appear successful.
    $global:LASTEXITCODE = $null
    try {
        $ErrorActionPreference = 'Continue'
        if ($null -ne $aetherLogFullPath) {
            & $aetherApplication.Path @Arguments 2>&1 | ForEach-Object {
                $aetherNativeLine = if ($_ -is [Management.Automation.ErrorRecord]) { $_.Exception.Message }
                                    else { $_.ToString() }
                & $aetherAppendLog $aetherNativeLine
                Write-Output $aetherNativeLine
            }
        } else {
            # In particular, keep CTest JSON stdout separate from diagnostic stderr.
            & $aetherApplication.Path @Arguments
        }
        $aetherNativeExitCode = $global:LASTEXITCODE
    } catch {
        $aetherNativeFailure = $_
        $aetherNativeExitCode = $global:LASTEXITCODE
    } finally {
        $ErrorActionPreference = $aetherPreviousErrorAction
        $aetherChangedInputs = [Collections.Generic.List[string]]::new()
        foreach ($aetherSourcePair in $aetherBoundInputs.GetEnumerator()) {
            $aetherSourceReadFailed = $false
            try { $aetherSourceAfter = & $aetherCaptureBoundInput $aetherSourcePair.Key $aetherSourcePair.Value }
            catch { $aetherSourceReadFailed = $true }
            # Keep log writes outside the source-read catch: an I/O error is an
            # evidence failure, not a fabricated missing-source observation.
            if ($aetherSourceReadFailed) {
                & $aetherAppendLog (([ordered]@{ kind = 'source-input-binding'; phase = 'after'; path = $aetherSourcePair.Key; status = 'missing-or-unreadable'; matches = $false }) | ConvertTo-Json -Compress)
                $aetherChangedInputs.Add($aetherSourcePair.Key + ' (missing or unreadable)')
            } else {
                $aetherSourcePrevious = $aetherSourceBefore[$aetherSourcePair.Key]
                $aetherSourceMatches = $aetherSourceAfter.bytes -eq $aetherSourcePrevious.bytes -and $aetherSourceAfter.sha256 -ceq $aetherSourcePrevious.sha256
                & $aetherAppendLog (([ordered]@{ kind = 'source-input-binding'; phase = 'after'; path = $aetherSourceAfter.path; bytes = $aetherSourceAfter.bytes; sha256 = $aetherSourceAfter.sha256; matches = $aetherSourceMatches }) | ConvertTo-Json -Compress)
                if (-not $aetherSourceMatches) { $aetherChangedInputs.Add($aetherSourcePair.Key) }
            }
        }
        if ($aetherChangedInputs.Count -gt 0) { $aetherSourceBindingFailure = 'Aether source inputs changed or became unreadable during the command: ' + ($aetherChangedInputs -join ', ') }
    }
    if ($null -ne $aetherLogFullPath) {
        $aetherSourceInputsUnchanged = $null
        if ($aetherBoundInputs.Count -gt 0) { $aetherSourceInputsUnchanged = ($null -eq $aetherSourceBindingFailure) }
        & $aetherAppendLog (([ordered]@{ kind = 'native-command-result'; command = $aetherApplication.Path; exitCode = $aetherNativeExitCode; invocationFailed = ($null -ne $aetherNativeFailure); sourceInputCount = $aetherBoundInputs.Count; sourceInputsUnchanged = $aetherSourceInputsUnchanged }) | ConvertTo-Json -Compress)
    }
    $aetherCommandFailures = [Collections.Generic.List[string]]::new()
    if ($null -ne $aetherNativeFailure) { $aetherCommandFailures.Add("$Command invocation or capture failed: " + $aetherNativeFailure.Exception.Message) }
    if ($null -eq $aetherNativeExitCode) { $aetherCommandFailures.Add("$Command did not return a native exit code") }
    elseif ($aetherNativeExitCode -ne 0) { $aetherCommandFailures.Add("$Command failed with exit code $aetherNativeExitCode") }
    if ($null -ne $aetherSourceBindingFailure) { $aetherCommandFailures.Add($aetherSourceBindingFailure) }
    if ($aetherCommandFailures.Count -gt 0) { throw ($aetherCommandFailures -join [Environment]::NewLine) }
}
