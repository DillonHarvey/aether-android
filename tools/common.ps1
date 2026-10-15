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
    param([string]$Command, [string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}
