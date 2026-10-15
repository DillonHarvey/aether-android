param(
    [ValidateSet('windows-debug', 'windows-release', 'windows-source-release')][string]$Preset = 'windows-release',
    [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\Aether')
)
. (Join-Path $PSScriptRoot 'common.ps1')
Initialize-AetherBuildEnvironment
$aetherRoot = Split-Path $PSScriptRoot -Parent
$aetherInstallPath = [System.IO.Path]::GetFullPath($Prefix)
if (-not [System.IO.Path]::IsPathRooted($Prefix) -or
    $aetherInstallPath -eq [System.IO.Path]::GetPathRoot($aetherInstallPath)) {
    throw 'Use an absolute, non-root installation directory.'
}
Push-Location $aetherRoot
try {
    Invoke-AetherChecked (Join-Path $aetherRoot "out/build/$Preset/aether.exe") @('runtime', 'prepare', '--root', $aetherInstallPath, '--yes', '--json')
    Invoke-AetherChecked cmake.exe @('--install', "out/build/$Preset", '--prefix', $aetherInstallPath)
    Invoke-AetherChecked (Join-Path $aetherInstallPath 'aether_runtime_setup.exe') @('--verify', (Join-Path $aetherInstallPath 'runtime\aether_worker.exe'))
    Invoke-AetherChecked (Join-Path $aetherInstallPath 'aether_runtime_setup.exe') @('--verify', (Join-Path $aetherInstallPath 'runtime\aether_graphics_worker.exe'))
    Invoke-AetherChecked (Join-Path $aetherInstallPath 'aether_runtime_setup.exe') @('--verify', (Join-Path $aetherInstallPath 'runtime\aether_icon_worker.exe'))
    Invoke-AetherChecked (Join-Path $aetherInstallPath 'aether.exe') @('runtime', 'finalize', '--yes', '--json')
    Write-Host "Aether installed and runtime permissions verified: $aetherInstallPath"
} finally { Pop-Location }
