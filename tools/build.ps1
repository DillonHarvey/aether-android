param(
    [ValidateSet('windows-debug', 'windows-release', 'windows-source-release')][string]$Preset = 'windows-debug',
    [ValidatePattern('^[a-zA-Z0-9_][a-zA-Z0-9_.+-]*$')][string[]]$Target = @(),
    [switch]$Configure
)
. (Join-Path $PSScriptRoot 'common.ps1')
Push-Location (Split-Path $PSScriptRoot -Parent)
$aetherOperationLease = $null
try {
    $aetherOperationLease = Enter-AetherBuildTestLease
    Initialize-AetherBuildEnvironment
    # Ninja already regenerates when CMake inputs change. Keep valid incremental
    # trees; explicitly reconfigure for changed toolchain/environment settings.
    if ($Configure -or -not (Test-Path -LiteralPath "out/build/$Preset/CMakeCache.txt")) {
        Invoke-AetherChecked cmake.exe @('--preset', $Preset)
    }
    $aetherBuildArguments = @('--build', '--preset', $Preset)
    if ($Target.Count) { $aetherBuildArguments += @('--target') + $Target }
    Invoke-AetherChecked cmake.exe $aetherBuildArguments
} finally {
    if ($null -ne $aetherOperationLease) {
        $aetherOperationLease.ReleaseMutex()
        $aetherOperationLease.Dispose()
    }
    Pop-Location
}
