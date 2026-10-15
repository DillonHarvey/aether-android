param([ValidateSet('windows-debug', 'windows-release')][string]$Preset = 'windows-debug', [string]$Output = 'out/diagnostics.json')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$aetherRoot = Split-Path $PSScriptRoot -Parent
$aetherExe = Join-Path $aetherRoot "out/build/$Preset/aether.exe"
if (-not (Test-Path -LiteralPath $aetherExe)) { throw "Build $Preset first using tools/build.ps1." }
$aetherReport = & $aetherExe doctor --json
if ($LASTEXITCODE -ne 0) { throw 'doctor reported an unsupported or unverified host.' }
$null = $aetherReport | ConvertFrom-Json
$aetherDestination = [IO.Path]::GetFullPath((Join-Path $aetherRoot $Output))
$null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($aetherDestination))
[IO.File]::WriteAllText($aetherDestination, ($aetherReport + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "Wrote $aetherDestination (contains tool installation paths; review before sharing)."
