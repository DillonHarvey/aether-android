# Embedded product controller. Root, identity and quiet are supplied as quoted
# literals by original native code, never taken from APK metadata.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$held = [System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
$success = $false
try {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [IO.Path]::Combine($root, 'aether-setup.exe')
    $start.Arguments = 'uninstall --cleanup-parent ' + $PID + ' --json'
    if ($quiet) { $start.Arguments += ' --yes' }
    $start.WorkingDirectory = [Environment]::SystemDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $child = [Diagnostics.Process]::Start($start)
    $output = $child.StandardOutput.ReadToEnd()
    $errorText = $child.StandardError.ReadToEnd()
    $child.WaitForExit()
    $exitCode = $child.ExitCode
    $child.Dispose()
    if ($exitCode -eq 2) { exit 2 }
    if ($exitCode -ne 0) { throw ($output + $errorText) }
    if ($output.Length -gt 65536) { throw 'Uninstall result exceeds its bound.' }
    $plan = $output | ConvertFrom-Json
    if ($plan.schemaVersion -ne 1 -or $plan.state -ne 'cleanup' -or
        $plan.root -cne $root -or $plan.identity -cne $identity -or
        $plan.handles.Count -lt 4 -or $plan.handles.Count -gt 200) {
        throw 'Uninstall controller received a mismatched removal identity.'
    }
    foreach ($number in $plan.handles) {
        if ([long]$number -le 0) { throw 'Invalid uninstall handle.' }
        $held.Add([Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr][long]$number, $true))
    }
    # Order: installer image, catalogue, exclusive runtime lease, root, ancestors.
    foreach ($index in @(0, 1)) {
        $view = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($held[$index].DangerousGetHandle(), $false)
        $stream = [IO.FileStream]::new($view, [IO.FileAccess]::Read)
        try {
            $limit = if ($index -eq 0) { 268435456 } else { 67108864 }
            if ($stream.Length -le 0 -or $stream.Length -gt $limit) { throw 'Invalid cleanup file size.' }
            $stream.Position = 0
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $digest = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
            finally { $sha.Dispose() }
            if ($digest -cne $plan.hashes[$index]) { throw 'Owned uninstall bytes changed; material is preserved.' }
        } finally { $stream.Dispose() }
    }
    $expected = @('aether-setup.exe', 'runtime.registry', 'runtime.lease')
    $actual = @([IO.Directory]::EnumerateFileSystemEntries($root))
    if ($actual.Count -ne 3) { throw 'Unrelated runtime material is preserved.' }
    foreach ($path in $actual) {
        if ($expected -cnotcontains [IO.Path]::GetFileName($path)) { throw 'Unknown cleanup path.' }
    }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser,
        [Microsoft.Win32.RegistryView]::Registry64)
    $parent = $base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall', $true)
    try {
        $key = $parent.OpenSubKey('Aether.Runtime', $false)
        if ($null -ne $key) {
            try {
                $names = @($key.GetValueNames())
                if ($key.SubKeyCount -ne 0 -or $names.Count -ne $plan.registration.Count) {
                    throw 'Unrelated runtime Windows registration is preserved.'
                }
                foreach ($value in $plan.registration) {
                    if ($names -cnotcontains $value.name -or
                        [string]$key.GetValueKind($value.name) -cne $value.kind -or
                        [string]$key.GetValue($value.name) -cne [string]$value.value) {
                        throw 'Runtime Windows registration changed; it is preserved.'
                    }
                }
            } finally { $key.Dispose() }
        }
        # Native validation pinned ancestors/root and the empty exclusive lease.
        # Delete only these three verified leaves, never traverse a directory.
        $held[0].Dispose()
        [IO.File]::Delete([IO.Path]::Combine($root, 'aether-setup.exe'))
        $held[1].Dispose()
        [IO.File]::Delete([IO.Path]::Combine($root, 'runtime.registry'))
        $held[2].Dispose()
        [IO.File]::Delete([IO.Path]::Combine($root, 'runtime.lease'))
        $held[3].Dispose()
        [IO.Directory]::Delete($root, $false)
        if ([IO.Directory]::Exists($root)) { throw 'Runtime directory removal is incomplete.' }
        $parent.DeleteSubKey('Aether.Runtime', $false)
        $parent.Flush()
        $remaining = $parent.OpenSubKey('Aether.Runtime')
        if ($null -ne $remaining) { $remaining.Dispose(); throw 'Windows registration removal is incomplete.' }
    } finally {
        if ($null -ne $parent) { $parent.Dispose() }
        $base.Dispose()
    }
    $success = $true
    [Console]::WriteLine('{"schemaVersion":1,"state":"removed","packageStoresPreserved":true}')
} catch {
    $message = 'Aether removal is incomplete. ' + $_.Exception.Message
    [Console]::Error.WriteLine($message)
    if (-not $quiet) {
        $popup = New-Object -ComObject WScript.Shell
        [void]$popup.Popup($message, 0, 'Aether uninstall', 16)
    }
} finally {
    foreach ($handle in $held) { $handle.Dispose() }
}
if ($success) { exit 0 } else { exit 1 }
