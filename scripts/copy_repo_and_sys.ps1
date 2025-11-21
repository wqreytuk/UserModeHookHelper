param(
    [Parameter(Mandatory=$true)]
    [string]$RemoteHost,
    [Parameter(Mandatory=$true)]
    [string]$Username,
    [Parameter(Mandatory=$true)]
    [string]$Password,
    [Parameter(Mandatory=$false)]
    [string]$RepoRoot = (Get-Location).Path,
    [Parameter(Mandatory=$false)]
    [string]$RemoteBase = "\\$RemoteHost\c$\users\x\Desktop\Documents",
    [Parameter(Mandatory=$false)]
    [string]$LocalSysPath = "$RepoRoot\x64\Debug\UserModeHookHelper.sys",
    [Parameter(Mandatory=$false)]
    [string]$LocalBootSysPath = "$RepoRoot\x64\Debug\UMHH.BootStart.sys",
    [Parameter(Mandatory=$false)]
    [string]$RemoteSysDestDir = "\\$RemoteHost\c$\users\x\Desktop\Documents\x64\Debug"
)

# Disconnect any previous connection (ignore errors)
try {
    net use "\\${RemoteHost}\c$" /delete *>$null
} catch {
    # ignore
}

# Map share
$mapOutput = net use "\\${RemoteHost}\c$" /user:$Username $Password 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error ("Failed to map share: " + ($mapOutput -join "`n"))
    exit 1
}

# Ensure destination exists
$null = New-Item -Path $RemoteBase -ItemType Directory -Force


# Copy git-tracked and unignored files
$filesRaw = git -C $RepoRoot ls-files --cached --others --exclude-standard -z 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error ("git ls-files failed: " + ($filesRaw -join "`n"))
    try { net use "\\${RemoteHost}\c$" /delete *>$null } catch {}
    exit 1
}
# Determine changed files using git (modified, staged, and untracked).
# This will catch changes even if they are not committed.
$changed = @()
try {
    $modifiedRaw = git -C $RepoRoot ls-files -m -z 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning ("git ls-files -m failed: {0}" -f ($modifiedRaw -join "`n")); $modifiedRaw = "" }
    $stagedRaw = git -C $RepoRoot diff --name-only --cached -z 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning ("git diff --cached failed: {0}" -f ($stagedRaw -join "`n")); $stagedRaw = "" }
    $untrackedRaw = git -C $RepoRoot ls-files --others --exclude-standard -z 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning ("git ls-files --others failed: {0}" -f ($untrackedRaw -join "`n")); $untrackedRaw = "" }

    if ($modifiedRaw) { $changed += ($modifiedRaw -split "`0" | Where-Object {$_ -ne ''}) }
    if ($stagedRaw) { $changed += ($stagedRaw -split "`0" | Where-Object {$_ -ne ''}) }
    if ($untrackedRaw) { $changed += ($untrackedRaw -split "`0" | Where-Object {$_ -ne ''}) }
} catch {
    Write-Warning ("Failed to compute git changed files: {0}" -f $_.Exception.Message)
}

$files = @()
if ($changed.Count -gt 0) {
    # Remove duplicates and normalize
    $files = $changed | Sort-Object -Unique
} else {
    # Fallback: if no changes detected, do nothing (skip copying tracked files)
    Write-Output "No changed or untracked files detected by git; nothing to copy."
}

foreach ($f in $files) {
    $src = Join-Path $RepoRoot $f
    if (!(Test-Path $src)) { Write-Warning ("Skipping missing file: {0}" -f $src); continue }
    $dst = Join-Path $RemoteBase $f
    $dir = Split-Path $dst -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
        Write-Output ("Copied: $f")
    } catch {
        Write-Warning ("Copy failed (ignored): {0} -> {1} : {2}" -f $src, $dst, $_.Exception.Message)
    }
}

# Ensure remote driver destination directory exists
try {
    New-Item -Path $RemoteSysDestDir -ItemType Directory -Force | Out-Null
} catch {
    Write-Warning ("Failed to create remote sys directory: {0} : {1}" -f $RemoteSysDestDir, $_.Exception.Message)
}

# Copy both driver .sys files if present: UMHH.BootStart.sys and UserModeHookHelper.sys
$sysFiles = @($LocalBootSysPath, $LocalSysPath)

foreach ($local in $sysFiles) {
    $leaf = Split-Path $local -Leaf
    if (Test-Path $local) {
        $dst = Join-Path $RemoteSysDestDir $leaf
        try {
            Copy-Item -LiteralPath $local -Destination $dst -Force -ErrorAction Stop
            Write-Output ("DriverSysCopied: {0} -> {1}" -f $local, $dst)
        } catch {
            Write-Warning ("Driver copy failed (ignored): {0} -> {1} : {2}" -f $local, $dst, $_.Exception.Message)
            Write-Output ("DriverSysCopyIgnored: {0} -> {1}" -f $local, $dst)
        }
    } else {
        Write-Output ("DriverSysNotFound: {0}" -f $local)
    }
}

# Unmap (ignore errors)
try {
    net use "\\${RemoteHost}\c$" /delete *>$null
} catch {
    # ignore
}
try {
    # Update remote marker to now (UTC) if we can write to the remote base
    $nowUtc = [DateTime]::UtcNow
    $markerContent = $nowUtc.ToString("o")
    try {
        $markerPathDir = Split-Path $markerFile -Parent
        if (!(Test-Path $markerPathDir)) { New-Item -ItemType Directory -Path $markerPathDir -Force | Out-Null }
        Set-Content -LiteralPath $markerFile -Value $markerContent -Force -ErrorAction Stop
        Write-Output ("Updated remote marker: $markerFile -> $markerContent")
    } catch {
        Write-Warning ("Failed to update remote marker file: {0}" -f $_.Exception.Message)
    }
} catch {
    # ignore marker update errors
}
Write-Output "Done"
