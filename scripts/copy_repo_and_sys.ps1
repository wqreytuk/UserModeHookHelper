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
    [string]$RemoteBase = "\\$RemoteHost\c$\users\public\UserModeHookHelper",
    [Parameter(Mandatory=$false)]
    [string]$LocalSysPath = "$RepoRoot\x64\Debug\UserModeHookHelper.sys",
    [Parameter(Mandatory=$false)]
    [string]$RemoteSysDest = "\\$RemoteHost\c$\users\public\UserModeHookHelper.sys"
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
$files = $filesRaw -split "`0" | Where-Object {$_ -ne ''}
foreach ($f in $files) {
    $src = Join-Path $RepoRoot $f
    $dst = Join-Path $RemoteBase $f
    $dir = Split-Path $dst -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
    } catch {
        Write-Warning ("Copy failed (ignored): {0} -> {1} : {2}" -f $src, $dst, $_.Exception.Message)
    }
}

# Copy driver .sys if present
if (Test-Path $LocalSysPath) {
    try {
        Copy-Item -LiteralPath $LocalSysPath -Destination $RemoteSysDest -Force -ErrorAction Stop
        Write-Output "DriverSysCopied: $LocalSysPath -> $RemoteSysDest"
    } catch {
        Write-Warning ("Driver copy failed (ignored): {0} -> {1} : {2}" -f $LocalSysPath, $RemoteSysDest, $_.Exception.Message)
        Write-Output "DriverSysCopyIgnored: $LocalSysPath -> $RemoteSysDest"
    }
} else {
    Write-Output "DriverSysNotFound: $LocalSysPath"
}

# Unmap (ignore errors)
try {
    net use "\\${RemoteHost}\c$" /delete *>$null
} catch {
    # ignore
}
Write-Output "Done"
