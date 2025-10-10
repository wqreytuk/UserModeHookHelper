param(
    [string]$RemoteHost = '192.168.42.213',
    [string]$Username = 'Administrator',
    [string]$Password = 'qwe123...'
)
try { net use "\\$RemoteHost\c$" /delete } catch {}
$map = net use "\\$RemoteHost\c$" /user:$Username $Password 2>&1
if ($LASTEXITCODE -ne 0) { Write-Output "MapError: $map"; exit 1 }
$root = "\\$RemoteHost\c$\users\public\UserModeHookHelper"
$filesToCheck = @(
    'EtwTracer\\EtwTracer.vcxproj',
    'EtwTracer\\EtwTracer.vcxproj.filters',
    'EtwTracer\\EtwTracer.cpp',
    'UMController\\UMController.vcxproj',
    'UserModeHookHelper\\UserModeHookHelper.vcxproj'
)
foreach ($f in $filesToCheck) {
    $p = Join-Path $root $f
    if (Test-Path $p) { Write-Output "FOUND: $f -> $p" } else { Write-Output "MISSING: $f" }
}
net use "\\$RemoteHost\c$" /delete | Out-Null
