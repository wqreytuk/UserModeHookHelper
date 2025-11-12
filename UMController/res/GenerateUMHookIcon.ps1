# Generates UMHook.ico from the UMHook.svg vector using ImageMagick if available.
# Multi-size: 16,24,32,48,64,128,256.
# Usage (PowerShell):
#   cd $PSScriptRoot
#   ./GenerateUMHookIcon.ps1
# Result: UMHook.ico placed in this folder.

$ErrorActionPreference = 'Stop'
$svg = Join-Path $PSScriptRoot 'UMHook.svg'
if (!(Test-Path $svg)) { Write-Error "UMHook.svg not found in $PSScriptRoot" }

# Check for 'magick' (ImageMagick)
$magick = (Get-Command magick -ErrorAction SilentlyContinue)
if (-not $magick) { Write-Error "ImageMagick 'magick' command not found. Install from https://imagemagick.org" }

# Temp output PNGs
$sizes = 16,24,32,48,64,128,256
$tmpDir = Join-Path $PSScriptRoot 'tmp_umhook'
if (!(Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir | Out-Null }

foreach ($s in $sizes) {
    $outPng = Join-Path $tmpDir "hook_$s.png"
    & magick convert $svg -resize ${s}x${s} -background none PNG32:$outPng
    Write-Host "Generated $outPng"
}

# Combine into ICO
$pngList = $sizes | ForEach-Object { Join-Path $tmpDir "hook_$_.png" }
$icoPath = Join-Path $PSScriptRoot 'UMHook.ico'
& magick convert $pngList $icoPath
Write-Host "Created $icoPath"

# Clean (optional)
# Remove-Item $tmpDir -Recurse -Force
Write-Host 'Done.'
