<#
Creates a multi-size Windows .ico file (16,32,48,64) for the UserModeHookHelper (UMHH).
Design: Dark navy background, subtle diagonal gradient, white "UM" over lime accent "HH" below, hook glyph (stylized J-shape) in lime on the right.
Usage:
  1. Run in PowerShell:  ./CreateUMHHIcon.ps1
  2. Generated file: UMHH.ico placed alongside script.
  3. Ensure Resource.h and UMController.rc reference IDI_UMHH_ICON (already patched).
  4. Rebuild solution; set as application icon if desired (Project -> Properties -> General -> Application Icon).
#>
Add-Type -AssemblyName System.Drawing

function New-Bitmap {
    param($W, $H)
    return New-Object System.Drawing.Bitmap($W, $H, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
}

function New-UMHHIconLayer {
    param($bmp)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::FromArgb(255,18,24,38)) # dark navy
    # Gradient overlay
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush([System.Drawing.Rectangle]::FromLTRB(0,0,$bmp.Width,$bmp.Height),
        [System.Drawing.Color]::FromArgb(40,80,90,120), [System.Drawing.Color]::FromArgb(10,18,24,38), 45)
    $g.FillRectangle($brush, 0,0,$bmp.Width,$bmp.Height)

    # Fonts scale with size; explicitly cast to float for constructor resolution
    $umSizePx = [float]([Math]::Max(6, $bmp.Width * 0.42))
    $hhSizePx = [float]([Math]::Max(5, $bmp.Width * 0.30))
    $fontUM = [System.Drawing.Font]::new('Segoe UI Semibold', $umSizePx, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $fontHH = [System.Drawing.Font]::new('Segoe UI', $hhSizePx, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $white = [System.Drawing.Brushes]::White
    $limeColor = [System.Drawing.Color]::FromArgb(255,140,200,60)
    $limeBrush = New-Object System.Drawing.SolidBrush($limeColor)

    # Measure UM
    $umSize = $g.MeasureString('UM', $fontUM)
    $hhSize = $g.MeasureString('HH', $fontHH)
    $centerX = $bmp.Width / 2.0
    $topUMY = ($bmp.Height * 0.10)
    $umX = $centerX - ($umSize.Width / 2.0)
    $hhX = $centerX - ($hhSize.Width / 2.0)
    $hhY = $topUMY + $umSize.Height - ($bmp.Height * 0.08)

    $g.DrawString('UM', $fontUM, $white, $umX, $topUMY)
    $g.DrawString('HH', $fontHH, $limeBrush,  $hhX, $hhY)

    # Hook glyph: stylized J/curve using Bezier to avoid arc dimension issues
    $hookPen = New-Object System.Drawing.Pen($limeColor, [float]([Math]::Max(1, $bmp.Width * 0.07)))
    $startX = [Math]::Min($bmp.Width - 3, [Math]::Max(3, $centerX + ($umSize.Width * 0.30)))
    $startY = $topUMY + ($umSize.Height * 0.10)
    $endY = $hhY + ($hhSize.Height * 0.85)
    $ctrl1X = $startX + ($bmp.Width * 0.15)
    $ctrl1Y = $startY + ($bmp.Height * 0.10)
    $ctrl2X = $startX + ($bmp.Width * 0.15)
    $ctrl2Y = $startY + ($bmp.Height * 0.50)
    $g.DrawBezier($hookPen, $startX, $startY, $ctrl1X, $ctrl1Y, $ctrl2X, $ctrl2Y, $startX, $endY)

    # Optional subtle border
    $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(90,255,255,255), 1)
    $g.DrawRectangle($borderPen, 0,0,$bmp.Width-1,$bmp.Height-1)
    $fontUM.Dispose(); $fontHH.Dispose(); $limeBrush.Dispose(); $hookPen.Dispose(); $borderPen.Dispose(); $brush.Dispose();
    $g.Dispose()
}

function Write-Ico {
    param([string]$OutPath, [System.Drawing.Bitmap[]]$Bitmaps)
    $fs = [System.IO.File]::Open($OutPath, 'Create')
    $bw = New-Object System.IO.BinaryWriter($fs)

    # ICONDIR
    $bw.Write([UInt16]0) # reserved
    $bw.Write([UInt16]1) # type = icon
    $bw.Write([UInt16]$Bitmaps.Length) # count

    $imageData = New-Object System.Collections.Generic.List[byte[]]
    $offset = 6 + (16 * $Bitmaps.Length)
    foreach($bmp in $Bitmaps){
        # Convert to PNG (modern approach for 32-bit icons) for smaller size
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $bytes = $ms.ToArray()
        $imageData.Add($bytes)
        $width = if ($bmp.Width -eq 256) {0} else { [byte]$bmp.Width }
        $height = if ($bmp.Height -eq 256) {0} else { [byte]$bmp.Height }
        $bw.Write([byte]$width)   # bWidth
        $bw.Write([byte]$height)  # bHeight
        $bw.Write([byte]0)        # bColorCount
        $bw.Write([byte]0)        # bReserved
        $bw.Write([UInt16]1)      # wPlanes
        $bw.Write([UInt16]32)     # wBitCount
        $bw.Write([UInt32]$bytes.Length) # dwBytesInRes
        $bw.Write([UInt32]$offset)       # dwImageOffset
        $offset += $bytes.Length
    }
    # Write image blobs
    foreach($blob in $imageData){ $bw.Write($blob) }
    $bw.Flush(); $bw.Dispose(); $fs.Close()
}

$sizes = 16,32,48,64
$bitmaps = @()
foreach($s in $sizes){
    $b = New-Bitmap -W $s -H $s
    New-UMHHIconLayer -bmp $b
    $bitmaps += $b
}

# Add 256px variant for high-DPI (stored as width=0,height=0 per ICO spec)
$b256 = New-Bitmap -W 256 -H 256
New-UMHHIconLayer -bmp $b256
$bitmaps += $b256

$output = Join-Path (Split-Path -Parent $PSCommandPath) 'UMHH.ico'
Write-Ico -OutPath $output -Bitmaps $bitmaps
Write-Host "Generated icon: $output" -ForegroundColor Green

foreach($b in $bitmaps){ $b.Dispose() }
