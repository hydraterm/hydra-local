#requires -Version 5.1
<# Resize the existing approved artwork, without cropping, recoloring or removing its
   white background. Uses the Windows .NET System.Drawing encoder, no downloaded tools.
   Optional PreviewDirectory receives the exact icon frames for small-size visual QA.
   Only the specified output/preview paths are written; no system policy is changed. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [string]$PreviewDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Icon generation requires Windows System.Drawing.' }
if (-not [IO.Path]::IsPathRooted($Source) -or -not [IO.Path]::IsPathRooted($OutputPath) -or
    [IO.Path]::GetExtension($OutputPath) -ine '.ico') { throw 'Use absolute source and .ico output paths.' }
$expected = 'f083a299ea8eb42250c56338c5184a0eaaf59def36faafbf12758f07e9e0b31c'
if ((Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) {
    throw 'Hydra icon source differs from the reviewed assets/Hydra.png; review artwork and update its digest deliberately.'
}
if (-not (Test-Path -LiteralPath (Split-Path $OutputPath -Parent) -PathType Container)) { throw 'Icon output parent must already exist.' }
if ($PreviewDirectory) {
    if (-not [IO.Path]::IsPathRooted($PreviewDirectory) -or -not (Test-Path -LiteralPath $PreviewDirectory -PathType Container)) {
        throw 'PreviewDirectory must be an existing absolute directory.'
    }
}
Add-Type -AssemblyName System.Drawing
$image = [Drawing.Image]::FromFile($Source)
$sizes = @(16,20,24,32,40,48,64,128,256)
$frames = New-Object 'Collections.Generic.List[byte[]]'
try {
    if ($image.Width -ne 1254 -or $image.Height -ne 1254) { throw 'Unexpected original Hydra artwork dimensions.' }
    foreach ($size in $sizes) {
        $bitmap = New-Object Drawing.Bitmap($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        $attributes = New-Object Drawing.Imaging.ImageAttributes
        $stream = New-Object IO.MemoryStream
        try {
            $graphics.Clear([Drawing.Color]::White)
            $graphics.CompositingMode = [Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
            $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $attributes.SetWrapMode([Drawing.Drawing2D.WrapMode]::TileFlipXY)
            $rectangle = New-Object Drawing.Rectangle(0,0,$size,$size)
            $graphics.DrawImage($image,$rectangle,0,0,$image.Width,$image.Height,[Drawing.GraphicsUnit]::Pixel,$attributes)
            $bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
            $bytes = $stream.ToArray()
            $frames.Add($bytes)
            if ($PreviewDirectory) { [IO.File]::WriteAllBytes((Join-Path $PreviewDirectory ("Hydra-$size.png")), $bytes) }
        } finally { $stream.Dispose(); $attributes.Dispose(); $graphics.Dispose(); $bitmap.Dispose() }
    }
} finally { $image.Dispose() }
$output = New-Object IO.MemoryStream
$writer = New-Object IO.BinaryWriter($output)
try {
    $writer.Write([UInt16]0) # Reserved.
    $writer.Write([UInt16]1) # ICO, not cursor.
    $writer.Write([UInt16]$sizes.Count)
    [UInt32]$offset = 6 + 16 * $sizes.Count
    for ($i=0; $i -lt $sizes.Count; $i++) {
        [byte]$dimension = 0 # ICO stores 256 as zero.
        if ($sizes[$i] -lt 256) { $dimension = [byte]$sizes[$i] }
        $writer.Write($dimension); $writer.Write($dimension)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([UInt16]1); $writer.Write([UInt16]32)
        $writer.Write([UInt32]$frames[$i].Length); $writer.Write($offset)
        $offset += [UInt32]$frames[$i].Length
    }
    foreach ($frame in $frames) { $writer.Write([byte[]]$frame) }
    $writer.Flush()
    [IO.File]::WriteAllBytes($OutputPath,$output.ToArray())
} finally { $writer.Dispose(); $output.Dispose() }
