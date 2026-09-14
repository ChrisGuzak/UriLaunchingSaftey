$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$exe = Join-Path $root "x64\Debug\LaunchResponseSample.exe"
if (!(Test-Path $exe)) { throw "Build the sample first: $exe" }

$assets = Join-Path $root "Assets"
New-Item -ItemType Directory -Force $assets | Out-Null
foreach ($name in "StoreLogo.png", "Square150x150Logo.png", "Square44x44Logo.png") {
    $path = Join-Path $assets $name
    if (!(Test-Path $path)) {
        Add-Type -AssemblyName System.Drawing
        $bitmap = New-Object Drawing.Bitmap 1, 1
        $bitmap.Save($path, [Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
    }
}

foreach ($role in "Requester", "Responder") {
    $layout = Join-Path $root "AppxLayout.$role"
    Remove-Item $layout -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $layout | Out-Null
    Copy-Item $exe (Join-Path $layout "LaunchResponseSample.exe")
    Copy-Item $assets (Join-Path $layout "Assets") -Recurse
    Copy-Item (Join-Path $root "AppxManifest.$role.xml") (Join-Path $layout "AppxManifest.xml")
    Write-Host "Created $layout"
}
