# package-win.ps1 — build the distributable Windows MSI (package.sh's twin).
# Release build (GUI subsystem, no console) into build-msi\, then WiX 3.x
# candle+light. Per-user MSI: installing needs no admin.
#
# Prereqs on PATH (or via -WixDir/-ToolchainBin):
#   cmake + ninja + gcc   (MSYS2 UCRT64: C:\...\msys64\ucrt64\bin)
#   candle.exe/light.exe  (WiX 3.x binaries)
param(
    [string]$Version = "0.1.2",
    [string]$WixDir = "",           # dir holding candle.exe/light.exe
    [string]$ToolchainBin = ""      # MSYS2 ucrt64\bin to prepend to PATH
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot     # repo root (this file is packaging\)

if ($ToolchainBin) { $env:PATH = "$ToolchainBin;$env:PATH" }
$candle = if ($WixDir) { Join-Path $WixDir 'candle.exe' } else { 'candle.exe' }
$light  = if ($WixDir) { Join-Path $WixDir 'light.exe' }  else { 'light.exe' }

$build = Join-Path $root 'build-msi'

cmake -S $root -B $build -G Ninja -DCMAKE_BUILD_TYPE=Release -DPEPENET_WIN_CONSOLE=OFF
if ($LASTEXITCODE) { exit 1 }
cmake --build $build
if ($LASTEXITCODE) { exit 1 }

& $candle -nologo -arch x64 "-dBuildDir=$build" "-dSrcDir=$root" "-dVersion=$Version" `
    (Join-Path $root 'packaging\pepenet.wxs') -o (Join-Path $build 'pepenet.wixobj')
if ($LASTEXITCODE) { exit 1 }

$msi = Join-Path $build "PepeNet-$Version.msi"
& $light -nologo -sice:ICE38 -sice:ICE43 -sice:ICE57 -sice:ICE61 -sice:ICE64 -sice:ICE91 `
    (Join-Path $build 'pepenet.wixobj') -o $msi
if ($LASTEXITCODE) { exit 1 }

Write-Output "MSI: $msi"
