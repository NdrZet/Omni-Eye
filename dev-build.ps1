param (
    [string]$OutputDir = "publish\OmniEye"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " OmniEye - Fast Dev (Debug) Build Pipeline                " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$distService = Join-Path $root "$OutputDir\Service"
$distTray = Join-Path $root "$OutputDir\Tray"

# 1. Publish Windows Service (Debug)
Write-Host "`n[1/2] Publishing OmniEyeSvc (Debug)..." -ForegroundColor Yellow
& dotnet publish "$root\OmniEyeSvc\OmniEyeSvc.csproj" -c Debug -o $distService
if ($LASTEXITCODE -ne 0) { throw "Failed to build OmniEyeSvc" }

# 2. Publish Tray App (Debug)
Write-Host "`n[2/2] Publishing OmniEyeTray (Debug)..." -ForegroundColor Yellow
& dotnet publish "$root\OmniEyeTray\OmniEyeTray.csproj" -c Debug -o $distTray
if ($LASTEXITCODE -ne 0) { throw "Failed to build OmniEyeTray" }

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " DEV BUILD READY!                                         " -ForegroundColor Green
Write-Host " Tray:    $distTray\OmniEyeTray.exe                       " -ForegroundColor Green
Write-Host " Service: $distService\OmniEyeSvc.exe                     " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
