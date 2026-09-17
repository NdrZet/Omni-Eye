param (
    [string]$Configuration = "Release",
    [string]$OutputDir = "publish\OmniEye",
    [string]$ArchiveName = "publish\OmniEye-Release-win-x64.zip"
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " OmniEye Zero-Trust System - Release Packaging Pipeline   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$distService = Join-Path $root "$OutputDir\Service"
$distTray = Join-Path $root "$OutputDir\Tray"

# 1. Clean Output Directory
Write-Host "`n[1/5] Cleaning output directories..." -ForegroundColor Yellow
if (Test-Path "$root\$OutputDir") {
    Remove-Item -Path "$root\$OutputDir" -Recurse -Force
}
New-Item -ItemType Directory -Path $distService -Force | Out-Null
New-Item -ItemType Directory -Path $distTray -Force | Out-Null

# 2. Publish Windows Service (Elevated Backend)
Write-Host "`n[2/5] Publishing OmniEyeSvc (Windows Background Service)..." -ForegroundColor Yellow
& dotnet publish "$root\OmniEyeSvc\OmniEyeSvc.csproj" -c $Configuration -o $distService
if ($LASTEXITCODE -ne 0) { throw "Failed to publish OmniEyeSvc" }

# 3. Publish Windows 11 Tray Application (GUI Frontend + Zapret Engine)
Write-Host "`n[3/5] Publishing OmniEyeTray (WPF Fluent UI + Zapret Native Engine)..." -ForegroundColor Yellow
& dotnet publish "$root\OmniEyeTray\OmniEyeTray.csproj" -c $Configuration -o $distTray
if ($LASTEXITCODE -ne 0) { throw "Failed to publish OmniEyeTray" }

# 4. Generate Management Scripts
Write-Host "`n[4/5] Generating management and installer scripts..." -ForegroundColor Yellow

# InstallService.bat
$installBat = @"
@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required. Please run this script as Administrator.
    pause
    exit /b 1
)

set "SVC_EXE=%~dp0Service\OmniEyeSvc.exe"
if not exist "%SVC_EXE%" (
    echo [ERROR] Service executable not found: %SVC_EXE%
    pause
    exit /b 1
)

echo [1/3] Stopping existing OmniEyeSvc (if running)...
sc.exe stop OmniEyeSvc >nul 2>&1
sc.exe delete OmniEyeSvc >nul 2>&1
timeout /t 1 /nobreak >nul

echo [2/3] Registering OmniEyeSvc in Windows SCM...
sc.exe create OmniEyeSvc binPath= "%SVC_EXE%" start= auto DisplayName= "OmniEye Zero-Trust Service"
sc.exe description OmniEyeSvc "OmniEye Zero-Trust Endpoint Protection and Anti-Exfiltration Kernel Service."

echo [3/3] Starting OmniEyeSvc...
sc.exe start OmniEyeSvc

echo.
echo ========================================================
echo  OmniEyeSvc has been successfully installed and started!
echo ========================================================
pause
"@

# UninstallService.bat
$uninstallBat = @"
@echo off
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required. Please run this script as Administrator.
    pause
    exit /b 1
)

echo Stopping OmniEyeSvc...
sc.exe stop OmniEyeSvc
timeout /t 1 /nobreak >nul

echo Removing OmniEyeSvc...
sc.exe delete OmniEyeSvc

echo.
echo ========================================================
echo  OmniEyeSvc has been successfully uninstalled.
echo ========================================================
pause
"@

# StartOmniEye.bat
$startBat = @"
@echo off
start "" "%~dp0Tray\OmniEyeTray.exe"
"@

# Readme.txt
$readmeTxt = @"
OmniEye Zero-Trust Endpoint Protection & DPI Bypass System
=========================================================

PACKAGE STRUCTURE:
- \Service\             Windows Background Service (OmniEyeSvc.exe)
- \Tray\                Fluent Design Tray & UI (OmniEyeTray.exe)
  +- \Zapret\           Native binaries (winws.exe, WinDivert64.sys, presets)
- InstallService.bat    One-click service installer (Run as Administrator)
- UninstallService.bat  One-click service uninstaller (Run as Administrator)
- StartOmniEye.bat      Quick launcher for OmniEyeTray GUI

DEPLOYMENT STEPS:
1. Extract this archive into a permanent folder (e.g. C:\Program Files\OmniEye).
2. Right-click 'InstallService.bat' and select 'Run as administrator'.
3. Run 'StartOmniEye.bat' or place a shortcut to 'Tray\OmniEyeTray.exe' in your Startup folder (shell:startup).
"@

[System.IO.File]::WriteAllText("$root\$OutputDir\InstallService.bat", $installBat)
[System.IO.File]::WriteAllText("$root\$OutputDir\UninstallService.bat", $uninstallBat)
[System.IO.File]::WriteAllText("$root\$OutputDir\StartOmniEye.bat", $startBat)
[System.IO.File]::WriteAllText("$root\$OutputDir\README.txt", $readmeTxt)

# 5. Create ZIP Archive
Write-Host "`n[5/5] Creating release ZIP archive: $ArchiveName..." -ForegroundColor Yellow
$archiveFullPath = Join-Path $root $ArchiveName
if (Test-Path $archiveFullPath) {
    Remove-Item $archiveFullPath -Force
}
Compress-Archive -Path "$root\$OutputDir\*" -DestinationPath $archiveFullPath -Force

$zipSizeMb = [math]::Round(((Get-Item $archiveFullPath).Length / 1MB), 2)
Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " PACKAGING COMPLETE!                                      " -ForegroundColor Green
Write-Host " Folder:  $root\$OutputDir                                " -ForegroundColor Green
Write-Host " Archive: $archiveFullPath ($zipSizeMb MB)                 " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
