<#
.SYNOPSIS
    Automated installer script for Sentient Endpoint Defense on Windows.
.DESCRIPTION
    Installs Sentient to Program Files or LocalAppData, sets up Start Menu
    and Desktop shortcuts, and registers in Windows Add/Remove Programs.
#>

[CmdletBinding()]
param (
    [string]$InstallDir = "",
    [switch]$UserMode,
    [switch]$Silent,
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "       🛡️  SENTIENT ENDPOINT DEFENSE - WINDOWS INSTALLER       " -ForegroundColor White
Write-Host "           High-Performance Offline Desktop Security            " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin -and -not $UserMode) {
    Write-Host "[!] Administrator privileges recommended for complete system integration." -ForegroundColor Yellow
    Write-Host "[*] Relaunching installer with elevated privileges via UAC..." -ForegroundColor Cyan
    try {
        $ScriptPath = $MyInvocation.MyCommand.Definition
        Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
        exit 0
    } catch {
        Write-Host "[*] Elevation cancelled. Falling back to Per-User installation." -ForegroundColor Yellow
    }
}

if (-not $InstallDir) {
    if ($IsAdmin) {
        $InstallDir = Join-Path $env:ProgramFiles "Sentient"
    } else {
        $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Sentient"
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$SourceExe = Join-Path $ScriptDir "..\..\sentient.exe"
if (-not (Test-Path $SourceExe)) {
    $SourceExe = Join-Path $ScriptDir "sentient.exe"
}
$SourceSigs = Join-Path $ScriptDir "..\..\signatures.json"
if (-not (Test-Path $SourceSigs)) {
    $SourceSigs = Join-Path $ScriptDir "signatures.json"
}
$SourceLogo = Join-Path $ScriptDir "..\..\assets\logo.png"
if (-not (Test-Path $SourceLogo)) {
    $SourceLogo = Join-Path $ScriptDir "logo.png"
}
$SourceIcon = Join-Path $ScriptDir "..\..\assets\icon.ico"
if (-not (Test-Path $SourceIcon)) {
    $SourceIcon = Join-Path $ScriptDir "icon.ico"
}
$SourceUninstPs1 = Join-Path $ScriptDir "uninstall.ps1"
$SourceUninstBat = Join-Path $ScriptDir "uninstall.bat"

Write-Host "[*] Installation Directory: $InstallDir" -ForegroundColor Cyan
Write-Host "[*] Privilege Mode:         $([string]::Format('{0}', $(if ($IsAdmin) {'Elevated Administrator'} else {'Standard User'})))" -ForegroundColor Cyan
Write-Host ""

# 1. Create Directories
Write-Host "[1/5] Creating application directories..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$AssetsDir = Join-Path $InstallDir "assets"
New-Item -ItemType Directory -Force -Path $AssetsDir | Out-Null

# 2. Copy Files
Write-Host "[2/5] Deploying binaries, icons, and threat signatures..."
$TargetExe = Join-Path $InstallDir "sentient.exe"
Copy-Item $SourceExe -Destination $TargetExe -Force
if (Test-Path $SourceSigs) {
    Copy-Item $SourceSigs -Destination (Join-Path $InstallDir "signatures.json") -Force
}
if (Test-Path $SourceLogo) {
    Copy-Item $SourceLogo -Destination (Join-Path $AssetsDir "logo.png") -Force
}
$TargetIcon = Join-Path $AssetsDir "icon.ico"
if (Test-Path $SourceIcon) {
    Copy-Item $SourceIcon -Destination $TargetIcon -Force
    Copy-Item $SourceIcon -Destination (Join-Path $InstallDir "icon.ico") -Force
}
if (Test-Path $SourceUninstPs1) {
    Copy-Item $SourceUninstPs1 -Destination (Join-Path $InstallDir "uninstall.ps1") -Force
}
if (Test-Path $SourceUninstBat) {
    Copy-Item $SourceUninstBat -Destination (Join-Path $InstallDir "uninstall.bat") -Force
}

# 3. Create Shortcuts
Write-Host "[3/5] Creating Windows Desktop and Start Menu shortcuts..."
$WshShell = New-Object -ComObject WScript.Shell

$DesktopPath = [Environment]::GetFolderPath("Desktop")
$DesktopShortcut = Join-Path $DesktopPath "Sentient.lnk"
$Shortcut = $WshShell.CreateShortcut($DesktopShortcut)
$Shortcut.TargetPath = $TargetExe
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.Description = "Sentient High-Performance Offline Endpoint Security"
$Shortcut.IconLocation = "$TargetIcon,0"
$Shortcut.Save()

$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "Sentient Endpoint Defense"
New-Item -ItemType Directory -Force -Path $StartMenuDir | Out-Null
$StartShortcutPath = Join-Path $StartMenuDir "Sentient.lnk"
$StartShortcut = $WshShell.CreateShortcut($StartShortcutPath)
$StartShortcut.TargetPath = $TargetExe
$StartShortcut.WorkingDirectory = $InstallDir
$StartShortcut.Description = "Sentient High-Performance Offline Endpoint Security"
$StartShortcut.IconLocation = "$TargetIcon,0"
$StartShortcut.Save()

# 4. Create Uninstaller & Registry Entry
Write-Host "[4/5] Registering Windows uninstaller..."
$RegRoot = if ($IsAdmin) { "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient" } else { "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient" }
$UninstBat = Join-Path $InstallDir "uninstall.bat"

if (-not (Test-Path $UninstBat)) {
    $UninstContent = @"
@echo off
title Sentient Endpoint Defense - Uninstaller
echo Stopping running instances...
taskkill /F /IM sentient.exe /T >nul 2>&1
echo Removing Shortcuts...
del /F /Q "$DesktopShortcut" >nul 2>&1
rmdir /S /Q "$StartMenuDir" >nul 2>&1
echo Removing Registry Keys...
reg delete "$RegRoot" /f >nul 2>&1
echo Removing Files...
timeout /t 1 /nobreak >nul
del /F /Q "$TargetExe" >nul 2>&1
del /F /Q "$InstallDir\signatures.json" >nul 2>&1
del /F /Q "$InstallDir\icon.ico" >nul 2>&1
rmdir /S /Q "$AssetsDir" >nul 2>&1
echo Sentient has been successfully uninstalled.
pause
(goto) 2>nul & del "%~f0"
"@
    Set-Content -Path $UninstBat -Value $UninstContent -Encoding ASCII
}

New-Item -Path $RegRoot -Force | Out-Null
Set-ItemProperty -Path $RegRoot -Name "DisplayName" -Value "Sentient Endpoint Defense"
Set-ItemProperty -Path $RegRoot -Name "DisplayVersion" -Value "1.0.0"
Set-ItemProperty -Path $RegRoot -Name "Publisher" -Value "Sentient Security"
Set-ItemProperty -Path $RegRoot -Name "DisplayIcon" -Value "$TargetIcon,0"
Set-ItemProperty -Path $RegRoot -Name "InstallLocation" -Value $InstallDir
Set-ItemProperty -Path $RegRoot -Name "UninstallString" -Value "`"$UninstBat`""
Set-ItemProperty -Path $RegRoot -Name "EstimatedSize" -Value 25000
Set-ItemProperty -Path $RegRoot -Name "NoModify" -Value 1
Set-ItemProperty -Path $RegRoot -Name "NoRepair" -Value 1

# 5. Done
Write-Host "[5/5] Finalizing setup..."
Write-Host ""
Write-Host "✔ Sentient Endpoint Defense successfully installed!" -ForegroundColor Green
Write-Host "  Destination:  $InstallDir"
Write-Host "  Desktop:      $DesktopShortcut"
Write-Host "  Start Menu:   $StartShortcutPath"
Write-Host "  Uninstaller:  $UninstBat"
Write-Host ""

if (-not $NoLaunch -and -not $Silent) {
    Write-Host "[*] Launching Sentient now..." -ForegroundColor Cyan
    Start-Process -FilePath $TargetExe
}
