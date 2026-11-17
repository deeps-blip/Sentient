<#
.SYNOPSIS
    Automated uninstaller script for Sentient Endpoint Defense on Windows.
.DESCRIPTION
    Stops running Sentient processes, removes Desktop and Start Menu shortcuts,
    unregisters from Windows Add/Remove Programs, and cleans up installation directories.
#>

[CmdletBinding()]
param (
    [string]$InstallDir = "",
    [switch]$PurgeData,
    [switch]$Silent
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "      🛡️  SENTIENT ENDPOINT DEFENSE - WINDOWS UNINSTALLER       " -ForegroundColor White
Write-Host "               Clean System Removal Routine                      " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[!] Checking for elevated privileges..." -ForegroundColor Yellow
    try {
        $ScriptPath = $MyInvocation.MyCommand.Definition
        Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
        exit 0
    } catch {
        Write-Host "[*] Elevation cancelled. Proceeding with current user privileges." -ForegroundColor Yellow
    }
}

# 1. Terminate running sentient processes
Write-Host "[1/5] Stopping any running instances of Sentient..." -ForegroundColor Cyan
Stop-Process -Name "sentient" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "sentient.exe" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 2. Locate installation directory
if (-not $InstallDir) {
    $ProgFilesDir = Join-Path $env:ProgramFiles "Sentient"
    $UserDir = Join-Path $env:LOCALAPPDATA "Programs\Sentient"
    if (Test-Path $ProgFilesDir) {
        $InstallDir = $ProgFilesDir
    } elseif (Test-Path $UserDir) {
        $InstallDir = $UserDir
    } else {
        $InstallDir = $ProgFilesDir
    }
}

# 3. Remove Desktop & Start Menu Shortcuts
Write-Host "[2/5] Removing Desktop and Start Menu shortcuts..." -ForegroundColor Cyan
$UserDesktop = Join-Path ([Environment]::GetFolderPath("Desktop")) "Sentient.lnk"
$PublicDesktop = Join-Path $env:PUBLIC "Desktop\Sentient.lnk"
Remove-Item -Path $UserDesktop -Force -ErrorAction SilentlyContinue
Remove-Item -Path $PublicDesktop -Force -ErrorAction SilentlyContinue

$UserStart = Join-Path ([Environment]::GetFolderPath("Programs")) "Sentient Endpoint Defense"
$ProgDataStart = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Sentient Endpoint Defense"
Remove-Item -Path $UserStart -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $ProgDataStart -Recurse -Force -ErrorAction SilentlyContinue

# 4. Remove Windows Registry Uninstall Keys
Write-Host "[3/5] Removing Windows Registry uninstallation entries..." -ForegroundColor Cyan
$RegHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient"
$RegHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient"
Remove-Item -Path $RegHKLM -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $RegHKCU -Recurse -Force -ErrorAction SilentlyContinue

# 5. Remove Application Binaries
Write-Host "[4/5] Removing application binaries and assets..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    Remove-Item -Path (Join-Path $InstallDir "sentient.exe") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $InstallDir "signatures.json") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $InstallDir "assets") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $InstallDir "icon.ico") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $InstallDir "uninstall.bat") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $InstallDir "uninstall.ps1") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 6. Optional: Purge local data directory
if ($PurgeData) {
    Write-Host "[5/5] Purging local quarantine and logs..." -ForegroundColor Cyan
    $LocalData = Join-Path $env:LOCALAPPDATA "Sentient"
    Remove-Item -Path $LocalData -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "[5/5] Preserving local quarantine vault and threat logs in LocalAppData." -ForegroundColor Gray
}

Write-Host ""
Write-Host "✔ Sentient Endpoint Defense has been successfully uninstalled from this system." -ForegroundColor Green
Write-Host ""
