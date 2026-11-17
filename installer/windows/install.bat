@echo off
setlocal
cd /d "%~dp0"
echo Launching Sentient Windows Installer...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if %errorlevel% neq 0 (
    echo.
    echo Installer exited with code %errorlevel%.
    pause
)
