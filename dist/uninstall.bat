@echo off
setlocal
title Sentient Endpoint Defense - Uninstaller
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %*
