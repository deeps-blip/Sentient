//! Sentient Endpoint Defense - Standalone Windows Installer Wizard
//! Self-contained native Windows executable embedding core binary, assets, and threat signatures.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EMBEDDED_PAYLOAD: &[u8] = include_bytes!("../../target/sentient.payload");
const EMBEDDED_SIGNATURES: &[u8] = include_bytes!("../../signatures.json");
const EMBEDDED_LOGO: &[u8] = include_bytes!("../../assets/logo.png");
const EMBEDDED_ICON: &[u8] = include_bytes!("../../assets/icon.ico");

fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use core::ffi::c_void;
        use core::mem::size_of;
        use core::ptr::null_mut;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn relaunch_as_admin() -> Result<(), String> {
    #[cfg(windows)]
    {
        use core::ptr::null_mut;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let exe_path = env::current_exe().map_err(|e| format!("Current exe failed: {e}"))?;
        let operation: Vec<u16> = "runas\0".encode_utf16().collect();
        let mut file: Vec<u16> = exe_path.as_os_str().encode_wide().collect();
        file.push(0);

        let args: Vec<String> = env::args().skip(1).collect();
        let args_str = args.join(" ");
        let mut params: Vec<u16> = args_str.encode_utf16().collect();
        params.push(0);

        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                operation.as_ptr(),
                file.as_ptr(),
                if args.is_empty() { null_mut() } else { params.as_ptr() },
                null_mut(),
                SW_SHOWNORMAL,
            )
        };

        if (result as isize) <= 32 {
            Err("UAC prompt was declined or cancelled.".to_string())
        } else {
            Ok(())
        }
    }
    #[cfg(not(windows))]
    {
        Err("Elevation only supported on Windows".to_string())
    }
}

fn create_shortcuts(target_exe: &Path, icon_path: &Path, is_admin: bool) -> Result<(), String> {
    let script = format!(
        r#"$ws = New-Object -ComObject WScript.Shell;
$exe = '{}';
$icon = '{},0';
$workdir = '{}';
$desc = 'Sentient High-Performance Offline Endpoint Security';

# 1. Desktop shortcut (handles OneDrive / redirected folders)
$desktop = $ws.SpecialFolders.Item('Desktop');
if (-not $desktop -or -not (Test-Path $desktop)) {{
    $desktop = [Environment]::GetFolderPath('Desktop');
}}
if ($desktop -and (Test-Path $desktop)) {{
    $s = $ws.CreateShortcut((Join-Path $desktop 'Sentient.lnk'));
    $s.TargetPath = $exe;
    $s.WorkingDirectory = $workdir;
    $s.Description = $desc;
    $s.IconLocation = $icon;
    $s.Save();
}}

# 2. Start Menu shortcut
$programs = $ws.SpecialFolders.Item('Programs');
if (-not $programs -or -not (Test-Path $programs)) {{
    $programs = [Environment]::GetFolderPath('Programs');
}}
if ($programs -and (Test-Path $programs)) {{
    $smDir = Join-Path $programs 'Sentient Endpoint Defense';
    if (-not (Test-Path $smDir)) {{ New-Item -ItemType Directory -Force -Path $smDir | Out-Null; }}
    $s2 = $ws.CreateShortcut((Join-Path $smDir 'Sentient.lnk'));
    $s2.TargetPath = $exe;
    $s2.WorkingDirectory = $workdir;
    $s2.Description = $desc;
    $s2.IconLocation = $icon;
    $s2.Save();
}}

# 3. Public Desktop for elevated installations
if ({}) {{
    $pubDesktop = $ws.SpecialFolders.Item('AllUsersDesktop');
    if ($pubDesktop -and (Test-Path $pubDesktop)) {{
        $s3 = $ws.CreateShortcut((Join-Path $pubDesktop 'Sentient.lnk'));
        $s3.TargetPath = $exe;
        $s3.WorkingDirectory = $workdir;
        $s3.Description = $desc;
        $s3.IconLocation = $icon;
        $s3.Save();
    }}
}}
"#,
        target_exe.display(),
        icon_path.display(),
        target_exe.parent().unwrap_or(Path::new("")).display(),
        if is_admin { "$true" } else { "$false" }
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .map_err(|e| format!("Failed to spawn powershell for shortcut creation: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn register_uninstall_entry(install_dir: &Path, is_admin: bool) {
    let reg_root = if is_admin { "HKLM" } else { "HKCU" };
    let key_path = format!(r"{reg_root}\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient");
    let icon_path = install_dir.join("assets").join("icon.ico");
    let uninst_bat = install_dir.join("uninstall.bat");

    let commands = [
        format!(r#"reg add "{key_path}" /v "DisplayName" /d "Sentient Endpoint Defense" /t REG_SZ /f"#),
        format!(r#"reg add "{key_path}" /v "DisplayVersion" /d "1.0.0" /t REG_SZ /f"#),
        format!(r#"reg add "{key_path}" /v "Publisher" /d "Sentient Security" /t REG_SZ /f"#),
        format!(r#"reg add "{key_path}" /v "DisplayIcon" /d "{},0" /t REG_SZ /f"#, icon_path.display()),
        format!(r#"reg add "{key_path}" /v "InstallLocation" /d "{}" /t REG_SZ /f"#, install_dir.display()),
        format!(r#"reg add "{key_path}" /v "UninstallString" /d "\"{}\"" /t REG_SZ /f"#, uninst_bat.display()),
        format!(r#"reg add "{key_path}" /v "EstimatedSize" /d 25000 /t REG_DWORD /f"#),
        format!(r#"reg add "{key_path}" /v "NoModify" /d 1 /t REG_DWORD /f"#),
        format!(r#"reg add "{key_path}" /v "NoRepair" /d 1 /t REG_DWORD /f"#),
    ];

    for cmd in commands {
        let _ = Command::new("cmd").args(["/C", &cmd]).output();
    }
}

fn create_uninstaller_script(install_dir: &Path, is_admin: bool) -> Result<(), String> {
    let reg_root = if is_admin { "HKLM" } else { "HKCU" };
    let key_path = format!(r"{reg_root}\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient");

    let ps1_script = format!(
        r#"# Sentient Endpoint Defense - PowerShell Uninstaller
$ErrorActionPreference = "SilentlyContinue"
Write-Host "Stopping running instances of Sentient..." -ForegroundColor Cyan
Stop-Process -Name "sentient" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "sentient.exe" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "Removing Desktop and Start Menu shortcuts..." -ForegroundColor Cyan
$ws = New-Object -ComObject WScript.Shell
$desktop = $ws.SpecialFolders.Item('Desktop')
if ($desktop) {{ Remove-Item (Join-Path $desktop 'Sentient.lnk') -Force -ErrorAction SilentlyContinue }}
$pubDesktop = $ws.SpecialFolders.Item('AllUsersDesktop')
if ($pubDesktop) {{ Remove-Item (Join-Path $pubDesktop 'Sentient.lnk') -Force -ErrorAction SilentlyContinue }}
Remove-Item "$env:USERPROFILE\Desktop\Sentient.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:PUBLIC\Desktop\Sentient.lnk" -Force -ErrorAction SilentlyContinue

$programs = $ws.SpecialFolders.Item('Programs')
if ($programs) {{ Remove-Item (Join-Path $programs 'Sentient Endpoint Defense') -Recurse -Force -ErrorAction SilentlyContinue }}
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Sentient Endpoint Defense" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentient Endpoint Defense" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing Registry uninstallation keys..." -ForegroundColor Cyan
Remove-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentient" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing binaries and assets..." -ForegroundColor Cyan
Remove-Item "{dir}\sentient.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "{dir}\signatures.json" -Force -ErrorAction SilentlyContinue
Remove-Item "{dir}\icon.ico" -Force -ErrorAction SilentlyContinue
Remove-Item "{dir}\assets" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "{dir}\uninstall.bat" -Force -ErrorAction SilentlyContinue
Remove-Item "{dir}\uninstall.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "{dir}" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "✔ Sentient has been successfully uninstalled." -ForegroundColor Green
"#,
        dir = install_dir.display().to_string().replace('\\', "\\\\")
    );
    let _ = fs::write(install_dir.join("uninstall.ps1"), ps1_script);

    let bat_script = format!(
        r#"@echo off
title Sentient Endpoint Defense - Uninstaller
echo ======================================================
echo    Sentient Endpoint Defense - Uninstallation
echo ======================================================
echo.
echo Stopping running instances of Sentient...
taskkill /F /IM sentient.exe /T >nul 2>&1

echo Removing Shortcuts...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $d = $ws.SpecialFolders.Item('Desktop'); if ($d) {{ Remove-Item (Join-Path $d 'Sentient.lnk') -Force -ErrorAction SilentlyContinue }}; $pd = $ws.SpecialFolders.Item('AllUsersDesktop'); if ($pd) {{ Remove-Item (Join-Path $pd 'Sentient.lnk') -Force -ErrorAction SilentlyContinue }}; $p = $ws.SpecialFolders.Item('Programs'); if ($p) {{ Remove-Item (Join-Path $p 'Sentient Endpoint Defense') -Recurse -Force -ErrorAction SilentlyContinue }}" >nul 2>&1
del /F /Q "%USERPROFILE%\Desktop\Sentient.lnk" >nul 2>&1
del /F /Q "%PUBLIC%\Desktop\Sentient.lnk" >nul 2>&1
rmdir /S /Q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Sentient Endpoint Defense" >nul 2>&1
rmdir /S /Q "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Sentient Endpoint Defense" >nul 2>&1

echo Removing Registry Uninstallation Keys...
reg delete "{key_path}" /f >nul 2>&1

echo Cleaning up installed binaries, icons, and signatures...
timeout /t 1 /nobreak >nul
del /F /Q "{dir}\sentient.exe" >nul 2>&1
del /F /Q "{dir}\signatures.json" >nul 2>&1
del /F /Q "{dir}\icon.ico" >nul 2>&1
del /F /Q "{dir}\uninstall.ps1" >nul 2>&1
rmdir /S /Q "{dir}\assets" >nul 2>&1

echo.
echo Sentient has been successfully uninstalled.
echo.
pause
(goto) 2>nul & del "%~f0"
"#,
        dir = install_dir.display()
    );

    fs::write(install_dir.join("uninstall.bat"), bat_script)
        .map_err(|e| format!("Failed to create uninstall script: {e}"))
}

fn print_banner() {
    println!("\x1b[36m=================================================================\x1b[0m");
    println!("\x1b[1;36m       🛡️  SENTIENT ENDPOINT DEFENSE - WINDOWS INSTALLER       \x1b[0m");
    println!("\x1b[32m           High-Performance Offline Desktop Security            \x1b[0m");
    println!("\x1b[36m=================================================================\x1b[0m");
    println!();
}

fn run_installer() {
    print_banner();

    let args: Vec<String> = env::args().collect();
    let is_silent = args.iter().any(|a| a == "/S" || a == "-s" || a == "--silent");
    let is_uninstall = args.iter().any(|a| a == "--uninstall" || a == "/uninstall");

    let admin = is_elevated();

    // If not admin and not explicitly per-user, prompt for elevation
    if !admin && !args.iter().any(|a| a == "--user") {
        println!("\x1b[33m[!] Administrator privileges recommended for complete system integration.\x1b[0m");
        println!("\x1b[36m[*] Requesting elevation via Windows UAC...\x1b[0m");
        if let Ok(()) = relaunch_as_admin() {
            std::process::exit(0);
        }
        println!("\x1b[33m[*] Proceeding in per-user installation mode.\x1b[0m");
    }

    let default_dir = if admin {
        let prog_files = env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
        PathBuf::from(prog_files).join("Sentient")
    } else {
        let local_appdata = env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\Users\Default\AppData\Local".to_string());
        PathBuf::from(local_appdata).join("Programs").join("Sentient")
    };

    let install_dir = args
        .iter()
        .find(|a| a.starts_with("/D=") || a.starts_with("--dir="))
        .map(|a| {
            if let Some(pos) = a.find('=') {
                PathBuf::from(&a[pos + 1..])
            } else {
                default_dir.clone()
            }
        })
        .unwrap_or(default_dir);

    if is_uninstall {
        println!("\x1b[31m[*] Running uninstallation...\x1b[0m");
        let uninst_bat = install_dir.join("uninstall.bat");
        if uninst_bat.exists() {
            let _ = Command::new("cmd").args(["/C", uninst_bat.to_str().unwrap()]).status();
        }
        return;
    }

    println!("\x1b[36m[*] Installation Target:\x1b[0m {}", install_dir.display());
    println!("\x1b[36m[*] Privilege Level:\x1b[0m     {}", if admin { "Elevated Administrator" } else { "Standard User" });
    println!();

    // Step 1: Create installation directory structure
    println!("[1/5] Creating application directories...");
    if let Err(e) = fs::create_dir_all(&install_dir) {
        eprintln!("\x1b[31m[ERROR] Failed to create destination directory: {e}\x1b[0m");
        std::process::exit(1);
    }
    let assets_dir = install_dir.join("assets");
    let _ = fs::create_dir_all(&assets_dir);

    // Step 2: Extract embedded binaries and payload
    println!("[2/5] Extracting core executable and threat intelligence...");
    let exe_dest = install_dir.join("sentient.exe");
    let unxored_exe: Vec<u8> = EMBEDDED_PAYLOAD.iter().map(|b| b ^ 0x5A).collect();
    if let Err(e) = fs::write(&exe_dest, unxored_exe) {
        eprintln!("\x1b[31m[ERROR] Failed to write sentient.exe: {e}\x1b[0m");
        std::process::exit(1);
    }

    let sigs_dest = install_dir.join("signatures.json");
    if let Err(e) = fs::write(&sigs_dest, EMBEDDED_SIGNATURES) {
        eprintln!("\x1b[31m[ERROR] Failed to write signatures.json: {e}\x1b[0m");
    }

    let logo_dest = assets_dir.join("logo.png");
    let _ = fs::write(&logo_dest, EMBEDDED_LOGO);

    let icon_dest = assets_dir.join("icon.ico");
    let _ = fs::write(&icon_dest, EMBEDDED_ICON);
    let root_icon = install_dir.join("icon.ico");
    let _ = fs::write(&root_icon, EMBEDDED_ICON);

    // Step 3: Create Start Menu and Desktop Shortcuts
    println!("[3/5] Creating Windows Desktop and Start Menu shortcuts with native icon...");
    if let Err(e) = create_shortcuts(&exe_dest, &icon_dest, admin) {
        eprintln!("\x1b[33m[!] Shortcut creation notice: {e}\x1b[0m");
    }

    // Step 4: Register Uninstaller in Windows Registry
    println!("[4/5] Registering Sentient in Windows Add/Remove Programs...");
    let _ = create_uninstaller_script(&install_dir, admin);
    register_uninstall_entry(&install_dir, admin);

    // Step 5: Complete
    println!("[5/5] Finalizing setup...");
    println!();
    println!("\x1b[1;32m✔ Sentient Endpoint Defense successfully installed!\x1b[0m");
    println!("  Installation Path: {}", install_dir.display());
    println!("  Desktop Shortcut:  Sentient.lnk (created on active desktop with native icon)");
    println!("  Start Menu:        Sentient Endpoint Defense\\Sentient.lnk");
    println!("  Uninstaller:       {}", install_dir.join("uninstall.bat").display());
    println!();

    if !is_silent {
        println!("\x1b[36m[*] Launching Sentient Endpoint Defense now...\x1b[0m");
        let _ = Command::new(&exe_dest).spawn();
    }
}

fn main() {
    run_installer();
}
