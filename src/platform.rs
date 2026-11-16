use std::path::Path;

/// Returns `true` when the current process runs with elevated Administrator / root privileges.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: Win32 handles and output structs are valid for the duration of the calls
    // and closed before returning.
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

/// Linux / Unix check: returns `true` if running as root (UID 0).
#[cfg(unix)]
pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Non-Windows, non-Unix fallback for cross-platform compilation.
#[cfg(not(any(windows, unix)))]
pub fn is_elevated() -> bool {
    false
}

/// Triggers a Windows UAC elevation prompt to relaunch the current executable as Administrator.
#[cfg(windows)]
pub fn relaunch_as_admin() -> Result<(), String> {
    use core::ptr::null_mut;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to locate Sentient executable path: {e}"))?;

    let operation: Vec<u16> = "runas\0".encode_utf16().collect();
    let mut file: Vec<u16> = exe_path.as_os_str().encode_wide().collect();
    file.push(0);

    // SAFETY: Both UTF-16 slices are NUL-terminated and live across the synchronous call.
    let result = unsafe {
        ShellExecuteW(
            null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    if (result as isize) <= 32 {
        Err(format!(
            "UAC elevation was declined or failed (ShellExecuteW returned {}).",
            result as isize
        ))
    } else {
        Ok(())
    }
}

/// Linux / Unix elevation prompt using PolicyKit (pkexec) or sudo.
#[cfg(unix)]
pub fn relaunch_as_admin() -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to locate Sentient executable path: {e}"))?;

    // Try PolicyKit first (desktop standard graphical elevation prompt)
    if which_command_exists("pkexec") {
        let child = std::process::Command::new("pkexec")
            .arg(&exe_path)
            .spawn();
        return match child {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("PolicyKit (pkexec) elevation launch failed: {e}")),
        };
    }

    // Fallback: try sudo
    if which_command_exists("sudo") {
        let child = std::process::Command::new("sudo")
            .arg("-E")
            .arg(&exe_path)
            .spawn();
        return match child {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("sudo elevation launch failed: {e}")),
        };
    }

    Err("Neither pkexec nor sudo is available on this system for elevation.".to_string())
}

#[cfg(unix)]
fn which_command_exists(cmd: &str) -> bool {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(cmd);
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

/// Fallback for other platforms.
#[cfg(not(any(windows, unix)))]
pub fn relaunch_as_admin() -> Result<(), String> {
    Err("Elevation is not supported on this platform.".to_string())
}

/// Applies Windows quarantine hardening to an isolated file:
/// - Sets standard read-only permission flag
/// - Marks file attributes `FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN`
/// - Denies `Everyone` (`*S-1-1-0`) Read/Write/Execute DACL permissions on NTFS (best-effort)
#[cfg(windows)]
pub fn harden_quarantined_file(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Storage::FileSystem::{
        SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        let _ = std::fs::set_permissions(path, perms);
    }

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 file path.
    unsafe {
        SetFileAttributesW(
            wide.as_ptr(),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN,
        );
    }

    // Best-effort NTFS DACL hardening using language-neutral Everyone SID (*S-1-1-0).
    let _ = std::process::Command::new("icacls")
        .arg(path)
        .arg("/deny")
        .arg("*S-1-1-0:(R,W,X)")
        .arg("/Q")
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    Ok(())
}

/// Linux / Unix quarantine hardening:
/// - Strips all read, write, and execute permissions (0o000)
/// - If running as root, applies immutable flag (`chattr +i`)
#[cfg(unix)]
pub fn harden_quarantined_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // 1. Remove all permissions so no process can execute or inspect raw content:
    let perms = std::fs::Permissions::from_mode(0o000);
    let _ = std::fs::set_permissions(path, perms);

    // 2. Best-effort immutable flag on Linux if running as root
    if is_elevated() {
        let _ = std::process::Command::new("chattr")
            .arg("+i")
            .arg(path)
            .output();
    }

    Ok(())
}

#[cfg(not(any(windows, unix)))]
pub fn harden_quarantined_file(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Reverses quarantine permission locks before restoring or securely wiping a file.
#[cfg(windows)]
pub fn unharden_quarantined_file(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_NORMAL};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Remove NTFS deny ACE first so subsequent attribute/IO operations succeed.
    let _ = std::process::Command::new("icacls")
        .arg(path)
        .arg("/remove:d")
        .arg("*S-1-1-0")
        .arg("/Q")
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 file path.
    unsafe {
        SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL);
    }

    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
    }

    Ok(())
}

/// Reverses quarantine permission locks on Linux / Unix:
/// - Removes immutable flag (`chattr -i`) if set
/// - Restores read & write permissions (0o600)
#[cfg(unix)]
pub fn unharden_quarantined_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // 1. Remove immutable flag if set
    if is_elevated() {
        let _ = std::process::Command::new("chattr")
            .arg("-i")
            .arg(path)
            .output();
    }

    // 2. Restore owner read/write (0o600: rw-------)
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;

    Ok(())
}

#[cfg(not(any(windows, unix)))]
pub fn unharden_quarantined_file(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}
