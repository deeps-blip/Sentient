use std::path::Path;

/// Returns `true` when the current process runs with elevated Administrator privileges.
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

/// Non-Windows fallback for cross-platform compilation.
#[cfg(not(windows))]
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

/// Non-Windows fallback for UAC relaunch.
#[cfg(not(windows))]
pub fn relaunch_as_admin() -> Result<(), String> {
    Err("UAC elevation is only supported on Windows.".to_string())
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

#[cfg(not(windows))]
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

#[cfg(not(windows))]
pub fn unharden_quarantined_file(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}
