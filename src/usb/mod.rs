use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Information regarding an attached removable USB drive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDriveInfo {
    pub path: PathBuf,
    pub label: String,
    pub is_removable: bool,
    pub has_autorun: bool,
    pub suspicious_files: Vec<PathBuf>,
}

/// Enumerates attached removable USB drives across Windows and Linux.
pub fn detect_removable_drives() -> Vec<UsbDriveInfo> {
    #[cfg(windows)]
    {
        detect_windows_removable_drives()
    }

    #[cfg(not(windows))]
    {
        detect_linux_removable_drives()
    }
}

/// Scans a removable drive's root directory for suspicious autorun droppers or hidden shortcuts.
pub fn inspect_removable_drive(root: &Path) -> UsbDriveInfo {
    let mut suspicious_files = Vec::new();
    let mut has_autorun = false;

    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            let file_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();

            if file_name == "autorun.inf" {
                has_autorun = true;
                suspicious_files.push(p.clone());
            }

            // Flag shortcut droppers (.lnk) or hidden executables (.exe/.elf/.vbs/.bat) in drive root
            if file_name.ends_with(".lnk")
                || file_name.ends_with(".vbs")
                || file_name.ends_with(".bat")
                || file_name.ends_with(".scr")
            {
                suspicious_files.push(p.clone());
            }

            if file_name.starts_with('.') && (file_name.ends_with(".exe") || file_name.ends_with(".elf")) {
                suspicious_files.push(p.clone());
            }
        }
    }

    UsbDriveInfo {
        path: root.to_path_buf(),
        label: root.display().to_string(),
        is_removable: true,
        has_autorun,
        suspicious_files,
    }
}

/// Immunizes a removable drive by neutralizing malicious `autorun.inf` and creating a locked placeholder.
pub fn immunize_drive(root: &Path) -> Result<(), String> {
    let autorun_path = root.join("autorun.inf");
    if autorun_path.is_file() {
        let _ = fs::remove_file(&autorun_path);
    }
    if !autorun_path.exists() {
        fs::create_dir_all(&autorun_path)
            .map_err(|e| format!("Failed to create immunization directory: {e}"))?;
        let dummy = autorun_path.join("sentient_immunized.lck");
        let _ = fs::write(dummy, b"Sentient Endpoint Security - USB Immunized");
    }
    Ok(())
}

#[cfg(windows)]
fn detect_windows_removable_drives() -> Vec<UsbDriveInfo> {
    let mut drives = Vec::new();

    // Check drive letters D: through Z:
    for letter in b'D'..=b'Z' {
        let drive_str = format!("{}:\\", letter as char);
        let path = PathBuf::from(&drive_str);

        if path.exists() {
            // Check if drive is removable using GetDriveTypeW (DRIVE_REMOVABLE = 2)
            let is_removable = unsafe {
                use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
                let wide_path: Vec<u16> = drive_str.encode_utf16().chain(std::iter::once(0)).collect();
                GetDriveTypeW(wide_path.as_ptr()) == 2
            };

            if is_removable {
                drives.push(inspect_removable_drive(&path));
            }
        }
    }

    drives
}

#[cfg(not(windows))]
fn detect_linux_removable_drives() -> Vec<UsbDriveInfo> {
    let mut drives = Vec::new();
    let candidates = ["/media", "/run/media", "/mnt"];

    for candidate in candidates {
        let root = Path::new(candidate);
        if root.exists() {
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        // In modern Linux (GNOME/KDE/UDisks2), mount points are placed at /media/$USER/<label>
                        // or /run/media/$USER/<label>. Check if subdirectories exist.
                        let mut found_sub_mount = false;
                        if let Ok(sub_entries) = fs::read_dir(&p) {
                            for sub in sub_entries.flatten() {
                                let sub_p = sub.path();
                                if sub_p.is_dir() {
                                    found_sub_mount = true;
                                    drives.push(inspect_removable_drive(&sub_p));
                                }
                            }
                        }
                        if !found_sub_mount {
                            drives.push(inspect_removable_drive(&p));
                        }
                    }
                }
            }
        }
    }

    drives
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_removable_drive_flags_autorun() {
        let dir = std::env::temp_dir().join("sentient_usb_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let autorun = dir.join("autorun.inf");
        fs::write(&autorun, b"[autorun]\nopen=evil.exe").unwrap();

        let dropper = dir.join("shortcut.lnk");
        fs::write(&dropper, b"fake lnk").unwrap();

        let info = inspect_removable_drive(&dir);
        assert!(info.has_autorun);
        assert_eq!(info.suspicious_files.len(), 2);

        let _ = immunize_drive(&dir);
        assert!(dir.join("autorun.inf").is_dir());

        let _ = fs::remove_dir_all(&dir);
    }
}
