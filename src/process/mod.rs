use crate::scanner::hash_engine::SignatureIndex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(not(windows))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;

/// Risk level assessment for a running process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessRisk {
    Clean,
    SuspiciousPath,
    KnownMalwareMatch,
    DeletedBinaryExecution,
    Masquerading,
}

impl ProcessRisk {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "Clean",
            Self::SuspiciousPath => "Suspicious Location",
            Self::KnownMalwareMatch => "CRITICAL - Malware Hash Match",
            Self::DeletedBinaryExecution => "Evasion - Deleted Executable",
            Self::Masquerading => "High - System Masquerade",
        }
    }

    pub fn is_threat(self) -> bool {
        !matches!(self, Self::Clean)
    }
}

/// Audit report entry for a single running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAuditItem {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<PathBuf>,
    pub sha256: Option<String>,
    pub memory_kb: u64,
    pub risk: ProcessRisk,
    pub threat_name: Option<String>,
    pub risk_reason: Option<String>,
}

/// Enumerates and audits all active running processes against threat databases and path heuristics.
pub fn audit_running_processes(signatures: &SignatureIndex) -> Vec<ProcessAuditItem> {
    #[cfg(windows)]
    {
        audit_windows_processes(signatures)
    }

    #[cfg(not(windows))]
    {
        audit_linux_processes(signatures)
    }
}

/// Terminates an active process by PID.
pub fn kill_process(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let output = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output()
            .map_err(|e| format!("Failed to spawn taskkill: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            Err(format!("taskkill failed for PID {pid}: {err}"))
        }
    }

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if ret == 0 {
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            Err(format!("SIGKILL failed for PID {pid}: {err}"))
        }
    }
}

#[cfg(windows)]
fn audit_windows_processes(signatures: &SignatureIndex) -> Vec<ProcessAuditItem> {
    let mut items = Vec::new();

    // Query running processes using tasklist CSV output
    let output = match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        Ok(out) => out,
        Err(_) => return items,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // CSV line format: "Image Name","PID","Session Name","Session#","Mem Usage"
        let parts: Vec<&str> = trimmed
            .split("\",\"")
            .map(|s| s.trim_matches('"'))
            .collect();

        if parts.len() < 5 {
            continue;
        }

        let name = parts[0].to_string();
        let pid: u32 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Memory usage parsing (e.g., "12,345 K")
        let mem_str = parts[4].replace([' ', ',', 'K', 'k'], "");
        let memory_kb: u64 = mem_str.parse().unwrap_or(0);

        // Attempt to resolve executable path
        let exe_path = resolve_windows_process_path(&name, pid);

        let mut risk = ProcessRisk::Clean;
        let mut threat_name = None;
        let mut risk_reason = None;
        let mut sha256_hex = None;

        if let Some(ref path) = exe_path {
            let path_str = path.to_string_lossy().to_lowercase();

            // Hash match check
            if let Ok(bytes) = fs::read(path) {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hex_str = hex::encode(hasher.finalize());

                if let Some(sig) = signatures.match_hashes(&hex_str, "") {
                    risk = ProcessRisk::KnownMalwareMatch;
                    threat_name = Some(sig.name.clone());
                    risk_reason = Some(format!("Matches known malware IOC: {}", sig.name));
                }
                sha256_hex = Some(hex_str);
            }

            // Path heuristics check
            if risk == ProcessRisk::Clean {
                let in_temp = path_str.contains(r"\temp\") || path_str.contains(r"\appdata\local\temp\");
                let in_downloads = path_str.contains(r"\downloads\");

                if in_temp || in_downloads {
                    risk = ProcessRisk::SuspiciousPath;
                    risk_reason = Some(format!("Executable running from temporary directory: {}", path.display()));
                }

                // Masquerade check (critical system names running in user locations)
                let sys_names = ["svchost.exe", "csrss.exe", "smss.exe", "lsass.exe", "services.exe", "explorer.exe"];
                if sys_names.iter().any(|&s| s.eq_ignore_ascii_case(&name)) {
                    let in_windows = path_str.starts_with(r"c:\windows\system32\")
                        || path_str.starts_with(r"c:\windows\syswow64\")
                        || (name.eq_ignore_ascii_case("explorer.exe") && path_str.starts_with(r"c:\windows\"));
                    if !in_windows {
                        risk = ProcessRisk::Masquerading;
                        risk_reason = Some(format!("Critical system binary '{name}' running outside Windows System32: {}", path.display()));
                    }
                }
            }
        }

        items.push(ProcessAuditItem {
            pid,
            name,
            exe_path,
            sha256: sha256_hex,
            memory_kb,
            risk,
            threat_name,
            risk_reason,
        });
    }

    items
}

#[cfg(windows)]
fn resolve_windows_process_path(name: &str, _pid: u32) -> Option<PathBuf> {
    // Check common standard directories
    let sys32 = PathBuf::from(r"C:\Windows\System32").join(name);
    if sys32.exists() {
        return Some(sys32);
    }
    let win = PathBuf::from(r"C:\Windows").join(name);
    if win.exists() {
        return Some(win);
    }
    None
}

#[cfg(not(windows))]
fn audit_linux_processes(signatures: &SignatureIndex) -> Vec<ProcessAuditItem> {
    let mut items = Vec::new();
    let proc_dir = Path::new("/proc");

    let entries = match fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(_) => return items,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue, // Ignore non-PID directories
        };

        let pid_dir = entry.path();
        let comm_path = pid_dir.join("comm");
        let proc_name = fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("PID_{pid}"));

        let exe_link = pid_dir.join("exe");
        let exe_path_raw = fs::read_link(&exe_link).ok();

        let mut risk = ProcessRisk::Clean;
        let mut threat_name = None;
        let mut risk_reason = None;
        let mut sha256_hex = None;

        let exe_path = if let Some(ref target) = exe_path_raw {
            let target_str = target.to_string_lossy();

            // Detect deleted binary execution (evasion technique)
            if target_str.ends_with(" (deleted)") {
                risk = ProcessRisk::DeletedBinaryExecution;
                risk_reason = Some("Process executable was unlinked/deleted from disk after launching (memory dropper evasion).".to_string());
            }

            // Path heuristics
            if risk == ProcessRisk::Clean {
                let in_temp = target.starts_with("/tmp")
                    || target.starts_with("/var/tmp")
                    || target.starts_with("/dev/shm");
                if in_temp {
                    risk = ProcessRisk::SuspiciousPath;
                    risk_reason = Some(format!("Process running from temporary/shared memory: {}", target.display()));
                }
            }

            // Hash match
            if let Ok(bytes) = fs::read(target) {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hex_str = hex::encode(hasher.finalize());

                if let Some(sig) = signatures.match_hashes(&hex_str, "") {
                    risk = ProcessRisk::KnownMalwareMatch;
                    threat_name = Some(sig.name.clone());
                    risk_reason = Some(format!("Matches known malware IOC: {}", sig.name));
                }
                sha256_hex = Some(hex_str);
            }

            Some(target.clone())
        } else {
            None
        };

        // Estimate memory from /proc/[pid]/statm (page count)
        let memory_kb = if let Ok(statm) = fs::read_to_string(pid_dir.join("statm")) {
            let resident_pages: u64 = statm
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            resident_pages * 4 // Assuming standard 4 KiB page
        } else {
            0
        };

        items.push(ProcessAuditItem {
            pid,
            name: proc_name,
            exe_path,
            sha256: sha256_hex,
            memory_kb,
            risk,
            threat_name,
            risk_reason,
        });
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_risk_assessment() {
        assert_eq!(ProcessRisk::Clean.is_threat(), false);
        assert_eq!(ProcessRisk::SuspiciousPath.is_threat(), true);
        assert_eq!(ProcessRisk::KnownMalwareMatch.is_threat(), true);
        assert_eq!(ProcessRisk::DeletedBinaryExecution.is_threat(), true);
    }
}
