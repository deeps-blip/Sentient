use crate::models::{
    now_timestamp, MrtReport, MrtThreatEntry, ScanEvent, ScanMode, ScanSummary, Threat,
    ThreatSource,
};
use crossbeam_channel::Sender;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Resolves `%windir%\system32\mrt.exe` (falling back to `C:\Windows\System32\mrt.exe`).
pub fn mrt_executable_path() -> PathBuf {
    let windir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    windir.join("System32").join("mrt.exe")
}

/// Resolves `C:\Windows\debug\mrt.log` via `%windir%`.
pub fn mrt_log_path() -> PathBuf {
    let windir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    windir.join("debug").join("mrt.log")
}

/// Reads and parses the latest scan entry currently recorded in `C:\Windows\debug\mrt.log`.
pub fn read_latest_mrt_report() -> Result<MrtReport, String> {
    let log_path = mrt_log_path();
    let bytes = std::fs::read(&log_path)
        .map_err(|e| format!("Unable to read system scan telemetry: {e}"))?;
    let content = decode_mrt_bytes(&bytes);
    parse_latest_mrt_entry(&content, None)
        .ok_or_else(|| "No completed system scan entries found yet.".to_string())
}

/// Executes Windows Malicious Software Removal Tool (`mrt.exe`) in Quick (`/Q`) or
/// Full (`/F /Q`) mode on a background thread and asynchronously watches `mrt.log`
/// until the process terminates and flushes its final report.
pub fn run_mrt_scan(full_scan: bool, cancel_flag: Arc<AtomicBool>, tx: Sender<ScanEvent>) {
    let mode = if full_scan {
        ScanMode::MrtFull
    } else {
        ScanMode::MrtQuick
    };
    let started_at = now_timestamp();
    let start_instant = Instant::now();

    let exe_path = mrt_executable_path();
    let log_path = mrt_log_path();

    if !exe_path.exists() {
        let msg =
            "Deep system scan engine component is unavailable on this workstation.".to_string();
        let _ = tx.send(ScanEvent::Error(msg));
        let _ = tx.send(ScanEvent::Complete {
            summary: ScanSummary {
                mode,
                target: "Local System".to_string(),
                started_at,
                finished_at: now_timestamp(),
                duration_secs: start_instant.elapsed().as_secs_f64(),
                files_scanned: 0,
                bytes_scanned: 0,
                threats_found: 0,
                skipped_inaccessible: 0,
                cancelled: false,
                detected_threats: Vec::new(),
                mrt_report: None,
            },
        });
        return;
    }

    if !crate::platform::is_elevated() {
        let msg = "System Scan requires Administrator privileges. Click 'Relaunch as Admin' in the sidebar.".to_string();
        let _ = tx.send(ScanEvent::Error(msg));
        let _ = tx.send(ScanEvent::Complete {
            summary: ScanSummary {
                mode,
                target: "Local System".to_string(),
                started_at,
                finished_at: now_timestamp(),
                duration_secs: start_instant.elapsed().as_secs_f64(),
                files_scanned: 0,
                bytes_scanned: 0,
                threats_found: 0,
                skipped_inaccessible: 0,
                cancelled: false,
                detected_threats: Vec::new(),
                mrt_report: None,
            },
        });
        return;
    }

    // Record baseline offset of mrt.log before launching mrt.exe so we isolate the new run.
    let baseline_len = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    let baseline_block_count = std::fs::read(&log_path)
        .map(|b| split_mrt_blocks(&decode_mrt_bytes(&b)).len())
        .unwrap_or(0);

    let args: Vec<&str> = if full_scan {
        vec!["/F", "/Q"]
    } else {
        vec!["/Q"]
    };

    let _ = tx.send(ScanEvent::Status(
        "Initializing Sentient deep system scan engine...".to_string(),
    ));
    let _ = tx.send(ScanEvent::FileScanned(PathBuf::from(
        "Sentient Core System Engine",
    )));

    let mut cmd = Command::new(&exe_path);
    cmd.args(&args);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to start system scan engine: {e}");
            let _ = tx.send(ScanEvent::Error(msg));
            let _ = tx.send(ScanEvent::Complete {
                summary: ScanSummary {
                    mode,
                    target: "Local System".to_string(),
                    started_at,
                    finished_at: now_timestamp(),
                    duration_secs: start_instant.elapsed().as_secs_f64(),
                    files_scanned: 0,
                    bytes_scanned: 0,
                    threats_found: 0,
                    skipped_inaccessible: 0,
                    cancelled: false,
                    detected_threats: Vec::new(),
                    mrt_report: None,
                },
            });
            return;
        }
    };

    let mut cancelled = false;
    let mut exit_code: Option<i32> = None;
    let mut last_status_tick = Instant::now();

    loop {
        if cancel_flag.load(Ordering::Relaxed) {
            cancelled = true;
            let _ = tx.send(ScanEvent::Status(
                "Stopping active system scan...".to_string(),
            ));
            let _ = child.kill();
            let _ = child.wait();
            break;
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if last_status_tick.elapsed() >= Duration::from_millis(500) {
                    let secs = start_instant.elapsed().as_secs();
                    let _ = tx.send(ScanEvent::Status(format!(
                        "Sentient {} running ({secs}s elapsed) — analyzing system paths & signatures...",
                        if full_scan {
                            "System Scan"
                        } else {
                            "Quick System Scan"
                        }
                    )));
                    let _ = tx.send(ScanEvent::Progress {
                        scanned: secs as usize,
                        total: None,
                    });
                    last_status_tick = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Error(format!(
                    "Error polling system scan status: {e}"
                )));
                break;
            }
        }
    }

    if cancelled {
        let _ = tx.send(ScanEvent::Complete {
            summary: ScanSummary {
                mode,
                target: "Local System".to_string(),
                started_at,
                finished_at: now_timestamp(),
                duration_secs: start_instant.elapsed().as_secs_f64(),
                files_scanned: 0,
                bytes_scanned: 0,
                threats_found: 0,
                skipped_inaccessible: 0,
                cancelled: true,
                detected_threats: Vec::new(),
                mrt_report: None,
            },
        });
        return;
    }

    let _ = tx.send(ScanEvent::Status(format!(
        "System scan completed (status {}). Finalizing telemetry report...",
        exit_code.map_or_else(|| "unknown".into(), |c| c.to_string())
    )));

    let mrt_report = wait_and_parse_mrt_log(
        &log_path,
        baseline_len,
        baseline_block_count,
        full_scan,
        exit_code,
    );

    let mut detected_threats = Vec::new();
    match &mrt_report {
        Ok(report) => {
            for (idx, item) in report.infected_items.iter().enumerate() {
                let path = extract_path_from_detail(&item.detail)
                    .unwrap_or_else(|| PathBuf::from(&item.detail));
                let threat = Threat {
                    id: format!("mrt_{}_{idx}", chrono::Local::now().format("%Y%m%d%H%M%S")),
                    path: path.clone(),
                    threat_name: item.threat_name.clone(),
                    sha256: String::new(),
                    md5: String::new(),
                    file_size: 0,
                    detected_at: now_timestamp(),
                    source: ThreatSource::WindowsMrt,
                    quarantined: false,
                };
                let _ = tx.send(ScanEvent::ThreatFound {
                    path,
                    threat_name: threat.threat_name.clone(),
                    hash: format!("SYS-ENG:{}", report.return_code_hex),
                });
                detected_threats.push(threat);
            }

            if detected_threats.is_empty() && is_infection_return_code(report.return_code) {
                let synthetic_name =
                    format!("System.Threat.Detected (Code {})", report.return_code_hex);
                let _ = tx.send(ScanEvent::ThreatFound {
                    path: PathBuf::from("Local System"),
                    threat_name: synthetic_name.clone(),
                    hash: format!("SYS-ENG:{}", report.return_code_hex),
                });
                detected_threats.push(Threat {
                    id: format!("sys_rc_{}", chrono::Local::now().format("%Y%m%d%H%M%S")),
                    path: PathBuf::from("Local System"),
                    threat_name: synthetic_name,
                    sha256: String::new(),
                    md5: String::new(),
                    file_size: 0,
                    detected_at: now_timestamp(),
                    source: ThreatSource::WindowsMrt,
                    quarantined: false,
                });
            }
        }
        Err(err) => {
            let _ = tx.send(ScanEvent::Error(err.clone()));
        }
    }

    let _ = tx.send(ScanEvent::Complete {
        summary: ScanSummary {
            mode,
            target: "Local System".to_string(),
            started_at,
            finished_at: now_timestamp(),
            duration_secs: start_instant.elapsed().as_secs_f64(),
            files_scanned: 1,
            bytes_scanned: 0,
            threats_found: detected_threats.len(),
            skipped_inaccessible: 0,
            cancelled: false,
            detected_threats,
            mrt_report: mrt_report.ok(),
        },
    });
}

fn wait_and_parse_mrt_log(
    log_path: &Path,
    baseline_len: u64,
    baseline_block_count: usize,
    full_scan: bool,
    process_exit_code: Option<i32>,
) -> Result<MrtReport, String> {
    let deadline = Instant::now() + Duration::from_millis(2000);
    let mut last_err = None;

    loop {
        match File::open(log_path) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                if let Err(e) = file.read_to_end(&mut bytes) {
                    last_err = Some(format!("Failed reading '{}': {e}", log_path.display()));
                } else {
                    let current_len = bytes.len() as u64;
                    let text = decode_mrt_bytes(&bytes);
                    let blocks = split_mrt_blocks(&text);

                    // Prefer newly appended content when mrt.log grew cleanly.
                    let candidate_text = if current_len > baseline_len && baseline_len > 0 {
                        let tail = decode_mrt_bytes(&bytes[baseline_len as usize..]);
                        if tail.contains("Finished On") || tail.contains("Return code:") {
                            Some(tail)
                        } else {
                            None
                        }
                    } else if blocks.len() > baseline_block_count {
                        blocks.last().cloned()
                    } else {
                        None
                    };

                    if let Some(block_text) = candidate_text {
                        if let Some(mut report) =
                            parse_latest_mrt_entry(&block_text, process_exit_code)
                        {
                            if report.scan_type.is_empty() {
                                report.scan_type = default_scan_type_label(full_scan);
                            }
                            return Ok(report);
                        }
                    }

                    // If mrt.log has finished entries even if baseline didn't advance before deadline,
                    // return the latest entry once the deadline expires.
                    if Instant::now() >= deadline {
                        if let Some(mut report) = parse_latest_mrt_entry(&text, process_exit_code) {
                            if report.scan_type.is_empty() {
                                report.scan_type = default_scan_type_label(full_scan);
                            }
                            return Ok(report);
                        }
                        return Err(
                            "System scan finished, but no updated scan summary was available."
                                .to_string(),
                        );
                    }
                }
            }
            Err(e) => {
                last_err = Some(format!("Unable to read system telemetry: {e}"));
            }
        }

        if Instant::now() >= deadline {
            return Err(last_err.unwrap_or_else(|| {
                "Timed out waiting for system scan telemetry update.".to_string()
            }));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn default_scan_type_label(full_scan: bool) -> String {
    if full_scan {
        "System Scan".to_string()
    } else {
        "Quick Scan".to_string()
    }
}

/// Decodes `mrt.log` raw bytes supporting both UTF-8/ASCII and UTF-16LE BOM formats.
pub fn decode_mrt_bytes(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) && bytes.len() >= 2 {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Splits `mrt.log` contents into individual scan run blocks delimited by dashed separator lines.
pub fn split_mrt_blocks(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.len() >= 20 && trimmed.chars().all(|c| c == '-') {
            if !current.is_empty() {
                let joined = current.join("\n");
                if !joined.trim().is_empty() {
                    blocks.push(joined);
                }
                current.clear();
            }
        } else {
            current.push(line);
        }
    }

    if !current.is_empty() {
        let joined = current.join("\n");
        if !joined.trim().is_empty() {
            blocks.push(joined);
        }
    }

    blocks
}

/// Parses the latest scan block from `mrt.log` text into a structured `MrtReport`.
pub fn parse_latest_mrt_entry(content: &str, fallback_exit_code: Option<i32>) -> Option<MrtReport> {
    let blocks = split_mrt_blocks(content);
    // Prefer the last block that contains a Started/Finished header, falling back to last block.
    let block = blocks
        .iter()
        .rev()
        .find(|b| {
            b.contains("Started On") || b.contains("Return code:") || b.contains("Results Summary")
        })
        .or_else(|| blocks.last())?;

    Some(parse_mrt_block(block, fallback_exit_code))
}

/// Parses a single `mrt.log` block into `MrtReport`.
pub fn parse_mrt_block(block: &str, fallback_exit_code: Option<i32>) -> MrtReport {
    let mut tool_version = String::new();
    let mut started_on = String::new();
    let mut finished_on = String::new();
    let mut scan_type = String::new();
    let mut engine_version = String::new();
    let mut signatures_version = String::new();
    let mut return_code = fallback_exit_code.unwrap_or(0);
    let mut return_code_hex = format!("0x{:x}", return_code);
    let mut full_scan_flag: Option<bool> = None;
    let mut quiet_flag: Option<bool> = None;

    let mut in_summary = false;
    let mut summary_lines: Vec<String> = Vec::new();
    let mut infected_items: Vec<MrtThreatEntry> = Vec::new();
    let mut current_threat: Option<String> = None;

    for raw_line in block.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if line.contains("full-scan-mode:") {
            if line.contains("full-scan-mode: 1") {
                full_scan_flag = Some(true);
            } else if line.contains("full-scan-mode: 0") {
                full_scan_flag = Some(false);
            }
            if line.contains("quiet-mode: 1") {
                quiet_flag = Some(true);
            }
        } else if line.starts_with("Microsoft Windows Malicious Software Removal Tool v") {
            tool_version = line.to_string();
        } else if let Some(rest) = line.strip_prefix("Started On ") {
            started_on = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Engine:") {
            engine_version = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Signatures:") {
            signatures_version = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Run Mode:") {
            scan_type = rest.trim().to_string();
        } else if line == "Results Summary:" {
            in_summary = true;
        } else if in_summary && line.chars().all(|c| c == '-') {
            continue;
        } else if let Some(idx) = line.find("Finished On ") {
            in_summary = false;
            finished_on = line[idx + "Finished On ".len()..].trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Return code:") {
            in_summary = false;
            let trimmed = rest.trim();
            if let Some((num_part, hex_part)) = parse_return_code(trimmed) {
                return_code = num_part;
                return_code_hex = hex_part;
            }
        } else if in_summary {
            summary_lines.push(line.to_string());
            if is_benign_summary_line(line) {
                continue;
            }

            // Parse infection details written by MRT under Results Summary.
            if let Some(detail) = line.strip_prefix("->") {
                let detail = detail.trim();
                let threat_name = current_threat
                    .clone()
                    .unwrap_or_else(|| "System Detected Threat".to_string());
                let action = extract_action_tag(detail);
                infected_items.push(MrtThreatEntry {
                    threat_name,
                    action,
                    detail: detail.to_string(),
                });
            } else {
                let cleaned_name = line
                    .strip_prefix("Infection found:")
                    .or_else(|| line.strip_prefix("Threat Detected:"))
                    .or_else(|| line.strip_prefix("Found "))
                    .unwrap_or(line)
                    .trim()
                    .to_string();
                let action = extract_action_tag(&cleaned_name);
                current_threat = Some(cleaned_name.clone());
                infected_items.push(MrtThreatEntry {
                    threat_name: cleaned_name,
                    action,
                    detail: line.to_string(),
                });
            }
        }
    }

    if scan_type.is_empty() {
        scan_type = match (full_scan_flag, quiet_flag) {
            (Some(true), _) => "System Scan".to_string(),
            (Some(false), _) => "Quick Scan".to_string(),
            _ => "System Engine Scan".to_string(),
        };
    } else if let Some(is_full) = full_scan_flag {
        if scan_type.to_lowercase().contains("windows update") {
            scan_type = if is_full {
                "System Scan (Scheduled)".to_string()
            } else {
                "Quick Scan (Scheduled)".to_string()
            };
        } else {
            let suffix = if is_full { "Full Scan" } else { "Quick Scan" };
            if !scan_type.to_lowercase().contains("full")
                && !scan_type.to_lowercase().contains("quick")
            {
                scan_type = format!("{scan_type} ({suffix})");
            }
        }
    }

    let raw_summary = if summary_lines.is_empty() {
        "No summary recorded.".to_string()
    } else {
        summary_lines.join("\n")
    };

    MrtReport {
        tool_version,
        started_on,
        finished_on,
        scan_type,
        engine_version,
        signatures_version,
        return_code,
        return_code_hex,
        infected_items,
        raw_summary,
    }
}

fn parse_return_code(text: &str) -> Option<(i32, String)> {
    let mut parts = text.split_whitespace();
    let dec = parts.next()?.parse::<i32>().ok()?;
    let hex = parts
        .next()
        .map(|s| s.trim_matches(|c| c == '(' || c == ')').to_string())
        .unwrap_or_else(|| format!("0x{dec:x}"));
    Some((dec, hex))
}

fn is_benign_summary_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower == "no infection found."
        || lower == "no infection found"
        || lower.starts_with("successfully submitted heartbeat report")
        || lower.starts_with("successfully submitted maps report")
        || lower.starts_with("heartbeat report")
        || lower.starts_with("error:")
}

fn extract_action_tag(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("removed") {
        "Removed".to_string()
    } else if lower.contains("reboot") {
        "Reboot Required".to_string()
    } else if lower.contains("quarantined") {
        "Quarantined".to_string()
    } else if lower.contains("partially") {
        "Partially Cleaned".to_string()
    } else {
        "Detected".to_string()
    }
}

fn extract_path_from_detail(detail: &str) -> Option<PathBuf> {
    if let Some(pos) = detail.find(":\\") {
        let start = pos.saturating_sub(1);
        let tail = &detail[start..];
        let end = tail.find(" (").unwrap_or(tail.len());
        return Some(PathBuf::from(tail[..end].trim()));
    }
    None
}

fn is_infection_return_code(code: i32) -> bool {
    matches!(code, 2 | 4..=13)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_clean_windows_11_mrt_log() {
        let sample = r#"
---------------------------------------------------------------------------------------
reboot-mode: 0, quiet-mode: 1, detect-only-mode: 0, full-scan-mode: 0, wu-mode: 1
Microsoft Windows Malicious Software Removal Tool v5.147, (build 5.147.26110.1001)
Started On Wed Nov 11 14:03:59 2026

MSRT Ring: Broad (unset)
Engine: 1.1.26100.4
Signatures: 1.463.1.0
MpGear: 1.1.26100.4
Run Mode: Scan Run From Windows Update

Results Summary:
----------------
No infection found.
Successfully Submitted Heartbeat Report
Microsoft Windows Malicious Software Removal Tool Finished On Wed Nov 11 14:10:42 2026


Return code: 0 (0x0)
"#;

        let report = parse_latest_mrt_entry(sample, None).unwrap();
        assert_eq!(report.started_on, "Wed Nov 11 14:03:59 2026");
        assert_eq!(report.finished_on, "Wed Nov 11 14:10:42 2026");
        assert_eq!(report.engine_version, "1.1.26100.4");
        assert_eq!(report.signatures_version, "1.463.1.0");
        assert_eq!(report.return_code, 0);
        assert_eq!(report.return_code_hex, "0x0");
        assert!(report.infected_items.is_empty());
        assert!(report.scan_type.contains("Quick Scan"));
    }

    #[test]
    fn test_parse_infected_mrt_log_entry() {
        let sample = r#"
---------------------------------------------------------------------------------------
reboot-mode: 0, quiet-mode: 1, detect-only-mode: 0, full-scan-mode: 1, wu-mode: 0
Microsoft Windows Malicious Software Removal Tool v5.147, (build 5.147.26110.1001)
Started On Wed Nov 11 18:00:00 2026

Engine: 1.1.26100.4
Signatures: 1.463.1.0
Run Mode: Interactive Graphical Mode

Results Summary:
----------------
Infection found: Worm:Win32/Conficker.B
->File: C:\Users\Public\evil.dll (Removed)
Microsoft Windows Malicious Software Removal Tool Finished On Wed Nov 11 18:22:10 2026

Return code: 6 (0x6)
"#;

        let report = parse_latest_mrt_entry(sample, None).unwrap();
        assert_eq!(report.return_code, 6);
        assert_eq!(report.return_code_hex, "0x6");
        assert!(report.scan_type.contains("Full Scan"));
        assert_eq!(report.infected_items.len(), 2);
        assert_eq!(
            report.infected_items[0].threat_name,
            "Worm:Win32/Conficker.B"
        );
        assert_eq!(report.infected_items[1].action, "Removed");
        assert_eq!(
            extract_path_from_detail(&report.infected_items[1].detail),
            Some(PathBuf::from(r"C:\Users\Public\evil.dll"))
        );
    }
}
