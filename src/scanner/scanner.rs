use crate::models::{
    now_timestamp, MrtReport, MrtThreatEntry, ScanEvent, ScanMode, ScanSummary, Threat,
    ThreatSource,
};
use crossbeam_channel::Sender;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
use std::io::Read;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Resolves the deep system scan engine executable path:
/// - Windows: `%windir%\system32\mrt.exe`
/// - Linux: `clamscan` if installed, or the current executable (Native Linux Engine)
#[cfg(windows)]
pub fn mrt_executable_path() -> PathBuf {
    let windir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    windir.join("System32").join("mrt.exe")
}

#[cfg(not(windows))]
pub fn mrt_executable_path() -> PathBuf {
    if let Some(clam) = which_clamscan() {
        return clam;
    }
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/bin/sentient"))
}

/// Resolves the system scan telemetry log path:
/// - Windows: `C:\Windows\debug\mrt.log`
/// - Linux: `$XDG_DATA_HOME/sentient/system_scan.log` (`~/.local/share/sentient/system_scan.log`)
#[cfg(windows)]
pub fn mrt_log_path() -> PathBuf {
    let windir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    windir.join("debug").join("mrt.log")
}

#[cfg(not(windows))]
pub fn mrt_log_path() -> PathBuf {
    crate::models::sentient_data_dir().join("system_scan.log")
}

/// Reads and parses the latest system scan entry from the platform telemetry log.
pub fn read_latest_mrt_report() -> Result<MrtReport, String> {
    let log_path = mrt_log_path();
    let bytes = std::fs::read(&log_path)
        .map_err(|e| format!("Unable to read system scan telemetry: {e}"))?;
    let content = decode_mrt_bytes(&bytes);
    parse_latest_mrt_entry(&content, None)
        .ok_or_else(|| "No completed system scan entries found yet.".to_string())
}

/// Modern alias for `read_latest_mrt_report`.
#[allow(dead_code)]
pub fn read_latest_system_report() -> Result<MrtReport, String> {
    read_latest_mrt_report()
}

/// Modern alias for `mrt_executable_path`.
#[allow(dead_code)]
pub fn system_executable_path() -> PathBuf {
    mrt_executable_path()
}

/// Modern alias for `mrt_log_path`.
#[allow(dead_code)]
pub fn system_log_path() -> PathBuf {
    mrt_log_path()
}

/// Dispatches background deep system inspection according to the active platform:
/// - Windows: Executes Windows Malicious Software Removal Tool (`mrt.exe /Q` or `/F /Q`)
/// - Linux: Executes ClamAV (if present) or Sentient Native Linux Deep System Engine
pub fn run_mrt_scan(full_scan: bool, cancel_flag: Arc<AtomicBool>, tx: Sender<ScanEvent>) {
    #[cfg(windows)]
    run_windows_mrt_scan(full_scan, cancel_flag, tx);

    #[cfg(not(windows))]
    run_linux_system_scan(full_scan, cancel_flag, tx);
}

/// Modern alias for `run_mrt_scan`.
#[allow(dead_code)]
pub fn run_system_scan(full_scan: bool, cancel_flag: Arc<AtomicBool>, tx: Sender<ScanEvent>) {
    run_mrt_scan(full_scan, cancel_flag, tx);
}

/// Windows implementation: executes `mrt.exe` and watches `mrt.log`.
#[cfg(windows)]
fn run_windows_mrt_scan(full_scan: bool, cancel_flag: Arc<AtomicBool>, tx: Sender<ScanEvent>) {
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

/// Linux implementation: dispatches to ClamAV if installed, or Sentient's Native Linux Deep System Engine.
#[cfg(not(windows))]
fn run_linux_system_scan(full_scan: bool, cancel_flag: Arc<AtomicBool>, tx: Sender<ScanEvent>) {
    let mode = if full_scan {
        ScanMode::MrtFull
    } else {
        ScanMode::MrtQuick
    };
    let started_at = now_timestamp();
    let start_instant = Instant::now();

    if let Some(clam_path) = which_clamscan() {
        run_clamscan_engine(
            clam_path,
            full_scan,
            mode,
            started_at,
            start_instant,
            cancel_flag,
            tx,
        );
    } else {
        run_native_linux_system_engine(
            full_scan,
            mode,
            started_at,
            start_instant,
            cancel_flag,
            tx,
        );
    }
}

/// Executes ClamAV scanner backend on Linux and streams live threat detections to the UI.
#[cfg(not(windows))]
fn run_clamscan_engine(
    clam_path: PathBuf,
    full_scan: bool,
    mode: ScanMode,
    started_at: String,
    start_instant: Instant,
    cancel_flag: Arc<AtomicBool>,
    tx: Sender<ScanEvent>,
) {
    let _ = tx.send(ScanEvent::Status(
        "Initializing Sentient System Engine (ClamAV backend)...".to_string(),
    ));

    let mut args = vec!["-r", "--bell", "-i"];
    let targets: Vec<PathBuf> = if full_scan {
        args.push("--exclude-dir=^/sys");
        args.push("--exclude-dir=^/proc");
        args.push("--exclude-dir=^/dev");
        args.push("--exclude-dir=^/run");
        vec![PathBuf::from("/")]
    } else {
        vec![
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/dev/shm"),
        ]
    };

    let mut cmd = std::process::Command::new(&clam_path);
    cmd.args(&args);
    for t in &targets {
        if t.exists() {
            cmd.arg(t);
        }
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to spawn ClamAV scanner ({e}), falling back to native Linux engine.");
            let _ = tx.send(ScanEvent::Status(msg));
            run_native_linux_system_engine(
                full_scan,
                mode,
                started_at,
                start_instant,
                cancel_flag,
                tx,
            );
            return;
        }
    };

    let mut detected_threats = Vec::new();
    let mut files_scanned = 0usize;
    let mut last_status = Instant::now();

    if let Some(stdout) = child.stdout.take() {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stdout);
        for line_res in reader.lines() {
            if cancel_flag.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = tx.send(ScanEvent::Complete {
                    summary: ScanSummary {
                        mode,
                        target: "Local Linux System".to_string(),
                        started_at,
                        finished_at: now_timestamp(),
                        duration_secs: start_instant.elapsed().as_secs_f64(),
                        files_scanned,
                        bytes_scanned: 0,
                        threats_found: detected_threats.len(),
                        skipped_inaccessible: 0,
                        cancelled: true,
                        detected_threats,
                        mrt_report: None,
                    },
                });
                return;
            }

            if let Ok(line) = line_res {
                files_scanned += 1;
                if last_status.elapsed() >= Duration::from_millis(300) {
                    let _ = tx.send(ScanEvent::Progress {
                        scanned: files_scanned,
                        total: None,
                    });
                    last_status = Instant::now();
                }

                if let Some((path, threat_name)) = parse_clamav_line(&line) {
                    let threat = Threat {
                        id: format!(
                            "clam_{}_{}",
                            chrono::Local::now().format("%Y%m%d%H%M%S"),
                            detected_threats.len()
                        ),
                        path: path.clone(),
                        threat_name: threat_name.clone(),
                        sha256: String::new(),
                        md5: String::new(),
                        file_size: 0,
                        detected_at: now_timestamp(),
                        source: ThreatSource::WindowsMrt,
                        quarantined: false,
                    };
                    let _ = tx.send(ScanEvent::ThreatFound {
                        path,
                        threat_name: threat_name.clone(),
                        hash: format!("CLAMAV:{}", threat_name),
                    });
                    detected_threats.push(threat);
                }
            }
        }
    }

    let status = child.wait().ok();
    let return_code = status.and_then(|s| s.code()).unwrap_or(0);
    let finished_at = now_timestamp();

    let log_path = mrt_log_path();
    let block = format_linux_system_scan_block(
        "ClamAV Engine",
        "1.4.0",
        &started_at,
        &finished_at,
        full_scan,
        return_code,
        &detected_threats,
    );
    append_system_scan_log(&log_path, &block);

    let report = parse_latest_mrt_entry(&block, Some(return_code));

    let _ = tx.send(ScanEvent::Complete {
        summary: ScanSummary {
            mode,
            target: "Local Linux System".to_string(),
            started_at,
            finished_at,
            duration_secs: start_instant.elapsed().as_secs_f64(),
            files_scanned,
            bytes_scanned: 0,
            threats_found: detected_threats.len(),
            skipped_inaccessible: 0,
            cancelled: false,
            detected_threats,
            mrt_report: report,
        },
    });
}

/// Executes Sentient's Native Linux Deep System Security Engine:
/// - Scans system directories (/bin, /sbin, /usr/bin, /etc, /tmp, /dev/shm)
/// - Evaluates 64 KiB chunked SHA-256 + MD5 + in-memory EICAR against `signatures.json`
/// - Performs Linux security heuristics:
///   1. Suspicious executable files in /tmp, /var/tmp, or /dev/shm (droppers)
///   2. World-writable system binaries in /bin, /sbin, /usr/bin
///   3. Hidden executable payloads
#[cfg(not(windows))]
fn run_native_linux_system_engine(
    full_scan: bool,
    mode: ScanMode,
    started_at: String,
    start_instant: Instant,
    cancel_flag: Arc<AtomicBool>,
    tx: Sender<ScanEvent>,
) {
    let _ = tx.send(ScanEvent::Status(
        "Initializing Sentient Native Linux Deep System Engine...".to_string(),
    ));

    let targets = if full_scan {
        vec![PathBuf::from("/")]
    } else {
        vec![
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/etc/cron.d"),
            PathBuf::from("/etc/cron.daily"),
            PathBuf::from("/etc/systemd/system"),
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/dev/shm"),
        ]
    };

    let sig_store = crate::scanner::hash_engine::SignatureStore::new();
    let signatures = sig_store.load_or_seed().unwrap_or_else(|_| {
        crate::scanner::hash_engine::SignatureIndex::from_database(
            crate::models::SignatureDatabase {
                version: "fallback".to_string(),
                updated_at: now_timestamp(),
                signatures: Vec::new(),
            },
        )
    });

    let q_dir = crate::models::sentient_data_dir().join("Quarantine");
    let mut detected_threats = Vec::new();
    let mut files_scanned = 0usize;
    let mut bytes_scanned = 0u64;
    let mut skipped_inaccessible = 0usize;
    let mut last_emit = Instant::now();
    let mut cancelled = false;

    for target in &targets {
        if cancel_flag.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        if !target.exists() {
            continue;
        }

        let walker = walkdir::WalkDir::new(target)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if full_scan {
                    let p = e.path();
                    if p.starts_with("/proc")
                        || p.starts_with("/sys")
                        || p.starts_with("/dev")
                        || p.starts_with("/run")
                        || p.starts_with("/media")
                        || p.starts_with("/mnt")
                    {
                        return false;
                    }
                }
                true
            });

        for entry in walker {
            if cancel_flag.load(Ordering::Relaxed) {
                cancelled = true;
                break;
            }

            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    skipped_inaccessible += 1;
                    continue;
                }
            };

            let path = entry.path().to_path_buf();
            if !entry.file_type().is_file() || path.starts_with(&q_dir) {
                continue;
            }

            files_scanned += 1;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = entry.metadata() {
                    let mode_bits = meta.permissions().mode();
                    let is_executable = (mode_bits & 0o111) != 0;
                    let is_world_writable = (mode_bits & 0o002) != 0;

                    if let Some(h_threat) =
                        check_linux_path_heuristics(&path, is_executable, is_world_writable)
                    {
                        let threat_name = h_threat.to_string();
                        let threat = Threat {
                            id: format!(
                                "lnx_{}_{}",
                                chrono::Local::now().format("%Y%m%d%H%M%S"),
                                detected_threats.len()
                            ),
                            path: path.clone(),
                            threat_name: threat_name.clone(),
                            sha256: String::new(),
                            md5: String::new(),
                            file_size: meta.len(),
                            detected_at: now_timestamp(),
                            source: ThreatSource::WindowsMrt,
                            quarantined: false,
                        };
                        let _ = tx.send(ScanEvent::ThreatFound {
                            path: path.clone(),
                            threat_name: threat_name.clone(),
                            hash: format!("LINUX-HEURISTIC:{}", threat_name),
                        });
                        detected_threats.push(threat);
                    }
                }
            }

            // Inspect streaming SHA-256 / MD5 / in-memory EICAR
            match std::fs::File::open(&path) {
                Ok(file) => {
                    let cancel = std::sync::atomic::AtomicBool::new(false);
                    if let Ok(outcome) =
                        crate::scanner::hash_engine::inspect_reader(file, &signatures, &cancel)
                    {
                        match outcome {
                            crate::scanner::hash_engine::InspectOutcome::Clean { size } => {
                                bytes_scanned += size;
                            }
                            crate::scanner::hash_engine::InspectOutcome::Threat {
                                size,
                                threat_name,
                                sha256,
                                md5,
                                source: _,
                            } => {
                                bytes_scanned += size;
                                let threat = Threat {
                                    id: format!(
                                        "lnx_{}_{}",
                                        chrono::Local::now().format("%Y%m%d%H%M%S"),
                                        detected_threats.len()
                                    ),
                                    path: path.clone(),
                                    threat_name: threat_name.clone(),
                                    sha256: sha256.clone(),
                                    md5: md5.clone(),
                                    file_size: size,
                                    detected_at: now_timestamp(),
                                    source: ThreatSource::WindowsMrt,
                                    quarantined: false,
                                };
                                let _ = tx.send(ScanEvent::ThreatFound {
                                    path: path.clone(),
                                    threat_name: threat_name.clone(),
                                    hash: if !sha256.is_empty() { sha256 } else { md5 },
                                });
                                detected_threats.push(threat);
                            }
                            crate::scanner::hash_engine::InspectOutcome::Cancelled => {
                                cancelled = true;
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    skipped_inaccessible += 1;
                }
            }

            if last_emit.elapsed() >= Duration::from_millis(150) {
                let _ = tx.send(ScanEvent::FileScanned(path));
                let _ = tx.send(ScanEvent::Progress {
                    scanned: files_scanned,
                    total: None,
                });
                let _ = tx.send(ScanEvent::Metrics {
                    bytes_scanned,
                    skipped_inaccessible,
                });
                last_emit = Instant::now();
            }
        }
    }

    let finished_at = now_timestamp();
    let duration_secs = start_instant.elapsed().as_secs_f64();
    let return_code = if detected_threats.is_empty() { 0 } else { 6 };

    let log_path = mrt_log_path();
    let block = format_linux_system_scan_block(
        "Sentient Linux Core Security Engine",
        "1.0.0-linux-native",
        &started_at,
        &finished_at,
        full_scan,
        return_code,
        &detected_threats,
    );
    append_system_scan_log(&log_path, &block);

    let report = parse_latest_mrt_entry(&block, Some(return_code));

    let _ = tx.send(ScanEvent::Complete {
        summary: ScanSummary {
            mode,
            target: "Local Linux System".to_string(),
            started_at,
            finished_at,
            duration_secs,
            files_scanned,
            bytes_scanned,
            threats_found: detected_threats.len(),
            skipped_inaccessible,
            cancelled,
            detected_threats,
            mrt_report: report,
        },
    });
}

/// Pure heuristic analyzer for Linux file paths and Unix permission bits.
/// Detects:
/// - `Linux.Suspicious.HiddenDropper`: Hidden executable in /tmp, /var/tmp, or /dev/shm
/// - `Linux.Suspicious.DropExecutable`: Executable in /tmp, /var/tmp, or /dev/shm
/// - `Linux.Vulnerability.WorldWritableBinary`: World-writable system binary in system bin dirs
#[allow(dead_code)]
pub fn check_linux_path_heuristics(
    path: &Path,
    is_executable: bool,
    is_world_writable: bool,
) -> Option<&'static str> {
    let path_str = path.to_str().unwrap_or("");
    let in_temp = path.starts_with("/tmp")
        || path.starts_with("/var/tmp")
        || path.starts_with("/dev/shm")
        || path_str.starts_with("/tmp/")
        || path_str.starts_with("/var/tmp/")
        || path_str.starts_with("/dev/shm/")
        || path_str == "/tmp"
        || path_str == "/var/tmp"
        || path_str == "/dev/shm";

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if in_temp && is_executable && !file_name.is_empty() {
        if file_name.starts_with('.') {
            return Some("Linux.Suspicious.HiddenDropper");
        } else {
            return Some("Linux.Suspicious.DropExecutable");
        }
    }

    let in_system_bin = path.starts_with("/bin")
        || path.starts_with("/sbin")
        || path.starts_with("/usr/bin")
        || path.starts_with("/usr/sbin")
        || path.starts_with("/usr/local/bin")
        || path_str.starts_with("/bin/")
        || path_str.starts_with("/sbin/")
        || path_str.starts_with("/usr/bin/")
        || path_str.starts_with("/usr/sbin/")
        || path_str.starts_with("/usr/local/bin/");

    if in_system_bin && is_world_writable {
        return Some("Linux.Vulnerability.WorldWritableBinary");
    }

    None
}

/// Parses a ClamAV stdout line. Returns `Some((path, threat_name))` if a threat was found.
/// Example line: `/tmp/malware.bin: Win.Test.EICAR_HDB-1 FOUND`
#[allow(dead_code)]
pub fn parse_clamav_line(line: &str) -> Option<(PathBuf, String)> {
    let trimmed = line.trim();
    if !trimmed.ends_with("FOUND") {
        return None;
    }
    let (path_part, rest) = trimmed.split_once(':')?;
    let path_clean = path_part.trim();
    if path_clean.is_empty() {
        return None;
    }
    let threat_candidate = rest.trim();
    let threat_name = if let Some(stripped) = threat_candidate.strip_suffix("FOUND") {
        stripped.trim().to_string()
    } else {
        threat_candidate.replace("FOUND", "").trim().to_string()
    };
    if threat_name.is_empty() {
        return None;
    }
    Some((PathBuf::from(path_clean), threat_name))
}

/// Formats a standardized system scan summary block compatible with the dashboard telemetry parser.
#[allow(dead_code)]
pub fn format_linux_system_scan_block(
    engine_name: &str,
    engine_ver: &str,
    started_at: &str,
    finished_at: &str,
    full_scan: bool,
    return_code: i32,
    threats: &[Threat],
) -> String {
    let mode_str = if full_scan {
        "full-scan-mode: 1"
    } else {
        "full-scan-mode: 0"
    };
    let mut out = String::new();
    out.push_str("---------------------------------------------------------------------------------------\n");
    out.push_str(&format!(
        "reboot-mode: 0, quiet-mode: 1, detect-only-mode: 0, {mode_str}, wu-mode: 0\n"
    ));
    out.push_str(&format!("{engine_name} v1.0.0\n"));
    out.push_str(&format!("Started On {started_at}\n\n"));
    out.push_str(&format!("Engine: {engine_ver}\n"));
    out.push_str("Signatures: 1.463.1.0\n");
    out.push_str(&format!(
        "Run Mode: {}\n\n",
        if full_scan {
            "Deep System Scan"
        } else {
            "Quick System Scan"
        }
    ));
    out.push_str("Results Summary:\n----------------\n");
    if threats.is_empty() {
        out.push_str("No infection found.\n");
    } else {
        for t in threats {
            out.push_str(&format!("Infection found: {}\n", t.threat_name));
            out.push_str(&format!("->File: {} (Detected)\n", t.path.display()));
        }
    }
    out.push_str(&format!("\n{engine_name} Finished On {finished_at}\n\n"));
    out.push_str(&format!("Return code: {return_code} (0x{return_code:x})\n"));
    out
}

/// Appends a formatted system scan report block to the local telemetry log.
#[allow(dead_code)]
pub fn append_system_scan_log(log_path: &Path, block: &str) {
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(file, "{block}");
    }
}

#[cfg(not(windows))]
fn which_clamscan() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("/usr/bin/clamscan"),
        PathBuf::from("/bin/clamscan"),
        PathBuf::from("/usr/local/bin/clamscan"),
    ];
    for p in &candidates {
        if p.exists() {
            return Some(p.clone());
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("clamscan");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
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

#[allow(dead_code)]
fn default_scan_type_label(full_scan: bool) -> String {
    if full_scan {
        "System Scan".to_string()
    } else {
        "Quick Scan".to_string()
    }
}

/// Decodes raw telemetry bytes supporting both UTF-8/ASCII and UTF-16LE BOM formats.
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

/// Splits telemetry log contents into individual scan run blocks delimited by dashed separator lines.
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

/// Parses the latest scan block from telemetry log text into a structured `MrtReport`.
pub fn parse_latest_mrt_entry(content: &str, fallback_exit_code: Option<i32>) -> Option<MrtReport> {
    let blocks = split_mrt_blocks(content);
    let block = blocks
        .iter()
        .rev()
        .find(|b| {
            b.contains("Started On") || b.contains("Return code:") || b.contains("Results Summary")
        })
        .or_else(|| blocks.last())?;

    Some(parse_mrt_block(block, fallback_exit_code))
}

/// Parses a single telemetry block into `MrtReport`.
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
        } else if line.starts_with("Microsoft Windows Malicious Software Removal Tool v")
            || line.starts_with("Sentient Linux Core Security Engine v")
            || line.starts_with("Sentient Linux Security Engine")
            || line.starts_with("ClamAV ")
        {
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

            // Parse infection details written by MRT or Linux Engine under Results Summary.
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

#[allow(dead_code)]
pub fn extract_path_from_detail(detail: &str) -> Option<PathBuf> {
    if let Some(pos) = detail.find(":\\") {
        let start = pos.saturating_sub(1);
        let tail = &detail[start..];
        let end = tail.find(" (").unwrap_or(tail.len());
        return Some(PathBuf::from(tail[..end].trim()));
    }
    if let Some(pos) = detail.find('/') {
        let tail = &detail[pos..];
        let end = tail.find(" (").or_else(|| tail.find(':')).unwrap_or(tail.len());
        let path_str = tail[..end].trim();
        if !path_str.is_empty() {
            return Some(PathBuf::from(path_str));
        }
    }
    None
}

#[cfg(windows)]
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

    #[test]
    fn test_parse_linux_system_scan_report() {
        let sample = r#"
---------------------------------------------------------------------------------------
reboot-mode: 0, quiet-mode: 1, detect-only-mode: 0, full-scan-mode: 0, wu-mode: 0
Sentient Linux Core Security Engine v1.0.0
Started On Mon Nov 16 10:30:00 2026

Engine: 1.0.0-linux-native
Signatures: 1.463.1.0
Run Mode: Quick System Scan

Results Summary:
----------------
Infection found: Linux.Suspicious.DropExecutable
->File: /tmp/suspicious_elf (Detected)

Sentient Linux Core Security Engine Finished On Mon Nov 16 10:30:15 2026

Return code: 6 (0x6)
"#;

        let report = parse_latest_mrt_entry(sample, None).unwrap();
        assert_eq!(report.return_code, 6);
        assert_eq!(report.return_code_hex, "0x6");
        assert_eq!(report.engine_version, "1.0.0-linux-native");
        assert_eq!(report.infected_items.len(), 2);
        assert_eq!(
            report.infected_items[0].threat_name,
            "Linux.Suspicious.DropExecutable"
        );
        assert_eq!(
            extract_path_from_detail(&report.infected_items[1].detail),
            Some(PathBuf::from("/tmp/suspicious_elf"))
        );
    }

    #[test]
    fn test_format_and_parse_linux_roundtrip() {
        let threats = vec![Threat {
            id: "t1".to_string(),
            path: PathBuf::from("/var/tmp/miner.bin"),
            threat_name: "Linux.CryptoMiner.XMR".to_string(),
            sha256: "abc".to_string(),
            md5: "def".to_string(),
            file_size: 1024,
            detected_at: "2026-11-16 10:00:00".to_string(),
            source: ThreatSource::WindowsMrt,
            quarantined: false,
        }];

        let block = format_linux_system_scan_block(
            "Sentient Linux Security Engine",
            "1.0.0-linux-native",
            "2026-11-16 10:00:00",
            "2026-11-16 10:00:05",
            false,
            6,
            &threats,
        );

        let report = parse_latest_mrt_entry(&block, Some(6)).unwrap();
        assert_eq!(report.return_code, 6);
        assert_eq!(report.infected_items[0].threat_name, "Linux.CryptoMiner.XMR");
        assert_eq!(
            extract_path_from_detail(&report.infected_items[1].detail),
            Some(PathBuf::from("/var/tmp/miner.bin"))
        );
    }

    #[test]
    fn test_check_linux_path_heuristics() {
        // Dropper in /tmp
        let p1 = PathBuf::from("/tmp/dropper.elf");
        assert_eq!(
            check_linux_path_heuristics(&p1, true, false),
            Some("Linux.Suspicious.DropExecutable")
        );
        // Non-executable in /tmp is not a dropper
        assert_eq!(check_linux_path_heuristics(&p1, false, false), None);

        // Hidden dropper in /dev/shm
        let p2 = PathBuf::from("/dev/shm/.miner");
        assert_eq!(
            check_linux_path_heuristics(&p2, true, false),
            Some("Linux.Suspicious.HiddenDropper")
        );

        // World-writable binary in /usr/bin
        let p3 = PathBuf::from("/usr/bin/sudo");
        assert_eq!(
            check_linux_path_heuristics(&p3, true, true),
            Some("Linux.Vulnerability.WorldWritableBinary")
        );
        // Normal non-world-writable binary in /bin
        let p4 = PathBuf::from("/bin/bash");
        assert_eq!(check_linux_path_heuristics(&p4, true, false), None);

        // Clean user file
        let p5 = PathBuf::from("/home/user/document.pdf");
        assert_eq!(check_linux_path_heuristics(&p5, false, false), None);
    }

    #[test]
    fn test_parse_clamav_line() {
        let line1 = "/tmp/malware.exe: Win.Test.EICAR_HDB-1 FOUND";
        assert_eq!(
            parse_clamav_line(line1),
            Some((
                PathBuf::from("/tmp/malware.exe"),
                "Win.Test.EICAR_HDB-1".to_string()
            ))
        );

        let line2 = "/home/user/test.elf: Unix.Trojan.Dropper-999 FOUND";
        assert_eq!(
            parse_clamav_line(line2),
            Some((
                PathBuf::from("/home/user/test.elf"),
                "Unix.Trojan.Dropper-999".to_string()
            ))
        );

        let clean_line = "/home/user/clean.txt: OK";
        assert_eq!(parse_clamav_line(clean_line), None);

        let summary_line = "----------- SCAN SUMMARY -----------";
        assert_eq!(parse_clamav_line(summary_line), None);
    }
}
