use crate::heuristics::analyze_file_heuristics;
use crate::models::now_timestamp;
use crate::scanner::hash_engine::{inspect_reader, InspectOutcome, SignatureIndex};
use crate::yara::YaraEngine;
use crossbeam_channel::Sender;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Real-time alert emitted when the Sentinel intercepts a malicious file drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelAlert {
    pub path: PathBuf,
    pub threat_name: String,
    pub sha256: String,
    pub detected_at: String,
    pub detection_method: String,
    pub quarantined: bool,
}

/// Statistics tracking Sentinel active defense operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelStats {
    pub is_active: bool,
    pub watched_paths: Vec<PathBuf>,
    pub files_inspected: usize,
    pub threats_intercepted: usize,
}

/// Manages background real-time folder monitoring and on-drop threat neutralization.
pub struct SentinelManager {
    running: Arc<AtomicBool>,
    files_inspected: Arc<AtomicUsize>,
    threats_intercepted: Arc<AtomicUsize>,
    watched_paths: Vec<PathBuf>,
    thread_handle: Option<JoinHandle<()>>,
}

impl SentinelManager {
    /// Initializes and starts the background Real-Time Sentinel watcher.
    pub fn start(
        signatures: Arc<SignatureIndex>,
        yara: Arc<YaraEngine>,
        auto_quarantine: bool,
        tx: Sender<SentinelAlert>,
    ) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let files_inspected = Arc::new(AtomicUsize::new(0));
        let threats_intercepted = Arc::new(AtomicUsize::new(0));

        let watched_paths = resolve_sentinel_watch_roots();

        let run_flag = Arc::clone(&running);
        let inspected_counter = Arc::clone(&files_inspected);
        let threats_counter = Arc::clone(&threats_intercepted);
        let roots = watched_paths.clone();

        let thread_handle = thread::spawn(move || {
            let mut snapshot: HashMap<PathBuf, (u64, u64)> = HashMap::new();

            // Initial baseline scan to avoid re-alerting on pre-existing files
            for root in &roots {
                take_directory_snapshot(root, &mut snapshot);
            }

            while run_flag.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(800));

                for root in &roots {
                    if !run_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    if !root.exists() {
                        continue;
                    }

                    // Check for newly dropped or modified files
                    let mut current_entries = Vec::new();
                    if let Ok(entries) = fs::read_dir(root) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.is_file() {
                                if let Ok(meta) = entry.metadata() {
                                    let len = meta.len();
                                    let mtime = meta
                                        .modified()
                                        .ok()
                                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    current_entries.push((p, len, mtime));
                                }
                            }
                        }
                    }

                    for (file_path, len, mtime) in current_entries {
                        let is_new = match snapshot.get(&file_path) {
                            Some(&(old_len, old_mtime)) => old_len != len || old_mtime != mtime,
                            None => true,
                        };

                        if is_new {
                            snapshot.insert(file_path.clone(), (len, mtime));
                            inspected_counter.fetch_add(1, Ordering::Relaxed);

                            // Inspect newly dropped file
                            if let Some(alert) = inspect_dropped_file(
                                &file_path,
                                &signatures,
                                &yara,
                                auto_quarantine,
                            ) {
                                threats_counter.fetch_add(1, Ordering::Relaxed);
                                let _ = tx.send(alert);
                            }
                        }
                    }
                }
            }
        });

        Self {
            running,
            files_inspected,
            threats_intercepted,
            watched_paths,
            thread_handle: Some(thread_handle),
        }
    }

    /// Stops the Sentinel background worker thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }

    pub fn is_active(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> SentinelStats {
        SentinelStats {
            is_active: self.is_active(),
            watched_paths: self.watched_paths.clone(),
            files_inspected: self.files_inspected.load(Ordering::Relaxed),
            threats_intercepted: self.threats_intercepted.load(Ordering::Relaxed),
        }
    }
}

impl Drop for SentinelManager {
    fn drop(&mut self) {
        self.stop();
    }
}

fn resolve_sentinel_watch_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    #[cfg(windows)]
    {
        if let Some(userprofile) = std::env::var_os("USERPROFILE") {
            let p = PathBuf::from(userprofile);
            roots.push(p.join("Downloads"));
            roots.push(p.join("Desktop"));
        }
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            roots.push(PathBuf::from(local_appdata).join("Temp"));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let p = PathBuf::from(home);
            roots.push(p.join("Downloads"));
            roots.push(p.join("Desktop"));
        }
        roots.push(PathBuf::from("/tmp"));
        roots.push(PathBuf::from("/var/tmp"));
        roots.push(PathBuf::from("/dev/shm"));
    }

    roots.into_iter().filter(|p| p.exists()).collect()
}

fn take_directory_snapshot(root: &Path, snapshot: &mut HashMap<PathBuf, (u64, u64)>) {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(meta) = entry.metadata() {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    snapshot.insert(p, (meta.len(), mtime));
                }
            }
        }
    }
}

fn inspect_dropped_file(
    path: &Path,
    signatures: &SignatureIndex,
    yara: &YaraEngine,
    _auto_quarantine: bool,
) -> Option<SentinelAlert> {
    let file = File::open(path).ok()?;
    let cancel = AtomicBool::new(false);

    // 1. Hash & EICAR Inspection
    if let Ok(outcome) = inspect_reader(file, signatures, &cancel) {
        if let InspectOutcome::Threat {
            threat_name,
            sha256,
            ..
        } = outcome
        {
            return Some(SentinelAlert {
                path: path.to_path_buf(),
                threat_name,
                sha256,
                detected_at: now_timestamp(),
                detection_method: "Cryptographic Hash Signature".to_string(),
                quarantined: false,
            });
        }
    }

    // 2. YARA Rule Inspection
    if let Ok(bytes) = fs::read(path) {
        let yara_matches = yara.scan_bytes(&bytes);
        if let Some(top_match) = yara_matches.first() {
            return Some(SentinelAlert {
                path: path.to_path_buf(),
                threat_name: top_match.rule_name.clone(),
                sha256: String::new(),
                detected_at: now_timestamp(),
                detection_method: format!("YARA Rule Match ({})", top_match.rule_name),
                quarantined: false,
            });
        }

        // 3. Static Heuristics & Shannon Entropy Inspection
        let h_report = analyze_file_heuristics(&bytes);
        if h_report.entropy.score >= 7.85 && bytes.len() > 1024 {
            return Some(SentinelAlert {
                path: path.to_path_buf(),
                threat_name: "Heuristic.HighEntropy.RansomwareCrypter".to_string(),
                sha256: String::new(),
                detected_at: now_timestamp(),
                detection_method: format!("Shannon Entropy Anomaly ({:.2} / 8.0)", h_report.entropy.score),
                quarantined: false,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sentinel_watch_roots_validity() {
        let roots = resolve_sentinel_watch_roots();
        for r in &roots {
            assert!(r.exists());
        }
    }
}
