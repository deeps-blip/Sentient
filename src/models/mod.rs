use chrono::Local;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Overall real-time system protection status displayed on the Sentient dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionStatus {
    Protected,
    Scanning,
    ThreatsDetected,
}

impl ProtectionStatus {
    /// Human-readable label for the dashboard badge.
    pub fn label(self) -> &'static str {
        match self {
            Self::Protected => "Protected",
            Self::Scanning => "Scanning in Progress",
            Self::ThreatsDetected => "Threats Detected",
        }
    }
}

/// Supported scan workflows in Sentient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    QuickHash,
    MrtQuick,
    MrtFull,
    CustomFolder,
}

impl ScanMode {
    /// Display name shown in the UI and activity logs.
    pub fn label(self) -> &'static str {
        match self {
            Self::QuickHash => "Quick Scan",
            Self::MrtQuick => "Quick System Scan",
            Self::MrtFull => "System Scan",
            Self::CustomFolder => "Custom Scan",
        }
    }
}

/// Origin engine that flagged a threat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSource {
    HashDatabase,
    InMemoryEicar,
    WindowsMrt,
}

impl ThreatSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::HashDatabase => "Signature Engine",
            Self::InMemoryEicar => "Heuristic / EICAR",
            Self::WindowsMrt => "Sentient Core Engine",
        }
    }
}

/// Represents a detected malware item or test signature match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub path: PathBuf,
    pub threat_name: String,
    pub sha256: String,
    pub md5: String,
    pub file_size: u64,
    pub detected_at: String,
    pub source: ThreatSource,
    pub quarantined: bool,
}

/// Individual infection entry extracted from `C:\Windows\debug\mrt.log`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrtThreatEntry {
    pub threat_name: String,
    pub action: String,
    pub detail: String,
}

/// Parsed execution report from a Windows Malicious Software Removal Tool (`mrt.exe`) run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MrtReport {
    pub tool_version: String,
    pub started_on: String,
    pub finished_on: String,
    pub scan_type: String,
    pub engine_version: String,
    pub signatures_version: String,
    pub return_code: i32,
    pub return_code_hex: String,
    pub infected_items: Vec<MrtThreatEntry>,
    pub raw_summary: String,
}

/// Summary statistics emitted when a scan completes or is cancelled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub mode: ScanMode,
    pub target: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_secs: f64,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub threats_found: usize,
    pub skipped_inaccessible: usize,
    pub cancelled: bool,
    pub detected_threats: Vec<Threat>,
    pub mrt_report: Option<MrtReport>,
}

/// Complete scan outcome persisted or reviewed by the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub errors: Vec<String>,
}

/// Streaming scan progress events sent from background worker threads to the GUI thread.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    FileScanned(PathBuf),
    ThreatFound {
        path: PathBuf,
        threat_name: String,
        hash: String,
    },
    Progress {
        scanned: usize,
        total: Option<usize>,
    },
    Complete {
        summary: ScanSummary,
    },
    Error(String),
    /// Supplementary live status update (e.g., MRT execution phase).
    Status(String),
    /// Supplementary live byte/skip counters for throughput & inaccessible metrics.
    Metrics {
        bytes_scanned: u64,
        skipped_inaccessible: usize,
    },
}

/// Metadata entry persisted in `%LOCALAPPDATA%\Sentient\quarantine_index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantined_path: PathBuf,
    pub threat_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub md5: String,
    pub detected_at: String,
    pub quarantined_at: String,
    pub xor_key: u8,
}

/// Root JSON structure for `quarantine_index.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineIndex {
    pub version: u32,
    pub items: Vec<QuarantineItem>,
}

impl Default for QuarantineIndex {
    fn default() -> Self {
        Self {
            version: 1,
            items: Vec::new(),
        }
    }
}

/// Single threat signature entry stored in `signatures.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub name: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub md5: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub description: String,
}

fn default_severity() -> String {
    "High".to_string()
}

/// Local JSON threat signature database (`signatures.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDatabase {
    pub version: String,
    pub updated_at: String,
    pub signatures: Vec<ThreatSignature>,
}

/// Severity level for entries in the Activity & Threat Logs view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Threat,
}

impl LogLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Success => "OK",
            Self::Warning => "WARN",
            Self::Threat => "THREAT",
        }
    }
}

/// Chronological event recorded in Sentient's activity and threat log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLogEntry {
    pub id: u64,
    pub timestamp: String,
    pub level: LogLevel,
    pub category: String,
    pub message: String,
    pub details: Option<String>,
}

/// User-configurable scanner and quarantine preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub auto_quarantine: bool,
    pub worker_threads: usize,
    pub max_file_size_mb: u64,
    pub log_inaccessible_files: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            auto_quarantine: true,
            worker_threads: cpus,
            max_file_size_mb: 0, // 0 = no size limit (safe due to 64 KiB chunked streaming)
            log_inaccessible_files: false,
        }
    }
}

/// Persistent application state saved under `%LOCALAPPDATA%\Sentient\state.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedAppState {
    pub last_scan_date: Option<String>,
    pub last_scan_mode: Option<String>,
    pub total_files_scanned_lifetime: u64,
    pub settings: AppSettings,
    pub last_mrt_report: Option<MrtReport>,
}

/// Returns `%LOCALAPPDATA%\Sentient` on Windows, or `$XDG_DATA_HOME/sentient` (`~/.local/share/sentient`) on Linux.
pub fn sentient_data_dir() -> PathBuf {
    #[cfg(windows)]
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("Sentient");
    }

    #[cfg(unix)]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("sentient");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local").join("share").join("sentient");
        }
    }

    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        return PathBuf::from(home).join(".sentient");
    }
    std::env::temp_dir().join("Sentient")
}

/// Formats the current local timestamp consistently across logs and UI cards.
pub fn now_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Formats byte counts into human-readable units.
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}
