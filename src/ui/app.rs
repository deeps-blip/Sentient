use crate::heuristics::{inspect_file_heuristics, HeuristicReport};
use crate::models::{
    format_bytes, now_timestamp, sentient_data_dir, ActivityLogEntry, LogLevel, MrtReport,
    PersistedAppState, ProtectionStatus, ScanEvent, ScanMode, ScanResult, Threat, ThreatSignature,
};
use crate::network::{scan_active_network_sockets, NetworkSocketEntry, SocketProtocol};
use crate::platform;
use crate::process::{audit_running_processes, kill_process, ProcessAuditItem, ProcessRisk};
use crate::quarantine::manager::QuarantineManager;
use crate::reports::{generate_html_report, generate_stix21_bundle};
use crate::scanner::hash_engine::{
    quick_scan_roots, run_hash_scan, run_in_memory_eicar_self_test, SignatureIndex, SignatureStore,
};
use crate::scanner::scanner::{
    mrt_executable_path, mrt_log_path, read_latest_mrt_report, run_mrt_scan,
};
use crate::sentinel::{SentinelAlert, SentinelManager};
use crate::usb::{detect_removable_drives, immunize_drive, UsbDriveInfo};
use crate::yara::{parse_yara_source, YaraEngine, YaraMatch};
use crossbeam_channel::{unbounded, Receiver};
use eframe::egui::{
    self, Align, Color32, CornerRadius, Frame, Layout, Margin, Pos2, Rect, RichText, ScrollArea,
    Stroke, Vec2,
};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const LOGO_PNG_BYTES: &[u8] = include_bytes!("../../assets/logo.png");
const MAX_LOG_ENTRIES: usize = 1000;

// Modern Next-Gen Cybersecurity Palette (Obsidian / Midnight / Electric Cyber Cyan)
const BG_APP: Color32 = Color32::from_rgb(10, 14, 23);
const BG_SIDEBAR: Color32 = Color32::from_rgb(14, 20, 33);
const BG_TOPBAR: Color32 = Color32::from_rgb(13, 18, 30);
const BG_CARD: Color32 = Color32::from_rgb(20, 28, 45);
const BG_ELEVATED: Color32 = Color32::from_rgb(26, 37, 58);
const BG_HERO_SAFE: Color32 = Color32::from_rgb(14, 34, 42);
const BG_HERO_SCAN: Color32 = Color32::from_rgb(15, 32, 54);
const BG_HERO_THREAT: Color32 = Color32::from_rgb(48, 20, 28);

const BORDER_SUBTLE: Color32 = Color32::from_rgb(38, 52, 78);
const BORDER_BRIGHT: Color32 = Color32::from_rgb(58, 80, 118);

// Accents
const ACCENT_CYAN: Color32 = Color32::from_rgb(34, 211, 238);
const ACCENT_CYAN_BTN: Color32 = Color32::from_rgb(14, 165, 233);
const ACCENT_INDIGO: Color32 = Color32::from_rgb(129, 140, 248);
const ACCENT_TEAL: Color32 = Color32::from_rgb(45, 212, 191);
const ACCENT_GREEN: Color32 = Color32::from_rgb(16, 185, 129);
const ACCENT_GREEN_SOFT: Color32 = Color32::from_rgb(110, 231, 183);
const ACCENT_AMBER: Color32 = Color32::from_rgb(245, 158, 11);
const ACCENT_AMBER_SOFT: Color32 = Color32::from_rgb(252, 211, 77);
const ACCENT_RED: Color32 = Color32::from_rgb(239, 68, 68);
const ACCENT_RED_DARK: Color32 = Color32::from_rgb(153, 27, 27);
const ACCENT_RED_SOFT: Color32 = Color32::from_rgb(252, 165, 165);

// Controls
const BTN_SECONDARY_BG: Color32 = Color32::from_rgb(34, 48, 74);
const BTN_NAV_ACTIVE_BG: Color32 = Color32::from_rgb(24, 39, 64);
const TEXT_ON_ACCENT: Color32 = Color32::from_rgb(8, 13, 24);

// Typography
const TEXT_PRIMARY: Color32 = Color32::from_rgb(248, 250, 252);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(203, 213, 225);
const TEXT_MUTED: Color32 = Color32::from_rgb(148, 163, 184);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NavTab {
    Dashboard,
    ScanCenter,
    LiveSentinel,
    ProcessAudit,
    NetworkSockets,
    YaraHeuristics,
    Quarantine,
    ActivityLogs,
    Preferences,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFilter {
    All,
    Threats,
    Warnings,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureIcon {
    QuickBolt,
    DeepShield,
    CustomTarget,
    VaultLock,
    PulseCheck,
    AuditTerminal,
}

struct ActiveScanState {
    mode: ScanMode,
    target: String,
    started_at: Instant,
    cancel_flag: Arc<AtomicBool>,
    rx: Receiver<ScanEvent>,
    current_file: String,
    status_text: String,
    files_scanned: usize,
    total_files: Option<usize>,
    bytes_scanned: u64,
    threats_found: usize,
    skipped_inaccessible: usize,
    auto_quarantined_paths: HashSet<PathBuf>,
    errors: Vec<String>,
}

/// Main Sentient desktop application state rendered by `eframe`.
pub struct SentientApp {
    active_tab: NavTab,
    is_elevated: bool,
    logo_texture: Option<egui::TextureHandle>,

    persisted: PersistedAppState,
    quarantine: QuarantineManager,
    sig_store: SignatureStore,
    signatures: Arc<SignatureIndex>,
    logs: Vec<ActivityLogEntry>,
    next_log_id: u64,

    active_scan: Option<ActiveScanState>,
    last_result: Option<ScanResult>,
    active_threats: Vec<Threat>,

    // Scan center & dialog inputs
    custom_folder_input: String,
    folder_rx: Option<Receiver<Option<PathBuf>>>,
    folder_picker_pending: bool,

    // Quarantine UI confirmations
    pending_delete_id: Option<String>,
    confirm_purge_all: bool,

    // Log UI filters
    log_filter: LogFilter,
    log_search: String,

    // Preferences / Custom signature editor
    new_sig_name: String,
    new_sig_sha256: String,
    new_sig_md5: String,
    new_sig_severity: String,
    banner_feedback: Option<(String, bool)>,

    // Active Defense & YARA
    yara_engine: Arc<YaraEngine>,
    sentinel_manager: Option<SentinelManager>,
    sentinel_rx: Option<Receiver<SentinelAlert>>,
    sentinel_alerts: Vec<SentinelAlert>,
    sentinel_enabled: bool,

    // Process & Network
    process_items: Vec<ProcessAuditItem>,
    process_search: String,
    socket_items: Vec<NetworkSocketEntry>,
    socket_search: String,
    usb_drives: Vec<UsbDriveInfo>,

    // Static Heuristics & Custom YARA
    heuristic_target: String,
    heuristic_report: Option<HeuristicReport>,
    yara_rule_input: String,
    yara_target_file: String,
    yara_match_results: Vec<YaraMatch>,
}

impl SentientApp {
    /// Initializes app state, loads logo texture & local JSON databases, and checks Windows privileges.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_sentient_theme(&cc.egui_ctx);
        let logo_texture = load_logo_texture(&cc.egui_ctx);

        let is_elevated = platform::is_elevated();
        let data_dir = sentient_data_dir();
        let _ = fs::create_dir_all(&data_dir);

        let mut persisted = load_persisted_state();
        if let Ok(report) = read_latest_mrt_report() {
            persisted.last_mrt_report = Some(report);
        }

        let sig_store = SignatureStore::new();
        let signatures = Arc::new(sig_store.load_or_seed().unwrap_or_else(|_| {
            SignatureIndex::from_database(crate::models::SignatureDatabase {
                version: "fallback".to_string(),
                updated_at: now_timestamp(),
                signatures: Vec::new(),
            })
        }));

        let quarantine = QuarantineManager::new().unwrap_or_else(|_| {
            let fallback_dir = std::env::temp_dir().join("SentientFallback");
            QuarantineManager::with_paths(
                fallback_dir.join("Quarantine"),
                fallback_dir.join("quarantine_index.json"),
            )
            .expect("Fallback temp quarantine creation failed")
        });

        let logs = load_activity_logs();
        let next_log_id = logs.iter().map(|l| l.id).max().unwrap_or(0) + 1;

        let default_folder = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(|p| PathBuf::from(p).join("Downloads").display().to_string())
            .unwrap_or_else(|| {
                if cfg!(windows) {
                    r"C:\Users".to_string()
                } else {
                    "/home".to_string()
                }
            });

        let yara_engine = Arc::new(YaraEngine::new());
        let (sentinel_tx, sentinel_rx) = unbounded();
        let sentinel_manager = Some(SentinelManager::start(
            Arc::clone(&signatures),
            Arc::clone(&yara_engine),
            persisted.settings.auto_quarantine,
            sentinel_tx,
        ));
        let usb_drives = detect_removable_drives();

        let mut app = Self {
            active_tab: NavTab::Dashboard,
            is_elevated,
            logo_texture,
            persisted,
            quarantine,
            sig_store,
            signatures,
            logs,
            next_log_id,
            active_scan: None,
            last_result: None,
            active_threats: Vec::new(),
            custom_folder_input: default_folder,
            folder_rx: None,
            folder_picker_pending: false,
            pending_delete_id: None,
            confirm_purge_all: false,
            log_filter: LogFilter::All,
            log_search: String::new(),
            new_sig_name: String::new(),
            new_sig_sha256: String::new(),
            new_sig_md5: String::new(),
            new_sig_severity: "High".to_string(),
            banner_feedback: None,
            yara_engine,
            sentinel_manager,
            sentinel_rx: Some(sentinel_rx),
            sentinel_alerts: Vec::new(),
            sentinel_enabled: true,
            process_items: Vec::new(),
            process_search: String::new(),
            socket_items: Vec::new(),
            socket_search: String::new(),
            usb_drives,
            heuristic_target: String::new(),
            heuristic_report: None,
            yara_rule_input: String::new(),
            yara_target_file: String::new(),
            yara_match_results: Vec::new(),
        };

        if app.logs.is_empty() {
            app.push_log(
                LogLevel::Info,
                "System",
                format!(
                    "Sentient initialized ({} offline signatures loaded, mode: {}).",
                    app.signatures.len(),
                    if is_elevated {
                        "Administrator"
                    } else {
                        "Standard User"
                    }
                ),
                None,
            );
        }

        app
    }

    fn protection_status(&self) -> ProtectionStatus {
        if self.active_scan.is_some() {
            ProtectionStatus::Scanning
        } else if self.active_threats.iter().any(|t| !t.quarantined) {
            ProtectionStatus::ThreatsDetected
        } else {
            ProtectionStatus::Protected
        }
    }

    fn push_log(
        &mut self,
        level: LogLevel,
        category: impl Into<String>,
        message: impl Into<String>,
        details: Option<String>,
    ) {
        let entry = ActivityLogEntry {
            id: self.next_log_id,
            timestamp: now_timestamp(),
            level,
            category: category.into(),
            message: message.into(),
            details,
        };
        self.next_log_id += 1;
        self.logs.insert(0, entry);
        if self.logs.len() > MAX_LOG_ENTRIES {
            self.logs.truncate(MAX_LOG_ENTRIES);
        }
        save_activity_logs(&self.logs);
    }

    fn save_state(&self) {
        save_persisted_state(&self.persisted);
    }

    fn start_hash_scan(&mut self, mode: ScanMode, roots: Vec<PathBuf>, target_label: String) {
        if self.active_scan.is_some() {
            return;
        }

        let (tx, rx) = unbounded();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let q_dir = self.quarantine.quarantine_dir().to_path_buf();
        let sigs = Arc::clone(&self.signatures);
        let threads = self.persisted.settings.worker_threads;
        let max_bytes = (self.persisted.settings.max_file_size_mb > 0)
            .then_some(self.persisted.settings.max_file_size_mb * 1024 * 1024);
        let log_inaccessible = self.persisted.settings.log_inaccessible_files;

        self.push_log(
            LogLevel::Info,
            "Scanner",
            format!("Started {}: {}", mode.label(), target_label),
            Some(format!("Worker threads: {threads}")),
        );

        let cancel_clone = Arc::clone(&cancel_flag);
        let target_clone = target_label.clone();
        std::thread::spawn(move || {
            run_hash_scan(
                roots,
                mode,
                target_clone,
                q_dir,
                sigs,
                threads,
                max_bytes,
                log_inaccessible,
                cancel_clone,
                tx,
            );
        });

        self.active_scan = Some(ActiveScanState {
            mode,
            target: target_label,
            started_at: Instant::now(),
            cancel_flag,
            rx,
            current_file: "Initializing directory walker...".to_string(),
            status_text: "Starting multithreaded scan...".to_string(),
            files_scanned: 0,
            total_files: None,
            bytes_scanned: 0,
            threats_found: 0,
            skipped_inaccessible: 0,
            auto_quarantined_paths: HashSet::new(),
            errors: Vec::new(),
        });
        self.active_tab = NavTab::ScanCenter;
        self.banner_feedback = None;
    }

    fn start_system_engine_scan(&mut self, full_scan: bool) {
        if self.active_scan.is_some() {
            return;
        }

        let mode = if full_scan {
            ScanMode::MrtFull
        } else {
            ScanMode::MrtQuick
        };
        let target = "Local System (All Drives & Critical Areas)".to_string();

        self.push_log(
            LogLevel::Info,
            "System Engine",
            format!("Started {}", mode.label()),
            Some("Deep signature & heuristic system inspection active".to_string()),
        );

        let (tx, rx) = unbounded();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel_flag);

        std::thread::spawn(move || {
            run_mrt_scan(full_scan, cancel_clone, tx);
        });

        self.active_scan = Some(ActiveScanState {
            mode,
            target,
            started_at: Instant::now(),
            cancel_flag,
            rx,
            current_file: "Sentient Core System Engine".to_string(),
            status_text: "Initializing deep system inspection...".to_string(),
            files_scanned: 0,
            total_files: None,
            bytes_scanned: 0,
            threats_found: 0,
            skipped_inaccessible: 0,
            auto_quarantined_paths: HashSet::new(),
            errors: Vec::new(),
        });
        self.active_tab = NavTab::ScanCenter;
        self.banner_feedback = None;
    }

    fn cancel_active_scan(&mut self) {
        if let Some(ref mut scan) = self.active_scan {
            scan.cancel_flag.store(true, Ordering::Relaxed);
            scan.status_text = "Cancellation requested — stopping workers...".to_string();
        }
    }

    fn open_folder_picker(&mut self, ctx: &egui::Context) {
        if self.folder_picker_pending {
            return;
        }
        let (tx, rx) = unbounded();
        let initial_dir = PathBuf::from(&self.custom_folder_input);
        let ctx_clone = ctx.clone();

        self.folder_rx = Some(rx);
        self.folder_picker_pending = true;

        std::thread::spawn(move || {
            let mut dialog = rfd::FileDialog::new().set_title("Select Folder for Sentient Scan");
            if initial_dir.exists() {
                dialog = dialog.set_directory(&initial_dir);
            }
            let chosen = dialog.pick_folder();
            let _ = tx.send(chosen);
            ctx_clone.request_repaint();
        });
    }

    fn drain_background_channels(&mut self) {
        if let Some(ref rx) = self.folder_rx {
            if let Ok(maybe_path) = rx.try_recv() {
                if let Some(path) = maybe_path {
                    self.custom_folder_input = path.display().to_string();
                }
                self.folder_rx = None;
                self.folder_picker_pending = false;
            }
        }

        let mut finished_summary: Option<crate::models::ScanSummary> = None;
        let mut pending_auto_quarantine: Vec<(PathBuf, String, String)> = Vec::new();
        let mut pending_logs: Vec<(LogLevel, String, String, Option<String>)> = Vec::new();

        if let Some(ref mut scan) = self.active_scan {
            while let Ok(event) = scan.rx.try_recv() {
                match event {
                    ScanEvent::FileScanned(path) => {
                        scan.current_file = path.display().to_string();
                    }
                    ScanEvent::Progress { scanned, total } => {
                        scan.files_scanned = scanned;
                        scan.total_files = total;
                    }
                    ScanEvent::Metrics {
                        bytes_scanned,
                        skipped_inaccessible,
                    } => {
                        scan.bytes_scanned = bytes_scanned;
                        scan.skipped_inaccessible = skipped_inaccessible;
                    }
                    ScanEvent::Status(msg) => {
                        scan.status_text = msg;
                    }
                    ScanEvent::ThreatFound {
                        path,
                        threat_name,
                        hash,
                    } => {
                        scan.threats_found += 1;
                        pending_logs.push((
                            LogLevel::Threat,
                            "Threat Match".to_string(),
                            format!("Detected '{}' at '{}'", threat_name, path.display()),
                            Some(format!("Indicator: {hash}")),
                        ));
                        if self.persisted.settings.auto_quarantine
                            && path.exists()
                            && !hash.starts_with("SYS-ENG:")
                        {
                            pending_auto_quarantine.push((path, threat_name, hash));
                        }
                    }
                    ScanEvent::Error(err) => {
                        if scan.errors.len() < 50 {
                            scan.errors.push(err.clone());
                        }
                        pending_logs.push((LogLevel::Warning, "Scanner".to_string(), err, None));
                    }
                    ScanEvent::Complete { summary } => {
                        finished_summary = Some(summary);
                        break;
                    }
                }
            }
        }

        for (lvl, cat, msg, det) in pending_logs {
            self.push_log(lvl, cat, msg, det);
        }

        for (path, threat_name, hash) in pending_auto_quarantine {
            match self
                .quarantine
                .quarantine_file(&path, &threat_name, &hash, "")
            {
                Ok(item) => {
                    if let Some(ref mut scan) = self.active_scan {
                        scan.auto_quarantined_paths.insert(path.clone());
                    }
                    self.push_log(
                        LogLevel::Success,
                        "Auto-Quarantine",
                        format!(
                            "Isolated '{}' -> '{}'",
                            threat_name,
                            item.quarantined_path.display()
                        ),
                        Some(format!("Original: {}", path.display())),
                    );
                }
                Err(e) => {
                    self.push_log(
                        LogLevel::Warning,
                        "Auto-Quarantine",
                        format!("Failed to auto-quarantine '{}': {e}", path.display()),
                        None,
                    );
                }
            }
        }

        if let Some(mut summary) = finished_summary {
            let (auto_paths, scan_errors) = self
                .active_scan
                .as_ref()
                .map(|s| (s.auto_quarantined_paths.clone(), s.errors.clone()))
                .unwrap_or_default();

            self.active_scan = None;

            for threat in &mut summary.detected_threats {
                if auto_paths.contains(&threat.path) {
                    threat.quarantined = true;
                }
            }

            for threat in &summary.detected_threats {
                if !threat.quarantined
                    && !self
                        .active_threats
                        .iter()
                        .any(|t| t.path == threat.path && t.threat_name == threat.threat_name)
                {
                    self.active_threats.push(threat.clone());
                }
            }

            self.persisted.last_scan_date = Some(summary.finished_at.clone());
            self.persisted.last_scan_mode = Some(summary.mode.label().to_string());
            self.persisted.total_files_scanned_lifetime += summary.files_scanned as u64;
            if let Some(ref report) = summary.mrt_report {
                self.persisted.last_mrt_report = Some(report.clone());
            }
            self.save_state();

            let log_level = if summary.threats_found > 0 {
                LogLevel::Threat
            } else if summary.cancelled {
                LogLevel::Warning
            } else {
                LogLevel::Success
            };

            let status_word = if summary.cancelled {
                "cancelled"
            } else {
                "completed"
            };
            let details = summary.mrt_report.as_ref().map(|r| {
                format!(
                    "Engine {} | Sigs {} | Status {} ({}) | {}",
                    r.engine_version,
                    r.signatures_version,
                    r.return_code,
                    r.return_code_hex,
                    r.raw_summary.replace('\n', " | ")
                )
            });

            self.push_log(
                log_level,
                "Scan Summary",
                format!(
                    "{} {} in {:.2}s — {} items ({}) scanned, {} threats found, {} skipped.",
                    summary.mode.label(),
                    status_word,
                    summary.duration_secs,
                    summary.files_scanned,
                    format_bytes(summary.bytes_scanned),
                    summary.threats_found,
                    summary.skipped_inaccessible
                ),
                details,
            );

            self.last_result = Some(ScanResult {
                summary,
                errors: scan_errors,
            });
        }

        let mut drained_sentinel_alerts = Vec::new();
        if let Some(ref rx) = self.sentinel_rx {
            while let Ok(alert) = rx.try_recv() {
                drained_sentinel_alerts.push(alert);
            }
        }

        for alert in drained_sentinel_alerts {
            self.push_log(
                LogLevel::Threat,
                "Live Sentinel",
                format!(
                    "Intercepted {} at '{}' ({})",
                    alert.threat_name,
                    alert.path.display(),
                    alert.detection_method
                ),
                Some(format!("SHA256: {}", alert.sha256)),
            );
            if alert.quarantined {
                self.push_log(
                    LogLevel::Success,
                    "Sentinel Quarantine",
                    format!("Quarantined dropped file '{}'", alert.path.display()),
                    None,
                );
            }
            self.sentinel_alerts.insert(0, alert);
            if self.sentinel_alerts.len() > 100 {
                self.sentinel_alerts.truncate(100);
            }
        }
    }

    fn quarantine_active_threat(&mut self, idx: usize) {
        if idx >= self.active_threats.len() {
            return;
        }
        let threat = self.active_threats[idx].clone();
        match self.quarantine.quarantine_file(
            &threat.path,
            &threat.threat_name,
            &threat.sha256,
            &threat.md5,
        ) {
            Ok(item) => {
                self.active_threats[idx].quarantined = true;
                self.banner_feedback = Some((
                    format!("Quarantined '{}' safely.", threat.threat_name),
                    false,
                ));
                self.push_log(
                    LogLevel::Success,
                    "Quarantine",
                    format!(
                        "Quarantined '{}' -> '{}'",
                        threat.threat_name,
                        item.quarantined_path.display()
                    ),
                    Some(format!("SHA-256: {}", item.sha256)),
                );
            }
            Err(err) => {
                self.banner_feedback = Some((err.clone(), true));
                self.push_log(LogLevel::Warning, "Quarantine", err, None);
            }
        }
    }

    fn run_eicar_diagnostic(&mut self) {
        match run_in_memory_eicar_self_test(&self.signatures) {
            Ok(threat) => {
                let msg = format!(
                    "In-memory EICAR self-test PASSED: detected '{}' (SHA-256: {})",
                    threat.threat_name, threat.sha256
                );
                self.banner_feedback = Some((msg.clone(), false));
                self.push_log(
                    LogLevel::Success,
                    "Self-Test",
                    msg,
                    Some(
                        "Verified 64 KiB streaming SHA-256, MD5, and in-memory EICAR inspection."
                            .into(),
                    ),
                );
            }
            Err(err) => {
                self.banner_feedback = Some((err.clone(), true));
                self.push_log(LogLevel::Warning, "Self-Test", err, None);
            }
        }
    }
}

impl eframe::App for SentientApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_background_channels();
        if self.active_scan.is_some() || self.folder_picker_pending {
            ctx.request_repaint_after(Duration::from_millis(16));
        } else {
            // Gentle ambient radar pulse when idle on dashboard
            ctx.request_repaint_after(Duration::from_millis(48));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let sidebar_frame = Frame::new()
            .fill(BG_SIDEBAR)
            .inner_margin(Margin::symmetric(14, 18))
            .stroke(Stroke::new(1.0, BORDER_SUBTLE));

        egui::Panel::left("sentient_sidebar")
            .exact_size(242.0)
            .resizable(false)
            .frame(sidebar_frame)
            .show(ui, |ui| {
                self.render_sidebar(ui);
            });

        let central_frame = Frame::new().fill(BG_APP).inner_margin(Margin::same(0));

        egui::CentralPanel::default()
            .frame(central_frame)
            .show(ui, |ui| {
                self.render_top_header(ui);

                Frame::new()
                    .fill(Color32::TRANSPARENT)
                    .inner_margin(Margin::symmetric(24, 18))
                    .show(ui, |ui| {
                        if let Some((msg, is_err)) = self.banner_feedback.clone() {
                            self.render_feedback_banner(ui, &msg, is_err);
                            ui.add_space(14.0);
                        }

                        ScrollArea::vertical().auto_shrink([false, false]).show(
                            ui,
                            |ui| match self.active_tab {
                                NavTab::Dashboard => self.render_dashboard(ui),
                                NavTab::ScanCenter => self.render_scan_center(ui),
                                NavTab::LiveSentinel => self.render_live_sentinel(ui),
                                NavTab::ProcessAudit => self.render_process_audit(ui),
                                NavTab::NetworkSockets => self.render_network_sockets(ui),
                                NavTab::YaraHeuristics => self.render_yara_heuristics(ui),
                                NavTab::Quarantine => self.render_quarantine_manager(ui),
                                NavTab::ActivityLogs => self.render_activity_logs(ui),
                                NavTab::Preferences => self.render_preferences(ui),
                            },
                        );
                    });
            });
    }
}

impl SentientApp {
    fn render_top_header(&self, ui: &mut egui::Ui) {
        let (title, subtitle) = match self.active_tab {
            NavTab::Dashboard => (
                "Security Overview",
                "Real-time offline endpoint status, threat diagnostics, and vault telemetry",
            ),
            NavTab::ScanCenter => (
                "Scan Center",
                "Multithreaded SHA-256 inspection & deep local system verification",
            ),
            NavTab::LiveSentinel => (
                "Live Sentinel & USB Guard",
                "Real-time drop interception, removable drive immunization, and air-gap defense",
            ),
            NavTab::ProcessAudit => (
                "Live Process & Memory Audit",
                "Active PID threat evaluation, masquerade detection, and instant termination",
            ),
            NavTab::NetworkSockets => (
                "Network Socket & C2 Auditor",
                "Listening endpoints, covert port heuristics, and reverse shell detection",
            ),
            NavTab::YaraHeuristics => (
                "YARA & Heuristics Engine",
                "Pure-Rust pattern matching, Shannon entropy calculation, and PE/ELF inspection",
            ),
            NavTab::Quarantine => (
                "Quarantine Vault",
                "Isolated threats scrambled with XOR 0x5A and locked from execution",
            ),
            NavTab::ActivityLogs => (
                "Threat & Activity Audit",
                "Chronological record of security scans, matches, and containment actions",
            ),
            NavTab::Preferences => (
                "Engine Preferences",
                "Worker concurrency, auto-quarantine rules, and local IOC intelligence",
            ),
        };

        Frame::new()
            .fill(BG_TOPBAR)
            .inner_margin(Margin::symmetric(24, 14))
            .stroke(Stroke::new(1.0, BORDER_SUBTLE))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(title)
                                .strong()
                                .size(22.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(subtitle)
                                .size(12.5)
                                .color(TEXT_MUTED),
                        );
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let status = self.protection_status();
                        let (badge_color, badge_bg) = match status {
                            ProtectionStatus::Protected => {
                                (ACCENT_GREEN, Color32::from_rgb(13, 46, 38))
                            }
                            ProtectionStatus::Scanning => {
                                (ACCENT_CYAN, Color32::from_rgb(15, 42, 62))
                            }
                            ProtectionStatus::ThreatsDetected => {
                                (ACCENT_RED_SOFT, Color32::from_rgb(76, 22, 28))
                            }
                        };
                        Frame::new()
                            .fill(badge_bg)
                            .stroke(Stroke::new(1.0, badge_color))
                            .corner_radius(CornerRadius::same(16))
                            .inner_margin(Margin::symmetric(14, 7))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let (dot_rect, _) = ui.allocate_exact_size(
                                        Vec2::new(8.0, 8.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().circle_filled(
                                        dot_rect.center(),
                                        4.0,
                                        badge_color,
                                    );
                                    ui.add_space(4.0);
                                    ui.label(
                                        RichText::new(status.label())
                                            .strong()
                                            .size(12.5)
                                            .color(badge_color),
                                    );
                                });
                            });
                    });
                });
            });
    }

    fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        // Mandatory Sentient Metallic Horned Helmet Logo inside a modern circular emblem halo
        ui.vertical_centered(|ui| {
            let halo_size = Vec2::new(112.0, 112.0);
            let (rect, _) = ui.allocate_exact_size(halo_size, egui::Sense::hover());
            let center = rect.center();
            ui.painter()
                .circle_filled(center, 54.0, Color32::from_rgb(52, 68, 92));
            ui.painter()
                .circle_stroke(center, 54.0, Stroke::new(1.5, ACCENT_CYAN));
            ui.painter().circle_stroke(
                center,
                50.0,
                Stroke::new(1.0, Color32::from_rgba_unmultiplied(34, 211, 238, 80)),
            );

            if let Some(ref tex) = self.logo_texture {
                let img_rect = Rect::from_center_size(center, Vec2::new(88.0, 86.0));
                egui::Image::new(tex)
                    .fit_to_exact_size(Vec2::new(88.0, 86.0))
                    .paint_at(ui, img_rect);
            }

            ui.add_space(10.0);
            ui.label(
                RichText::new("SENTIENT")
                    .strong()
                    .size(20.0)
                    .color(TEXT_PRIMARY),
            );
            ui.label(
                RichText::new("ENDPOINT DEFENSE")
                    .strong()
                    .size(10.0)
                    .color(ACCENT_CYAN),
            );
        });

        ui.add_space(18.0);

        let line_rect = ui.available_rect_before_wrap();
        ui.painter().line_segment(
            [line_rect.left_top(), line_rect.right_top()],
            Stroke::new(1.0, BORDER_SUBTLE),
        );
        ui.add_space(14.0);

        let q_count = self.quarantine.items().len();
        let threat_count = self
            .active_threats
            .iter()
            .filter(|t| !t.quarantined)
            .count();

        let sentinel_count = self.sentinel_alerts.len();
        let nav_items: [(NavTab, &str, &str, Option<(usize, Color32)>); 8] = [
            (NavTab::Dashboard, "Dashboard", "HOME", None),
            (
                NavTab::ScanCenter,
                "Scan Center",
                "SCAN",
                (threat_count > 0).then_some((threat_count, ACCENT_RED)),
            ),
            (
                NavTab::LiveSentinel,
                "Live Sentinel",
                "GUARD",
                (sentinel_count > 0).then_some((sentinel_count, ACCENT_CYAN)),
            ),
            (NavTab::ProcessAudit, "Process Audit", "TASKS", None),
            (NavTab::NetworkSockets, "Network Sockets", "PORTS", None),
            (NavTab::YaraHeuristics, "YARA & Entropy", "YARA", None),
            (
                NavTab::Quarantine,
                "Quarantine Vault",
                "VAULT",
                (q_count > 0).then_some((q_count, ACCENT_AMBER)),
            ),
            (NavTab::ActivityLogs, "Activity Logs", "LOGS", None),
        ];

        for (tab, label, tag, badge) in nav_items {
            let selected = self.active_tab == tab;
            if modern_nav_button(ui, label, tag, selected, badge).clicked() {
                self.active_tab = tab;
            }
            ui.add_space(6.0);
        }

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            ui.add_space(2.0);

            Frame::new()
                .fill(BG_CARD)
                .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(10))
                .inner_margin(Margin::same(11))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    let (priv_text, priv_color) = if self.is_elevated {
                        ("Administrator Shield", ACCENT_GREEN)
                    } else {
                        ("Standard User Mode", ACCENT_AMBER)
                    };
                    ui.horizontal(|ui| {
                        let (d, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), egui::Sense::hover());
                        ui.painter().circle_filled(d.center(), 3.5, priv_color);
                        ui.label(
                            RichText::new(priv_text)
                                .strong()
                                .size(12.0)
                                .color(priv_color),
                        );
                    });
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new(format!(
                            "Signatures v{} ({} IOCs)",
                            self.signatures.version,
                            self.signatures.len()
                        ))
                        .size(11.0)
                        .color(TEXT_MUTED),
                    );
                });

            ui.add_space(8.0);

            if !self.is_elevated {
                let btn = egui::Button::new(
                    RichText::new("Elevate to Admin (UAC)")
                        .size(12.5)
                        .strong()
                        .color(TEXT_ON_ACCENT),
                )
                .fill(ACCENT_AMBER)
                .corner_radius(CornerRadius::same(8))
                .min_size(Vec2::new(ui.available_width(), 34.0));

                if ui.add(btn).clicked() {
                    match platform::relaunch_as_admin() {
                        Ok(()) => std::process::exit(0),
                        Err(e) => {
                            self.banner_feedback = Some((e.clone(), true));
                            self.push_log(LogLevel::Warning, "Privilege", e, None);
                        }
                    }
                }
                ui.add_space(8.0);
            }

            let pref_selected = self.active_tab == NavTab::Preferences;
            if modern_nav_button(ui, "Preferences", "CONF", pref_selected, None).clicked() {
                self.active_tab = NavTab::Preferences;
            }
        });
    }

    fn render_feedback_banner(&mut self, ui: &mut egui::Ui, msg: &str, is_err: bool) {
        let accent = if is_err {
            ACCENT_RED_SOFT
        } else {
            ACCENT_GREEN_SOFT
        };
        let bg = if is_err {
            Color32::from_rgb(76, 22, 28)
        } else {
            Color32::from_rgb(13, 52, 42)
        };
        Frame::new()
            .fill(bg)
            .stroke(Stroke::new(1.0, accent))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::symmetric(16, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(msg).color(TEXT_PRIMARY).size(13.0));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, "Dismiss", 80.0, 28.0).clicked() {
                            self.banner_feedback = None;
                        }
                    });
                });
            });
    }

    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        let status = self.protection_status();
        let busy = self.active_scan.is_some();
        let active_threat_count = self
            .active_threats
            .iter()
            .filter(|t| !t.quarantined)
            .count();
        let quarantined_count = self.quarantine.items().len();
        let lifetime_files = self.persisted.total_files_scanned_lifetime;
        let sig_count = self.signatures.len();
        let last_scan_str = self
            .persisted
            .last_scan_date
            .clone()
            .unwrap_or_else(|| "Never".to_string());
        let last_mode_str = self
            .persisted
            .last_scan_mode
            .clone()
            .unwrap_or_else(|| "Ready for initial scan".to_string());

        // HERO PROTECTION BANNER (Modern AV Focal Point)
        let (hero_bg, hero_border, hero_accent, hero_title, hero_desc) = match status {
            ProtectionStatus::Protected => (
                BG_HERO_SAFE,
                ACCENT_GREEN,
                ACCENT_GREEN,
                "Your Device Is Protected",
                "Local SHA-256 / MD5 inspection engine and offline quarantine vault are active.",
            ),
            ProtectionStatus::Scanning => (
                BG_HERO_SCAN,
                ACCENT_CYAN,
                ACCENT_CYAN,
                "Active Security Sweep in Progress",
                "Multithreaded workers are inspecting system paths without freezing your desktop.",
            ),
            ProtectionStatus::ThreatsDetected => (
                BG_HERO_THREAT,
                ACCENT_RED,
                ACCENT_RED_SOFT,
                "Security Action Required",
                "Unquarantined threat signatures were flagged. Review and isolate them immediately.",
            ),
        };

        let time_secs = ui.input(|i| i.time);

        Frame::new()
            .fill(hero_bg)
            .stroke(Stroke::new(1.2, hero_border))
            .corner_radius(CornerRadius::same(14))
            .inner_margin(Margin::same(20))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    // Animated Hero Radar Ring
                    let (radar_rect, _) =
                        ui.allocate_exact_size(Vec2::new(76.0, 76.0), egui::Sense::hover());
                    paint_hero_radar(ui.painter(), radar_rect, status, hero_accent, time_secs);

                    ui.add_space(16.0);

                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(hero_title)
                                .strong()
                                .size(22.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(4.0);
                        ui.label(RichText::new(hero_desc).size(13.0).color(TEXT_SECONDARY));
                        ui.add_space(10.0);
                        ui.horizontal_wrapped(|ui| {
                            status_chip(ui, "Hash Engine: Active", ACCENT_GREEN);
                            status_chip(
                                ui,
                                if self.persisted.settings.auto_quarantine {
                                    "Auto-Quarantine: ON"
                                } else {
                                    "Auto-Quarantine: Manual"
                                },
                                if self.persisted.settings.auto_quarantine {
                                    ACCENT_CYAN
                                } else {
                                    ACCENT_AMBER
                                },
                            );
                            status_chip(
                                ui,
                                &format!("{} Signatures", sig_count),
                                ACCENT_INDIGO,
                            );
                        });
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if active_threat_count > 0 {
                            if danger_button(
                                ui,
                                &format!("Review {} Threat(s)", active_threat_count),
                                175.0,
                                40.0,
                            )
                            .clicked()
                            {
                                self.active_tab = NavTab::ScanCenter;
                            }
                        } else if busy {
                            if primary_button(ui, "View Live Scan", 160.0, 40.0, ACCENT_CYAN)
                                .clicked()
                            {
                                self.active_tab = NavTab::ScanCenter;
                            }
                        } else if primary_button(
                            ui,
                            "Run Quick Scan",
                            165.0,
                            40.0,
                            ACCENT_CYAN,
                        )
                        .clicked()
                        {
                            let roots = quick_scan_roots();
                            self.start_hash_scan(
                                ScanMode::QuickHash,
                                roots,
                                "Critical User Locations".to_string(),
                            );
                        }
                    });
                });
            });

        ui.add_space(16.0);

        // Top KPI Row
        ui.columns(4, |cols| {
            render_kpi_card(
                &mut cols[0],
                "LAST SCAN",
                &last_scan_str,
                &last_mode_str,
                ACCENT_CYAN,
            );
            render_kpi_card(
                &mut cols[1],
                "QUARANTINE VAULT",
                &quarantined_count.to_string(),
                "XOR 0x5A isolated files",
                if quarantined_count > 0 {
                    ACCENT_AMBER
                } else {
                    ACCENT_GREEN
                },
            );
            render_kpi_card(
                &mut cols[2],
                "ITEMS INSPECTED",
                &lifetime_files.to_string(),
                "Lifetime files verified",
                ACCENT_INDIGO,
            );
            render_kpi_card(
                &mut cols[3],
                "IOC INTELLIGENCE",
                &format!("{sig_count} Rules"),
                &format!("v{} Offline DB", self.signatures.version),
                ACCENT_TEAL,
            );
        });

        ui.add_space(16.0);

        // Row 1: Primary Scan Engines
        ui.columns(3, |cols| {
            if modern_action_card(
                &mut cols[0],
                FeatureIcon::QuickBolt,
                ACCENT_CYAN,
                "Quick Scan",
                "Inspects startup entries, downloads, desktop & temp directories at max throughput.",
                if busy { "View Active" } else { "Start Quick Scan" },
                true,
            ) {
                if busy {
                    self.active_tab = NavTab::ScanCenter;
                } else {
                    let roots = quick_scan_roots();
                    self.start_hash_scan(
                        ScanMode::QuickHash,
                        roots,
                        "Critical User Locations".to_string(),
                    );
                }
            }

            if modern_action_card(
                &mut cols[1],
                FeatureIcon::DeepShield,
                ACCENT_INDIGO,
                "System Scan",
                "Deep system-level sweep checking system binaries, critical areas, and root directories.",
                if busy { "View Active" } else { "Start System Scan" },
                true,
            ) {
                if busy {
                    self.active_tab = NavTab::ScanCenter;
                } else {
                    self.start_system_engine_scan(true);
                }
            }

            if modern_action_card(
                &mut cols[2],
                FeatureIcon::CustomTarget,
                ACCENT_TEAL,
                "Custom Scan",
                "Select any folder or external drive for multithreaded SHA-256 & heuristic inspection.",
                "Select Folder",
                true,
            ) {
                self.active_tab = NavTab::ScanCenter;
            }
        });

        ui.add_space(14.0);

        // Row 2: Vault, Diagnostics, Audit
        ui.columns(3, |cols| {
            if modern_action_card(
                &mut cols[0],
                FeatureIcon::VaultLock,
                ACCENT_AMBER,
                "Quarantine Vault",
                "Inspect isolated payloads, restore false positives, or perform permanent zero-wipes.",
                "Open Vault",
                true,
            ) {
                self.active_tab = NavTab::Quarantine;
            }

            if modern_action_card(
                &mut cols[1],
                FeatureIcon::PulseCheck,
                ACCENT_GREEN,
                "Engine Self-Test",
                "Execute safe in-memory EICAR pattern verification without touching local storage.",
                "Run Diagnostic",
                true,
            ) {
                self.run_eicar_diagnostic();
            }

            if modern_action_card(
                &mut cols[2],
                FeatureIcon::AuditTerminal,
                ACCENT_CYAN,
                "Security Audit Logs",
                "Review chronological scan summaries, threat hashes, and quarantine timestamps.",
                "Open Audit Log",
                true,
            ) {
                self.active_tab = NavTab::ActivityLogs;
            }
        });

        ui.add_space(16.0);

        // Bottom 2-Column Telemetry Split
        ui.columns(2, |cols| {
            card_frame(BG_CARD).show(&mut cols[0], |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Latest System Engine Report")
                            .strong()
                            .size(15.5)
                            .color(TEXT_PRIMARY),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, "Refresh", 76.0, 26.0).clicked() {
                            match read_latest_mrt_report() {
                                Ok(report) => {
                                    self.persisted.last_mrt_report = Some(report);
                                    self.save_state();
                                    self.banner_feedback = Some((
                                        "Refreshed latest system scan report.".into(),
                                        false,
                                    ));
                                }
                                Err(e) => {
                                    self.banner_feedback = Some((e, true));
                                }
                            }
                        }
                    });
                });
                ui.add_space(10.0);

                if let Some(ref report) = self.persisted.last_mrt_report {
                    render_system_report_details(ui, report);
                } else {
                    ui.label(
                        RichText::new("No prior deep system scan report recorded yet.")
                            .color(TEXT_MUTED),
                    );
                }
            });

            card_frame(BG_CARD).show(&mut cols[1], |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Recent Security Feed")
                            .strong()
                            .size(15.5)
                            .color(TEXT_PRIMARY),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, "View All", 76.0, 26.0).clicked() {
                            self.active_tab = NavTab::ActivityLogs;
                        }
                    });
                });
                ui.add_space(10.0);
                if self.logs.is_empty() {
                    ui.label(RichText::new("No recorded events yet.").color(TEXT_MUTED));
                } else {
                    for entry in self.logs.iter().take(4) {
                        render_log_row(ui, entry);
                        ui.add_space(5.0);
                    }
                }
            });
        });
    }

    fn render_scan_center(&mut self, ui: &mut egui::Ui) {
        let is_scanning = self.active_scan.is_some();

        // Quick Scan Card
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::QuickBolt, ACCENT_CYAN);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Quick Scan")
                                .strong()
                                .size(18.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(6.0);
                        tag_pill(ui, "FAST", ACCENT_CYAN);
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(
                            "Rapid multithreaded scan of startup folders, Downloads, Desktop, and Temp locations.",
                        )
                        .size(12.5)
                        .color(TEXT_MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_enabled_ui(!is_scanning, |ui| {
                        if primary_button(ui, "Start Quick Scan", 150.0, 36.0, ACCENT_CYAN)
                            .clicked()
                        {
                            let roots = quick_scan_roots();
                            self.start_hash_scan(
                                ScanMode::QuickHash,
                                roots,
                                "Critical User Locations".to_string(),
                            );
                        }
                    });
                });
            });
        });

        ui.add_space(12.0);

        // Deep System Scan Card
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::DeepShield, ACCENT_INDIGO);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("System Scan")
                                .strong()
                                .size(18.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(6.0);
                        tag_pill(ui, "DEEP ENGINE", ACCENT_INDIGO);
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(
                            "Comprehensive inspection of system binaries, core OS directories, and active persistence locations.",
                        )
                        .size(12.5)
                        .color(TEXT_MUTED),
                    );
                    if !self.is_elevated {
                        ui.add_space(3.0);
                        ui.label(
                            RichText::new("Administrator privilege required for full system engine sweep.")
                                .size(11.5)
                                .color(ACCENT_AMBER),
                        );
                    }
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_enabled_ui(!is_scanning, |ui| {
                        if primary_button(ui, "Start System Scan", 150.0, 36.0, ACCENT_INDIGO)
                            .clicked()
                        {
                            self.start_system_engine_scan(true);
                        }
                        ui.add_space(8.0);
                        if secondary_button(ui, "Quick System Check", 155.0, 36.0).clicked() {
                            self.start_system_engine_scan(false);
                        }
                    });
                });
            });
        });

        ui.add_space(12.0);

        // Custom Folder Scan Card
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::CustomTarget, ACCENT_TEAL);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Custom Folder Scan")
                                .strong()
                                .size(18.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(6.0);
                        tag_pill(ui, "TARGETED", ACCENT_TEAL);
                    });
                    ui.label(
                        RichText::new(
                            "Select any folder or drive for chunked 64 KiB streaming SHA-256 / MD5 + in-memory EICAR inspection.",
                        )
                        .size(12.5)
                        .color(TEXT_MUTED),
                    );
                });
            });

            ui.add_space(12.0);
            ui.add_enabled_ui(!is_scanning, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.custom_folder_input)
                            .desired_width((ui.available_width() - 275.0).max(160.0))
                            .hint_text(r"C:\Path\To\Scan"),
                    );
                    if secondary_button(ui, "Browse...", 95.0, 32.0).clicked() {
                        self.open_folder_picker(ui.ctx());
                    }
                    if primary_button(ui, "Start Custom Scan", 160.0, 32.0, ACCENT_TEAL).clicked()
                    {
                        let target_path = PathBuf::from(self.custom_folder_input.trim());
                        if !target_path.exists() {
                            self.banner_feedback = Some((
                                format!("Folder does not exist: '{}'", target_path.display()),
                                true,
                            ));
                        } else {
                            let label = target_path.display().to_string();
                            self.start_hash_scan(ScanMode::CustomFolder, vec![target_path], label);
                        }
                    }
                });
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Quick targets:").size(11.5).color(TEXT_MUTED));
                    if let Some(home_os) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
                        let home = PathBuf::from(home_os);
                        if ui.small_button("Downloads").clicked() {
                            self.custom_folder_input =
                                home.join("Downloads").display().to_string();
                        }
                        if ui.small_button("Desktop").clicked() {
                            self.custom_folder_input = home.join("Desktop").display().to_string();
                        }
                        if ui.small_button("Documents").clicked() {
                            self.custom_folder_input =
                                home.join("Documents").display().to_string();
                        }
                    }
                    if let Some(temp) = std::env::var_os("TEMP").or_else(|| std::env::var_os("TMPDIR")) {
                        if ui.small_button("Temp").clicked() {
                            self.custom_folder_input = PathBuf::from(temp).display().to_string();
                        }
                    } else if !cfg!(windows) {
                        if ui.small_button("/tmp").clicked() {
                            self.custom_folder_input = "/tmp".to_string();
                        }
                    }
                });
            });
        });

        ui.add_space(16.0);

        // Live Scan Telemetry Console
        if let Some(ref scan) = self.active_scan {
            let elapsed = scan.started_at.elapsed().as_secs_f64().max(0.001);
            let files_per_sec = scan.files_scanned as f64 / elapsed;
            let mb_per_sec = (scan.bytes_scanned as f64 / (1024.0 * 1024.0)) / elapsed;

            let progress_val = if let Some(total) = scan.total_files {
                if total == 0 {
                    1.0
                } else {
                    (scan.files_scanned as f32 / total as f32).clamp(0.0, 1.0)
                }
            } else {
                ((elapsed * 0.45) % 1.0) as f32
            };

            let progress_label = match scan.total_files {
                Some(total) => format!(
                    "{:.1}%  ({} / {} files)",
                    progress_val * 100.0,
                    scan.files_scanned,
                    total
                ),
                None => format!(
                    "{:.0} files/sec  ({:.1} MB/s)  •  {:.1}s elapsed",
                    files_per_sec, mb_per_sec, elapsed
                ),
            };

            let mut cancel_clicked = false;
            card_frame_with_stroke(BG_HERO_SCAN, ACCENT_CYAN).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(format!("SCANNING LIVE — {}", scan.mode.label()))
                                .strong()
                                .size(15.5)
                                .color(ACCENT_CYAN),
                        );
                        ui.label(
                            RichText::new(&scan.status_text)
                                .size(12.5)
                                .color(TEXT_SECONDARY),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if danger_button(ui, "Abort Scan", 130.0, 34.0).clicked() {
                            cancel_clicked = true;
                        }
                    });
                });

                ui.add_space(12.0);
                ui.add(
                    egui::ProgressBar::new(progress_val)
                        .text(progress_label)
                        .animate(true)
                        .corner_radius(CornerRadius::same(8))
                        .fill(ACCENT_CYAN_BTN),
                );
                ui.add_space(12.0);

                Frame::new()
                    .fill(BG_APP)
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.label(
                            RichText::new(format!("Target: {}", scan.target))
                                .size(11.5)
                                .color(TEXT_MUTED),
                        );
                        ui.label(
                            RichText::new(format!("Inspecting: {}", scan.current_file))
                                .monospace()
                                .size(12.0)
                                .color(ACCENT_CYAN),
                        );
                    });

                ui.add_space(12.0);
                ui.columns(4, |cols| {
                    render_kpi_card(
                        &mut cols[0],
                        "FILES SCANNED",
                        &scan.files_scanned.to_string(),
                        &format_bytes(scan.bytes_scanned),
                        TEXT_PRIMARY,
                    );
                    render_kpi_card(
                        &mut cols[1],
                        "THREATS FOUND",
                        &scan.threats_found.to_string(),
                        if self.persisted.settings.auto_quarantine {
                            "Auto-quarantine ON"
                        } else {
                            "Manual review"
                        },
                        if scan.threats_found > 0 {
                            ACCENT_RED_SOFT
                        } else {
                            ACCENT_GREEN
                        },
                    );
                    render_kpi_card(
                        &mut cols[2],
                        "SKIPPED LOCKED",
                        &scan.skipped_inaccessible.to_string(),
                        "Protected OS files",
                        ACCENT_AMBER,
                    );
                    render_kpi_card(
                        &mut cols[3],
                        "ENGINE THROUGHPUT",
                        &format!("{files_per_sec:.0} /s"),
                        &format!("{mb_per_sec:.1} MB/s"),
                        ACCENT_CYAN,
                    );
                });
            });

            if cancel_clicked {
                self.cancel_active_scan();
            }
            ui.add_space(16.0);
        } else if let Some(ref result) = self.last_result {
            let summary = &result.summary;
            let border = if summary.threats_found > 0 {
                ACCENT_RED
            } else if summary.cancelled {
                ACCENT_AMBER
            } else {
                ACCENT_GREEN
            };
            let mut export_feedback: Option<(String, bool)> = None;
            let mut export_log: Option<(LogLevel, String, String)> = None;

            card_frame_with_stroke(BG_CARD, border).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(
                    RichText::new(format!(
                        "Last Completed Scan: {} ({})",
                        summary.mode.label(),
                        if summary.cancelled {
                            "Cancelled"
                        } else {
                            "Clean / Finished"
                        }
                    ))
                    .strong()
                    .size(15.5)
                    .color(if summary.threats_found > 0 {
                        ACCENT_RED_SOFT
                    } else if summary.cancelled {
                        ACCENT_AMBER_SOFT
                    } else {
                        ACCENT_GREEN_SOFT
                    }),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!(
                        "Target: {}  •  Duration: {:.2}s  •  Items: {} ({})  •  Threats: {}  •  Skipped: {}",
                        summary.target,
                        summary.duration_secs,
                        summary.files_scanned,
                        format_bytes(summary.bytes_scanned),
                        summary.threats_found,
                        summary.skipped_inaccessible
                    ))
                    .size(12.5)
                    .color(TEXT_SECONDARY),
                );
                if let Some(ref report) = summary.mrt_report {
                    ui.add_space(10.0);
                    render_system_report_details(ui, report);
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if secondary_button(ui, "Export Forensic HTML", 160.0, 30.0).clicked() {
                        let html = generate_html_report(summary);
                        let default_name = format!(
                            "sentient-forensic-report-{}.html",
                            now_timestamp().replace([':', ' ', '-'], "_")
                        );
                        if let Some(dest) = rfd::FileDialog::new()
                            .set_file_name(&default_name)
                            .add_filter("HTML Report", &["html"])
                            .save_file()
                        {
                            if let Err(e) = fs::write(&dest, html) {
                                export_feedback =
                                    Some((format!("Failed to write HTML report: {e}"), true));
                            } else {
                                let msg = format!("Forensic HTML report saved to '{}'", dest.display());
                                export_feedback = Some((msg.clone(), false));
                                export_log = Some((LogLevel::Success, "ForensicReport".to_string(), msg));
                            }
                        }
                    }

                    if secondary_button(ui, "Export STIX 2.1 (JSON)", 160.0, 30.0).clicked() {
                        let stix = generate_stix21_bundle(summary);
                        let default_name = format!(
                            "sentient-stix21-{}.json",
                            now_timestamp().replace([':', ' ', '-'], "_")
                        );
                        if let Some(dest) = rfd::FileDialog::new()
                            .set_file_name(&default_name)
                            .add_filter("STIX JSON", &["json"])
                            .save_file()
                        {
                            if let Err(e) = fs::write(&dest, stix) {
                                export_feedback =
                                    Some((format!("Failed to write STIX bundle: {e}"), true));
                            } else {
                                let msg = format!("STIX 2.1 bundle saved to '{}'", dest.display());
                                export_feedback = Some((msg.clone(), false));
                                export_log = Some((LogLevel::Success, "ForensicReport".to_string(), msg));
                            }
                        }
                    }
                });
                if !result.errors.is_empty() {
                    ui.add_space(8.0);
                    for err in result.errors.iter().take(3) {
                        ui.label(
                            RichText::new(format!("Notice: {err}"))
                                .size(11.5)
                                .color(ACCENT_AMBER),
                        );
                    }
                }
            });

            if let Some((msg, is_err)) = export_feedback {
                self.banner_feedback = Some((msg, is_err));
            }
            if let Some((lvl, cat, msg)) = export_log {
                self.push_log(lvl, cat, msg, None);
            }

            ui.add_space(16.0);
        }

        // Detected Threats Queue
        if !self.active_threats.is_empty() {
            card_frame_with_stroke(BG_HERO_THREAT, ACCENT_RED).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Detected Threats Requiring Containment")
                            .strong()
                            .size(16.0)
                            .color(ACCENT_RED_SOFT),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if secondary_button(ui, "Clear Resolved", 120.0, 28.0).clicked() {
                            self.active_threats.retain(|t| !t.quarantined);
                        }
                    });
                });
                ui.add_space(10.0);

                let len = self.active_threats.len();
                let mut quarantine_idx = None;
                for i in 0..len {
                    let t = &self.active_threats[i];
                    Frame::new()
                        .fill(BG_ELEVATED)
                        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{}  [{}]",
                                            t.threat_name,
                                            t.source.label()
                                        ))
                                        .strong()
                                        .color(ACCENT_RED_SOFT),
                                    );
                                    ui.label(
                                        RichText::new(t.path.display().to_string())
                                            .monospace()
                                            .size(12.0)
                                            .color(TEXT_PRIMARY),
                                    );
                                    if !t.sha256.is_empty() {
                                        ui.label(
                                            RichText::new(format!(
                                                "SHA-256: {}  •  Size: {}",
                                                t.sha256,
                                                format_bytes(t.file_size)
                                            ))
                                            .size(11.5)
                                            .color(TEXT_MUTED),
                                        );
                                    }
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if t.quarantined {
                                        tag_pill(ui, "QUARANTINED", ACCENT_GREEN);
                                    } else if t.path.exists() {
                                        if danger_button(ui, "Quarantine File", 135.0, 32.0)
                                            .clicked()
                                        {
                                            quarantine_idx = Some(i);
                                        }
                                    } else {
                                        ui.label(
                                            RichText::new("Handled / Missing").color(TEXT_MUTED),
                                        );
                                    }
                                });
                            });
                        });
                    ui.add_space(8.0);
                }

                if let Some(idx) = quarantine_idx {
                    self.quarantine_active_threat(idx);
                }
            });
        }
    }

    fn render_quarantine_manager(&mut self, ui: &mut egui::Ui) {
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Isolated Vault Directory")
                            .strong()
                            .size(13.5)
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{}  •  Cipher: XOR 0x5A  •  NTFS Execute Lock: Active",
                            self.quarantine.quarantine_dir().display()
                        ))
                        .monospace()
                        .size(11.5)
                        .color(TEXT_MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !self.quarantine.items().is_empty() {
                        if self.confirm_purge_all {
                            if danger_button(ui, "Confirm Purge All", 145.0, 30.0).clicked() {
                                match self.quarantine.purge_all() {
                                    Ok(count) => {
                                        self.banner_feedback = Some((
                                            format!("Securely wiped {count} quarantined files."),
                                            false,
                                        ));
                                        self.push_log(
                                            LogLevel::Success,
                                            "Quarantine",
                                            format!(
                                                "Securely wiped and removed {count} quarantined files."
                                            ),
                                            None,
                                        );
                                    }
                                    Err(e) => {
                                        self.banner_feedback = Some((e, true));
                                    }
                                }
                                self.confirm_purge_all = false;
                            }
                            if secondary_button(ui, "Cancel", 75.0, 30.0).clicked() {
                                self.confirm_purge_all = false;
                            }
                        } else if danger_button(ui, "Purge Vault", 115.0, 30.0).clicked() {
                            self.confirm_purge_all = true;
                        }
                        ui.add_space(6.0);
                    }
                    if secondary_button(ui, "Reload Vault", 110.0, 30.0).clicked() {
                        if let Err(e) = self.quarantine.reload() {
                            self.banner_feedback = Some((e, true));
                        }
                    }
                });
            });
        });

        ui.add_space(12.0);

        let items = self.quarantine.items().to_vec();
        if items.is_empty() {
            card_frame(BG_CARD).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new("Quarantine Vault Is Empty")
                            .strong()
                            .size(16.0)
                            .color(ACCENT_GREEN),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Detected threats quarantined by Sentient appear here with XOR 0x5A header scrambling, .quarantined renaming, and locked Windows permissions.",
                        )
                        .size(12.5)
                        .color(TEXT_MUTED),
                    );
                    ui.add_space(16.0);
                });
            });
            return;
        }

        let mut restore_id: Option<String> = None;
        let mut delete_id: Option<String> = None;

        for item in &items {
            card_frame(BG_CARD).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(&item.threat_name)
                                    .strong()
                                    .size(15.5)
                                    .color(ACCENT_RED_SOFT),
                            );
                            tag_pill(ui, &format_bytes(item.file_size), ACCENT_AMBER);
                            ui.label(
                                RichText::new(format!("Isolated {}", item.quarantined_at))
                                    .size(11.5)
                                    .color(TEXT_MUTED),
                            );
                        });
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(format!("Original Path: {}", item.original_path.display()))
                                .monospace()
                                .size(12.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.label(
                            RichText::new(format!("Vault File: {}", item.quarantined_path.display()))
                                .monospace()
                                .size(11.5)
                                .color(TEXT_MUTED),
                        );
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("SHA-256: {}", item.sha256))
                                    .monospace()
                                    .size(11.0)
                                    .color(ACCENT_CYAN),
                            );
                            if ui.small_button("Copy Hash").clicked() {
                                ui.ctx().copy_text(item.sha256.clone());
                            }
                        });
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if self.pending_delete_id.as_deref() == Some(&item.id) {
                            if danger_button(ui, "Confirm Zero Wipe", 145.0, 32.0).clicked() {
                                delete_id = Some(item.id.clone());
                                self.pending_delete_id = None;
                            }
                            if secondary_button(ui, "Cancel", 75.0, 32.0).clicked() {
                                self.pending_delete_id = None;
                            }
                        } else {
                            if danger_button(ui, "Delete Forever", 125.0, 32.0).clicked() {
                                self.pending_delete_id = Some(item.id.clone());
                            }
                            ui.add_space(6.0);
                            if primary_button(ui, "Restore File", 115.0, 32.0, ACCENT_CYAN).clicked()
                            {
                                restore_id = Some(item.id.clone());
                            }
                        }
                    });
                });
            });
            ui.add_space(10.0);
        }

        if let Some(id) = restore_id {
            match self.quarantine.restore_item(&id) {
                Ok(restored_path) => {
                    let msg = format!(
                        "Restored quarantined file to '{}'.",
                        restored_path.display()
                    );
                    self.banner_feedback = Some((msg.clone(), false));
                    self.push_log(LogLevel::Warning, "Quarantine Restore", msg, None);
                }
                Err(e) => {
                    self.banner_feedback = Some((e.clone(), true));
                    self.push_log(LogLevel::Warning, "Quarantine Restore", e, None);
                }
            }
        }

        if let Some(id) = delete_id {
            match self.quarantine.secure_delete_item(&id) {
                Ok(deleted) => {
                    let msg = format!(
                        "Securely zeroed and permanently deleted '{}'.",
                        deleted.original_path.display()
                    );
                    self.banner_feedback = Some((msg.clone(), false));
                    self.push_log(LogLevel::Success, "Quarantine Delete", msg, None);
                }
                Err(e) => {
                    self.banner_feedback = Some((e.clone(), true));
                    self.push_log(LogLevel::Warning, "Quarantine Delete", e, None);
                }
            }
        }
    }

    fn render_activity_logs(&mut self, ui: &mut egui::Ui) {
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.log_filter, LogFilter::All, "All Events");
                ui.selectable_value(&mut self.log_filter, LogFilter::Threats, "Threats");
                ui.selectable_value(&mut self.log_filter, LogFilter::Warnings, "Warnings");
                ui.selectable_value(&mut self.log_filter, LogFilter::Info, "Info & Clean");
                ui.add_space(12.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.log_search)
                        .desired_width(250.0)
                        .hint_text("Search paths, events, or SHA-256..."),
                );

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if danger_button(ui, "Clear Logs", 96.0, 28.0).clicked() {
                        self.logs.clear();
                        save_activity_logs(&self.logs);
                    }
                    ui.add_space(6.0);
                    if secondary_button(ui, "Export JSON", 104.0, 28.0).clicked() {
                        let export_path = sentient_data_dir().join("sentient_logs_export.json");
                        if let Ok(json) = serde_json::to_string_pretty(&self.logs) {
                            match fs::write(&export_path, json) {
                                Ok(()) => {
                                    self.banner_feedback = Some((
                                        format!("Exported logs to '{}'.", export_path.display()),
                                        false,
                                    ));
                                }
                                Err(e) => {
                                    self.banner_feedback =
                                        Some((format!("Export failed: {e}"), true));
                                }
                            }
                        }
                    }
                });
            });
        });

        ui.add_space(12.0);

        let search_lower = self.log_search.trim().to_ascii_lowercase();
        let filtered: Vec<&ActivityLogEntry> = self
            .logs
            .iter()
            .filter(|entry| match self.log_filter {
                LogFilter::All => true,
                LogFilter::Threats => entry.level == LogLevel::Threat,
                LogFilter::Warnings => entry.level == LogLevel::Warning,
                LogFilter::Info => matches!(entry.level, LogLevel::Info | LogLevel::Success),
            })
            .filter(|entry| {
                if search_lower.is_empty() {
                    true
                } else {
                    entry.message.to_ascii_lowercase().contains(&search_lower)
                        || entry.category.to_ascii_lowercase().contains(&search_lower)
                        || entry
                            .details
                            .as_deref()
                            .unwrap_or("")
                            .to_ascii_lowercase()
                            .contains(&search_lower)
                }
            })
            .collect();

        if filtered.is_empty() {
            card_frame(BG_CARD).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("No matching log entries.").color(TEXT_MUTED));
            });
        } else {
            card_frame(BG_CARD).show(ui, |ui| {
                for entry in filtered {
                    render_log_row(ui, entry);
                    ui.add_space(6.0);
                }
            });
        }
    }

    fn render_preferences(&mut self, ui: &mut egui::Ui) {
        let max_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
            .max(1);

        let mut settings_changed = false;

        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                RichText::new("Scanner & Containment Rules")
                    .strong()
                    .size(16.0)
                    .color(TEXT_PRIMARY),
            );
            ui.add_space(10.0);

            settings_changed |= ui
                .checkbox(
                    &mut self.persisted.settings.auto_quarantine,
                    "Automatically quarantine detected threats (.quarantined, XOR 0x5A scramble, execute lock)",
                )
                .changed();

            settings_changed |= ui
                .checkbox(
                    &mut self.persisted.settings.log_inaccessible_files,
                    "Log every locked / permission-denied OS file individually",
                )
                .changed();

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label("Parallel worker threads:");
                settings_changed |= ui
                    .add(egui::Slider::new(
                        &mut self.persisted.settings.worker_threads,
                        1..=max_cpus,
                    ))
                    .changed();
            });

            ui.horizontal(|ui| {
                ui.label("Maximum file size limit (MB, 0 = unlimited):");
                settings_changed |= ui
                    .add(egui::Slider::new(
                        &mut self.persisted.settings.max_file_size_mb,
                        0..=4096,
                    ))
                    .changed();
            });
        });

        if settings_changed {
            self.save_state();
        }

        ui.add_space(14.0);

        // Signature DB card
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Offline Threat Signature Database (signatures.json)")
                            .strong()
                            .size(16.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(format!(
                            "Location: {}  •  Version: {}  •  Indexed Threat Signatures: {}",
                            self.sig_store.path().display(),
                            self.signatures.version,
                            self.signatures.len()
                        ))
                        .size(12.0)
                        .color(TEXT_MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if secondary_button(ui, "Reload DB", 90.0, 30.0).clicked() {
                        match self.sig_store.load_or_seed() {
                            Ok(idx) => {
                                self.signatures = Arc::new(idx);
                                self.banner_feedback = Some((
                                    format!("Loaded {} threat signatures.", self.signatures.len()),
                                    false,
                                ));
                            }
                            Err(e) => {
                                self.banner_feedback = Some((e, true));
                            }
                        }
                    }

                    if secondary_button(ui, "Import Feed (JSON)", 140.0, 30.0).clicked() {
                        let dialog = rfd::FileDialog::new()
                            .set_title("Import Offline Threat Intelligence (JSON)")
                            .add_filter("Threat Intelligence JSON", &["json"]);
                        if let Some(file_path) = dialog.pick_file() {
                            match self.sig_store.import_threat_intel_file(&file_path) {
                                Ok((idx, added)) => {
                                    self.signatures = Arc::new(idx);
                                    let file_name = file_path
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("feed");
                                    let msg = format!(
                                        "Imported {added} new threats from '{file_name}'. Total indexed: {}.",
                                        self.signatures.len()
                                    );
                                    self.banner_feedback = Some((msg.clone(), false));
                                    self.push_log(LogLevel::Info, "ThreatIntel", msg, None);
                                }
                                Err(e) => {
                                    self.banner_feedback = Some((e, true));
                                }
                            }
                        }
                    }

                    if primary_button(ui, "Update Threat Intel", 150.0, 30.0, ACCENT_CYAN).clicked() {
                        match self.sig_store.sync_with_embedded_or_workspace_intel() {
                            Ok((idx, added)) => {
                                self.signatures = Arc::new(idx);
                                let msg = if added > 0 {
                                    format!(
                                        "Threat intelligence updated! Merged {added} new threat hashes. Total indexed: {}.",
                                        self.signatures.len()
                                    )
                                } else {
                                    format!(
                                        "Threat intelligence database is already up to date. Total indexed: {}.",
                                        self.signatures.len()
                                    )
                                };
                                self.banner_feedback = Some((msg.clone(), false));
                                self.push_log(LogLevel::Info, "ThreatIntel", msg, None);
                            }
                            Err(e) => {
                                self.banner_feedback = Some((e, true));
                            }
                        }
                    }
                });
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("🛡️ Offline Security Guarantee: Updates run ONLY to update the hash database and threat intelligence. Core binaries, executables, and scanning engines remain 100% offline with zero cloud telemetry.")
                        .size(11.5)
                        .color(ACCENT_CYAN),
                );
            });

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(10.0);
            ui.label(
                RichText::new("Add Custom Threat Signature (IOC)")
                    .strong()
                    .size(13.5)
                    .color(ACCENT_CYAN),
            );
            ui.add_space(8.0);

            egui::Grid::new("add_sig_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Threat Name:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_sig_name)
                            .desired_width(360.0)
                            .hint_text("e.g., Custom.Malware.Indicator"),
                    );
                    ui.end_row();

                    ui.label("SHA-256 (optional if MD5 set):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_sig_sha256)
                            .desired_width(480.0)
                            .hint_text("64 hexadecimal characters"),
                    );
                    ui.end_row();

                    ui.label("MD5 (optional if SHA-256 set):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_sig_md5)
                            .desired_width(360.0)
                            .hint_text("32 hexadecimal characters"),
                    );
                    ui.end_row();

                    ui.label("Severity:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_sig_severity).desired_width(180.0),
                    );
                    ui.end_row();
                });

            ui.add_space(10.0);
            if primary_button(
                ui,
                "Save Signature to signatures.json",
                245.0,
                34.0,
                ACCENT_CYAN,
            )
            .clicked()
            {
                let name = self.new_sig_name.trim().to_string();
                let sha = self.new_sig_sha256.trim().to_ascii_lowercase();
                let md5 = self.new_sig_md5.trim().to_ascii_lowercase();
                if name.is_empty() || (sha.is_empty() && md5.is_empty()) {
                    self.banner_feedback = Some((
                        "Provide a threat name and at least one SHA-256 or MD5 hash.".into(),
                        true,
                    ));
                } else {
                    let sig = ThreatSignature {
                        name: name.clone(),
                        sha256: sha,
                        md5,
                        severity: self.new_sig_severity.trim().to_string(),
                        description: "User-added local IOC".to_string(),
                    };
                    match self.sig_store.add_signature(sig) {
                        Ok(idx) => {
                            self.signatures = Arc::new(idx);
                            self.new_sig_name.clear();
                            self.new_sig_sha256.clear();
                            self.new_sig_md5.clear();
                            self.banner_feedback = Some((
                                format!("Added signature '{name}' to signatures.json."),
                                false,
                            ));
                            self.push_log(
                                LogLevel::Info,
                                "Signatures",
                                format!("Added custom IOC '{name}'."),
                                None,
                            );
                        }
                        Err(e) => {
                            self.banner_feedback = Some((e, true));
                        }
                    }
                }
            }
        });

        ui.add_space(14.0);

        // Engine Diagnostics & Privileges
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                RichText::new("Engine Diagnostics & Privilege Status")
                    .strong()
                    .size(16.0)
                    .color(TEXT_PRIMARY),
            );
            ui.add_space(10.0);

            let deep_engine_ready = mrt_executable_path().exists();
            let telemetry_ready = mrt_log_path().exists();
            ui.label(
                RichText::new(format!(
                    "Deep System Engine: {}",
                    if deep_engine_ready {
                        "Ready"
                    } else {
                        "Unavailable"
                    }
                ))
                .size(12.5)
                .color(TEXT_SECONDARY),
            );
            ui.label(
                RichText::new(format!(
                    "System Telemetry Store: {}",
                    if telemetry_ready {
                        "Active"
                    } else {
                        "Pending First Scan"
                    }
                ))
                .size(12.5)
                .color(TEXT_SECONDARY),
            );
            ui.label(
                RichText::new(format!(
                    "Process Privileges: {}",
                    if self.is_elevated {
                        "Elevated Administrator"
                    } else {
                        "Standard User (Full System Scan requires Administrator)"
                    }
                ))
                .size(12.5)
                .color(if self.is_elevated {
                    ACCENT_GREEN
                } else {
                    ACCENT_AMBER
                }),
            );

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if primary_button(
                    ui,
                    "Run In-Memory EICAR Self-Test",
                    230.0,
                    34.0,
                    ACCENT_GREEN,
                )
                .clicked()
                {
                    self.run_eicar_diagnostic();
                }

                if !self.is_elevated
                    && ui
                        .add(
                            egui::Button::new(
                                RichText::new("Relaunch Sentient as Administrator")
                                    .color(TEXT_ON_ACCENT)
                                    .strong(),
                            )
                            .fill(ACCENT_AMBER)
                            .corner_radius(CornerRadius::same(8))
                            .min_size(Vec2::new(240.0, 34.0)),
                        )
                        .clicked()
                {
                    match platform::relaunch_as_admin() {
                        Ok(()) => std::process::exit(0),
                        Err(e) => {
                            self.banner_feedback = Some((e, true));
                        }
                    }
                }
            });
        });
    }

    // -------------------------------------------------------------
    // Tab: Live Sentinel & USB Removable Media Auto-Defender
    // -------------------------------------------------------------
    fn render_live_sentinel(&mut self, ui: &mut egui::Ui) {
        let stats = self.sentinel_manager.as_ref().map(|s| s.stats()).unwrap_or_default();
        let is_running = self.sentinel_manager.as_ref().map(|s| s.is_active()).unwrap_or(false);

        // Card 1: Sentinel Status & Control
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::DeepShield, if is_running { ACCENT_GREEN } else { ACCENT_AMBER });
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Real-Time Sentinel Engine")
                                .strong()
                                .size(17.0)
                                .color(TEXT_PRIMARY),
                        );
                        ui.add_space(6.0);
                        if is_running {
                            tag_pill(ui, "ACTIVE GUARD", ACCENT_GREEN);
                        } else {
                            tag_pill(ui, "PAUSED", ACCENT_AMBER);
                        }
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("Continuous background filesystem watcher with on-drop triple inspection (Hash + YARA + Shannon Entropy Crypter detection).")
                            .size(12.0)
                            .color(TEXT_MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if is_running {
                        if danger_button(ui, "Pause Sentinel", 130.0, 32.0).clicked() {
                            if let Some(ref mut mgr) = self.sentinel_manager {
                                mgr.stop();
                            }
                            self.sentinel_enabled = false;
                            self.push_log(LogLevel::Warning, "Sentinel", "Real-time background watcher paused by user.", None);
                        }
                    } else {
                        if primary_button(ui, "Resume Sentinel", 140.0, 32.0, ACCENT_GREEN).clicked() {
                            let (sentinel_tx, sentinel_rx) = unbounded();
                            self.sentinel_manager = Some(SentinelManager::start(
                                Arc::clone(&self.signatures),
                                Arc::clone(&self.yara_engine),
                                self.persisted.settings.auto_quarantine,
                                sentinel_tx,
                            ));
                            self.sentinel_rx = Some(sentinel_rx);
                            self.sentinel_enabled = true;
                            self.push_log(LogLevel::Success, "Sentinel", "Real-time background watcher resumed.", None);
                        }
                    }
                });
            });

            ui.add_space(12.0);
            ui.columns(3, |cols| {
                render_kpi_card(
                    &mut cols[0],
                    "INSPECTED DROPS",
                    &stats.files_inspected.to_string(),
                    "Background analyzed",
                    ACCENT_CYAN,
                );
                render_kpi_card(
                    &mut cols[1],
                    "THREATS INTERCEPTED",
                    &stats.threats_intercepted.to_string(),
                    "Zero-day & known drops",
                    if stats.threats_intercepted > 0 { ACCENT_RED } else { ACCENT_GREEN },
                );
                render_kpi_card(
                    &mut cols[2],
                    "WATCHED ROOTS",
                    &stats.watched_paths.len().to_string(),
                    "User drop directories",
                    ACCENT_INDIGO,
                );
            });
        });

        ui.add_space(14.0);

        // Card 2: Removable Media & USB Auto-Defender
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Removable Media & Air-Gap USB Defender")
                        .strong()
                        .size(16.0)
                        .color(TEXT_PRIMARY),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if secondary_button(ui, "Rescan USB Drives", 150.0, 30.0).clicked() {
                        self.usb_drives = detect_removable_drives();
                        let count = self.usb_drives.len();
                        self.push_log(LogLevel::Info, "USBGuard", format!("Detected {count} removable storage devices."), None);
                    }
                });
            });
            ui.add_space(8.0);
            ui.label(
                RichText::new("Detects USB flash drives and external media. Immunizes drives by neutralizing autorun worms and blocking .inf-based execution traps.")
                    .size(12.0)
                    .color(TEXT_MUTED),
            );
            ui.add_space(10.0);

            if self.usb_drives.is_empty() {
                Frame::new()
                    .fill(BG_ELEVATED)
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.label(RichText::new("No removable USB drives currently inserted.").size(12.5).color(TEXT_MUTED));
                    });
            } else {
                let mut immunize_target: Option<PathBuf> = None;
                for drive in &self.usb_drives {
                    let is_immunized = drive.path.join("autorun.inf").is_dir();
                    Frame::new()
                        .fill(BG_ELEVATED)
                        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(format!("Drive: {}", drive.path.display()))
                                                .strong()
                                                .size(14.0)
                                                .color(TEXT_PRIMARY),
                                        );
                                        ui.add_space(6.0);
                                        if is_immunized {
                                            tag_pill(ui, "IMMUNIZED", ACCENT_GREEN);
                                        } else {
                                            tag_pill(ui, "UNPROTECTED", ACCENT_AMBER);
                                        }
                                        if drive.has_autorun && !is_immunized {
                                            ui.add_space(4.0);
                                            tag_pill(ui, "AUTORUN DETECTED", ACCENT_RED);
                                        }
                                    });
                                    ui.add_space(2.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "Label: {} • Removable: {} • Suspicious files: {}",
                                            drive.label,
                                            drive.is_removable,
                                            drive.suspicious_files.len()
                                        ))
                                        .size(11.5)
                                        .color(TEXT_MUTED),
                                    );
                                });

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if !is_immunized {
                                        if primary_button(ui, "Immunize Drive", 130.0, 30.0, ACCENT_CYAN).clicked() {
                                            immunize_target = Some(drive.path.clone());
                                        }
                                    } else {
                                        ui.label(RichText::new("Vaccinated against worms").size(11.5).color(ACCENT_GREEN));
                                    }
                                });
                            });
                        });
                    ui.add_space(6.0);
                }

                if let Some(target) = immunize_target {
                    match immunize_drive(&target) {
                        Ok(()) => {
                            let msg = format!("Drive '{}' successfully immunized against autorun worm vectors.", target.display());
                            self.banner_feedback = Some((msg.clone(), false));
                            self.push_log(LogLevel::Success, "USBGuard", msg, None);
                            self.usb_drives = detect_removable_drives();
                        }
                        Err(e) => {
                            self.banner_feedback = Some((format!("Immunization failed: {e}"), true));
                        }
                    }
                }
            }
        });

        ui.add_space(14.0);

        // Card 3: Intercepted Dropped Files Ledger
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("Real-Time Drop Interceptions ({})", self.sentinel_alerts.len()))
                        .strong()
                        .size(16.0)
                        .color(if self.sentinel_alerts.is_empty() { TEXT_PRIMARY } else { ACCENT_RED_SOFT }),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !self.sentinel_alerts.is_empty() && secondary_button(ui, "Clear Interceptions", 140.0, 28.0).clicked() {
                        self.sentinel_alerts.clear();
                    }
                });
            });
            ui.add_space(10.0);

            if self.sentinel_alerts.is_empty() {
                Frame::new()
                    .fill(BG_ELEVATED)
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("No suspicious file drops intercepted yet. Watched user folders are healthy.")
                                .size(12.5)
                                .color(TEXT_MUTED),
                        );
                    });
            } else {
                for alert in &self.sentinel_alerts {
                    Frame::new()
                        .fill(BG_HERO_THREAT)
                        .stroke(Stroke::new(1.0, ACCENT_RED))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(Margin::same(12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(&alert.threat_name)
                                                .strong()
                                                .size(14.0)
                                                .color(ACCENT_RED_SOFT),
                                        );
                                        ui.add_space(6.0);
                                        tag_pill(ui, &alert.detection_method, ACCENT_AMBER);
                                        if alert.quarantined {
                                            ui.add_space(4.0);
                                            tag_pill(ui, "AUTO-QUARANTINED", ACCENT_GREEN);
                                        }
                                    });
                                    ui.add_space(3.0);
                                    ui.label(
                                        RichText::new(format!("Location: {}", alert.path.display()))
                                            .size(12.0)
                                            .color(TEXT_PRIMARY),
                                    );
                                    ui.label(
                                        RichText::new(format!("SHA-256: {} • Intercepted: {}", alert.sha256, alert.detected_at))
                                            .monospace()
                                            .size(10.5)
                                            .color(TEXT_MUTED),
                                    );
                                });
                            });
                        });
                    ui.add_space(6.0);
                }
            }
        });
    }

    // -------------------------------------------------------------
    // Tab: Live Process & Memory Threat Audit
    // -------------------------------------------------------------
    fn render_process_audit(&mut self, ui: &mut egui::Ui) {
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::AuditTerminal, ACCENT_CYAN);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Live Process & Running Tasks Inspector")
                            .strong()
                            .size(17.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("Inspects active PIDs, hashes in-memory binary disks against offline signatures, detects fake system processes, and checks Temp directory execution.")
                            .size(12.0)
                            .color(TEXT_MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if primary_button(ui, "Scan Running Tasks", 160.0, 34.0, ACCENT_CYAN).clicked() {
                        self.process_items = audit_running_processes(&self.signatures);
                        let flagged = self.process_items.iter().filter(|p| p.risk.is_threat()).count();
                        let total = self.process_items.len();
                        let msg = format!("Audited {total} processes: {flagged} flagged suspicious.");
                        self.push_log(if flagged > 0 { LogLevel::Threat } else { LogLevel::Info }, "ProcessAudit", msg, None);
                    }
                });
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Filter:").size(12.5).color(TEXT_MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.process_search)
                        .hint_text("Search PID, process name, or path...")
                        .desired_width(320.0),
                );
                if !self.process_search.is_empty() && secondary_button(ui, "Clear", 60.0, 24.0).clicked() {
                    self.process_search.clear();
                }

                let total = self.process_items.len();
                let flagged = self.process_items.iter().filter(|p| p.risk.is_threat()).count();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("Total: {total} PIDs  •  Flagged: {flagged}"))
                            .size(12.0)
                            .color(if flagged > 0 { ACCENT_RED_SOFT } else { TEXT_MUTED }),
                    );
                });
            });
        });

        ui.add_space(14.0);

        // Process List Card
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if self.process_items.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(
                        RichText::new("Click 'Scan Running Tasks' to evaluate live memory and process integrity.")
                            .size(13.0)
                            .color(TEXT_MUTED),
                    );
                    ui.add_space(20.0);
                });
            } else {
                let search_lower = self.process_search.to_lowercase();
                let filtered: Vec<&ProcessAuditItem> = self
                    .process_items
                    .iter()
                    .filter(|p| {
                        if search_lower.is_empty() {
                            return true;
                        }
                        p.name.to_lowercase().contains(&search_lower)
                            || p.pid.to_string().contains(&search_lower)
                            || p.exe_path.as_ref().map(|path| path.display().to_string().to_lowercase().contains(&search_lower)).unwrap_or(false)
                    })
                    .collect();

                let mut kill_pid: Option<u32> = None;

                for item in filtered.iter().take(150) {
                    let is_clean = !item.risk.is_threat();
                    let risk_color = match item.risk {
                        ProcessRisk::KnownMalwareMatch => ACCENT_RED,
                        ProcessRisk::Masquerading | ProcessRisk::DeletedBinaryExecution => ACCENT_RED_SOFT,
                        ProcessRisk::SuspiciousPath => ACCENT_AMBER,
                        ProcessRisk::Clean => ACCENT_GREEN,
                    };

                    Frame::new()
                        .fill(if is_clean { BG_ELEVATED } else { BG_HERO_THREAT })
                        .stroke(Stroke::new(1.0, if is_clean { BORDER_SUBTLE } else { risk_color }))
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(Margin::symmetric(12, 8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("PID {}", item.pid))
                                        .monospace()
                                        .strong()
                                        .size(12.0)
                                        .color(ACCENT_CYAN),
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(&item.name)
                                        .strong()
                                        .size(13.0)
                                        .color(TEXT_PRIMARY),
                                );
                                ui.add_space(6.0);
                                tag_pill(ui, item.risk.label(), risk_color);

                                if let Some(ref path) = item.exe_path {
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new(path.display().to_string())
                                            .size(11.0)
                                            .color(TEXT_MUTED),
                                    );
                                }

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if !is_clean {
                                        if danger_button(ui, "Kill PID", 80.0, 26.0).clicked() {
                                            kill_pid = Some(item.pid);
                                        }
                                    }
                                    if item.memory_kb > 0 {
                                        let mb = item.memory_kb as f64 / 1024.0;
                                        ui.label(
                                            RichText::new(format!("{mb:.1} MB"))
                                                .monospace()
                                                .size(11.5)
                                                .color(TEXT_SECONDARY),
                                        );
                                    }
                                    if let Some(ref reason) = item.risk_reason {
                                        ui.label(
                                            RichText::new(reason)
                                                .size(11.0)
                                                .color(risk_color),
                                        );
                                    }
                                });
                            });
                        });
                    ui.add_space(4.0);
                }

                if let Some(pid) = kill_pid {
                    match kill_process(pid) {
                        Ok(()) => {
                            let msg = format!("Terminated PID {pid}.");
                            self.banner_feedback = Some((msg.clone(), false));
                            self.push_log(LogLevel::Success, "ProcessAudit", msg, None);
                            self.process_items.retain(|p| p.pid != pid);
                        }
                        Err(e) => {
                            let err_msg = format!("Failed to terminate PID {pid}: {e}");
                            self.banner_feedback = Some((err_msg.clone(), true));
                            self.push_log(LogLevel::Warning, "ProcessAudit", err_msg, None);
                        }
                    }
                }
            }
        });
    }

    // -------------------------------------------------------------
    // Tab: Active Network Sockets & Covert C2 Monitor
    // -------------------------------------------------------------
    fn render_network_sockets(&mut self, ui: &mut egui::Ui) {
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::PulseCheck, ACCENT_INDIGO);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Active Network Sockets & C2 Beacon Monitor")
                            .strong()
                            .size(17.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("Real-time TCP/UDP socket auditor. Flags known Metasploit/C2 beacon ports (4444, 1337, 31337, 9001) and unauthenticated 0.0.0.0 listeners.")
                            .size(12.0)
                            .color(TEXT_MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if primary_button(ui, "Audit Sockets", 140.0, 34.0, ACCENT_INDIGO).clicked() {
                        self.socket_items = scan_active_network_sockets();
                        let sus = self.socket_items.iter().filter(|s| s.risk.is_suspicious()).count();
                        let total = self.socket_items.len();
                        let msg = format!("Audited {total} network sockets: {sus} flagged suspicious/C2.");
                        self.push_log(if sus > 0 { LogLevel::Threat } else { LogLevel::Info }, "NetworkAudit", msg, None);
                    }
                });
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Filter:").size(12.5).color(TEXT_MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.socket_search)
                        .hint_text("Search IP, Port, PID, or protocol...")
                        .desired_width(320.0),
                );
                if !self.socket_search.is_empty() && secondary_button(ui, "Clear", 60.0, 24.0).clicked() {
                    self.socket_search.clear();
                }

                let total = self.socket_items.len();
                let sus = self.socket_items.iter().filter(|s| s.risk.is_suspicious()).count();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("Open Sockets: {total}  •  C2 / Suspicious: {sus}"))
                            .size(12.0)
                            .color(if sus > 0 { ACCENT_RED_SOFT } else { TEXT_MUTED }),
                    );
                });
            });
        });

        ui.add_space(14.0);

        // Socket Table Card
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            if self.socket_items.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(
                        RichText::new("Click 'Audit Sockets' to capture local listening ports and active outbound connections.")
                            .size(13.0)
                            .color(TEXT_MUTED),
                    );
                    ui.add_space(20.0);
                });
            } else {
                let search_lower = self.socket_search.to_lowercase();
                let filtered: Vec<&NetworkSocketEntry> = self
                    .socket_items
                    .iter()
                    .filter(|s| {
                        if search_lower.is_empty() {
                            return true;
                        }
                        let proto_str = match s.protocol {
                            SocketProtocol::Tcp => "tcp",
                            SocketProtocol::Udp => "udp",
                        };
                        s.local_addr.to_lowercase().contains(&search_lower)
                            || s.foreign_addr.to_lowercase().contains(&search_lower)
                            || proto_str.contains(&search_lower)
                            || s.state.to_lowercase().contains(&search_lower)
                            || s.pid.map(|p| p.to_string().contains(&search_lower)).unwrap_or(false)
                    })
                    .collect();

                let mut kill_pid: Option<u32> = None;

                for socket in filtered.iter().take(150) {
                    let is_suspicious = socket.risk.is_suspicious();
                    let proto_str = match socket.protocol {
                        SocketProtocol::Tcp => "TCP",
                        SocketProtocol::Udp => "UDP",
                    };

                    Frame::new()
                        .fill(if is_suspicious { BG_HERO_THREAT } else { BG_ELEVATED })
                        .stroke(Stroke::new(1.0, if is_suspicious { ACCENT_RED } else { BORDER_SUBTLE }))
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(Margin::symmetric(12, 8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                tag_pill(ui, proto_str, ACCENT_CYAN);
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(format!("Local: {}", socket.local_addr))
                                        .monospace()
                                        .strong()
                                        .size(12.0)
                                        .color(TEXT_PRIMARY),
                                );
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(format!("-> Foreign: {}", socket.foreign_addr))
                                        .monospace()
                                        .size(12.0)
                                        .color(TEXT_SECONDARY),
                                );
                                ui.add_space(6.0);
                                tag_pill(ui, &socket.state, TEXT_MUTED);

                                if let Some(pid) = socket.pid {
                                    ui.add_space(6.0);
                                    let proc_tag = socket.process_name.as_deref().unwrap_or("PID");
                                    ui.label(
                                        RichText::new(format!("{proc_tag}:{pid}"))
                                            .monospace()
                                            .size(11.5)
                                            .color(ACCENT_AMBER),
                                    );
                                }

                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if is_suspicious {
                                        if let Some(pid) = socket.pid {
                                            if danger_button(ui, "Kill PID", 80.0, 24.0).clicked() {
                                                kill_pid = Some(pid);
                                            }
                                        }
                                        if let Some(ref note) = socket.warning {
                                            ui.label(
                                                RichText::new(note)
                                                    .strong()
                                                    .size(11.0)
                                                    .color(ACCENT_RED_SOFT),
                                            );
                                        }
                                    }
                                });
                            });
                        });
                    ui.add_space(4.0);
                }

                if let Some(pid) = kill_pid {
                    match kill_process(pid) {
                        Ok(()) => {
                            let msg = format!("Terminated socket owner PID {pid}.");
                            self.banner_feedback = Some((msg.clone(), false));
                            self.push_log(LogLevel::Success, "NetworkAudit", msg, None);
                            self.socket_items.retain(|s| s.pid != Some(pid));
                        }
                        Err(e) => {
                            let err_msg = format!("Failed to terminate PID {pid}: {e}");
                            self.banner_feedback = Some((err_msg.clone(), true));
                            self.push_log(LogLevel::Warning, "NetworkAudit", err_msg, None);
                        }
                    }
                }
            }
        });
    }

    // -------------------------------------------------------------
    // Tab: Robust YARA Rules Engine & Shannon Entropy Heuristics
    // -------------------------------------------------------------
    fn render_yara_heuristics(&mut self, ui: &mut egui::Ui) {
        // Section 1: Static Heuristics & Shannon Entropy Analysis
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                paint_badge_icon(ui, FeatureIcon::CustomTarget, ACCENT_CYAN);
                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("Static Binary Heuristics & Crypter Entropy Analyzer")
                            .strong()
                            .size(17.0)
                            .color(TEXT_PRIMARY),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new("Evaluates mathematical Shannon entropy (0.0 to 8.0) to detect packed/crypted malware, inspects PE/ELF headers for W+X execution rights, and flags process injection APIs.")
                            .size(12.0)
                            .color(TEXT_MUTED),
                    );
                });
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Target File:").size(12.5).color(TEXT_MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.heuristic_target)
                        .hint_text("Absolute path to binary (.exe, .dll, ELF, or dropper)...")
                        .desired_width(450.0),
                );
                if secondary_button(ui, "Browse...", 85.0, 28.0).clicked() {
                    if let Some(picked) = rfd::FileDialog::new().pick_file() {
                        self.heuristic_target = picked.display().to_string();
                    }
                }
                if primary_button(ui, "Inspect File", 120.0, 28.0, ACCENT_CYAN).clicked() {
                    let target_path = PathBuf::from(&self.heuristic_target);
                    if !target_path.exists() {
                        self.banner_feedback = Some((format!("File '{}' not found.", target_path.display()), true));
                    } else {
                        match inspect_file_heuristics(&target_path) {
                            Ok(rep) => {
                                let entropy = rep.entropy.score;
                                let format_str = if rep.pe.is_some() {
                                    "Windows PE"
                                } else if rep.elf.is_some() {
                                    "Linux ELF"
                                } else {
                                    "Binary / Raw Data"
                                };
                                self.heuristic_report = Some(rep);
                                self.push_log(
                                    LogLevel::Info,
                                    "Heuristics",
                                    format!("Inspected '{}': format {format_str}, entropy {entropy:.2}/8.0", target_path.display()),
                                    None,
                                );
                            }
                            Err(e) => {
                                self.banner_feedback = Some((format!("Heuristic analysis error: {e}"), true));
                            }
                        }
                    }
                }
            });

            if let Some(ref report) = self.heuristic_report {
                ui.add_space(12.0);
                Frame::new()
                    .fill(BG_ELEVATED)
                    .stroke(Stroke::new(1.0, BORDER_BRIGHT))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::same(14))
                    .show(ui, |ui| {
                        let format_str = if report.pe.is_some() {
                            "Windows PE Executable"
                        } else if report.elf.is_some() {
                            "Linux ELF Binary"
                        } else {
                            "Binary / Raw Data"
                        };
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(format!("Format: {format_str}  •  Size: {} bytes", report.file_size))
                                        .strong()
                                        .size(13.5)
                                        .color(TEXT_PRIMARY),
                                );
                                ui.add_space(4.0);
                                let entropy_color = if report.entropy.is_anomalous {
                                    ACCENT_RED
                                } else if report.entropy.score > 7.0 {
                                    ACCENT_AMBER
                                } else {
                                    ACCENT_GREEN
                                };
                                ui.label(
                                    RichText::new(format!(
                                        "Shannon Entropy: {:.3} / 8.000 — {} ({})",
                                        report.entropy.score, report.entropy.category, report.entropy.description
                                    ))
                                    .strong()
                                    .size(12.5)
                                    .color(entropy_color),
                                );
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if report.entropy.is_anomalous {
                                    tag_pill(ui, "CRYPTER / PACKED ALERT", ACCENT_RED);
                                } else {
                                    tag_pill(ui, "NORMAL ENTROPY", ACCENT_GREEN);
                                }
                            });
                        });

                        if !report.risk_indicators.is_empty() {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.add_space(6.0);
                            ui.label(RichText::new("Header Anomalies & Injection Indicators:").strong().size(12.0).color(ACCENT_AMBER));
                            for anom in &report.risk_indicators {
                                ui.label(RichText::new(format!("• {anom}")).size(11.5).color(TEXT_SECONDARY));
                            }
                        }
                    });
            }
        });

        ui.add_space(14.0);

        // Section 2: Robust YARA Rules Engine
        card_frame(BG_CARD).show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("Offline Curated YARA Engine ({} Loaded Rules)", self.yara_engine.rule_count()))
                        .strong()
                        .size(16.0)
                        .color(TEXT_PRIMARY),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    tag_pill(ui, "PURE RUST YARA 1.0", ACCENT_CYAN);
                });
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new("Robust pure-Rust engine executing string/hex matching with wildcards (??), UTF-16LE wide strings, case-insensitivity, and compound boolean conditions. Bundles 10 curated offline signatures for WannaCry, LockBit 3.0, Mirai, Kinsing, BPFDoor, RedLine, Cobalt Strike Beacon, WebShells, Process Hollowing, and Obfuscated Droppers.")
                    .size(12.0)
                    .color(TEXT_MUTED),
            );

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scan Target:").size(12.5).color(TEXT_MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.yara_target_file)
                        .hint_text("Path to inspect with YARA rule set...")
                        .desired_width(450.0),
                );
                if secondary_button(ui, "Browse...", 85.0, 28.0).clicked() {
                    if let Some(picked) = rfd::FileDialog::new().pick_file() {
                        self.yara_target_file = picked.display().to_string();
                    }
                }
                if primary_button(ui, "Run YARA Scan", 130.0, 28.0, ACCENT_CYAN).clicked() {
                    let target_path = PathBuf::from(&self.yara_target_file);
                    if !target_path.exists() {
                        self.banner_feedback = Some((format!("File '{}' does not exist.", target_path.display()), true));
                    } else {
                        match self.yara_engine.scan_file(&target_path) {
                            Ok(matches) => {
                                let count = matches.len();
                                self.yara_match_results = matches;
                                let msg = if count > 0 {
                                    format!("YARA matched {count} rule(s) on '{}'!", target_path.display())
                                } else {
                                    format!("Clean: 0 YARA matches on '{}'.", target_path.display())
                                };
                                self.banner_feedback = Some((msg.clone(), count > 0));
                                self.push_log(if count > 0 { LogLevel::Threat } else { LogLevel::Success }, "YARA", msg, None);
                            }
                            Err(e) => {
                                self.banner_feedback = Some((format!("YARA scan failed: {e}"), true));
                            }
                        }
                    }
                }
            });

            if !self.yara_match_results.is_empty() {
                ui.add_space(10.0);
                ui.label(RichText::new("YARA Detection Matches:").strong().size(13.0).color(ACCENT_RED_SOFT));
                for m in &self.yara_match_results {
                    Frame::new()
                        .fill(BG_HERO_THREAT)
                        .stroke(Stroke::new(1.0, ACCENT_RED))
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&m.rule_name)
                                        .strong()
                                        .size(13.5)
                                        .color(ACCENT_RED_SOFT),
                                );
                                ui.add_space(6.0);
                                tag_pill(ui, &m.severity, ACCENT_RED);
                            });
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!("Description: {}", m.description))
                                    .size(11.5)
                                    .color(TEXT_SECONDARY),
                            );
                            ui.label(
                                RichText::new(format!("Matched patterns: {}", m.matched_patterns.join(", ")))
                                    .monospace()
                                    .size(11.0)
                                    .color(TEXT_MUTED),
                            );
                        });
                    ui.add_space(4.0);
                }
            }

            ui.add_space(14.0);
            ui.separator();
            ui.add_space(10.0);

            // Custom YARA Rule Tester
            ui.label(
                RichText::new("Custom YARA Rule Compiler & Tester")
                    .strong()
                    .size(14.0)
                    .color(TEXT_PRIMARY),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Write or paste a custom YARA rule to compile in-memory and test against any payload:")
                    .size(11.5)
                    .color(TEXT_MUTED),
            );
            ui.add_space(6.0);

            ui.add(
                egui::TextEdit::multiline(&mut self.yara_rule_input)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("rule Custom_Test {\n    meta:\n        description = \"Test Rule\"\n    strings:\n        $s1 = \"cmd.exe /c\"\n    condition:\n        $s1\n}")
                    .desired_width(ui.available_width())
                    .desired_rows(6),
            );
            ui.add_space(6.0);
            if secondary_button(ui, "Compile & Test Custom Rule", 220.0, 30.0).clicked() {
                if self.yara_rule_input.trim().is_empty() {
                    self.banner_feedback = Some(("Please enter YARA rule source text.".to_string(), true));
                } else {
                    match parse_yara_source(&self.yara_rule_input) {
                        Ok(rules) => {
                            let rule_names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
                            let msg = format!("Compiled {} custom rule(s) successfully: {}", rules.len(), rule_names.join(", "));
                            self.banner_feedback = Some((msg.clone(), false));
                            self.push_log(LogLevel::Info, "YARA", msg, None);
                        }
                        Err(e) => {
                            self.banner_feedback = Some((format!("Syntax error in custom YARA rule: {e}"), true));
                        }
                    }
                }
            }
        });
    }
}

fn load_logo_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let img = image::load_from_memory(LOGO_PNG_BYTES).ok()?.to_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw());
    Some(ctx.load_texture("sentient_logo", color_image, egui::TextureOptions::LINEAR))
}

fn modern_nav_button(
    ui: &mut egui::Ui,
    label: &str,
    tag: &str,
    selected: bool,
    badge: Option<(usize, Color32)>,
) -> egui::Response {
    let desired_size = Vec2::new(ui.available_width(), 40.0);
    let (rect, response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

    let fill = if selected {
        BTN_NAV_ACTIVE_BG
    } else if response.hovered() {
        BG_CARD
    } else {
        Color32::TRANSPARENT
    };

    let stroke = if selected {
        Stroke::new(1.0, BORDER_BRIGHT)
    } else {
        Stroke::NONE
    };

    ui.painter()
        .rect(rect, CornerRadius::same(8), fill, stroke, egui::StrokeKind::Inside);

    if selected {
        let bar = Rect::from_min_max(
            Pos2::new(rect.left() + 3.0, rect.top() + 8.0),
            Pos2::new(rect.left() + 6.5, rect.bottom() - 8.0),
        );
        ui.painter()
            .rect_filled(bar, CornerRadius::same(2), ACCENT_CYAN);
    }

    let tag_color = if selected { ACCENT_CYAN } else { TEXT_MUTED };
    let text_color = if selected {
        TEXT_PRIMARY
    } else if response.hovered() {
        TEXT_PRIMARY
    } else {
        TEXT_SECONDARY
    };

    ui.painter().text(
        Pos2::new(rect.left() + 14.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        tag,
        egui::FontId::monospace(10.0),
        tag_color,
    );

    ui.painter().text(
        Pos2::new(rect.left() + 60.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.5),
        text_color,
    );

    if let Some((count, badge_color)) = badge {
        let badge_rect = Rect::from_center_size(
            Pos2::new(rect.right() - 18.0, rect.center().y),
            Vec2::new(22.0, 18.0),
        );
        ui.painter()
            .rect_filled(badge_rect, CornerRadius::same(9), badge_color);
        ui.painter().text(
            badge_rect.center(),
            egui::Align2::CENTER_CENTER,
            count.to_string(),
            egui::FontId::proportional(11.0),
            TEXT_ON_ACCENT,
        );
    }

    response
}

fn primary_button(
    ui: &mut egui::Ui,
    label: &str,
    width: f32,
    height: f32,
    bg: Color32,
) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label)
            .strong()
            .size(13.0)
            .color(TEXT_ON_ACCENT),
    )
    .fill(bg)
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(8))
    .min_size(Vec2::new(width, height));

    ui.add(btn)
}

fn secondary_button(ui: &mut egui::Ui, label: &str, width: f32, height: f32) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label)
            .strong()
            .size(12.5)
            .color(TEXT_PRIMARY),
    )
    .fill(BTN_SECONDARY_BG)
    .stroke(Stroke::new(1.0, BORDER_BRIGHT))
    .corner_radius(CornerRadius::same(8))
    .min_size(Vec2::new(width, height));

    ui.add(btn)
}

fn danger_button(ui: &mut egui::Ui, label: &str, width: f32, height: f32) -> egui::Response {
    let btn = egui::Button::new(
        RichText::new(label)
            .strong()
            .size(12.5)
            .color(TEXT_PRIMARY),
    )
    .fill(ACCENT_RED_DARK)
    .stroke(Stroke::new(1.0, ACCENT_RED))
    .corner_radius(CornerRadius::same(8))
    .min_size(Vec2::new(width, height));

    ui.add(btn)
}

fn tag_pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    let bg = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 28);
    Frame::new()
        .fill(bg)
        .stroke(Stroke::new(1.0, color))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).strong().size(10.0).color(color));
        });
}

fn status_chip(ui: &mut egui::Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (d, _) = ui.allocate_exact_size(Vec2::new(6.0, 6.0), egui::Sense::hover());
                ui.painter().circle_filled(d.center(), 3.0, color);
                ui.label(RichText::new(text).size(11.0).color(TEXT_SECONDARY));
            });
        });
}

fn modern_action_card(
    ui: &mut egui::Ui,
    icon: FeatureIcon,
    accent: Color32,
    title: &str,
    description: &str,
    button_label: &str,
    enabled: bool,
) -> bool {
    let mut clicked = false;
    card_frame(BG_CARD).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.set_min_height(152.0);
        ui.horizontal(|ui| {
            paint_badge_icon(ui, icon, accent);
            ui.add_space(10.0);
            ui.label(
                RichText::new(title)
                    .strong()
                    .size(16.5)
                    .color(TEXT_PRIMARY),
            );
        });
        ui.add_space(8.0);
        ui.label(
            RichText::new(description)
                .size(12.5)
                .color(TEXT_MUTED),
        );
        ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
            ui.add_enabled_ui(enabled, |ui| {
                if secondary_button(ui, button_label, ui.available_width(), 32.0).clicked() {
                    clicked = true;
                }
            });
        });
    });
    clicked
}

fn paint_hero_radar(
    painter: &egui::Painter,
    rect: Rect,
    status: ProtectionStatus,
    accent: Color32,
    time_secs: f64,
) {
    let c = rect.center();
    let base_fill = Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 26);
    painter.circle_filled(c, 34.0, base_fill);
    painter.circle_stroke(c, 34.0, Stroke::new(1.5, accent));

    let pulse = ((time_secs * 1.8).sin() * 0.5 + 0.5) as f32;
    let ring_r = 24.0 + pulse * 10.0;
    let ring_alpha = ((1.0 - pulse) * 140.0) as u8;
    painter.circle_stroke(
        c,
        ring_r,
        Stroke::new(
            1.5,
            Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), ring_alpha),
        ),
    );

    match status {
        ProtectionStatus::Protected => {
            // Crisp protection checkmark inside ring
            let p1 = Pos2::new(c.x - 10.0, c.y + 1.0);
            let p2 = Pos2::new(c.x - 2.0, c.y + 9.0);
            let p3 = Pos2::new(c.x + 12.0, c.y - 8.0);
            painter.line_segment([p1, p2], Stroke::new(3.0, accent));
            painter.line_segment([p2, p3], Stroke::new(3.0, accent));
        }
        ProtectionStatus::Scanning => {
            // Rotating radar sweep spoke
            let angle = (time_secs * 3.5) as f32;
            let end = Pos2::new(c.x + angle.cos() * 26.0, c.y + angle.sin() * 26.0);
            painter.circle_stroke(c, 16.0, Stroke::new(1.5, accent));
            painter.line_segment([c, end], Stroke::new(2.5, accent));
            painter.circle_filled(c, 4.0, accent);
        }
        ProtectionStatus::ThreatsDetected => {
            // Alert exclamation symbol
            painter.line_segment(
                [Pos2::new(c.x, c.y - 12.0), Pos2::new(c.x, c.y + 3.0)],
                Stroke::new(3.2, accent),
            );
            painter.circle_filled(Pos2::new(c.x, c.y + 10.0), 2.5, accent);
        }
    }
}

fn paint_badge_icon(ui: &mut egui::Ui, icon: FeatureIcon, accent: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(34.0, 34.0), egui::Sense::hover());
    let c = rect.center();
    let p = ui.painter();
    let bg = Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 32);
    p.rect(
        rect,
        CornerRadius::same(9),
        bg,
        Stroke::new(1.0, Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 120)),
        egui::StrokeKind::Inside,
    );

    match icon {
        FeatureIcon::QuickBolt => {
            p.line_segment(
                [Pos2::new(c.x + 2.0, c.y - 8.0), Pos2::new(c.x - 4.0, c.y)],
                Stroke::new(2.0, accent),
            );
            p.line_segment(
                [Pos2::new(c.x - 4.0, c.y), Pos2::new(c.x + 4.0, c.y)],
                Stroke::new(2.0, accent),
            );
            p.line_segment(
                [Pos2::new(c.x + 4.0, c.y), Pos2::new(c.x - 2.0, c.y + 8.0)],
                Stroke::new(2.0, accent),
            );
        }
        FeatureIcon::DeepShield => {
            let top_l = Pos2::new(c.x - 7.0, c.y - 7.0);
            let top_r = Pos2::new(c.x + 7.0, c.y - 7.0);
            let mid_l = Pos2::new(c.x - 7.0, c.y + 1.0);
            let mid_r = Pos2::new(c.x + 7.0, c.y + 1.0);
            let bot = Pos2::new(c.x, c.y + 9.0);
            p.line_segment([top_l, top_r], Stroke::new(1.8, accent));
            p.line_segment([top_l, mid_l], Stroke::new(1.8, accent));
            p.line_segment([top_r, mid_r], Stroke::new(1.8, accent));
            p.line_segment([mid_l, bot], Stroke::new(1.8, accent));
            p.line_segment([mid_r, bot], Stroke::new(1.8, accent));
        }
        FeatureIcon::CustomTarget => {
            p.circle_stroke(c, 7.0, Stroke::new(1.8, accent));
            p.circle_filled(c, 2.5, accent);
            p.line_segment(
                [Pos2::new(c.x - 10.0, c.y), Pos2::new(c.x - 5.0, c.y)],
                Stroke::new(1.5, accent),
            );
            p.line_segment(
                [Pos2::new(c.x + 5.0, c.y), Pos2::new(c.x + 10.0, c.y)],
                Stroke::new(1.5, accent),
            );
        }
        FeatureIcon::VaultLock => {
            p.rect_stroke(
                Rect::from_center_size(Pos2::new(c.x, c.y + 3.0), Vec2::new(14.0, 10.0)),
                CornerRadius::same(2),
                Stroke::new(1.8, accent),
                egui::StrokeKind::Inside,
            );
            p.circle_stroke(Pos2::new(c.x, c.y - 4.0), 4.0, Stroke::new(1.8, accent));
        }
        FeatureIcon::PulseCheck => {
            p.line_segment(
                [Pos2::new(c.x - 9.0, c.y), Pos2::new(c.x - 4.0, c.y)],
                Stroke::new(1.8, accent),
            );
            p.line_segment(
                [Pos2::new(c.x - 4.0, c.y), Pos2::new(c.x - 1.0, c.y - 7.0)],
                Stroke::new(1.8, accent),
            );
            p.line_segment(
                [Pos2::new(c.x - 1.0, c.y - 7.0), Pos2::new(c.x + 2.0, c.y + 7.0)],
                Stroke::new(1.8, accent),
            );
            p.line_segment(
                [Pos2::new(c.x + 2.0, c.y + 7.0), Pos2::new(c.x + 5.0, c.y)],
                Stroke::new(1.8, accent),
            );
            p.line_segment(
                [Pos2::new(c.x + 5.0, c.y), Pos2::new(c.x + 9.0, c.y)],
                Stroke::new(1.8, accent),
            );
        }
        FeatureIcon::AuditTerminal => {
            p.line_segment(
                [Pos2::new(c.x - 7.0, c.y - 4.0), Pos2::new(c.x - 2.0, c.y)],
                Stroke::new(1.8, accent),
            );
            p.line_segment(
                [Pos2::new(c.x - 2.0, c.y), Pos2::new(c.x - 7.0, c.y + 4.0)],
                Stroke::new(1.8, accent),
            );
            p.line_segment(
                [Pos2::new(c.x, c.y + 4.0), Pos2::new(c.x + 7.0, c.y + 4.0)],
                Stroke::new(1.8, accent),
            );
        }
    }
}

fn card_frame(fill: Color32) -> Frame {
    card_frame_with_stroke(fill, BORDER_SUBTLE)
}

fn card_frame_with_stroke(fill: Color32, border: Color32) -> Frame {
    Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(16))
}

fn render_kpi_card(ui: &mut egui::Ui, title: &str, value: &str, sub: &str, accent: Color32) {
    card_frame(BG_CARD).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(3.0, 14.0), egui::Sense::hover());
            ui.painter()
                .rect_filled(bar_rect, CornerRadius::same(2), accent);
            ui.label(RichText::new(title).size(10.5).strong().color(TEXT_MUTED));
        });
        ui.add_space(6.0);
        ui.label(RichText::new(value).size(18.5).strong().color(TEXT_PRIMARY));
        ui.add_space(3.0);
        ui.label(RichText::new(sub).size(11.5).color(TEXT_MUTED));
    });
}

fn render_system_report_details(ui: &mut egui::Ui, report: &MrtReport) {
    egui::Grid::new("system_report_grid")
        .num_columns(2)
        .spacing([14.0, 6.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Scan Type:").color(TEXT_MUTED).size(12.0));
            ui.label(
                RichText::new(&report.scan_type)
                    .color(TEXT_PRIMARY)
                    .size(12.0),
            );
            ui.end_row();

            ui.label(RichText::new("Started:").color(TEXT_MUTED).size(12.0));
            ui.label(
                RichText::new(&report.started_on)
                    .color(TEXT_PRIMARY)
                    .size(12.0),
            );
            ui.end_row();

            ui.label(RichText::new("Finished:").color(TEXT_MUTED).size(12.0));
            ui.label(
                RichText::new(&report.finished_on)
                    .color(TEXT_PRIMARY)
                    .size(12.0),
            );
            ui.end_row();

            ui.label(RichText::new("Engine / Sigs:").color(TEXT_MUTED).size(12.0));
            ui.label(
                RichText::new(format!(
                    "{} / {}",
                    report.engine_version, report.signatures_version
                ))
                .color(TEXT_PRIMARY)
                .size(12.0),
            );
            ui.end_row();

            ui.label(RichText::new("Status Code:").color(TEXT_MUTED).size(12.0));
            let rc_color = if report.return_code == 0 {
                ACCENT_GREEN
            } else {
                ACCENT_RED_SOFT
            };
            ui.label(
                RichText::new(format!(
                    "{} ({})",
                    report.return_code, report.return_code_hex
                ))
                .strong()
                .color(rc_color)
                .size(12.0),
            );
            ui.end_row();

            ui.label(RichText::new("Findings:").color(TEXT_MUTED).size(12.0));
            let findings_text = if report.infected_items.is_empty() {
                "No infection found.".to_string()
            } else {
                format!("{} threat entry(s) detected", report.infected_items.len())
            };
            ui.label(
                RichText::new(findings_text)
                    .color(if report.infected_items.is_empty() {
                        ACCENT_GREEN
                    } else {
                        ACCENT_RED_SOFT
                    })
                    .size(12.0),
            );
            ui.end_row();
        });
}

fn render_log_row(ui: &mut egui::Ui, entry: &ActivityLogEntry) {
    let badge_color = match entry.level {
        LogLevel::Info => ACCENT_CYAN,
        LogLevel::Success => ACCENT_GREEN,
        LogLevel::Warning => ACCENT_AMBER,
        LogLevel::Threat => ACCENT_RED_SOFT,
    };

    Frame::new()
        .fill(BG_ELEVATED)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("[{}]", entry.level.label()))
                        .strong()
                        .monospace()
                        .size(11.0)
                        .color(badge_color),
                );
                ui.label(
                    RichText::new(&entry.timestamp)
                        .monospace()
                        .size(11.0)
                        .color(TEXT_MUTED),
                );
                ui.label(
                    RichText::new(format!("[{}]", entry.category))
                        .strong()
                        .size(12.0)
                        .color(TEXT_PRIMARY),
                );
                ui.label(
                    RichText::new(&entry.message)
                        .size(12.5)
                        .color(TEXT_SECONDARY),
                );
            });
            if let Some(ref details) = entry.details {
                ui.label(
                    RichText::new(details)
                        .monospace()
                        .size(11.0)
                        .color(TEXT_MUTED),
                );
            }
        });
}

fn apply_sentient_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = BG_CARD;
    visuals.panel_fill = BG_APP;
    visuals.extreme_bg_color = BG_APP;
    visuals.faint_bg_color = BG_SIDEBAR;
    visuals.override_text_color = Some(TEXT_PRIMARY);
    visuals.widgets.noninteractive.bg_fill = BG_CARD;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.inactive.bg_fill = BG_ELEVATED;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(36, 51, 78);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT_CYAN);
    visuals.widgets.active.bg_fill = Color32::from_rgb(44, 64, 96);
    visuals.selection.bg_fill = Color32::from_rgb(14, 116, 144);
    ctx.set_visuals(visuals);
}

fn state_file_path() -> PathBuf {
    sentient_data_dir().join("state.json")
}

fn logs_file_path() -> PathBuf {
    sentient_data_dir().join("activity_logs.json")
}

fn load_persisted_state() -> PersistedAppState {
    let path = state_file_path();
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_persisted_state(state: &PersistedAppState) {
    let path = state_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = fs::write(path, json);
    }
}

fn load_activity_logs() -> Vec<ActivityLogEntry> {
    let path = logs_file_path();
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_activity_logs(logs: &[ActivityLogEntry]) {
    let path = logs_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(logs) {
        let _ = fs::write(path, json);
    }
}
