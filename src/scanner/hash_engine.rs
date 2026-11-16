use crate::models::{
    now_timestamp, sentient_data_dir, ScanEvent, ScanMode, ScanSummary, SignatureDatabase, Threat,
    ThreatSignature, ThreatSource,
};
use crossbeam_channel::Sender;
use md5::Md5;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use walkdir::WalkDir;

const CHUNK_SIZE: usize = 64 * 1024;
const DEFAULT_SIGNATURES_JSON: &str = include_str!("../../signatures.json");

/// Standard 68-byte EICAR anti-malware test signature detected directly in memory.
pub const EICAR_TEST_SIGNATURE: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

/// Fast O(1) lookup index built from `signatures.json`.
#[derive(Debug, Clone)]
pub struct SignatureIndex {
    pub version: String,
    pub updated_at: String,
    pub entries: Vec<ThreatSignature>,
    sha256_map: HashMap<String, ThreatSignature>,
    md5_map: HashMap<String, ThreatSignature>,
}

impl SignatureIndex {
    /// Builds an indexed hash lookup map from a parsed `SignatureDatabase`.
    pub fn from_database(db: SignatureDatabase) -> Self {
        let mut sha256_map = HashMap::with_capacity(db.signatures.len());
        let mut md5_map = HashMap::with_capacity(db.signatures.len());

        for sig in &db.signatures {
            let sha = sig.sha256.trim().to_ascii_lowercase();
            if !sha.is_empty() {
                sha256_map.insert(sha, sig.clone());
            }
            let md5 = sig.md5.trim().to_ascii_lowercase();
            if !md5.is_empty() {
                md5_map.insert(md5, sig.clone());
            }
        }

        Self {
            version: db.version,
            updated_at: db.updated_at,
            entries: db.signatures,
            sha256_map,
            md5_map,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks a lowercase SHA-256 and MD5 pair against the local signature maps.
    pub fn match_hashes(&self, sha256: &str, md5: &str) -> Option<&ThreatSignature> {
        self.sha256_map
            .get(sha256)
            .or_else(|| self.md5_map.get(md5))
    }

    pub fn to_database(&self) -> SignatureDatabase {
        SignatureDatabase {
            version: self.version.clone(),
            updated_at: self.updated_at.clone(),
            signatures: self.entries.clone(),
        }
    }
}

/// Manages loading, seeding, and updating `%LOCALAPPDATA%\Sentient\signatures.json`.
pub struct SignatureStore {
    path: PathBuf,
}

impl SignatureStore {
    pub fn new() -> Self {
        Self {
            path: sentient_data_dir().join("signatures.json"),
        }
    }

    #[allow(dead_code)]
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads `signatures.json` from `%LOCALAPPDATA%\Sentient\signatures.json`,
    /// seeding it from `./signatures.json` or the embedded default database if missing.
    pub fn load_or_seed(&self) -> Result<SignatureIndex, String> {
        if !self.path.exists() {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create signature directory: {e}"))?;
            }
            let local_seed = Path::new("signatures.json");
            let seed_content = if local_seed.exists() {
                fs::read_to_string(local_seed)
                    .unwrap_or_else(|_| DEFAULT_SIGNATURES_JSON.to_string())
            } else {
                DEFAULT_SIGNATURES_JSON.to_string()
            };
            let _ = fs::write(&self.path, &seed_content);
            let db: SignatureDatabase = serde_json::from_str(&seed_content)
                .map_err(|e| format!("Failed to parse seed signatures.json: {e}"))?;
            return Ok(SignatureIndex::from_database(db));
        }

        let content = fs::read_to_string(&self.path).map_err(|e| {
            format!(
                "Failed to read signature database '{}': {e}",
                self.path.display()
            )
        })?;
        let db: SignatureDatabase = serde_json::from_str(&content).map_err(|e| {
            format!(
                "Failed to parse signature database '{}': {e}",
                self.path.display()
            )
        })?;
        Ok(SignatureIndex::from_database(db))
    }

    /// Appends a user-supplied SHA-256 or MD5 signature and persists `signatures.json`.
    pub fn add_signature(&self, sig: ThreatSignature) -> Result<SignatureIndex, String> {
        let mut index = self.load_or_seed()?;
        let mut db = index.to_database();
        db.updated_at = now_timestamp();
        db.signatures.push(sig);
        let json = serde_json::to_string_pretty(&db)
            .map_err(|e| format!("Failed to serialize signatures.json: {e}"))?;
        fs::write(&self.path, json)
            .map_err(|e| format!("Failed to save '{}': {e}", self.path.display()))?;
        index = SignatureIndex::from_database(db);
        Ok(index)
    }
}

/// Returns high-risk user-accessible directories for fast native Quick Hash Scans.
pub fn quick_scan_roots() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    #[cfg(windows)]
    {
        if let Some(profile) = std::env::var_os("USERPROFILE") {
            let home = PathBuf::from(profile);
            candidates.push(home.join("Downloads"));
            candidates.push(home.join("Desktop"));
        }
        if let Some(temp) = std::env::var_os("TEMP") {
            candidates.push(PathBuf::from(temp));
        }
        if let Some(appdata) = std::env::var_os("APPDATA") {
            candidates.push(
                PathBuf::from(appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup"),
            );
        }
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(PathBuf::from(local_appdata).join("Temp"));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(home_os) = std::env::var_os("HOME") {
            let home = PathBuf::from(home_os);
            candidates.push(home.join("Downloads"));
            candidates.push(home.join("Desktop"));
            candidates.push(home.join(".local").join("bin"));
            candidates.push(home.join(".config").join("autostart"));
        }
        candidates.push(PathBuf::from("/tmp"));
        candidates.push(PathBuf::from("/var/tmp"));
        candidates.push(PathBuf::from("/dev/shm"));
    }

    let mut unique = Vec::new();
    for p in candidates {
        if p.exists() && !unique.iter().any(|u: &PathBuf| u == &p) {
            unique.push(p);
        }
    }
    if unique.is_empty() {
        if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
            let p = PathBuf::from(home);
            if p.exists() {
                unique.push(p);
            }
        }
        if unique.is_empty() {
            unique.push(std::env::temp_dir());
        }
    }
    unique
}

/// Scans one or more target directories concurrently using `walkdir`, a bounded `rayon` worker pool,
/// and 64 KiB chunked streaming SHA-256 + MD5 + in-memory EICAR inspection.
#[allow(clippy::too_many_arguments)]
pub fn run_hash_scan(
    roots: Vec<PathBuf>,
    mode: ScanMode,
    target_label: String,
    quarantine_dir: PathBuf,
    signatures: Arc<SignatureIndex>,
    worker_threads: usize,
    max_file_size_bytes: Option<u64>,
    log_inaccessible: bool,
    cancel_flag: Arc<AtomicBool>,
    tx: Sender<ScanEvent>,
) {
    let started_at = now_timestamp();
    let start_instant = Instant::now();

    let canonical_quarantine =
        fs::canonicalize(&quarantine_dir).unwrap_or_else(|_| quarantine_dir.clone());

    let files_scanned = Arc::new(AtomicUsize::new(0));
    let bytes_scanned = Arc::new(AtomicU64::new(0));
    let skipped_inaccessible = Arc::new(AtomicUsize::new(0));
    let last_ui_emit_ms = Arc::new(AtomicU64::new(0));
    let detected_threats: Arc<Mutex<Vec<Threat>>> = Arc::new(Mutex::new(Vec::new()));

    let threads = worker_threads.clamp(1, 64);
    let pool = match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
        Ok(p) => p,
        Err(e) => {
            let _ = tx.send(ScanEvent::Error(format!(
                "Failed to initialize scanner thread pool: {e}"
            )));
            let _ = tx.send(ScanEvent::Complete {
                summary: ScanSummary {
                    mode,
                    target: target_label,
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

    let _ = tx.send(ScanEvent::Status(format!(
        "Scanning {} across {threads} worker threads...",
        target_label
    )));

    pool.install(|| {
        for root in &roots {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }
            if !root.exists() {
                let _ = tx.send(ScanEvent::Error(format!(
                    "Target directory does not exist: '{}'",
                    root.display()
                )));
                continue;
            }

            let q_dir_raw = quarantine_dir.clone();
            let q_dir_canon = canonical_quarantine.clone();
            let cancel_walk = Arc::clone(&cancel_flag);
            let walker = WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_entry(move |entry| {
                    if cancel_walk.load(Ordering::Relaxed) {
                        return false;
                    }
                    // Never scan Sentient's own quarantine vault.
                    let entry_path = entry.path();
                    if entry_path == q_dir_raw || entry_path == q_dir_canon {
                        return false;
                    }
                    true
                });

            walker.par_bridge().for_each(|entry_res| {
                if cancel_flag.load(Ordering::Relaxed) {
                    return;
                }

                let entry = match entry_res {
                    Ok(e) => e,
                    Err(err) => {
                        skipped_inaccessible.fetch_add(1, Ordering::Relaxed);
                        if log_inaccessible {
                            let _ = tx.send(ScanEvent::Error(format!(
                                "Skipped inaccessible entry: {err}"
                            )));
                        }
                        return;
                    }
                };

                if !entry.file_type().is_file() {
                    return;
                }

                let path = entry.path().to_path_buf();

                if let Some(max_bytes) = max_file_size_bytes {
                    if let Ok(meta) = entry.metadata() {
                        if meta.len() > max_bytes {
                            skipped_inaccessible.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                match inspect_file(&path, &signatures, &cancel_flag) {
                    Ok(InspectOutcome::Cancelled) => {}
                    Ok(InspectOutcome::Clean { size }) => {
                        let count = files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
                        let total_bytes = bytes_scanned.fetch_add(size, Ordering::Relaxed) + size;
                        emit_throttled_progress(
                            &tx,
                            &start_instant,
                            &last_ui_emit_ms,
                            &path,
                            count,
                            total_bytes,
                            skipped_inaccessible.load(Ordering::Relaxed),
                        );
                    }
                    Ok(InspectOutcome::Threat {
                        size,
                        threat_name,
                        sha256,
                        md5,
                        source,
                    }) => {
                        let count = files_scanned.fetch_add(1, Ordering::Relaxed) + 1;
                        let total_bytes = bytes_scanned.fetch_add(size, Ordering::Relaxed) + size;
                        let threat = Threat {
                            id: format!(
                                "th_{}_{count}",
                                chrono::Local::now().format("%Y%m%d%H%M%S")
                            ),
                            path: path.clone(),
                            threat_name: threat_name.clone(),
                            sha256: sha256.clone(),
                            md5,
                            file_size: size,
                            detected_at: now_timestamp(),
                            source,
                            quarantined: false,
                        };
                        if let Ok(mut list) = detected_threats.lock() {
                            list.push(threat);
                        }
                        let _ = tx.send(ScanEvent::ThreatFound {
                            path: path.clone(),
                            threat_name,
                            hash: sha256,
                        });
                        emit_throttled_progress(
                            &tx,
                            &start_instant,
                            &last_ui_emit_ms,
                            &path,
                            count,
                            total_bytes,
                            skipped_inaccessible.load(Ordering::Relaxed),
                        );
                    }
                    Err(err) => {
                        // Gracefully skip locked/inaccessible Windows system files without crashing.
                        skipped_inaccessible.fetch_add(1, Ordering::Relaxed);
                        if log_inaccessible {
                            let _ = tx.send(ScanEvent::Error(format!(
                                "Skipped '{}': {err}",
                                path.display()
                            )));
                        }
                    }
                }
            });
        }
    });

    let final_scanned = files_scanned.load(Ordering::Relaxed);
    let final_bytes = bytes_scanned.load(Ordering::Relaxed);
    let final_skipped = skipped_inaccessible.load(Ordering::Relaxed);
    let cancelled = cancel_flag.load(Ordering::Relaxed);
    let threats = detected_threats
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();

    let _ = tx.send(ScanEvent::Progress {
        scanned: final_scanned,
        total: Some(final_scanned),
    });
    let _ = tx.send(ScanEvent::Metrics {
        bytes_scanned: final_bytes,
        skipped_inaccessible: final_skipped,
    });
    let _ = tx.send(ScanEvent::Complete {
        summary: ScanSummary {
            mode,
            target: target_label,
            started_at,
            finished_at: now_timestamp(),
            duration_secs: start_instant.elapsed().as_secs_f64(),
            files_scanned: final_scanned,
            bytes_scanned: final_bytes,
            threats_found: threats.len(),
            skipped_inaccessible: final_skipped,
            cancelled,
            detected_threats: threats,
            mrt_report: None,
        },
    });
}

pub enum InspectOutcome {
    Clean {
        size: u64,
    },
    Threat {
        size: u64,
        threat_name: String,
        sha256: String,
        md5: String,
        source: ThreatSource,
    },
    Cancelled,
}

fn inspect_file(
    path: &Path,
    signatures: &SignatureIndex,
    cancel_flag: &AtomicBool,
) -> io::Result<InspectOutcome> {
    let file = File::open(path)?;
    inspect_reader(file, signatures, cancel_flag)
}

/// Core chunked reader inspector shared between live file scanning and in-memory EICAR self-tests.
pub fn inspect_reader<R: Read>(
    mut reader: R,
    signatures: &SignatureIndex,
    cancel_flag: &AtomicBool,
) -> io::Result<InspectOutcome> {
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut sha256_hasher = Sha256::new();
    let mut md5_hasher = Md5::new();
    let mut total_size = 0u64;
    let mut eicar_detected = false;
    let mut overlap = Vec::new();

    loop {
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(InspectOutcome::Cancelled);
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        sha256_hasher.update(chunk);
        md5_hasher.update(chunk);

        if !eicar_detected {
            eicar_detected = check_eicar_chunk(chunk, &mut overlap);
        }

        total_size += n as u64;
    }

    let sha256_hex = hex::encode(sha256_hasher.finalize());
    let md5_hex = hex::encode(md5_hasher.finalize());

    if let Some(sig) = signatures.match_hashes(&sha256_hex, &md5_hex) {
        return Ok(InspectOutcome::Threat {
            size: total_size,
            threat_name: sig.name.clone(),
            sha256: sha256_hex,
            md5: md5_hex,
            source: if eicar_detected {
                ThreatSource::InMemoryEicar
            } else {
                ThreatSource::HashDatabase
            },
        });
    }

    if eicar_detected {
        return Ok(InspectOutcome::Threat {
            size: total_size,
            threat_name: "EICAR-Standard-Anti-Virus-Test-File (In-Memory)".to_string(),
            sha256: sha256_hex,
            md5: md5_hex,
            source: ThreatSource::InMemoryEicar,
        });
    }

    Ok(InspectOutcome::Clean { size: total_size })
}

/// Checks whether the EICAR test string appears in the current chunk (including across chunk boundaries).
fn check_eicar_chunk(chunk: &[u8], overlap: &mut Vec<u8>) -> bool {
    let needle = EICAR_TEST_SIGNATURE;
    if overlap.is_empty() && chunk.len() >= needle.len() && contains_subslice(chunk, needle) {
        return true;
    }

    if !overlap.is_empty() {
        let take = chunk.len().min(needle.len() - 1);
        let mut boundary = Vec::with_capacity(overlap.len() + take);
        boundary.extend_from_slice(overlap);
        boundary.extend_from_slice(&chunk[..take]);
        if contains_subslice(&boundary, needle) {
            return true;
        }
    }

    if chunk.len() >= needle.len() && contains_subslice(chunk, needle) {
        return true;
    }

    // Retain trailing `needle.len() - 1` bytes to detect signatures split across 64 KiB boundaries.
    let keep = chunk.len().min(needle.len() - 1);
    overlap.clear();
    overlap.extend_from_slice(&chunk[chunk.len() - keep..]);
    false
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    // Fast initial byte filter before running windowed comparison.
    let Some(&first) = needle.first() else {
        return false;
    };
    let mut pos = 0;
    while pos + needle.len() <= haystack.len() {
        if let Some(rel) = haystack[pos..haystack.len() - needle.len() + 1]
            .iter()
            .position(|&b| b == first)
        {
            let idx = pos + rel;
            if &haystack[idx..idx + needle.len()] == needle {
                return true;
            }
            pos = idx + 1;
        } else {
            break;
        }
    }
    false
}

fn emit_throttled_progress(
    tx: &Sender<ScanEvent>,
    start: &Instant,
    last_emit_ms: &AtomicU64,
    path: &Path,
    scanned: usize,
    bytes_scanned: u64,
    skipped_inaccessible: usize,
) {
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let prev = last_emit_ms.load(Ordering::Relaxed);
    if scanned <= 5 || elapsed_ms.saturating_sub(prev) >= 25 {
        if last_emit_ms
            .compare_exchange(prev, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let _ = tx.send(ScanEvent::FileScanned(path.to_path_buf()));
            let _ = tx.send(ScanEvent::Progress {
                scanned,
                total: None,
            });
            let _ = tx.send(ScanEvent::Metrics {
                bytes_scanned,
                skipped_inaccessible,
            });
        }
    }
}

/// Runs an immediate in-memory EICAR detection verification through Sentient's hash + pattern engine
/// without writing any trigger bytes to disk.
pub fn run_in_memory_eicar_self_test(signatures: &SignatureIndex) -> Result<Threat, String> {
    let cancel = AtomicBool::new(false);
    let outcome = inspect_reader(io::Cursor::new(EICAR_TEST_SIGNATURE), signatures, &cancel)
        .map_err(|e| format!("In-memory EICAR self-test I/O failure: {e}"))?;

    match outcome {
        InspectOutcome::Threat {
            size,
            threat_name,
            sha256,
            md5,
            source,
        } => Ok(Threat {
            id: format!("selftest_{}", chrono::Local::now().format("%Y%m%d%H%M%S")),
            path: PathBuf::from("<in-memory://EICAR-Standard-Test-Buffer>"),
            threat_name,
            sha256,
            md5,
            file_size: size,
            detected_at: now_timestamp(),
            source,
            quarantined: false,
        }),
        _ => Err("In-memory EICAR self-test failed to trigger detection.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    #[test]
    fn test_in_memory_eicar_self_test() {
        let db: SignatureDatabase = serde_json::from_str(DEFAULT_SIGNATURES_JSON).unwrap();
        let index = SignatureIndex::from_database(db);
        let threat = run_in_memory_eicar_self_test(&index).unwrap();
        assert_eq!(
            threat.sha256,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
        assert_eq!(threat.md5, "44d88612fea8a8f36de82e1278abb02f");
        assert_eq!(threat.source, ThreatSource::InMemoryEicar);
    }

    #[test]
    fn test_eicar_split_across_chunk_boundary() {
        let db: SignatureDatabase = serde_json::from_str(DEFAULT_SIGNATURES_JSON).unwrap();
        let index = SignatureIndex::from_database(db);
        let mut payload = vec![b'A'; CHUNK_SIZE - 10];
        payload.extend_from_slice(EICAR_TEST_SIGNATURE);
        payload.extend_from_slice(b"TRAILING_BYTES");

        let cancel = AtomicBool::new(false);
        let outcome = inspect_reader(io::Cursor::new(payload), &index, &cancel).unwrap();
        match outcome {
            InspectOutcome::Threat { source, .. } => {
                assert_eq!(source, ThreatSource::InMemoryEicar);
            }
            _ => panic!("Expected EICAR detection across chunk boundary"),
        }
    }

    #[test]
    fn test_multithreaded_directory_scan_detects_simulated_sample() {
        let dir = std::env::temp_dir().join("sentient_scan_test_dir");
        let q_dir = dir.join("Quarantine");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&q_dir).unwrap();

        let clean_file = dir.join("notes.txt");
        let sample_file = dir.join("sim_threat.bin");
        fs::write(&clean_file, b"hello sentient clean file").unwrap();
        fs::write(&sample_file, b"SENTIENT-LOCAL-SIMULATED-MALWARE-SAMPLE-V1").unwrap();

        let db: SignatureDatabase = serde_json::from_str(DEFAULT_SIGNATURES_JSON).unwrap();
        let index = Arc::new(SignatureIndex::from_database(db));
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = unbounded();

        run_hash_scan(
            vec![dir.clone()],
            ScanMode::CustomFolder,
            dir.display().to_string(),
            q_dir,
            index,
            2,
            None,
            true,
            cancel,
            tx,
        );

        let events: Vec<ScanEvent> = rx.try_iter().collect();
        let summary = events
            .iter()
            .find_map(|e| match e {
                ScanEvent::Complete { summary } => Some(summary),
                _ => None,
            })
            .expect("Expected ScanEvent::Complete");

        assert_eq!(summary.files_scanned, 2);
        assert_eq!(summary.threats_found, 1);
        assert_eq!(
            summary.detected_threats[0].threat_name,
            "Sentient.Test.SimulatedThreat.A"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_signature_store_seed_and_add() {
        let dir = std::env::temp_dir().join("sentient_sigstore_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sig_path = dir.join("signatures.json");

        let store = SignatureStore::with_path(sig_path.clone());
        let seeded = store.load_or_seed().unwrap();
        assert!(!seeded.is_empty());
        assert!(sig_path.exists());

        let updated = store
            .add_signature(ThreatSignature {
                name: "UnitTest.Custom.IOC".to_string(),
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                md5: String::new(),
                severity: "High".to_string(),
                description: "Test IOC".to_string(),
            })
            .unwrap();
        assert_eq!(updated.len(), seeded.len() + 1);
        assert!(updated
            .match_hashes(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ""
            )
            .is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_quick_scan_roots_returns_existing_directories() {
        let roots = quick_scan_roots();
        assert!(!roots.is_empty(), "quick_scan_roots should never be empty");
        for r in &roots {
            assert!(r.exists(), "Returned root '{}' must exist", r.display());
        }
    }
}
