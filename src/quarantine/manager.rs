use crate::models::{now_timestamp, sentient_data_dir, QuarantineIndex, QuarantineItem};
use crate::platform::{harden_quarantined_file, unharden_quarantined_file};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// XOR obfuscation key applied to quarantined files so Windows cannot parse PE/script headers.
pub const QUARANTINE_XOR_KEY: u8 = 0x5A;

const CHUNK_SIZE: usize = 64 * 1024;
static ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Manages isolated malicious files in `%LOCALAPPDATA%\Sentient\Quarantine`
/// and persists metadata in `quarantine_index.json`.
pub struct QuarantineManager {
    quarantine_dir: PathBuf,
    index_path: PathBuf,
    index: QuarantineIndex,
}

impl QuarantineManager {
    /// Initializes the quarantine manager using `%LOCALAPPDATA%\Sentient`.
    pub fn new() -> Result<Self, String> {
        let base = sentient_data_dir();
        let quarantine_dir = base.join("Quarantine");
        let index_path = base.join("quarantine_index.json");
        Self::with_paths(quarantine_dir, index_path)
    }

    /// Initializes a quarantine manager with custom storage paths (useful for testing).
    pub fn with_paths(quarantine_dir: PathBuf, index_path: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&quarantine_dir).map_err(|e| {
            format!(
                "Failed to create quarantine directory '{}': {e}",
                quarantine_dir.display()
            )
        })?;
        if let Some(parent) = index_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create index directory: {e}"))?;
        }

        let index = load_index(&index_path)?;
        Ok(Self {
            quarantine_dir,
            index_path,
            index,
        })
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    pub fn index_path(&self) -> &Path {
        &self.index_path
    }

    pub fn items(&self) -> &[QuarantineItem] {
        &self.index.items
    }

    /// Reloads `quarantine_index.json` from disk.
    pub fn reload(&mut self) -> Result<(), String> {
        self.index = load_index(&self.index_path)?;
        Ok(())
    }

    /// Isolates a detected threat file:
    /// 1. Appends `.quarantined` extension
    /// 2. Stream-applies XOR cipher (`0x5A`) into the Sentient Quarantine directory
    /// 3. Strips write/execute/read permissions & marks hidden/read-only
    /// 4. Removes the original file from its source path
    /// 5. Persists entry metadata into `quarantine_index.json`
    pub fn quarantine_file(
        &mut self,
        source_path: &Path,
        threat_name: &str,
        sha256: &str,
        md5: &str,
    ) -> Result<QuarantineItem, String> {
        if !source_path.exists() {
            return Err(format!(
                "Source file no longer exists: '{}'",
                source_path.display()
            ));
        }

        if is_inside_dir(source_path, &self.quarantine_dir) {
            return Err(format!(
                "File is already inside Sentient quarantine: '{}'",
                source_path.display()
            ));
        }

        let id = generate_item_id();
        let file_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown_sample");
        let sanitized_name: String = file_name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();

        let quarantined_path = self
            .quarantine_dir
            .join(format!("{id}_{sanitized_name}.quarantined"));

        let (file_size, computed_sha256) = xor_transform_and_hash(
            source_path,
            &quarantined_path,
            QUARANTINE_XOR_KEY,
            sha256.is_empty(),
        )
        .map_err(|e| {
            let _ = fs::remove_file(&quarantined_path);
            format!(
                "Failed to isolate '{}' into quarantine: {e}",
                source_path.display()
            )
        })?;

        let final_sha256 = if sha256.is_empty() {
            computed_sha256
        } else {
            sha256.to_lowercase()
        };

        if let Err(e) = remove_original_file(source_path) {
            // Roll back quarantined copy so we don't leave duplicates behind on failure.
            let _ = unharden_quarantined_file(&quarantined_path);
            let _ = fs::remove_file(&quarantined_path);
            return Err(format!(
                "Copied to quarantine but failed to remove original file '{}': {e}",
                source_path.display()
            ));
        }

        if let Err(e) = harden_quarantined_file(&quarantined_path) {
            let _ = e; // Non-fatal if OS/filesystem rejects extended attribute hardening.
        }

        let now = now_timestamp();
        let item = QuarantineItem {
            id,
            original_path: source_path.to_path_buf(),
            quarantined_path,
            threat_name: threat_name.to_string(),
            file_size,
            sha256: final_sha256,
            md5: md5.to_lowercase(),
            detected_at: now.clone(),
            quarantined_at: now,
            xor_key: QUARANTINE_XOR_KEY,
        };

        self.index.items.push(item.clone());
        save_index(&self.index_path, &self.index)?;
        Ok(item)
    }

    /// Decrypts (de-XORs) a quarantined file and restores it to its original path.
    pub fn restore_item(&mut self, item_id: &str) -> Result<PathBuf, String> {
        let idx = self
            .index
            .items
            .iter()
            .position(|i| i.id == item_id)
            .ok_or_else(|| format!("Quarantine item '{item_id}' not found."))?;

        let item = self.index.items[idx].clone();
        if !item.quarantined_path.exists() {
            return Err(format!(
                "Quarantined payload missing on disk: '{}'",
                item.quarantined_path.display()
            ));
        }

        if item.original_path.exists() {
            return Err(format!(
                "Cannot restore because a file already exists at '{}'. Move or delete it first.",
                item.original_path.display()
            ));
        }

        if let Some(parent) = item.original_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to ensure restore directory '{}': {e}",
                    parent.display()
                )
            })?;
        }

        unharden_quarantined_file(&item.quarantined_path).map_err(|e| {
            format!(
                "Failed to unlock permissions on '{}': {e}",
                item.quarantined_path.display()
            )
        })?;

        if let Err(e) = xor_transform_and_hash(
            &item.quarantined_path,
            &item.original_path,
            item.xor_key,
            false,
        ) {
            let _ = fs::remove_file(&item.original_path);
            let _ = harden_quarantined_file(&item.quarantined_path);
            return Err(format!(
                "Failed to restore '{}' to '{}': {e}",
                item.quarantined_path.display(),
                item.original_path.display()
            ));
        }

        let _ = unharden_quarantined_file(&item.original_path);
        fs::remove_file(&item.quarantined_path).map_err(|e| {
            format!(
                "File restored to '{}', but failed to remove quarantined copy '{}': {e}",
                item.original_path.display(),
                item.quarantined_path.display()
            )
        })?;

        self.index.items.remove(idx);
        save_index(&self.index_path, &self.index)?;
        Ok(item.original_path)
    }

    /// Securely zeroes out every byte of the quarantined payload on disk and deletes it permanently.
    pub fn secure_delete_item(&mut self, item_id: &str) -> Result<QuarantineItem, String> {
        let idx = self
            .index
            .items
            .iter()
            .position(|i| i.id == item_id)
            .ok_or_else(|| format!("Quarantine item '{item_id}' not found."))?;

        let item = self.index.items[idx].clone();
        if item.quarantined_path.exists() {
            unharden_quarantined_file(&item.quarantined_path).map_err(|e| {
                format!(
                    "Failed to unlock quarantined file '{}' for deletion: {e}",
                    item.quarantined_path.display()
                )
            })?;

            secure_wipe_file(&item.quarantined_path).map_err(|e| {
                format!(
                    "Failed to securely wipe '{}': {e}",
                    item.quarantined_path.display()
                )
            })?;
        }

        self.index.items.remove(idx);
        save_index(&self.index_path, &self.index)?;
        Ok(item)
    }

    /// Securely zeroes and deletes all currently quarantined items.
    pub fn purge_all(&mut self) -> Result<usize, String> {
        let ids: Vec<String> = self.index.items.iter().map(|i| i.id.clone()).collect();
        let mut deleted = 0usize;
        for id in ids {
            self.secure_delete_item(&id)?;
            deleted += 1;
        }
        Ok(deleted)
    }
}

/// Shared stream helper that copies `src` to `dst` while XORing every byte with `key`
/// (symmetric for both quarantine scrambling and restoration).
fn xor_transform_and_hash(
    src: &Path,
    dst: &Path,
    key: u8,
    compute_src_sha256: bool,
) -> io::Result<(u64, String)> {
    let mut reader = File::open(src)?;
    let mut writer = File::create(dst)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total_bytes = 0u64;
    let mut hasher = compute_src_sha256.then(Sha256::new);

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let slice = &mut buf[..n];
        if let Some(ref mut h) = hasher {
            h.update(&*slice);
        }
        for byte in slice.iter_mut() {
            *byte ^= key;
        }
        writer.write_all(slice)?;
        total_bytes += n as u64;
    }

    writer.flush()?;
    writer.sync_all()?;

    let digest = hasher
        .map(|h| hex::encode(h.finalize()))
        .unwrap_or_default();
    Ok((total_bytes, digest))
}

/// Overwrites a file in-place with zero bytes, syncs to disk, and unlinks it.
fn secure_wipe_file(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len();
    {
        let mut file = OpenOptions::new().write(true).open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let zeros = vec![0u8; CHUNK_SIZE];
        let mut remaining = len;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..chunk])?;
            remaining -= chunk as u64;
        }
        file.flush()?;
        file.sync_all()?;
    }
    fs::remove_file(path)
}

fn remove_original_file(path: &Path) -> io::Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.permissions().readonly() {
            let mut perms = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
    fs::remove_file(path)
}

fn load_index(index_path: &Path) -> Result<QuarantineIndex, String> {
    if !index_path.exists() {
        return Ok(QuarantineIndex::default());
    }
    let content = fs::read_to_string(index_path).map_err(|e| {
        format!(
            "Failed to read quarantine index '{}': {e}",
            index_path.display()
        )
    })?;
    if content.trim().is_empty() {
        return Ok(QuarantineIndex::default());
    }
    serde_json::from_str(&content).map_err(|e| {
        format!(
            "Failed to parse quarantine index '{}': {e}",
            index_path.display()
        )
    })
}

fn save_index(index_path: &Path, index: &QuarantineIndex) -> Result<(), String> {
    let json = serde_json::to_string_pretty(index)
        .map_err(|e| format!("Failed to serialize quarantine index: {e}"))?;
    let tmp_path = index_path.with_extension("json.tmp");
    fs::write(&tmp_path, &json)
        .map_err(|e| format!("Failed to write quarantine index temp file: {e}"))?;
    fs::rename(&tmp_path, index_path)
        .or_else(|_| fs::write(index_path, &json))
        .map_err(|e| {
            format!(
                "Failed to save quarantine index '{}': {e}",
                index_path.display()
            )
        })
}

fn is_inside_dir(path: &Path, dir: &Path) -> bool {
    let norm_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let norm_dir = fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    norm_path.starts_with(norm_dir)
}

fn generate_item_id() -> String {
    let seq = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S");
    format!("q_{ts}_{seq:04}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentient_quarantine_test_{name}_{}",
            ID_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_quarantine_xor_and_restore_roundtrip() {
        let root = temp_test_dir("roundtrip");
        let q_dir = root.join("Quarantine");
        let idx_path = root.join("quarantine_index.json");
        let sample_path = root.join("malware_sample.exe");
        let original_bytes = b"MZ\x90\x00SENTIENT_TEST_PAYLOAD_123456";
        fs::write(&sample_path, original_bytes).unwrap();

        let mut mgr = QuarantineManager::with_paths(q_dir.clone(), idx_path.clone()).unwrap();
        let item = mgr
            .quarantine_file(&sample_path, "Test.Trojan.Generic", "", "")
            .unwrap();

        assert!(!sample_path.exists());
        assert!(item.quarantined_path.exists());
        assert!(item.quarantined_path.extension().and_then(|s| s.to_str()) == Some("quarantined"));
        assert_eq!(item.file_size, original_bytes.len() as u64);

        // Unlock temporarily to verify XOR bytes on disk.
        let _ = unharden_quarantined_file(&item.quarantined_path);
        let scrambled = fs::read(&item.quarantined_path).unwrap();
        assert_ne!(scrambled.as_slice(), original_bytes);
        assert_eq!(scrambled[0], original_bytes[0] ^ QUARANTINE_XOR_KEY);
        let _ = harden_quarantined_file(&item.quarantined_path);

        let restored = mgr.restore_item(&item.id).unwrap();
        assert_eq!(restored, sample_path);
        assert!(sample_path.exists());
        assert!(!item.quarantined_path.exists());
        assert_eq!(fs::read(&sample_path).unwrap(), original_bytes);
        assert!(mgr.items().is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_secure_delete_removes_payload_and_index() {
        let root = temp_test_dir("delete");
        let q_dir = root.join("Quarantine");
        let idx_path = root.join("quarantine_index.json");
        let sample_path = root.join("bad.bin");
        fs::write(&sample_path, b"payload_to_wipe").unwrap();

        let mut mgr = QuarantineManager::with_paths(q_dir, idx_path).unwrap();
        let item = mgr
            .quarantine_file(&sample_path, "Test.Wiper", "deadbeef", "cafebabe")
            .unwrap();
        let q_path = item.quarantined_path.clone();

        mgr.secure_delete_item(&item.id).unwrap();
        assert!(!q_path.exists());
        assert!(mgr.items().is_empty());

        let _ = fs::remove_dir_all(&root);
    }
}
