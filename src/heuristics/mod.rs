use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Shannon entropy score breakdown and assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub score: f64,
    pub is_anomalous: bool,
    pub category: String,
    pub description: String,
}

/// Computes the Shannon entropy of a byte slice in bits per byte [0.0, 8.0].
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Evaluates whether the entropy indicates packing, encryption, or code obfuscation.
pub fn evaluate_entropy(data: &[u8]) -> EntropyReport {
    let score = calculate_shannon_entropy(data);

    let (is_anomalous, category, description) = if score >= 7.2 {
        (
            true,
            "Critical - Packed / Encrypted",
            "Extremely high entropy consistent with ransomware crypters, UPX packers, or encrypted payloads.",
        )
    } else if score >= 6.8 {
        (
            true,
            "Elevated - Obfuscated Code",
            "Above-average entropy indicating compressed assets or mild code obfuscation.",
        )
    } else if score >= 5.0 {
        (
            false,
            "Normal - Standard Executable",
            "Typical entropy range for compiled C/Rust/Go machine code.",
        )
    } else {
        (
            false,
            "Low - Uncompressed / Plaintext",
            "Low entropy typical of plaintext, documentation, or sparse data.",
        )
    };

    EntropyReport {
        score,
        is_anomalous,
        category: category.to_string(),
        description: description.to_string(),
    }
}

/// Inspection results for Windows Portable Executable (PE) headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInspection {
    pub is_pe: bool,
    pub section_names: Vec<String>,
    pub suspicious_sections: Vec<String>,
    pub has_wx_sections: bool,
    pub detected_injection_apis: Vec<String>,
}

/// Inspection results for Linux Executable and Linkable Format (ELF) headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfInspection {
    pub is_elf: bool,
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub has_suspicious_packer_strings: bool,
    pub detected_evasion_tokens: Vec<String>,
}

/// Combined static heuristic assessment of a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicReport {
    pub file_size: u64,
    pub entropy: EntropyReport,
    pub pe: Option<PeInspection>,
    pub elf: Option<ElfInspection>,
    pub risk_indicators: Vec<String>,
    pub is_suspicious: bool,
}

/// Analyzes PE structure in memory without executing code.
pub fn inspect_pe_headers(bytes: &[u8]) -> Option<PeInspection> {
    if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
        return None;
    }

    // Read e_lfanew (pointer to PE header at offset 0x3C)
    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    if pe_offset + 24 > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let num_sections = u16::from_le_bytes([bytes[pe_offset + 6], bytes[pe_offset + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([bytes[pe_offset + 20], bytes[pe_offset + 21]]) as usize;
    let sections_start = pe_offset + 24 + opt_header_size;

    let mut section_names = Vec::new();
    let mut suspicious_sections = Vec::new();
    let mut has_wx_sections = false;

    let known_packer_sections = [
        "upx0", "upx1", "upx2", ".packed", "themida", ".vmp", "aspack", ".enigma",
        "pec2", "pecompact", ".fsg", ".nsp", ".mpress",
    ];

    for idx in 0..num_sections.min(96) {
        let entry_offset = sections_start + idx * 40;
        if entry_offset + 40 > bytes.len() {
            break;
        }

        // Section name is 8 bytes
        let raw_name = &bytes[entry_offset..entry_offset + 8];
        let name_str = raw_name
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect::<String>();
        let clean_name = name_str.trim().to_string();
        let lower = clean_name.to_lowercase();

        if known_packer_sections.iter().any(|&p| lower.contains(p)) {
            suspicious_sections.push(clean_name.clone());
        }

        // Characteristics offset +36 (4 bytes)
        let chars = u32::from_le_bytes([
            bytes[entry_offset + 36],
            bytes[entry_offset + 37],
            bytes[entry_offset + 38],
            bytes[entry_offset + 39],
        ]);
        // IMAGE_SCN_MEM_EXECUTE (0x20000000) and IMAGE_SCN_MEM_WRITE (0x80000000)
        let is_executable = (chars & 0x2000_0000) != 0;
        let is_writable = (chars & 0x8000_0000) != 0;
        if is_executable && is_writable {
            has_wx_sections = true;
        }

        section_names.push(clean_name);
    }

    // Scan for dangerous Windows injection APIs
    let known_injection_apis = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "QueueUserAPC",
        "SetWindowsHookExW",
        "RtlCreateUserThread",
    ];

    let mut detected_injection_apis = Vec::new();
    for api in known_injection_apis {
        if bytes_contain_ascii_or_wide(bytes, api) {
            detected_injection_apis.push(api.to_string());
        }
    }

    Some(PeInspection {
        is_pe: true,
        section_names,
        suspicious_sections,
        has_wx_sections,
        detected_injection_apis,
    })
}

/// Analyzes ELF structure in memory without executing code.
pub fn inspect_elf_headers(bytes: &[u8]) -> Option<ElfInspection> {
    if bytes.len() < 16 || &bytes[0..4] != b"\x7fELF" {
        return None;
    }

    let is_64bit = bytes[4] == 2;
    let is_little_endian = bytes[5] == 1;

    let known_evasion_tokens = [
        "/proc/self/mem",
        "ptrace",
        "PTRACE_POKETEXT",
        "socket(AF_INET, SOCK_RAW",
        "/dev/shm",
        "chattr +i",
    ];

    let mut detected_evasion_tokens = Vec::new();
    for token in known_evasion_tokens {
        if bytes_contain_ascii_or_wide(bytes, token) {
            detected_evasion_tokens.push(token.to_string());
        }
    }

    let has_suspicious_packer_strings = bytes_contain_ascii_or_wide(bytes, "UPX!")
        || bytes_contain_ascii_or_wide(bytes, "$Info: This file is packed with the UPX executable packer$");

    Some(ElfInspection {
        is_elf: true,
        is_64bit,
        is_little_endian,
        has_suspicious_packer_strings,
        detected_evasion_tokens,
    })
}

/// Unified heuristic analyzer examining entropy, PE/ELF anomalies, and crypter traits.
pub fn analyze_file_heuristics(bytes: &[u8]) -> HeuristicReport {
    let entropy = evaluate_entropy(bytes);
    let pe = inspect_pe_headers(bytes);
    let elf = inspect_elf_headers(bytes);

    let mut risk_indicators = Vec::new();

    if entropy.is_anomalous {
        risk_indicators.push(format!(
            "High Shannon Entropy ({:.2} / 8.0): {}",
            entropy.score, entropy.category
        ));
    }

    if let Some(ref p) = pe {
        for s in &p.suspicious_sections {
            risk_indicators.push(format!("PE Known Packer Section: '{s}'"));
        }
        if p.has_wx_sections {
            risk_indicators.push("PE W+X Section: Contains section with simultaneous write and execute permissions (self-modifying code indicator).".to_string());
        }
        if !p.detected_injection_apis.is_empty() {
            risk_indicators.push(format!(
                "Suspicious Process Injection APIs: {}",
                p.detected_injection_apis.join(", ")
            ));
        }
    }

    if let Some(ref e) = elf {
        if e.has_suspicious_packer_strings {
            risk_indicators.push("ELF UPX Compression Signature Detected".to_string());
        }
        if !e.detected_evasion_tokens.is_empty() {
            risk_indicators.push(format!(
                "Linux Anti-Analysis / Evasion Tokens: {}",
                e.detected_evasion_tokens.join(", ")
            ));
        }
    }

    let is_suspicious = !risk_indicators.is_empty();

    HeuristicReport {
        file_size: bytes.len() as u64,
        entropy,
        pe,
        elf,
        risk_indicators,
        is_suspicious,
    }
}

/// Reads file from disk and performs full heuristic analysis.
pub fn inspect_file_heuristics(path: &Path) -> std::io::Result<HeuristicReport> {
    let bytes = fs::read(path)?;
    Ok(analyze_file_heuristics(&bytes))
}

fn bytes_contain_ascii_or_wide(data: &[u8], token: &str) -> bool {
    let ascii_bytes = token.as_bytes();
    if data.windows(ascii_bytes.len()).any(|w| w == ascii_bytes) {
        return true;
    }
    let wide_bytes: Vec<u8> = token.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
    data.windows(wide_bytes.len()).any(|w| w == wide_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_constant_bytes() {
        let zeroes = vec![0u8; 1024];
        let ent = calculate_shannon_entropy(&zeroes);
        assert_eq!(ent, 0.0);
    }

    #[test]
    fn test_shannon_entropy_random_bytes() {
        // Pseudo-random uniform bytes
        let mut uniform = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                uniform.push(b);
            }
        }
        let ent = calculate_shannon_entropy(&uniform);
        // Shannon entropy of uniform 256 distribution is exactly 8.0
        assert!((ent - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_pe_header_inspection() {
        let mut pe_mock = vec![0u8; 512];
        pe_mock[0] = b'M';
        pe_mock[1] = b'Z';
        pe_mock[0x3C] = 0x80; // e_lfanew
        pe_mock[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe_mock[0x86] = 1; // 1 section
        pe_mock[0x87] = 0;
        pe_mock[0x94] = 0; // opt header size = 0
        pe_mock[0x95] = 0;

        // Section header offset: 0x80 + 24 = 0x98
        // Section name: "UPX0\0\0\0\0"
        pe_mock[0x98..0xA0].copy_from_slice(b"UPX0\0\0\0\0");
        // Characteristics at +36: 0xA0 + 36 = 0xC4
        // W+X: 0x20000000 | 0x80000000 = 0xA0000000
        pe_mock[0x98 + 36..0x98 + 40].copy_from_slice(&0xA000_0000u32.to_le_bytes());

        let inspection = inspect_pe_headers(&pe_mock).expect("Should parse PE");
        assert_eq!(inspection.suspicious_sections, vec!["UPX0"]);
        assert!(inspection.has_wx_sections);
    }

    #[test]
    fn test_elf_header_inspection() {
        let mut elf_mock = vec![0u8; 128];
        elf_mock[0..4].copy_from_slice(b"\x7fELF");
        elf_mock[4] = 2; // 64-bit
        elf_mock[5] = 1; // Little-endian
        let inspection = inspect_elf_headers(&elf_mock).expect("Should parse ELF");
        assert!(inspection.is_64bit);
        assert!(inspection.is_little_endian);
    }
}
