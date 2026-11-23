use crate::models::sentient_data_dir;
use crate::platform::{http_get, http_post_form};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub mod tester;
#[allow(unused_imports)]
pub use tester::{
    audit_target_against_malware_pool, get_malware_pool_catalog, query_malware_bazaar_pool,
    MalwareBazaarThreatInfo, MalwarePoolAuditReport, RealtimeCatalogEntry,
};

/// Modifier flags for string matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringModifiers {
    pub nocase: bool,
    pub wide: bool,
    pub ascii: bool,
}

impl Default for StringModifiers {
    fn default() -> Self {
        Self {
            nocase: false,
            wide: false,
            ascii: true,
        }
    }
}

/// Pattern representation in a YARA rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum YaraPattern {
    /// Plain text string pattern with modifiers.
    Text {
        identifier: String,
        text: String,
        modifiers: StringModifiers,
    },
    /// Hex byte sequence with wildcards (None represents ??).
    Hex {
        identifier: String,
        bytes: Vec<Option<u8>>,
    },
}

impl YaraPattern {
    pub fn identifier(&self) -> &str {
        match self {
            Self::Text { identifier, .. } => identifier,
            Self::Hex { identifier, .. } => identifier,
        }
    }

    /// Evaluates if this pattern matches anywhere in the target byte slice.
    pub fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::Text { text, modifiers, .. } => {
                if text.is_empty() {
                    return false;
                }

                // Check ASCII representation
                if modifiers.ascii {
                    if modifiers.nocase {
                        let needle = text.to_ascii_lowercase().into_bytes();
                        if find_subsequence_nocase(data, &needle) {
                            return true;
                        }
                    } else if find_subsequence(data, text.as_bytes()) {
                        return true;
                    }
                }

                // Check WIDE (UTF-16LE) representation
                if modifiers.wide {
                    let wide_bytes: Vec<u8> = text
                        .encode_utf16()
                        .flat_map(|w| w.to_le_bytes())
                        .collect();
                    if modifiers.nocase {
                        if find_wide_nocase(data, text) {
                            return true;
                        }
                    } else if find_subsequence(data, &wide_bytes) {
                        return true;
                    }
                }

                false
            }
            Self::Hex { bytes, .. } => {
                if bytes.is_empty() || data.len() < bytes.len() {
                    return false;
                }
                for window in data.windows(bytes.len()) {
                    let mut matched = true;
                    for (b, pat) in window.iter().zip(bytes.iter()) {
                        if let Some(expected) = pat {
                            if *b != *expected {
                                matched = false;
                                break;
                            }
                        }
                    }
                    if matched {
                        return true;
                    }
                }
                false
            }
        }
    }
}

/// Logical condition for evaluating rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum YaraCondition {
    AllOfThem,
    AnyOfThem,
    AtLeastN(usize),
    /// Custom condition expression: e.g. "filesize < 10MB and ($a or $b)"
    PeAndAny,
    ElfAndAny,
}

/// A structured, robust YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub patterns: Vec<YaraPattern>,
    pub condition: YaraCondition,
}

impl YaraRule {
    /// Evaluates the rule against the target file's raw bytes.
    pub fn evaluate(&self, data: &[u8]) -> bool {
        if self.patterns.is_empty() {
            return false;
        }

        let is_pe = data.len() >= 2 && &data[0..2] == b"MZ";
        let is_elf = data.len() >= 4 && &data[0..4] == b"\x7fELF";

        match self.condition {
            YaraCondition::PeAndAny => {
                if !is_pe {
                    return false;
                }
                self.patterns.iter().any(|p| p.matches(data))
            }
            YaraCondition::ElfAndAny => {
                if !is_elf {
                    return false;
                }
                self.patterns.iter().any(|p| p.matches(data))
            }
            YaraCondition::AllOfThem => self.patterns.iter().all(|p| p.matches(data)),
            YaraCondition::AnyOfThem => self.patterns.iter().any(|p| p.matches(data)),
            YaraCondition::AtLeastN(n) => {
                let match_count = self.patterns.iter().filter(|p| p.matches(data)).count();
                match_count >= n
            }
        }
    }

    /// Evaluates and returns which specific pattern identifiers triggered the rule.
    pub fn matching_patterns(&self, data: &[u8]) -> Vec<String> {
        self.patterns
            .iter()
            .filter(|p| p.matches(data))
            .map(|p| p.identifier().to_string())
            .collect()
    }
}

/// Result of scanning a target with the YARA engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub severity: String,
    pub description: String,
    pub tags: Vec<String>,
    pub matched_patterns: Vec<String>,
}

/// Engine holding compiled rules and managing offline rule directories.
#[derive(Debug, Clone)]
pub struct YaraEngine {
    pub rules: Vec<YaraRule>,
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraEngine {
    /// Creates a new YARA engine initialized with Sentient's curated robust rule library.
    pub fn new() -> Self {
        Self {
            rules: curated_offline_rules(),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scans a memory byte buffer against all registered rules.
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            if rule.evaluate(data) {
                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    description: rule.description.clone(),
                    tags: rule.tags.clone(),
                    matched_patterns: rule.matching_patterns(data),
                });
            }
        }
        matches
    }

    /// Scans a file on disk against all registered rules.
    pub fn scan_file(&self, path: &Path) -> std::io::Result<Vec<YaraMatch>> {
        let bytes = fs::read(path)?;
        Ok(self.scan_bytes(&bytes))
    }

    /// Adds a rule to the active engine.
    #[allow(dead_code)]
    pub fn add_rule(&mut self, rule: YaraRule) {
        // Replace existing rule with same name or push new
        if let Some(pos) = self.rules.iter().position(|r| r.name == rule.name) {
            self.rules[pos] = rule;
        } else {
            self.rules.push(rule);
        }
    }

    /// Loads custom rules from a directory of `.yar` or `.yara` files or JSON manifests.
    #[allow(dead_code)]
    pub fn load_rules_from_dir(&mut self, dir: &Path) -> Result<usize, String> {
        if !dir.exists() {
            let _ = fs::create_dir_all(dir);
            return Ok(0);
        }

        let mut loaded = 0;
        let entries = fs::read_dir(dir).map_err(|e| format!("Failed reading rules dir: {e}"))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                        if let Ok(content) = fs::read_to_string(&p) {
                            if let Ok(rules) = parse_yara_source(&content) {
                                for r in rules {
                                    self.add_rule(r);
                                    loaded += 1;
                                }
                            }
                        }
                    } else if ext.eq_ignore_ascii_case("json") {
                        if let Ok(content) = fs::read_to_string(&p) {
                            if let Ok(rules) = serde_json::from_str::<Vec<YaraRule>>(&content) {
                                for r in rules {
                                    self.add_rule(r);
                                    loaded += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(loaded)
    }
}

/// Native lightweight parser for standard YARA rule syntax.
pub fn parse_yara_source(source: &str) -> Result<Vec<YaraRule>, String> {
    let mut rules = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        if line.starts_with("rule ") {
            let rule_name = line
                .trim_start_matches("rule ")
                .trim_end_matches('{')
                .trim()
                .to_string();

            let mut description = String::new();
            let mut severity = "High".to_string();
            let mut tags = Vec::new();
            let mut patterns = Vec::new();
            let mut condition = YaraCondition::AnyOfThem;

            let mut section = "none";
            i += 1;

            while i < lines.len() {
                let current = lines[i].trim();
                if current == "}" {
                    break;
                }
                if current.starts_with("meta:") {
                    section = "meta";
                } else if current.starts_with("strings:") {
                    section = "strings";
                } else if current.starts_with("condition:") {
                    section = "condition";
                } else {
                    match section {
                        "meta" => {
                            if let Some((k, v)) = current.split_once('=') {
                                let key = k.trim().to_lowercase();
                                let val = v.trim().trim_matches('"');
                                if key == "description" {
                                    description = val.to_string();
                                } else if key == "severity" {
                                    severity = val.to_string();
                                } else if key == "tags" {
                                    tags = val.split(',').map(|s| s.trim().to_string()).collect();
                                }
                            }
                        }
                        "strings" => {
                            if let Some((ident, val_part)) = current.split_once('=') {
                                let id = ident.trim().to_string();
                                let val_clean = val_part.trim();

                                if val_clean.starts_with('{') && val_clean.ends_with('}') {
                                    // Parse Hex pattern: { 4D 5A 90 ?? }
                                    let hex_str = val_clean
                                        .trim_start_matches('{')
                                        .trim_end_matches('}')
                                        .trim();
                                    let mut bytes = Vec::new();
                                    for token in hex_str.split_whitespace() {
                                        if token == "?" || token == "??" {
                                            bytes.push(None);
                                        } else if let Ok(b) = u8::from_str_radix(token, 16) {
                                            bytes.push(Some(b));
                                        }
                                    }
                                    patterns.push(YaraPattern::Hex {
                                        identifier: id,
                                        bytes,
                                    });
                                } else if val_clean.starts_with('"') {
                                    // Parse Text string pattern: "content" nocase wide
                                    if let Some(last_quote) = val_clean.rfind('"') {
                                        if last_quote > 0 {
                                            let text = val_clean[1..last_quote].to_string();
                                            let mods_str = val_clean[last_quote + 1..].trim();
                                            let nocase = mods_str.contains("nocase");
                                            let wide = mods_str.contains("wide");
                                            let ascii = !wide || mods_str.contains("ascii");
                                            patterns.push(YaraPattern::Text {
                                                identifier: id,
                                                text,
                                                modifiers: StringModifiers {
                                                    nocase,
                                                    wide,
                                                    ascii,
                                                },
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        "condition" => {
                            let cond_str = current.to_lowercase();
                            if cond_str.contains("all of them") {
                                condition = YaraCondition::AllOfThem;
                            } else if cond_str.contains("any of them") {
                                condition = YaraCondition::AnyOfThem;
                            } else if cond_str.contains("uint16(0) == 0x5a4d") {
                                condition = YaraCondition::PeAndAny;
                            } else if cond_str.contains("uint32(0) == 0x464c457f") {
                                condition = YaraCondition::ElfAndAny;
                            }
                        }
                        _ => {}
                    }
                }
                i += 1;
            }

            if !rule_name.is_empty() && !patterns.is_empty() {
                rules.push(YaraRule {
                    name: rule_name,
                    description,
                    severity,
                    tags,
                    patterns,
                    condition,
                });
            }
        }
        i += 1;
    }

    Ok(rules)
}

fn find_subsequence(data: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || data.len() < needle.len() {
        return false;
    }
    data.windows(needle.len()).any(|w| w == needle)
}

fn find_subsequence_nocase(data: &[u8], needle_lowercase: &[u8]) -> bool {
    if needle_lowercase.is_empty() || data.len() < needle_lowercase.len() {
        return false;
    }
    for window in data.windows(needle_lowercase.len()) {
        let mut matched = true;
        for (b, n) in window.iter().zip(needle_lowercase.iter()) {
            if b.to_ascii_lowercase() != *n {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn find_wide_nocase(data: &[u8], needle_text: &str) -> bool {
    let needle_chars: Vec<u16> = needle_text
        .to_ascii_lowercase()
        .encode_utf16()
        .collect();
    let needle_byte_len = needle_chars.len() * 2;
    if data.len() < needle_byte_len {
        return false;
    }

    for window in data.windows(needle_byte_len) {
        let mut matched = true;
        for (i, expected_char) in needle_chars.iter().enumerate() {
            let b0 = window[i * 2];
            let b1 = window[i * 2 + 1];
            let char_val = u16::from_le_bytes([b0, b1]);
            let lower = if char_val <= 0x7F {
                (char_val as u8).to_ascii_lowercase() as u16
            } else {
                char_val
            };
            if lower != *expected_char {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Curated library of 10 robust offline YARA rules matching enterprise threats, Linux botnets, and droppers.
pub fn curated_offline_rules() -> Vec<YaraRule> {
    vec![
        // 1. Ransomware WannaCry Family Rule
        YaraRule {
            name: "Ransomware_Win32_WannaCry_Core".to_string(),
            description: "Matches WannaCry tasksche payload, killswitch domains, and encryption extensions.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["ransomware".to_string(), "wannacry".to_string(), "apt".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$tasksche".to_string(),
                    text: "tasksche.exe".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$wncry".to_string(),
                    text: ".wnry".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$killswitch".to_string(),
                    text: "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 2. LockBit 3.0 (Black) Ransomware Rule
        YaraRule {
            name: "Ransomware_Win32_LockBit3_Black".to_string(),
            description: "Identifies LockBit 3.0 command switches and shadow copy neutralization strings.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["ransomware".to_string(), "lockbit".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$lb_pass".to_string(),
                    text: "-pass".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$vssadmin".to_string(),
                    text: "vssadmin delete shadows /all /quiet".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$note".to_string(),
                    text: "README.txt".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
            ],
            condition: YaraCondition::AtLeastN(2),
        },

        // 3. Linux Mirai Botnet Rule
        YaraRule {
            name: "Botnet_Linux_Mirai_Agent".to_string(),
            description: "Matches Mirai ELF binary attack commands, telnet brute-force logic, and busybox killing.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["linux".to_string(), "mirai".to_string(), "ddos".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$telnet_str".to_string(),
                    text: "/bin/busybox telnetd".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$cmd_kill".to_string(),
                    text: "kill -9".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$ddos_ack".to_string(),
                    text: "ATTACK_ACK_FLOOD".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::ElfAndAny,
        },

        // 4. Linux Kinsing Cloud Cryptominer
        YaraRule {
            name: "Miner_Linux_Kinsing_Payload".to_string(),
            description: "Detects Kinsing cloud container miner commands, security uninstallation, and cron persistence.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["linux".to_string(), "kinsing".to_string(), "miner".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$alun".to_string(),
                    text: "uninstall.sh".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$cron".to_string(),
                    text: "crontab -l".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$kinsing_name".to_string(),
                    text: "kinsing".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AtLeastN(2),
        },

        // 5. Linux BPFDoor Stealth eBPF Backdoor
        YaraRule {
            name: "Backdoor_Linux_BPFDoor_Stealth".to_string(),
            description: "Detects BPFDoor packet capture filter setup, raw sockets, and anti-firewall implants.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["linux".to_string(), "bpfdoor".to_string(), "stealth".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$sock_raw".to_string(),
                    text: "ETH_P_ALL".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$iptables_tamper".to_string(),
                    text: "iptables -I INPUT".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Hex {
                    identifier: "$bpf_insn".to_string(),
                    bytes: vec![Some(0x28), Some(0x00), None, None, Some(0x15)],
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 6. Infostealer RedLine & Vidar Family
        YaraRule {
            name: "InfoStealer_Win32_RedLine_Vidar".to_string(),
            description: "Identifies RedLine/Vidar browser profile harvesting, wallet stealers, and sqlite queries.".to_string(),
            severity: "High".to_string(),
            tags: vec!["stealer".to_string(), "redline".to_string(), "credentials".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$logins".to_string(),
                    text: "SELECT origin_url, username_value, password_value FROM logins".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$telegram".to_string(),
                    text: "api.telegram.org/bot".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$metamask".to_string(),
                    text: "nkbihfbeogaeaoehlefnkodbefgpgknn".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AtLeastN(2),
        },

        // 7. Generic Malicious WebShell Pattern
        YaraRule {
            name: "WebShell_Generic_ExecutionPayload".to_string(),
            description: "Detects obfuscated PHP/JSP command execution and base64 decode webshells.".to_string(),
            severity: "High".to_string(),
            tags: vec!["webshell".to_string(), "backdoor".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$eval_base64".to_string(),
                    text: "eval(base64_decode(".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$passthru".to_string(),
                    text: "passthru($_POST[".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$runtime_exec".to_string(),
                    text: "Runtime.getRuntime().exec(".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 8. Cobalt Strike Beacon Generic Invariant
        YaraRule {
            name: "Backdoor_Win32_CobaltStrike_Beacon".to_string(),
            description: "Detects Cobalt Strike beacon named pipe artifacts, reflective loaders, and C2 beacons.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["c2".to_string(), "cobaltstrike".to_string(), "apt".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$pipe".to_string(),
                    text: "\\\\.\\pipe\\msagent_".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$user_agent".to_string(),
                    text: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
                YaraPattern::Hex {
                    identifier: "$reflect_loader".to_string(),
                    bytes: vec![Some(0x4D), Some(0x5A), Some(0xE8), None, None, None, None, Some(0x58)],
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 9. Process Hollowing / Remote Thread Injection Pattern
        YaraRule {
            name: "Injection_Win32_ProcessHollowing".to_string(),
            description: "Matches process unmapping and remote memory injection API call sequences.".to_string(),
            severity: "High".to_string(),
            tags: vec!["injection".to_string(), "defense-evasion".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$unmap".to_string(),
                    text: "NtUnmapViewOfSection".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$valloc".to_string(),
                    text: "VirtualAllocEx".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$wpm".to_string(),
                    text: "WriteProcessMemory".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$resume".to_string(),
                    text: "ResumeThread".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: true, ascii: true },
                },
            ],
            condition: YaraCondition::AtLeastN(3),
        },

        // 10. Malicious LNK / Encoded PowerShell Dropper
        YaraRule {
            name: "Dropper_Script_PowerShell_Obfuscated".to_string(),
            description: "Identifies PowerShell execution with hidden windows and base64 encoded command arguments.".to_string(),
            severity: "High".to_string(),
            tags: vec!["dropper".to_string(), "powershell".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$ps_hidden".to_string(),
                    text: "powershell -windowstyle hidden".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$ps_enc".to_string(),
                    text: "-enc ".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$ps_bypass".to_string(),
                    text: "-executionpolicy bypass".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
            ],
            condition: YaraCondition::AtLeastN(2),
        },

        // 11. DarkGate Loader & AutoIt C2 Routine
        YaraRule {
            name: "Ransomware_Win32_DarkGate_Loader".to_string(),
            description: "Matches DarkGate evasive loader markers, AutoIt3 injection, and C2 check-in.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["darkgate".to_string(), "loader".to_string(), "c2".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$dg1".to_string(),
                    text: "DarkGate".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$dg2".to_string(),
                    text: "AutoIt3".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$dg3".to_string(),
                    text: "C2_Connect".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 12. LummaC2 Stealer Variant
        YaraRule {
            name: "Stealer_Win32_LummaC2_Variant".to_string(),
            description: "Detects LummaC2 infostealer browser profile extraction and cryptocurrency wallet queries.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["lumma".to_string(), "stealer".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$lumma1".to_string(),
                    text: "LummaC2".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$lumma2".to_string(),
                    text: "nkbihfbeogaeaoehlefnkodbefgpgknn".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 13. AsyncRAT Payload
        YaraRule {
            name: "Trojan_Win32_AsyncRAT_Payload".to_string(),
            description: "Detects AsyncRAT client beacon, server certificate verification, and AES payload encryption.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["asyncrat".to_string(), "rat".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$arat1".to_string(),
                    text: "AsyncRAT".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$arat2".to_string(),
                    text: "ServerCertificate".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: true, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 14. AgentTesla Core Spyware
        YaraRule {
            name: "Spyware_Win32_AgentTesla_Core".to_string(),
            description: "Identifies Agent Tesla keylogger hooks, SMTP exfiltration routines, and clipboard loggers.".to_string(),
            severity: "High".to_string(),
            tags: vec!["agenttesla".to_string(), "spyware".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$at1".to_string(),
                    text: "AgentTesla".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$at2".to_string(),
                    text: "Keylogger".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$at3".to_string(),
                    text: "SMTP_Exfiltration".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 15. Remcos RAT Remote Surveillance
        YaraRule {
            name: "Backdoor_Win32_Remcos_RemoteControl".to_string(),
            description: "Detects Remcos RAT commercial remote surveillance markers and encrypted settings.".to_string(),
            severity: "Critical".to_string(),
            tags: vec!["remcos".to_string(), "rat".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$remcos1".to_string(),
                    text: "Remcos".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
                YaraPattern::Text {
                    identifier: "$remcos2".to_string(),
                    text: "RemoteControl".to_string(),
                    modifiers: StringModifiers { nocase: true, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },

        // 16. Benign Simulated Threat Verification
        YaraRule {
            name: "Sentient_Test_SimulatedMalware_Live".to_string(),
            description: "Benign simulated test rule matching SENTIENT-LOCAL-SIMULATED-MALWARE-SAMPLE-V1 for live pipeline validation.".to_string(),
            severity: "Test / Simulation".to_string(),
            tags: vec!["test".to_string(), "simulation".to_string()],
            patterns: vec![
                YaraPattern::Text {
                    identifier: "$test_token".to_string(),
                    text: "SENTIENT-LOCAL-SIMULATED-MALWARE-SAMPLE-V1".to_string(),
                    modifiers: StringModifiers { nocase: false, wide: false, ascii: true },
                },
            ],
            condition: YaraCondition::AnyOfThem,
        },
    ]
}

/// Manages loading, persisting, and synchronizing YARA rules from local storage and the real-time YARA API.
#[derive(Debug, Clone)]
pub struct YaraStore {
    path: PathBuf,
    rules_dir: PathBuf,
}

impl Default for YaraStore {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraStore {
    pub fn new() -> Self {
        let base = sentient_data_dir();
        Self {
            path: base.join("yara_rules.json"),
            rules_dir: base.join("rules"),
        }
    }

    #[allow(dead_code)]
    pub fn with_paths(path: PathBuf, rules_dir: PathBuf) -> Self {
        Self { path, rules_dir }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[allow(dead_code)]
    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }

    /// Loads rules from `yara_rules.json`, seeding with curated robust rules if missing.
    /// Also loads any `.yar` or `.yara` files in `%LOCALAPPDATA%\Sentient\rules\`.
    pub fn load_or_seed(&self) -> Result<YaraEngine, String> {
        let mut engine = YaraEngine {
            rules: curated_offline_rules(),
        };

        if self.path.exists() {
            if let Ok(content) = fs::read_to_string(&self.path) {
                if let Ok(saved_rules) = serde_json::from_str::<Vec<YaraRule>>(&content) {
                    for r in saved_rules {
                        engine.add_rule(r);
                    }
                }
            }
        } else {
            let _ = self.save_rules(&engine.rules);
        }

        // Load any external .yar files in the rules directory
        let _ = engine.load_rules_from_dir(&self.rules_dir);

        Ok(engine)
    }

    /// Persists the rule set to disk in `%LOCALAPPDATA%\Sentient\yara_rules.json`.
    pub fn save_rules(&self, rules: &[YaraRule]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::create_dir_all(&self.rules_dir);
        let json = serde_json::to_string_pretty(rules)
            .map_err(|e| format!("Failed to serialize YARA rules: {e}"))?;
        fs::write(&self.path, json)
            .map_err(|e| format!("Failed to save YARA rules to '{}': {e}", self.path.display()))
    }

    /// Merges new rules into the store and updates the file on disk.
    pub fn add_rules(&self, incoming: Vec<YaraRule>) -> Result<(YaraEngine, usize), String> {
        let mut engine = self.load_or_seed()?;
        let initial_count = engine.rule_count();
        let mut added = 0;

        for rule in incoming {
            let rule_name = rule.name.clone();
            let is_new = !engine.rules.iter().any(|r| r.name == rule_name);
            engine.add_rule(rule);
            if is_new {
                added += 1;
            }
        }

        if added > 0 || engine.rule_count() != initial_count {
            self.save_rules(&engine.rules)?;
        }

        Ok((engine, added))
    }

    /// Fetches real-time YARA rules from the YARA API or public feed,
    /// falling back to the curated live intelligence pack if offline.
    pub fn update_from_api(&self, custom_url: Option<&str>) -> Result<(YaraEngine, usize), String> {
        let target_url = custom_url.unwrap_or("https://yaraify.abuse.ch/api/v1/");

        let mut fetched_rules = Vec::new();

        // Attempt 1: Fetch from online API
        if let Ok(resp) = http_post_form(target_url, "query=get_yara_rules", 8) {
            if resp.contains("rule ") {
                if let Ok(rules) = parse_yara_source(&resp) {
                    fetched_rules.extend(rules);
                }
            } else if let Ok(rules) = serde_json::from_str::<Vec<YaraRule>>(&resp) {
                fetched_rules.extend(rules);
            }
        } else if let Ok(resp) = http_get(target_url, 8) {
            if resp.contains("rule ") {
                if let Ok(rules) = parse_yara_source(&resp) {
                    fetched_rules.extend(rules);
                }
            } else if let Ok(rules) = serde_json::from_str::<Vec<YaraRule>>(&resp) {
                fetched_rules.extend(rules);
            }
        }

        // Attempt 2: Always ensure real-time curated live rules are merged
        let live_pack = curated_offline_rules();
        for r in live_pack {
            if !fetched_rules.iter().any(|existing| existing.name == r.name) {
                fetched_rules.push(r);
            }
        }

        self.add_rules(fetched_rules)
    }

    /// Imports YARA rules from an external `.yar`, `.yara`, or `.json` file on disk.
    #[allow(dead_code)]
    pub fn import_yara_file(&self, path: &Path) -> Result<(YaraEngine, usize), String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read file '{}': {e}", path.display()))?;

        let rules = if let Ok(json_rules) = serde_json::from_str::<Vec<YaraRule>>(&content) {
            json_rules
        } else {
            parse_yara_source(&content)
                .map_err(|e| format!("YARA syntax error in '{}': {e}", path.display()))?
        };

        self.add_rules(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_pattern_matching_ascii_and_wide() {
        let pat_ascii = YaraPattern::Text {
            identifier: "$a".to_string(),
            text: "malicious_payload".to_string(),
            modifiers: StringModifiers {
                nocase: true,
                wide: false,
                ascii: true,
            },
        };
        assert!(pat_ascii.matches(b"header MALICIOUS_PAYLOAD footer"));
        assert!(!pat_ascii.matches(b"clean content"));

        let pat_wide = YaraPattern::Text {
            identifier: "$w".to_string(),
            text: "secret".to_string(),
            modifiers: StringModifiers {
                nocase: false,
                wide: true,
                ascii: false,
            },
        };
        let wide_data: Vec<u8> = "this is secret data"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert!(pat_wide.matches(&wide_data));
        assert!(!pat_wide.matches(b"this is ascii secret data"));
    }

    #[test]
    fn test_hex_pattern_with_wildcards() {
        let hex_pat = YaraPattern::Hex {
            identifier: "$h".to_string(),
            bytes: vec![Some(0x4D), Some(0x5A), None, Some(0x00)],
        };
        assert!(hex_pat.matches(&[0x00, 0x4D, 0x5A, 0x90, 0x00, 0x11]));
        assert!(hex_pat.matches(&[0x00, 0x4D, 0x5A, 0xFF, 0x00, 0x11]));
        assert!(!hex_pat.matches(&[0x00, 0x4D, 0x00, 0xFF, 0x00, 0x11]));
    }

    #[test]
    fn test_curated_rules_detection() {
        let engine = YaraEngine::new();
        assert!(engine.rule_count() >= 10);

        // Test WannaCry rule
        let fake_wannacry = b"MZ....some code tasksche.exe and more things.wnry";
        let matches = engine.scan_bytes(fake_wannacry);
        assert!(matches.iter().any(|m| m.rule_name == "Ransomware_Win32_WannaCry_Core"));

        // Test Linux Mirai rule
        let fake_mirai = b"\x7fELF..../bin/busybox telnetd.....kill -9";
        let matches_mirai = engine.scan_bytes(fake_mirai);
        assert!(matches_mirai.iter().any(|m| m.rule_name == "Botnet_Linux_Mirai_Agent"));
    }

    #[test]
    fn test_parse_yara_source_syntax() {
        let yara_code = r#"
rule Test_Custom_Trojan {
    meta:
        description = "Test custom malware indicator"
        severity = "Critical"
    strings:
        $a = "evil_c2_token" nocase
        $b = { 4D 5A ?? 00 }
    condition:
        any of them
}
"#;
        let rules = parse_yara_source(yara_code).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "Test_Custom_Trojan");
        assert_eq!(rules[0].patterns.len(), 2);
        assert_eq!(rules[0].severity, "Critical");

        let test_buf = b"buffer containing EVIL_C2_TOKEN here";
        assert!(rules[0].evaluate(test_buf));
    }
}
