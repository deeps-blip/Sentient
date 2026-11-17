<div align="center">

<img src="assets/logo.png" alt="Sentient Endpoint Security Logo" width="140" />

# 🛡️ SENTIENT

**High-Performance, Offline-First Desktop Antivirus Engineered in Pure Rust**

[![Rust](https://img.shields.io/badge/Built%20With-Rust%202021-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![Platform Linux](https://img.shields.io/badge/Platform-Linux%20x64-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.kernel.org/)
[![GUI](https://img.shields.io/badge/UI-eframe%20%2F%20egui%200.37-22D3EE?style=for-the-badge)](https://github.com/emilk/egui)
[![Privacy](https://img.shields.io/badge/Telemetry-Zero%20Cloud%20%7C%20100%25%20Offline-10B981?style=for-the-badge)](#privacy--zero-telemetry-philosophy)

*Zero telemetry. Zero cloud uploads. Standalone native binary with hardware-accelerated UI, parallel cryptographic threat scanning, and dual-engine cross-platform architecture.*

</div>

---

## ✨ Overview

**Sentient** is a lightweight, privacy-focused desktop endpoint security application written in **pure Rust (2021 edition)** supporting both **Windows and Linux**. Designed for air-gapped workstations, security researchers, and privacy-conscious power users, Sentient combines a **multithreaded chunked SHA-256 / MD5 inspection engine**, **in-memory EICAR verification**, a **cross-platform Deep System Engine** (Windows MRT on Windows; ClamAV & Native Linux Security Engine on Linux), and a **hardened XOR-scrambled Quarantine Vault** inside a sleek cyber-obsidian dashboard running at 60 FPS.

---

## ⚖️ Cross-Platform Feature Matrix

| Security Capability | Windows Implementation | Linux Implementation |
| :--- | :--- | :--- |
| **Real-Time On-Access Sentinel** | Background watcher for `%USERPROFILE%\Downloads`, `Desktop`, `Temp` | Background watcher for `$HOME/Downloads`, `Desktop`, `/tmp`, `/dev/shm` |
| **Live Process & Memory Audit** | Windows `tasklist` + executable disk hashing + svchost/csrss masquerade detection | Linux `/proc` filesystem audit + executable target hashing + `(deleted)` evasion check |
| **Network Socket & C2 Monitor** | Windows `netstat -ano` active socket parser + C2 beacon port heuristics | Linux `/proc/net/tcp` / `ss -tuna` parser + C2 beacon port heuristics |
| **USB & Removable Media Defender** | Win32 `GetDriveTypeW` + `autorun.inf` directory locking & immunization | Linux mount point auditor (`/media`, `/run/media`, `/mnt`) + autorun immunization |
| **Static Heuristics & Entropy** | Shannon entropy ($H \in [0, 8]$) + PE header W+X & injection API checks | Shannon entropy + ELF header 32/64-bit & evasion token checks (`/proc/self/mem`) |
| **Robust Offline YARA Engine** | Pure-Rust text/wide/hex engine with 10 robust curated rules + custom compiler | Pure-Rust text/wide/hex engine with 10 robust curated rules + custom compiler |
| **Forensic Reporting & STIX 2.1** | Standalone cyber-obsidian HTML report + OASIS STIX 2.1 JSON Threat Bundle | Standalone cyber-obsidian HTML report + OASIS STIX 2.1 JSON Threat Bundle |
| **Deep System Engine** | Windows Malicious Software Removal Tool (`mrt.exe /Q`, `/F /Q`) | **Dual-Mode**: ClamAV (`clamscan`) auto-detect + Native Linux Audit Engine |
| **System Heuristics** | Kernel / registry / system file verification | Droppers in `/tmp` & `/dev/shm`, world-writable system binaries, hidden executables |
| **Quick Scan Locations** | `%USERPROFILE%\Downloads`, `%TEMP%`, Startup entries | `$HOME/Downloads`, `$HOME/Desktop`, `/tmp`, `/var/tmp`, `/dev/shm` |
| **Quarantine Hardening** | NTFS DACL deny `Everyone (*S-1-1-0)` + Read-only/Hidden attributes | POSIX `chmod 000` (zero-access) + `chattr +i` (immutable file attribute) |
| **Privilege Escalation** | Windows UAC token elevation (`ShellExecuteW` `"runas"`) | PolicyKit graphical prompt (`pkexec`) with automated `sudo -E` fallback |
| **Data & Vault Path** | `%LOCALAPPDATA%\Sentient\` | XDG Standard: `$XDG_DATA_HOME/sentient/` (`~/.local/share/sentient/`) |
| **Display Server** | Native Win32 Desktop Window Manager | Wayland / X11 via `eframe` and `winit` |

---

## 🚀 Key Features

### 🎨 Next-Gen Cyber-Obsidian UI (`eframe` / `egui`)
- **Animated Protection Radar & Hero Status Banner**: Real-time endpoint posture feedback (*Protected*, *Scanning in Progress*, *Threats Detected*).
- **Live Telemetry Console**: Real-time progress tracking, `files/sec` and `MB/s` throughput metrics, active inspected path stream, and instant **Abort Scan** support without ever blocking the GUI thread.
- **Cross-Platform Standalone Native Binary**: Runs with native performance and hardware acceleration on both Windows and Linux (Wayland / X11).

### ⚡ Dual-Engine Threat Detection (Windows & Linux)
1. **Multithreaded Local Hash & Heuristic Engine (`hash_engine.rs`)**:
   - Traverses directory trees concurrently using `walkdir` + `rayon` thread pools.
   - Computes **SHA-256** and **MD5** digests using constant **64 KiB streaming buffers** (inspects multi-gigabyte archives without memory spikes).
   - Evaluates files against the curated offline IOC database ([`signatures.json`](file:///C:/Sentient/signatures.json)) containing 50+ prominent ransomware, botnet, infostealer, and wiper signatures across Windows and Linux, plus **cross-chunk rolling-window EICAR detection** in memory.
   - Gracefully handles locked or protected OS files and reports skipped counts cleanly.
2. **Deep System Scanner Integration (`scanner.rs`)**:
   - **On Windows**: Executes background Windows Malicious Software Removal Tool (`mrt.exe /Q` or `/F /Q`) with silent telemetry report parsing into Sentient's dashboard and audit logs.
   - **On Linux**:
     - **ClamAV Integration**: Automatically detects and leverages `clamscan` if installed on `/usr/bin/clamscan`, `/bin/clamscan`, `/usr/local/bin/clamscan`, or on `$PATH`, streaming live infected file detections to the UI.
     - **Native Linux Deep System Security Engine**: Self-contained, zero-dependency embedded scanner that inspects core system binaries (`/bin`, `/sbin`, `/usr/bin`, `/usr/local/bin`, `/etc/cron.*`, `/etc/systemd/system`, `/tmp`, `/dev/shm`).
     - **Linux Security Heuristics**:
       - *Suspicious Dropper Executables*: Detects and flags unauthorized executable binaries dropped into `/tmp`, `/var/tmp`, or `/dev/shm` (`Linux.Suspicious.DropExecutable`).
       - *World-Writable Binaries*: Flags dangerous permissions (`0o777`) on system executables in `/bin`, `/sbin`, `/usr/bin` (`Linux.Vulnerability.WorldWritableBinary`).
       - *Hidden Executable Artifacts*: Identifies hidden executable files (`.name` with execute bit) in temporary or in-memory shared memory storage (`Linux.Suspicious.HiddenDropper`).

### 🛡️ Real-Time On-Access Sentinel (`sentinel/mod.rs`)
- **Continuous Background Drop Watcher**: Monitors user drop folders (`Downloads`, `Desktop`, `Temp`, `/tmp`, `/var/tmp`, `/dev/shm`) without consuming excessive CPU cycles.
- **Triple-Tier Interception Pipeline**:
  1. *Instant Cryptographic Hash Match*: Looks up file digests in $O(1)$ time against the offline IOC index.
  2. *Curated YARA Evaluation*: Evaluates files against 10 built-in rules for zero-day heuristics.
  3. *Shannon Entropy Crypter Alert*: Flags files with extreme entropy ($H \ge 7.85$) characteristic of ransomware and packers.
- **Instant Auto-Quarantine**: Automatically isolates intercepted malicious drops into the quarantine vault if auto-quarantine is enabled.

### 💾 Air-Gap USB & Removable Media Auto-Defender (`usb/mod.rs`)
- **Removable Storage Enumeration**: Auto-detects inserted USB flash drives, memory cards, and external hard drives on Windows (`GetDriveTypeW == 2`) and Linux (`/media`, `/run/media`, `/mnt`).
- **Autorun & Worm Vector Neutralization**: Scans drive roots for `autorun.inf`, suspicious `.lnk` shortcut traps, and hidden executables.
- **One-Click Drive Immunization**: Neutralizes malicious `autorun.inf` and creates locked, vaccinated directory structures to block autorun worms from infecting the air-gapped drive.

### ⚙️ Live Process & Memory Threat Audit (`process/mod.rs`)
- **Active Task & PID Inspector**: Enumerate all running processes across Windows (via structured `tasklist`) and Linux (via direct `/proc/[pid]` virtual filesystem traversal).
- **Executable Image Verification**: Resolves disk paths, calculates SHA-256 fingerprints, and matches them in real time against known offline signatures.
- **Evasion & Masquerade Detection**:
  - Flags processes executing out of `%TEMP%`, `Downloads`, `/tmp`, or `/dev/shm`.
  - Flags system binary masquerading (e.g. non-system `svchost.exe`, `csrss.exe`).
  - Detects Linux ` (deleted)` binary execution where droppers unlink their executable image from disk to evade filesystem scans.
- **Process Termination**: One-click termination of malicious PIDs via `taskkill /F` (Windows) or `libc::kill(pid, SIGKILL)` (Linux).

### 🌐 Active Network Socket & Covert C2 Monitor (`network/mod.rs`)
- **TCP / UDP Endpoint Enumeration**: Real-time inspection of listening ports and active outbound connections.
- **Kernel-Level Linux Fallback**: Uses `ss -tunap` or `netstat -tunap` with process PID capture, and includes a zero-dependency kernel fallback reading directly from `/proc/net/tcp` and `/proc/net/udp`.
- **C2 & Backdoor Heuristics**:
  - Flags known C2 / Metasploit / Cobalt Strike beacon ports (`4444`, `1337`, `31337`, `9001`, `6667`, `8888`, `5555`, `8088`).
  - Flags unauthenticated high-range listener ports bound to `0.0.0.0`.
  - Direct socket owner PID termination.

### 📊 Static Binary Heuristics & Shannon Entropy Analyzer (`heuristics/mod.rs`)
- **Mathematical Shannon Entropy**: Calculates exact entropy $H(X) = -\sum P(x) \log_2 P(x) \in [0.0, 8.0]$ bits/byte to uncover packed, crypted, or encrypted binaries without executing them.
- **PE Header Inspection (Windows)**: Parses `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, section tables; checks for known packers (`UPX0`, `themida`, `.vmp`), identifies dangerous writable and executable sections (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`), and detects process injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
- **ELF Header Inspection (Linux)**: Validates ELF magic (`\x7fELF`), bitness, endianness, and inspects strings for stealth evasion tokens (`/proc/self/mem`, `ptrace`, raw socket bindings).

### 🎯 Robust Pure-Rust Offline YARA Rules Engine (`yara/mod.rs`)
- **100% Portable Pure-Rust Engine**: Zero reliance on external C libraries (`libyara`) ensures seamless, error-free cross-compilation across Windows MSVC and Linux MUSL static targets.
- **Pattern Matching Primitives**: Supports ASCII strings, UTF-16LE wide strings, case-insensitivity (`nocase`), and hex byte sequences with wildcards (`??`).
- **Compound Condition Evaluator**: Supports `all of them`, `any of them`, `at least N`, `pe and any of them`, and `elf and any of them`.
- **10 Curated Offline Signatures**:
  1. `Ransomware_WannaCry_Core`: WannaCry killswitch domain, tasksche, mssecsvc.exe.
  2. `Ransomware_LockBit3_Black`: LockBit 3.0 wallpaper tokens, command-line arguments, pass-key hashes.
  3. `Botnet_Mirai_Agent`: Mirai attack tokens, CNC commands, killer routines.
  4. `Cryptominer_Kinsing_Payload`: Kinsing mining scripts, masscan calls, crontab persistence.
  5. `Backdoor_Linux_BPFDoor`: BPFDoor packet filtering, stealth raw sockets.
  6. `Infostealer_RedLine_Vidar`: Browser credential stealers, crypto wallet path queries.
  7. `CobaltStrike_Beacon_Payload`: Cobalt Strike named pipes, default stagers, beacon metadata.
  8. `WebShell_Generic_PHP_JSP`: Common web shells (b374k, c99, r57, passthru execution).
  9. `ProcessInjection_Hollowing_API`: Process hollowing API sequences (`NtUnmapViewOfSection`, `VirtualAllocEx`).
  10. `Dropper_Obfuscated_PowerShell`: Encoded droppers (`-enc`, `FromBase64String`, `DownloadString`).
- **In-Memory Custom Rule Compiler**: Write, compile, and validate custom `.yar` rules directly inside the dashboard.

### 📑 Executive & Technical Forensic Reports (`reports/mod.rs`)
- **Standalone Cyber-Obsidian HTML Report**: Interactive, styled offline single-page HTML report summarizing threat findings, file indicators, metadata, and print-to-PDF CSS.
- **OASIS STIX 2.1 JSON Threat Bundle**: Standardized format (`bundle`, `identity`, `indicator`, `malware`, `relationship`) for seamless SOC / SIEM ingestion (Splunk, Elastic Security, Microsoft Sentinel).

### 🔒 Cryptographic Quarantine Vault (`quarantine/manager.rs`)
Detected threats are neutralized using a multi-stage defense-in-depth sequence inside the platform quarantine directory (`%LOCALAPPDATA%\Sentient\Quarantine` on Windows, `~/.local/share/sentient/Quarantine` on Linux):
1. **Extension Neutralization**: Appends `.quarantined` to prevent accidental shell double-click execution.
2. **Header & Stream Scrambling**: Applies a reversible byte-level **XOR (`0x5A`) cipher**, invalidating executable (`MZ` / `ELF`) headers on disk.
3. **OS Permission Hardening**:
   - **Windows**: Denies `Everyone` (`*S-1-1-0`) Read/Write/Execute permissions via NTFS ACLs and sets `FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN`.
   - **Linux**: Strips all read, write, and execute permissions (`chmod 000`) and applies immutable attributes (`chattr +i`) when running as root.
4. **Metadata Persistence (`quarantine_index.json`)**: Records original path, timestamp, threat classification, file size, and SHA-256 fingerprint.
5. **Restore or Secure Zero-Wipe**: De-XOR and return false positives cleanly to their original path, or overwrite bytes with zeros prior to unlinking.

### 📜 Audit Logs, Privilege Escalation & Threat Intelligence
- **Filterable Threat & Activity Audit**: Filter by *All*, *Threats*, *Warnings*, or *Info & Clean*; instant search by path or hash; one-click **Export JSON**.
- **Cross-Platform Elevation (`platform.rs`)**:
   - **Windows**: Detects token elevation and provides one-click Windows UAC relaunch (`ShellExecuteW`).
   - **Linux**: Detects UID 0 (root) and supports graphical PolicyKit (`pkexec`) elevation with `sudo` fallback.
- **Offline Threat Intelligence & Hash DB Updates**:
   - **100% Offline Database**: Bundles embedded threat definitions (`signatures.json`), enabling full scanning capabilities in completely air-gapped environments.
   - **Strictly Scoped Updates**: Update operations are strictly restricted to validating and synchronizing the offline hash database / threat intelligence (`signatures.json`). Sentient will never download binary patches, execute remote payloads, or transmit telemetry.
   - **Air-Gapped Feed Importer**: One-click import of external threat intelligence JSON bundles from secure offline drives or network shares.
   - **Custom IOC Editor**: Add custom SHA-256 or MD5 threat rules directly into `signatures.json` from **Preferences**.

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SENTIENT GUI THREAD (60 FPS)                              │
│       eframe / egui • Protection Radar • Telemetry Console • Forensic Exporter        │
│    Dashboard • Scan Center • Live Sentinel • Process Audit • Sockets • YARA • Vault   │
└───────────────────────────────────────────▲────────────────────────────────────────────┘
                                            │
                         crossbeam-channel (Non-blocking async telemetry stream)
                                            │
┌───────────────────────────────────────────┴────────────────────────────────────────────┐
│                       MULTI-LAYER THREAT DETECTION & AUDIT SUITE                       │
├───────────────────────────────┬───────────────────────────────┬────────────────────────┤
│ 1. Hash & EICAR Engine        │ 2. Deep System Engine         │ 3. Real-Time Sentinel  │
│ • walkdir + rayon concurrency │ • Win: Native core engine     │ • Background watcher   │
│ • 64 KiB chunked SHA-256/MD5  │ • Linux: ClamAV / Native      │ • Downloads/Desktop/Tmp│
│ • Offline IOCs (signatures)   │ • Telemetry log parser        │ • Triple-check filter  │
├───────────────────────────────┼───────────────────────────────┼────────────────────────┤
│ 4. Process & Memory Audit     │ 5. Network Socket Auditor     │ 6. USB Auto-Defender   │
│ • Active PID inspection       │ • TCP / UDP endpoint audit    │ • Drive detection      │
│ • Image hash verification     │ • C2 port heuristics          │ • Autorun worm block   │
│ • Deleted binary evasion      │ • Direct socket PID kill      │ • Drive immunization   │
├───────────────────────────────┼───────────────────────────────┴────────────────────────┤
│ 7. Static Heuristics & YARA   │ 8. Executive & Technical Forensics                     │
│ • Shannon entropy crypter eval│ • Cyber-Obsidian standalone HTML forensic reports      │
│ • PE / ELF header anomalies   │ • Standard OASIS STIX 2.1 JSON Threat Intelligence     │
│ • 10 curated offline rules    │ • SIEM / SOC ingestion format (Splunk, Elastic)        │
└───────────────────────────────┴────────────────────────────────────────────────────────┘
                                            │ Threat Match / Auto-Quarantine
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                             QUARANTINE & PLATFORM HARDENING                            │
│  • Windows: %LOCALAPPDATA%\Sentient\Quarantine • XOR 0x5A Scramble • NTFS DACL Deny   │
│  • Linux:   ~/.local/share/sentient/Quarantine • XOR 0x5A Scramble • chmod 000        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```text
C:\Sentient
├── Cargo.toml                  # Cross-platform dependencies & LTO release profiles
├── signatures.json             # Offline IOC threat signature database (SHA-256 & MD5)
├── run_sentient.ps1            # Automated Windows toolchain setup & launch script
├── assets\
│   └── logo.png                # Sentient metallic cyber-helmet emblem
├── dist\                       # Pre-compiled ready-to-deploy distribution packages
│   ├── SentientSetup.exe       # Standalone native Windows installer wizard
│   ├── sentient_1.0.0_amd64.deb # Debian / Ubuntu / Kali native package
│   ├── sentient-v1.0.0-linux-x86_64.tar.gz # Self-contained Linux distribution
│   └── sentient-v1.0.0-windows-x64.zip    # Portable Windows release zip
├── installer\
│   ├── windows\
│   │   ├── SentientSetup.exe   # Standalone installer executable
│   │   ├── install.ps1         # PowerShell automated deployment script
│   │   └── install.bat         # Batch launcher
│   └── linux\
│       ├── install.sh          # POSIX shell installer with PolKit & desktop integration
│       ├── uninstall.sh        # Complete clean uninstaller
│       ├── sentient.desktop    # FreeDesktop application entry
│       └── org.sentient.security.policy # PolicyKit elevation policy
├── scripts\
│   └── build_linux_packages.py # Tarball & Debian .deb automated builder
└── src\
    ├── main.rs                 # Native viewport, icon embedding & app bootstrap
    ├── platform.rs             # Cross-platform UAC / pkexec elevation & quarantine ACL hardening
    ├── bin\
    │   └── installer.rs        # Native Windows standalone setup wizard
    ├── models\
    │   └── mod.rs              # Shared models, XDG / LocalAppData paths, ScanEvent, Threat
    ├── sentinel\
    │   └── mod.rs              # Real-Time On-Access Sentinel (continuous file drop watcher)
    ├── process\
    │   └── mod.rs              # Live Process & memory inspector (tasklist / /proc auditing & kill)
    ├── network\
    │   └── mod.rs              # Active socket & covert C2 connection auditor (netstat / ss /proc)
    ├── usb\
    │   └── mod.rs              # Removable media & USB auto-defender (autorun worm immunization)
    ├── heuristics\
    │   └── mod.rs              # Shannon entropy analyzer, PE/ELF header anomalies & crypter detection
    ├── yara\
    │   └── mod.rs              # Pure-Rust offline YARA engine (10 curated rules + custom parser)
    ├── reports\
    │   └── mod.rs              # Forensic report generator (cyber-obsidian HTML & OASIS STIX 2.1 JSON)
    ├── scanner\
    │   ├── mod.rs              # Module exports & backwards-compatibility aliases
    │   ├── hash_engine.rs      # Rayon parallel walker, 64 KiB hasher & EICAR matcher
    │   └── scanner.rs          # Dual-engine system scanner (Windows Core + Linux ClamAV/Native)
    ├── quarantine\
    │   ├── mod.rs
    │   └── manager.rs          # XOR 0x5A scrambler, quarantine indexer & secure zero-wipe
    └── ui\
        ├── mod.rs
        └── app.rs              # Cyber-obsidian dashboard, tabs, real-time widgets & vector icons
```

---

## ⚡ Installation & Quick Start

### 🪟 Windows Installation

You can install Sentient on Windows using any of the following methods:

#### Method 1: Standalone Native Installer (Recommended)
Double-click `dist\SentientSetup.exe` or `installer\windows\SentientSetup.exe`.
- Checks for administrative privileges (prompts for UAC or falls back to per-user install).
- Deploys `sentient.exe`, offline signatures, and assets to `C:\Program Files\Sentient`.
- Creates Desktop & Start Menu shortcuts.
- Registers Sentient in Windows **Installed Apps / Add or Remove Programs** with full uninstaller support.
- Supports silent IT deployment via command line:
  ```powershell
  .\dist\SentientSetup.exe /S
  ```

#### Method 2: Automated PowerShell Script
Run the included PowerShell installer from an elevated prompt:
```powershell
powershell -ExecutionPolicy Bypass -File .\installer\windows\install.ps1
```

#### Method 3: Portable Archive
Extract `dist\sentient-v1.0.0-windows-x64.zip` and run `sentient.exe` directly.

#### Windows Uninstallation
To cleanly remove Sentient and all shortcuts at any time:
- Via PowerShell uninstaller:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\installer\windows\uninstall.ps1
  ```
- Via Batch uninstaller: Double-click `installer\windows\uninstall.bat` or run `uninstall.bat` from `C:\Program Files\Sentient\`.
- Or through Windows **Settings &rarr; Installed Apps / Add or Remove Programs &rarr; Sentient Endpoint Defense &rarr; Uninstall**.

---

### 🐧 Linux Installation

Sentient provides both a native Debian package (`.deb`) and a universal self-contained tarball:

#### Method 1: Debian / Ubuntu / Kali / Mint Package (`.deb`)
Install using `dpkg` or `apt`:
```bash
sudo dpkg -i dist/sentient_1.0.0_amd64.deb
# Or via apt to automatically resolve any optional system libraries:
sudo apt install ./dist/sentient_1.0.0_amd64.deb
```
- Installs binary to `/usr/bin/sentient`.
- Registers FreeDesktop application launcher (`sentient.desktop`).
- Sets up PolicyKit action (`org.sentient.security.policy`) for seamless elevated scans.
- Installs offline signatures to `/etc/sentient/signatures.json`.

#### Method 2: Universal Tarball & Shell Installer
Unpack and run the installer on any Linux distribution (Arch, Fedora, openSUSE, Alpine, etc.):
```bash
tar -xzvf dist/sentient-v1.0.0-linux-x86_64.tar.gz
cd sentient-v1.0.0-linux-x86_64
sudo ./install.sh
```
To uninstall at any time:
```bash
sudo sentient-uninstall
```

---

## 🛠️ Building from Source & Testing

### Windows Build Options
Sentient compiles with either **MSVC** or a self-contained **GNU / LLVM (`gnullvm`)** Rust toolchain:

#### Option A: Included PowerShell Script (No Visual Studio Needed)
```powershell
powershell -ExecutionPolicy Bypass -File C:\Sentient\run_sentient.ps1
```

#### Option B: Standard Cargo
```powershell
cargo test
cargo build --release
cargo run --release
```

### Linux Build Options
On Ubuntu, Debian, Fedora, Arch, or other Linux distributions:

```bash
# 1. Install standard GUI dependencies (if not already present):
# Ubuntu / Debian:
sudo apt install libxkbcommon-dev libwayland-dev libx11-dev

# Fedora:
sudo dnf install libxkbcommon-devel wayland-devel libX11-devel

# Arch:
sudo pacman -S libxkbcommon wayland libx11

# 2. Build and run:
cargo test
cargo build --release
./target/release/sentient
```

### Automated Unit Test Suite (28 Passed)
Sentient includes **28 comprehensive unit tests** validating Windows and Linux scanning engines, heuristic algorithms, quarantine isolation, YARA rule matching, Shannon entropy, process audits, network socket risk evaluation, and forensic reporting:
- **Pure-Rust YARA Engine (`test_text_pattern_matching_ascii_and_wide`, `test_hex_pattern_with_wildcards`, `test_curated_rules_detection`, `test_parse_yara_source_syntax`)**: Validates text, wide UTF-16LE, hex wildcards (`??`), curated ransomware rules (WannaCry, LockBit 3.0), and custom syntax parsing.
- **Shannon Entropy & Binary Heuristics (`test_shannon_entropy_constant_bytes`, `test_shannon_entropy_random_bytes`, `test_pe_header_inspection`, `test_elf_header_inspection`)**: Validates mathematical entropy calculation, crypter threshold detection ($>7.8$), and PE/ELF header parser safety.
- **Real-Time Sentinel Watcher (`test_sentinel_watch_roots_validity`)**: Validates resolution of user drop directories across platforms (`Downloads`, `Desktop`, `Temp`, `/tmp`, `/dev/shm`).
- **Live Process Risk Evaluator (`test_process_risk_assessment`)**: Verifies masquerade detection, hash matching against active IOCs, and path risk scoring.
- **Network Socket Auditor (`test_assess_socket_risk_flags_metasploit_port`)**: Validates port risk heuristics against Metasploit/Cobalt Strike listener ports (`4444`, `1337`, `31337`).
- **USB Auto-Defender (`test_inspect_removable_drive_flags_autorun`)**: Validates detection of malicious `autorun.inf` and immunization locking mechanisms.
- **Forensic Reporting (`test_html_and_stix_report_generation`)**: Verifies valid HTML rendering and compliant OASIS STIX 2.1 JSON bundle structure.
- **Curated Offline Malware Database (`test_embedded_database_contains_curated_threats`)**: Validates $O(1)$ fast indexing and hash matching for 50+ prominent threat families.
- **Strict Threat Intel Updates (`test_update_threat_intelligence_strictly_appends_hashes`)**: Validates that database updates strictly accept and append hash entries, discard malformed records, and cleanly deduplicate.
- **Linux Security Heuristics (`test_check_linux_path_heuristics`)**: Validates detection of unauthorized executables in `/tmp`, hidden droppers in `/dev/shm`, and world-writable binary audits in `/usr/bin`.
- **ClamAV Live Parser (`test_parse_clamav_line`)**: Tests stdout line-by-line parsing for real-time `path: ThreatName FOUND` stream telemetry.
- **Linux Engine Telemetry Round-Trip (`test_format_and_parse_linux_roundtrip`, `test_parse_linux_system_scan_report`)**: Validates structured report formatting and parsing across Linux system scan executions.
- **Windows System Telemetry (`test_parse_clean_windows_11_mrt_log`, `test_parse_infected_mrt_log_entry`)**: Validates clean and infected scan report parsing.
- **Linux & Windows Target Roots (`test_quick_scan_roots_returns_existing_directories`)**: Verifies dynamic resolution of user directories (`$HOME/Downloads`, `~/.local/bin`, `/tmp`, etc.).
- **Quarantine Isolation & Zero-Wipe (`test_quarantine_xor_and_restore_roundtrip`, `test_secure_delete_removes_payload_and_index`)**: Verifies `.quarantined` extension, XOR `0x5A` scrambling, restoration fidelity, and secure zero-fill wipe.
- **Streaming Hasher & Chunk Boundaries (`test_eicar_split_across_chunk_boundary`, `test_in_memory_eicar_self_test`)**: Tests 64 KiB streaming SHA-256/MD5 calculation and rolling-window EICAR detection across buffer boundaries.
- **Multithreaded Concurrent Scanner (`test_multithreaded_directory_scan_detects_simulated_sample`)**: Validates Rayon thread-pool traversal and thread-safe threat aggregation.
- **Dynamic Signature Seeding & Persistence (`test_signature_store_seed_and_add`)**: Tests local database seeding, custom IOC addition, and runtime persistence.

---

## 🧪 Safe Verification Guide (No Live Malware Needed)

1. **In-Memory EICAR Self-Test (Zero Disk Writes)**
   - Navigate to **Preferences** &rarr; click **Run In-Memory EICAR Self-Test**.
   - Streams the standard 68-byte EICAR pattern purely through RAM to verify engine readiness without triggering OS disk alerts.

2. **End-to-End Folder Quarantine Walkthrough**
   - Create a harmless test file (e.g. `test_threat.txt`) containing:
     ```text
     SENTIENT-LOCAL-SIMULATED-MALWARE-SAMPLE-V1
     ```
   - Open **Scan Center** &rarr; **Custom Folder Scan**, select the folder, and start scanning.
   - Sentient flags `Sentient.Test.SimulatedThreat.A`, isolates it into the quarantine directory scrambled with XOR `0x5A`, and allows you to test **Restore File** or **Delete Forever** in **Quarantine Vault**.

3. **Pure-Rust Offline YARA Rule Diagnostic**
   - Open the **YARA & Entropy** tab.
   - In the **Custom YARA Rule Compiler & Tester** panel, paste a test rule:
     ```yara
     rule Test_Detection {
         strings:
             $str = "SENTIENT_TEST_TOKEN"
         condition:
             $str
     }
     ```
   - Click **Compile & Test Custom Rule** to verify instant in-memory compilation and rule syntax validation.

4. **Shannon Entropy Crypter Analysis**
   - In **YARA & Entropy** &rarr; **Static Binary Heuristics**, select any binary or test file and click **Inspect File**.
   - Review the Shannon entropy score ($0.0 - 8.0$), PE / ELF structural anomalies, section execution permissions, and packer detections.

5. **Forensic Report & STIX 2.1 Threat Export**
   - After completing any scan in **Scan Center**, click **Export Forensic HTML** to generate an offline, standalone executive forensic report.
   - Click **Export STIX 2.1 (JSON)** to produce an OASIS-compliant CTI bundle suitable for SIEM/SOC ingestion.

---

## 🛡️ Tech Stack

| Layer | Crates / APIs / Standards |
| :--- | :--- |
| **Language** | Rust (2021 Edition, Strict Memory Safety) |
| **Desktop UI** | `eframe 0.37.0`, `egui 0.37.0`, `image 0.25.10` (Hardware accelerated 60 FPS) |
| **Concurrency & Channels** | `rayon 1.10.0`, `crossbeam-channel 0.5.15` (Zero-latency background threads) |
| **Cryptography & Hashing** | `sha2 0.11.1`, `md-5 0.11.0`, `hex 0.4.3`, `walkdir 2.5.0` |
| **Pattern & Rule Engine** | Native Pure-Rust YARA engine (ASCII, UTF-16LE, hex wildcards `??`, compound logic) |
| **Heuristics & Math** | Shannon Entropy Calculation ($H \in [0, 8]$), PE & ELF Header Decoders |
| **Threat Intelligence** | OASIS STIX 2.1 JSON Schema, Cyber-Obsidian HTML Report Generator |
| **Serialization & Time** | `serde 1.0`, `serde_json 1.0`, `chrono 0.4` |
| **Platform Integration** | `windows-sys 0.61.2` (Windows Win32/NTFS), `libc 0.2` (Linux POSIX/ProcFS), `rfd 0.17.0` |
| **Packaging & Distribution** | Native Windows PE Installer (`SentientSetup.exe`), Debian `.deb`, POSIX `.tar.gz` |

---

## Privacy & Zero-Telemetry Philosophy

Sentient is engineered strictly **offline-first**:
- Zero outbound HTTP requests or cloud hash lookups.
- All configuration, threat logs, and quarantine metadata live locally on the workstation.
- Fully memory-safe, transparent Rust codebase designed for high-assurance environments.
