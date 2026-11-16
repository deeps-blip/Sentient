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
   - Evaluates files against the local offline IOC database (`signatures.json`) plus **cross-chunk rolling-window EICAR detection** in memory.
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

### 🔒 Cryptographic Quarantine Vault (`quarantine/manager.rs`)
Detected threats are neutralized using a multi-stage defense-in-depth sequence inside the platform quarantine directory (`%LOCALAPPDATA%\Sentient\Quarantine` on Windows, `~/.local/share/sentient/Quarantine` on Linux):
1. **Extension Neutralization**: Appends `.quarantined` to prevent accidental shell double-click execution.
2. **Header & Stream Scrambling**: Applies a reversible byte-level **XOR (`0x5A`) cipher**, invalidating executable (`MZ` / `ELF`) headers on disk.
3. **OS Permission Hardening**:
   - **Windows**: Denies `Everyone` (`*S-1-1-0`) Read/Write/Execute permissions via NTFS ACLs and sets `FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN`.
   - **Linux**: Strips all read, write, and execute permissions (`chmod 000`) and applies immutable attributes (`chattr +i`) when running as root.
4. **Metadata Persistence (`quarantine_index.json`)**: Records original path, timestamp, threat classification, file size, and SHA-256 fingerprint.
5. **Restore or Secure Zero-Wipe**: De-XOR and return false positives cleanly to their original path, or overwrite bytes with zeros prior to unlinking.

### 📜 Audit Logs, Privilege Escalation & Custom IOCs
- **Filterable Threat & Activity Audit**: Filter by *All*, *Threats*, *Warnings*, or *Info & Clean*; instant search by path or hash; one-click **Export JSON**.
- **Cross-Platform Elevation (`platform.rs`)**:
   - **Windows**: Detects token elevation and provides one-click Windows UAC relaunch (`ShellExecuteW`).
   - **Linux**: Detects UID 0 (root) and supports graphical PolicyKit (`pkexec`) elevation with `sudo` fallback.
- **Custom Signature Editor**: Add custom SHA-256 or MD5 threat rules directly into `signatures.json` from **Preferences**.

---

## 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                       SENTIENT GUI THREAD (60 FPS)                      │
│     eframe / egui • Hero Radar • Live Telemetry • Quarantine Vault     │
└───────────────────────────────▲─────────────────────────────────────────┘
                                │
             crossbeam-channel (ScanEvent non-blocking stream)
                                │
┌───────────────────────────────┴─────────────────────────────────────────┐
│                     BACKGROUND SCANNER ORCHESTRATOR                     │
├───────────────────────────────────┬─────────────────────────────────────┤
│   Local Hash & EICAR Engine       │   Deep System Inspection Engine     │
│   • walkdir + rayon thread pool   │   • Windows: Native MRT engine      │
│   • 64 KiB chunked SHA-256 / MD5  │   • Linux: ClamAV / Native Audit    │
│   • signatures.json offline IOCs  │   • Linux Heuristics (/tmp droppers)│
│   • Cross-chunk EICAR detection   │   • Telemetry report parsing        │
└───────────────┬───────────────────┴─────────────────────────────────────┘
                │ Threat Match / Auto-Quarantine
                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      QUARANTINE & PLATFORM HARDENING                    │
│  • Windows: %LOCALAPPDATA%\Sentient\Quarantine • XOR 0x5A • NTFS DACLs  │
│  • Linux:   ~/.local/share/sentient/Quarantine • XOR 0x5A • chmod 000   │
└─────────────────────────────────────────────────────────────────────────┘
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
└── src\
    ├── main.rs                 # Native viewport, icon embedding & app bootstrap
    ├── platform.rs             # Cross-platform UAC / pkexec elevation & quarantine ACL hardening
    ├── models\
    │   └── mod.rs              # Shared models, XDG / LocalAppData paths, ScanEvent, Threat
    ├── scanner\
    │   ├── mod.rs              # Module exports & backwards-compatibility aliases
    │   ├── hash_engine.rs      # Rayon parallel walker, 64 KiB hasher & EICAR matcher
    │   └── scanner.rs          # Dual-engine system scanner (Windows Core + Linux ClamAV/Native)
    ├── quarantine\
    │   ├── mod.rs
    │   └── manager.rs          # XOR 0x5A scrambler, quarantine indexer & secure zero-wipe
    └── ui\
        ├── mod.rs
        └── app.rs              # Cyber-obsidian dashboard, vector icons, telemetry & tabs
```

---

## ⚡ Quick Start & Usage

### Running on Windows
Launch directly from File Explorer or PowerShell:
```powershell
cd C:\Sentient
.\sentient.exe
```
> **Tip:** Right-click `sentient.exe` &rarr; **Run as administrator** (or click **Elevate to Admin (UAC)** inside the sidebar) for privileged deep system scans.

### Running on Linux
Build and launch natively using standard Cargo:
```bash
cargo run --release
```
> **Tip:** For full system access across root directories, launch with PolicyKit (`pkexec ./target/release/sentient`) or click **Elevate to Admin** in the sidebar.

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

### Automated Unit Test Suite
Sentient includes 13 comprehensive unit tests validating Windows and Linux scanning engines, heuristic algorithms, quarantine isolation, and cryptographic integrity:
- **Linux Security Heuristics (`test_check_linux_path_heuristics`)**: Validates detection of unauthorized executables in `/tmp`, hidden droppers in `/dev/shm` (`.miner`), and world-writable binary audits in `/usr/bin`.
- **ClamAV Live Parser (`test_parse_clamav_line`)**: Tests stdout line-by-line parsing for real-time `path: ThreatName FOUND` stream telemetry.
- **Linux Engine Telemetry Round-Trip (`test_format_and_parse_linux_roundtrip`, `test_parse_linux_system_scan_report`)**: Validates structured report formatting and parsing across Linux system scan executions.
- **Windows System Telemetry (`test_parse_clean_windows_11_mrt_log`, `test_parse_infected_mrt_log_entry`)**: Validates clean and infected scan report parsing.
- **Linux & Windows Target Roots (`test_quick_scan_roots_returns_existing_directories`)**: Verifies dynamic resolution of user directories (`$HOME/Downloads`, `~/.local/bin`, `/tmp`, etc.).
- **Quarantine Isolation & Zero-Wipe (`test_quarantine_xor_and_restore_roundtrip`, `test_secure_delete_removes_payload_and_index`)**: Verifies `.quarantined` extension, XOR `0x5A` scrambling, restoration fidelity, and secure zero-fill wipe.
- **Streaming Hasher & Chunk Boundaries (`test_eicar_split_across_chunk_boundary`, `test_in_memory_eicar_self_test`)**: Tests 64 KiB streaming SHA-256/MD5 calculation and rolling-window EICAR detection across buffer boundaries.
- **Multithreaded Concurrent Scanner (`test_multithreaded_directory_scan_detects_simulated_sample`)**: Validates Rayon thread-pool traversal and thread-safe threat aggregation.

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

---

## 🛡️ Tech Stack

| Layer | Crates / APIs |
| :--- | :--- |
| **Language** | Rust (2021 Edition) |
| **Desktop UI** | `eframe 0.37.0`, `egui 0.37.0`, `image 0.25.10` |
| **Concurrency** | `rayon 1.10.0`, `crossbeam-channel 0.5.15` |
| **Cryptography & FS** | `sha2 0.11.1`, `md-5 0.11.0`, `hex 0.4.3`, `walkdir 2.5.0` |
| **Serialization & Time** | `serde 1.0`, `serde_json 1.0`, `chrono 0.4` |
| **Platform APIs** | `windows-sys 0.61.2` (Windows), `libc 0.2` (Linux), `rfd 0.17.0` |

---

## Privacy & Zero-Telemetry Philosophy

Sentient is engineered strictly **offline-first**:
- Zero outbound HTTP requests or cloud hash lookups.
- All configuration, threat logs, and quarantine metadata live locally on the workstation.
- Fully memory-safe, transparent Rust codebase designed for high-assurance environments.
