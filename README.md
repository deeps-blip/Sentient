<div align="center">

<img src="assets/logo.png" alt="Sentient Endpoint Security Logo" width="140" />

# 🛡️ SENTIENT

**High-Performance, Offline-First Desktop Antivirus Engineered in Pure Rust**

[![Rust](https://img.shields.io/badge/Built%20With-Rust%202021-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![GUI](https://img.shields.io/badge/UI-eframe%20%2F%20egui%200.37-22D3EE?style=for-the-badge)](https://github.com/emilk/egui)
[![Privacy](https://img.shields.io/badge/Telemetry-Zero%20Cloud%20%7C%20100%25%20Offline-10B981?style=for-the-badge)](#privacy--zero-telemetry-philosophy)

*Zero telemetry. Zero cloud uploads. Single standalone native binary with hardware-accelerated UI and parallel cryptographic threat scanning.*

</div>

---

## ✨ Overview

**Sentient** is a lightweight, privacy-focused Windows desktop endpoint security application built in **pure Rust (2021 edition)**. Designed for air-gapped workstations, security researchers, and privacy-conscious power users, Sentient combines a **multithreaded chunked SHA-256 / MD5 inspection engine**, **in-memory EICAR verification**, a **deep Windows system scanner engine**, and a **hardened XOR-scrambled Quarantine Vault** inside a sleek cyber-obsidian dashboard running at 60 FPS.

---

## 🚀 Key Features

### 🎨 Next-Gen Cyber-Obsidian UI (`eframe` / `egui`)
- **Animated Protection Radar & Hero Status Banner**: Real-time endpoint posture feedback (*Protected*, *Scanning in Progress*, *Threats Detected*).
- **Live Telemetry Console**: Real-time progress tracking, `files/sec` and `MB/s` throughput metrics, active inspected path stream, and instant **Abort Scan** support without ever blocking the GUI thread.
- **Responsive Standalone Executable**: Ships as a single self-contained native `sentient.exe` binary with zero runtime dependencies.

### ⚡ Dual-Engine Threat Detection
1. **Multithreaded Local Hash & Heuristic Engine (`hash_engine.rs`)**:
   - Traverses directory trees concurrently using `walkdir` + `rayon` thread pools.
   - Computes **SHA-256** and **MD5** digests using constant **64 KiB streaming buffers** (inspects multi-gigabyte archives without memory spikes).
   - Evaluates files against the local offline IOC database (`signatures.json`) plus **cross-chunk rolling-window EICAR detection** in memory.
   - Gracefully skips locked or protected OS files (`pagefile.sys`, system handles) and reports skipped counts cleanly.
2. **Deep System Scanner Integration (`mrt.rs`)**:
   - Executes native background system-wide inspection cleanly with silent telemetry report parsing into Sentient's dashboard and audit logs.

### 🔒 Cryptographic Quarantine Vault (`quarantine/manager.rs`)
Detected threats are neutralized using a multi-stage defense-in-depth sequence inside `%LOCALAPPDATA%\Sentient\Quarantine`:
1. **Extension Neutralization**: Appends `.quarantined` to prevent accidental shell double-click execution.
2. **Header & Stream Scrambling**: Applies a reversible byte-level **XOR (`0x5A`) cipher**, invalidating Windows PE (`MZ`) headers on disk.
3. **NTFS Permission Hardening**: Sets `FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN` and restricts execution privileges via Windows ACLs.
4. **Metadata Persistence (`quarantine_index.json`)**: Records original path, timestamp, threat classification, file size, and SHA-256 fingerprint.
5. **Restore or Secure Zero-Wipe**: De-XOR and return false positives cleanly to their original path, or overwrite bytes with zeros prior to unlinking.

### 📜 Audit Logs, UAC Privileges & Custom IOCs
- **Filterable Threat & Activity Audit**: Filter by *All*, *Threats*, *Warnings*, or *Info & Clean*; instant search by path or hash; one-click **Export JSON**.
- **In-App UAC Elevation (`platform.rs`)**: Detects standard vs. Administrator token privileges via Win32 APIs and provides one-click UAC relaunch (`ShellExecuteW`).
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
│   • walkdir + rayon thread pool   │   • Quiet system sweep execution    │
│   • 64 KiB chunked SHA-256 / MD5  │   • Asynchronous log parsing        │
│   • signatures.json offline IOCs  │   • Return code & threat surfacing  │
└───────────────┬───────────────────┴─────────────────────────────────────┘
                │ Threat Match / Auto-Quarantine
                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      QUARANTINE & PLATFORM HARDENING                    │
│  %LOCALAPPDATA%\Sentient\Quarantine • .quarantined • XOR 0x5A • ACLs    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```text
C:\Sentient
├── Cargo.toml                  # Dependencies, Win32 features & LTO release profile
├── signatures.json             # Offline IOC threat signature seed (SHA-256 & MD5)
├── run_sentient.ps1            # Automated toolchain setup & launch script
├── assets\
│   └── logo.png                # Sentient metallic cyber-helmet emblem
└── src\
    ├── main.rs                 # Native Windows viewport, icon embedding & app bootstrap
    ├── platform.rs             # Win32 UAC token inspection, elevation & NTFS ACL locks
    ├── models\
    │   └── mod.rs              # Shared models (ProtectionStatus, ScanEvent, Threat, etc.)
    ├── scanner\
    │   ├── mod.rs
    │   ├── hash_engine.rs      # Rayon parallel walker, 64 KiB hasher & EICAR matcher
    │   └── mrt.rs              # Background system engine executor & report parser
    ├── quarantine\
    │   ├── mod.rs
    │   └── manager.rs          # XOR 0x5A scrambler, quarantine indexer & secure zero-wipe
    └── ui\
        ├── mod.rs
        └── app.rs              # Cyber-obsidian dashboard, vector icons, telemetry & tabs
```

---

## ⚡ Quick Start & Usage

### Run the Pre-Built Binary
Launch directly from File Explorer or PowerShell:
```powershell
cd C:\Sentient
.\sentient.exe
```
> **Tip:** Right-click `sentient.exe` &rarr; **Run as administrator** (or click **Elevate to Admin (UAC)** inside the sidebar) to enable full privileged System Scans.

---

## 🛠️ Building from Source & Testing

### Toolchain Options (Windows)
Sentient compiles cleanly with either **MSVC** or a self-contained **GNU / LLVM (`gnullvm`)** Rust toolchain:

#### Option A: Launch via Included PowerShell Script (No Visual Studio Needed)
```powershell
powershell -ExecutionPolicy Bypass -File C:\Sentient\run_sentient.ps1
```

#### Option B: Standard Cargo (MSVC with Visual Studio C++ Build Tools)
```powershell
cargo test
cargo build --release
cargo run --release
```

### Included Automated Test Suite
Running `cargo test` validates core security modules end-to-end:
- **Quarantine Round-Trip & Zero-Wipe**: Verifies `.quarantined` extension, XOR `0x5A` byte scrambling, restoration fidelity, and secure zeroing before file deletion.
- **Streaming Hashing & Chunk Boundaries**: Verifies 64 KiB streaming SHA-256/MD5 calculation, EICAR detection across chunk splits, and multithreaded directory traversal.
- **System Report Parser**: Verifies accurate extraction of scan timestamps, engine versions, return codes, and threat entries.

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
   - Sentient flags `Sentient.Test.SimulatedThreat.A`, isolates it into `%LOCALAPPDATA%\Sentient\Quarantine` scrambled with XOR `0x5A`, and allows you to test **Restore File** or **Delete Forever** in **Quarantine Vault**.

---

## 🛡️ Tech Stack

| Layer | Crates / APIs |
| :--- | :--- |
| **Language** | Rust (2021 Edition) |
| **Desktop UI** | `eframe 0.37.0`, `egui 0.37.0`, `image 0.25.10` |
| **Concurrency** | `rayon 1.10.0`, `crossbeam-channel 0.5.15` |
| **Cryptography & FS** | `sha2 0.11.1`, `md-5 0.11.0`, `hex 0.4.3`, `walkdir 2.5.0` |
| **Serialization & Time** | `serde 1.0`, `serde_json 1.0`, `chrono 0.4` |
| **OS & Dialogs** | `windows-sys 0.61.2`, `rfd 0.17.0` |

---

## Privacy & Zero-Telemetry Philosophy

Sentient is engineered strictly **offline-first**:
- Zero outbound HTTP requests or cloud hash lookups.
- All configuration, threat logs, and quarantine metadata live locally in `%LOCALAPPDATA%\Sentient\`.
- Designed as a transparent, memory-safe Rust alternative for endpoint inspection and incident verification.
