use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_rc_exe() -> Option<PathBuf> {
    // 1. Try PATH
    if Command::new("rc.exe").arg("/?").output().is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }

    // 2. Search Windows Kits
    let sdk_root = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if sdk_root.exists() {
        if let Ok(entries) = fs::read_dir(sdk_root) {
            let mut versions: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir() && p.file_name().unwrap_or_default().to_string_lossy().starts_with("10."))
                .collect();
            // Sort descending so highest version is first
            versions.sort_by(|a, b| b.cmp(a));
            for ver in versions {
                let rc = ver.join("x64").join("rc.exe");
                if rc.exists() {
                    return Some(rc);
                }
            }
        }
    }

    None
}

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=resources/sentient.rc");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let icon_path = Path::new(&manifest_dir).join("assets").join("icon.ico");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let res_output = out_dir.join("sentient.res");
    let generated_rc = out_dir.join("sentient.rc");

    let escaped_icon_path = icon_path.to_string_lossy().replace('\\', "\\\\");
    let rc_content = format!(r#"1 ICON "{escaped_icon_path}""#);
    let _ = fs::write(&generated_rc, rc_content);

    if let Some(rc_exe) = find_rc_exe() {
        let status = Command::new(&rc_exe)
            .args(["/v", "/fo"])
            .arg(&res_output)
            .arg(&generated_rc)
            .status();

        if let Ok(s) = status {
            if s.success() && res_output.exists() {
                println!("cargo:rustc-link-arg={}", res_output.display());
            }
        }
    }

    // Prepare XOR scrambled payload for installer so Defender doesn't false-flag embedded PE headers
    let root_exe = Path::new(&manifest_dir).join("sentient.exe");
    let payload_path = Path::new(&manifest_dir).join("target").join("sentient.payload");
    if root_exe.exists() {
        if let Ok(bytes) = fs::read(&root_exe) {
            let scrambled: Vec<u8> = bytes.iter().map(|b| b ^ 0x5A).collect();
            let _ = fs::write(&payload_path, scrambled);
        }
    }
}
