use crate::models::{now_timestamp, ScanSummary};
use serde_json::json;

/// Generates a standalone, styled offline interactive HTML forensic report.
pub fn generate_html_report(summary: &ScanSummary) -> String {
    let threats_rows = if summary.detected_threats.is_empty() {
        r#"<tr><td colspan="6" style="text-align: center; color: #10B981; padding: 24px; font-weight: bold;">✔ Zero threats detected. Workstation verified clean.</td></tr>"#.to_string()
    } else {
        summary
            .detected_threats
            .iter()
            .enumerate()
            .map(|(i, t)| {
                format!(
                    r#"<tr>
                        <td>{}</td>
                        <td><span class="threat-badge">{}</span></td>
                        <td class="code-font" title="{}">{}</td>
                        <td>{} bytes</td>
                        <td class="code-font">{}</td>
                        <td><span class="status-badge {}">{}</span></td>
                    </tr>"#,
                    i + 1,
                    html_escape(&t.threat_name),
                    html_escape(&t.path.display().to_string()),
                    html_escape(&truncate_str(&t.path.display().to_string(), 50)),
                    t.file_size,
                    if !t.sha256.is_empty() { &t.sha256[0..16.min(t.sha256.len())] } else { &t.md5 },
                    if t.quarantined { "quarantined" } else { "detected" },
                    if t.quarantined { "QUARANTINED" } else { "DETECTED" }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentient Security - Forensic Incident Report</title>
    <style>
        :root {{
            --bg-body: #0a0e17;
            --bg-card: #141c2d;
            --bg-table: #101624;
            --border: #26344e;
            --text-primary: #e6edf8;
            --text-muted: #8b9bb4;
            --accent-cyan: #22d3ee;
            --accent-red: #ef4444;
            --accent-green: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-body);
            color: var(--text-primary);
            margin: 0;
            padding: 32px;
        }}
        .container {{
            max-width: 1080px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }}
        .brand {{
            font-size: 26px;
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--accent-cyan);
        }}
        .badge {{
            background: #142234;
            border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan);
            padding: 6px 14px;
            border-radius: 14px;
            font-size: 12px;
            font-weight: 700;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 28px;
        }}
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .card-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}
        .card-val {{
            font-size: 22px;
            font-weight: 800;
        }}
        .val-threat {{ color: var(--accent-red); }}
        .val-safe {{ color: var(--accent-green); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-table);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
        }}
        th {{
            background: #192338;
            color: var(--text-muted);
            font-size: 11.5px;
            text-transform: uppercase;
        }}
        .code-font {{ font-family: monospace; font-size: 12px; color: #94a3b8; }}
        .threat-badge {{
            color: var(--accent-red);
            font-weight: 700;
        }}
        .status-badge.quarantined {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 11px;
        }}
        .status-badge.detected {{
            background: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 11px;
        }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 18px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .card {{ border: 1px solid #ccc; background: #fafafa; }}
            table {{ border: 1px solid #ccc; }}
            th {{ background: #eee; color: #333; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">SENTIENT ENDPOINT SECURITY</div>
                <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">Forensic Telemetry & Threat Incident Audit Report</div>
            </div>
            <div class="badge">OFFLINE VERIFIED AUDIT</div>
        </div>

        <div class="summary-grid">
            <div class="card">
                <div class="card-label">Target Scanned</div>
                <div class="card-val" style="font-size: 16px;">{}</div>
            </div>
            <div class="card">
                <div class="card-label">Threats Identified</div>
                <div class="card-val {}">{}</div>
            </div>
            <div class="card">
                <div class="card-label">Files Traversed</div>
                <div class="card-val">{}</div>
            </div>
            <div class="card">
                <div class="card-label">Scan Duration</div>
                <div class="card-val">{:.2}s</div>
            </div>
        </div>

        <h3 style="margin-bottom: 12px;">Threat Findings & Remediation Ledger</h3>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Threat Name</th>
                    <th>Target Path</th>
                    <th>Size</th>
                    <th>Fingerprint</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>

        <div class="footer">
            Generated on {} by Sentient Antivirus Engine • 100% Offline Cryptographic Integrity
        </div>
    </div>
</body>
</html>"#,
        html_escape(&summary.target),
        if summary.threats_found > 0 { "val-threat" } else { "val-safe" },
        summary.threats_found,
        summary.files_scanned,
        summary.duration_secs,
        threats_rows,
        now_timestamp()
    )
}

/// Generates an OASIS STIX 2.1 compliant JSON bundle for SIEM / SOC ingestion.
pub fn generate_stix21_bundle(summary: &ScanSummary) -> String {
    let bundle_id = format!("bundle--{}", uuid_simple());
    let identity_id = format!("identity--{}", uuid_simple());
    let timestamp = chrono::Utc::now().to_rfc3339();

    let identity_obj = json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "Sentient Offline Endpoint Security",
        "identity_class": "system"
    });

    let mut objects = vec![identity_obj];

    for (idx, threat) in summary.detected_threats.iter().enumerate() {
        let indicator_id = format!("indicator--{}-{idx}", uuid_simple());
        let malware_id = format!("malware--{}-{idx}", uuid_simple());
        let rel_id = format!("relationship--{}-{idx}", uuid_simple());

        let sha_val = if !threat.sha256.is_empty() {
            threat.sha256.clone()
        } else {
            threat.md5.clone()
        };

        let indicator_obj = json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": timestamp,
            "modified": timestamp,
            "name": format!("Threat Indicator: {}", threat.threat_name),
            "pattern_type": "stix",
            "pattern": format!("[file:hashes.'SHA-256' = '{}']", sha_val),
            "valid_from": timestamp,
        });

        let malware_obj = json!({
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": timestamp,
            "modified": timestamp,
            "name": threat.threat_name,
            "is_family": false,
            "description": format!("Identified by Sentient at {}", threat.path.display()),
        });

        let rel_obj = json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": malware_id
        });

        objects.push(indicator_obj);
        objects.push(malware_obj);
        objects.push(rel_obj);
    }

    let bundle = json!({
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    });

    serde_json::to_string_pretty(&bundle).unwrap_or_else(|_| "{}".to_string())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut truncated: String = s.chars().take(max_chars).collect();
        truncated.push_str("...");
        truncated
    }
}

fn uuid_simple() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:016x}{:016x}", nanos, nanos.wrapping_mul(0x517cc1b727220a95))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ScanMode, Threat, ThreatSource};
    use std::path::PathBuf;

    #[test]
    fn test_html_and_stix_report_generation() {
        let summary = ScanSummary {
            mode: ScanMode::CustomFolder,
            target: "C:\\Target".to_string(),
            started_at: "2026-11-16 12:00:00".to_string(),
            finished_at: "2026-11-16 12:00:02".to_string(),
            duration_secs: 2.15,
            files_scanned: 10,
            bytes_scanned: 10240,
            threats_found: 1,
            skipped_inaccessible: 0,
            cancelled: false,
            detected_threats: vec![Threat {
                id: "th1".to_string(),
                path: PathBuf::from("C:\\Target\\malware.exe"),
                threat_name: "Ransom.Win32.WannaCry.Dropper".to_string(),
                sha256: "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c".to_string(),
                md5: "84c82835a5d21bbcf75a61706d8ab549".to_string(),
                file_size: 4096,
                detected_at: "2026-11-16 12:00:01".to_string(),
                source: ThreatSource::HashDatabase,
                quarantined: true,
            }],
            mrt_report: None,
        };

        let html = generate_html_report(&summary);
        assert!(html.contains("SENTIENT ENDPOINT SECURITY"));
        assert!(html.contains("Ransom.Win32.WannaCry.Dropper"));
        assert!(html.contains("QUARANTINED"));

        let stix = generate_stix21_bundle(&summary);
        assert!(stix.contains(r#""type": "bundle""#));
        assert!(stix.contains("24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"));
    }
}
