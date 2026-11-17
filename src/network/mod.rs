use serde::{Deserialize, Serialize};
use std::process::Command;

/// Protocol of the monitored network endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

/// Security risk rating of an active socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketRisk {
    Normal,
    SuspiciousC2Port,
    UnauthorizedListener,
}

impl SocketRisk {
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::SuspiciousC2Port => "WARNING - Known C2/Backdoor Port",
            Self::UnauthorizedListener => "Elevated - High Port Listener",
        }
    }

    pub fn is_suspicious(self) -> bool {
        !matches!(self, Self::Normal)
    }
}

/// Information regarding an active network socket connection or listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSocketEntry {
    pub protocol: SocketProtocol,
    pub local_addr: String,
    pub foreign_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub risk: SocketRisk,
    pub warning: Option<String>,
}

/// Scans active network connections and listening ports across Windows and Linux.
pub fn scan_active_network_sockets() -> Vec<NetworkSocketEntry> {
    #[cfg(windows)]
    {
        scan_windows_sockets()
    }

    #[cfg(not(windows))]
    {
        scan_linux_sockets()
    }
}

#[cfg(windows)]
fn scan_windows_sockets() -> Vec<NetworkSocketEntry> {
    let mut entries = Vec::new();

    // Query active TCP/UDP endpoints via netstat
    let output = match Command::new("netstat").args(["-ano"]).output() {
        Ok(out) => out,
        Err(_) => return entries,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // Format: TCP 127.0.0.1:port 0.0.0.0:0 LISTENING 1234
        // Format: UDP 0.0.0.0:port *:* 1234
        if tokens[0].eq_ignore_ascii_case("TCP") && tokens.len() >= 5 {
            let local_addr = tokens[1].to_string();
            let foreign_addr = tokens[2].to_string();
            let state = tokens[3].to_string();
            let pid = tokens[4].parse::<u32>().ok();

            let (risk, warning) = assess_socket_risk(&local_addr, &foreign_addr);

            entries.push(NetworkSocketEntry {
                protocol: SocketProtocol::Tcp,
                local_addr,
                foreign_addr,
                state,
                pid,
                process_name: None,
                risk,
                warning,
            });
        } else if tokens[0].eq_ignore_ascii_case("UDP") && tokens.len() >= 4 {
            let local_addr = tokens[1].to_string();
            let foreign_addr = tokens[2].to_string();
            let state = "UDP".to_string();
            let pid = tokens[3].parse::<u32>().ok();

            let (risk, warning) = assess_socket_risk(&local_addr, &foreign_addr);

            entries.push(NetworkSocketEntry {
                protocol: SocketProtocol::Udp,
                local_addr,
                foreign_addr,
                state,
                pid,
                process_name: None,
                risk,
                warning,
            });
        }
    }

    entries
}

#[cfg(not(windows))]
fn scan_linux_sockets() -> Vec<NetworkSocketEntry> {
    let mut entries = Vec::new();

    // 1. Attempt ss command with process info (-tunap)
    if let Ok(out) = Command::new("ss").args(["-tunap"]).output() {
        if out.status.success() && !out.stdout.is_empty() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().skip(1) {
                if let Some(entry) = parse_ss_line(line) {
                    entries.push(entry);
                }
            }
            if !entries.is_empty() {
                return entries;
            }
        }
    }

    // 2. Fallback: Attempt netstat command (-tunap or -tuna)
    let netstat_output = Command::new("netstat")
        .args(["-tunap"])
        .output()
        .or_else(|_| Command::new("netstat").args(["-tuna"]).output());

    if let Ok(out) = netstat_output {
        if out.status.success() && !out.stdout.is_empty() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().skip(1) {
                if let Some(entry) = parse_netstat_line(line) {
                    entries.push(entry);
                }
            }
            if !entries.is_empty() {
                return entries;
            }
        }
    }

    // 3. Kernel fallback: Direct /proc/net/tcp and /proc/net/udp parsing (universal on Linux)
    parse_proc_net_file("/proc/net/tcp", SocketProtocol::Tcp, &mut entries);
    parse_proc_net_file("/proc/net/udp", SocketProtocol::Udp, &mut entries);

    entries
}

#[cfg(not(windows))]
fn parse_ss_line(line: &str) -> Option<NetworkSocketEntry> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 5 {
        return None;
    }
    let proto = if tokens[0].to_lowercase().contains("tcp") {
        SocketProtocol::Tcp
    } else {
        SocketProtocol::Udp
    };

    let (state, local_addr, foreign_addr, proc_token) = if tokens.len() >= 6 {
        (tokens[1].to_string(), tokens[4].to_string(), tokens[5].to_string(), tokens.get(6).copied())
    } else {
        ("UNKNOWN".to_string(), tokens[3].to_string(), tokens[4].to_string(), tokens.get(5).copied())
    };

    let mut pid = None;
    let mut process_name = None;

    if let Some(proc_str) = proc_token {
        if let Some(pid_idx) = proc_str.find("pid=") {
            let rest = &proc_str[pid_idx + 4..];
            let pid_digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            pid = pid_digits.parse::<u32>().ok();
        }
        if let Some(quote_start) = proc_str.find('"') {
            if let Some(quote_end) = proc_str[quote_start + 1..].find('"') {
                process_name = Some(proc_str[quote_start + 1..quote_start + 1 + quote_end].to_string());
            }
        }
    }

    let (risk, warning) = assess_socket_risk(&local_addr, &foreign_addr);
    Some(NetworkSocketEntry {
        protocol: proto,
        local_addr,
        foreign_addr,
        state,
        pid,
        process_name,
        risk,
        warning,
    })
}

#[cfg(not(windows))]
fn parse_netstat_line(line: &str) -> Option<NetworkSocketEntry> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 5 {
        return None;
    }
    let proto = if tokens[0].to_lowercase().starts_with("tcp") {
        SocketProtocol::Tcp
    } else if tokens[0].to_lowercase().starts_with("udp") {
        SocketProtocol::Udp
    } else {
        return None;
    };

    let local_addr = tokens.get(3)?.to_string();
    let foreign_addr = tokens.get(4)?.to_string();
    let state = tokens.get(5).copied().unwrap_or("UNKNOWN").to_string();

    let mut pid = None;
    let mut process_name = None;
    if let Some(pid_prog) = tokens.get(6) {
        if let Some((p, n)) = pid_prog.split_once('/') {
            pid = p.parse::<u32>().ok();
            process_name = Some(n.to_string());
        }
    }

    let (risk, warning) = assess_socket_risk(&local_addr, &foreign_addr);
    Some(NetworkSocketEntry {
        protocol: proto,
        local_addr,
        foreign_addr,
        state,
        pid,
        process_name,
        risk,
        warning,
    })
}

#[cfg(not(windows))]
fn parse_proc_net_file(path: &str, proto: SocketProtocol, entries: &mut Vec<NetworkSocketEntry>) {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines().skip(1) {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 4 {
                let local_addr = parse_proc_hex_endpoint(tokens[1]);
                let foreign_addr = parse_proc_hex_endpoint(tokens[2]);
                let state = match tokens[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "04" => "FIN_WAIT1",
                    "05" => "FIN_WAIT2",
                    "06" => "TIME_WAIT",
                    "07" => "CLOSE",
                    "08" => "CLOSE_WAIT",
                    "09" => "LAST_ACK",
                    "0A" => "LISTEN",
                    "0B" => "CLOSING",
                    _ => "UNKNOWN",
                }
                .to_string();

                let (risk, warning) = assess_socket_risk(&local_addr, &foreign_addr);
                entries.push(NetworkSocketEntry {
                    protocol: proto,
                    local_addr,
                    foreign_addr,
                    state,
                    pid: None,
                    process_name: None,
                    risk,
                    warning,
                });
            }
        }
    }
}

#[cfg(not(windows))]
fn parse_proc_hex_endpoint(hex_endpoint: &str) -> String {
    let mut parts = hex_endpoint.split(':');
    let ip_hex = parts.next().unwrap_or("00000000");
    let port_hex = parts.next().unwrap_or("0000");

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    if let Ok(num) = u32::from_str_radix(ip_hex, 16) {
        let b = num.to_le_bytes();
        format!("{}.{}.{}.{}:{}", b[0], b[1], b[2], b[3], port)
    } else {
        format!("0.0.0.0:{port}")
    }
}

fn assess_socket_risk(local_addr: &str, foreign_addr: &str) -> (SocketRisk, Option<String>) {
    let known_c2_ports = [4444, 1337, 6667, 8888, 9001, 31337, 5555, 8088, 8889];

    let local_port = local_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);

    let foreign_port = foreign_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);

    if known_c2_ports.contains(&local_port) || known_c2_ports.contains(&foreign_port) {
        return (
            SocketRisk::SuspiciousC2Port,
            Some(format!(
                "Port {} is associated with Metasploit, Cobalt Strike, or known C2 backdoors.",
                if known_c2_ports.contains(&local_port) { local_port } else { foreign_port }
            )),
        );
    }

    if local_port > 40000 && local_addr.starts_with("0.0.0.0") {
        return (
            SocketRisk::UnauthorizedListener,
            Some(format!("High-range listening port {local_port} bound on all interfaces (0.0.0.0).")),
        );
    }

    (SocketRisk::Normal, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assess_socket_risk_flags_metasploit_port() {
        let (risk, warning) = assess_socket_risk("0.0.0.0:4444", "0.0.0.0:0");
        assert_eq!(risk, SocketRisk::SuspiciousC2Port);
        assert!(warning.unwrap().contains("4444"));

        let (risk_clean, _) = assess_socket_risk("127.0.0.1:80", "127.0.0.1:51234");
        assert_eq!(risk_clean, SocketRisk::Normal);
    }
}
