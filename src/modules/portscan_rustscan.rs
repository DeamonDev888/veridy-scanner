#![allow(dead_code)]
//! Port scan ultra-rapide via RustScan + intégration Nmap.
//! Version recréée après suppression accidentelle.

use std::time::Instant;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RustScanResult {
    pub host: String,
    pub open_ports: Vec<u16>,
    pub scan_duration_ms: u64,
    pub success: bool,
}

pub struct RustScanWrapper;

impl RustScanWrapper {
    pub fn is_available() -> bool {
        which("rustscan").is_some()
    }

    pub fn scan_ports(target: &str, timeout_secs: u64) -> Result<RustScanResult, String> {
        if !Self::is_available() {
            return Err("rustscan non installé".into());
        }
        let start = Instant::now();
        let output = crate::utils::run_tool(
            "rustscan",
            &[
                "-a",
                target,
                "--ulimit",
                "5000",
                "-t",
                &timeout_secs.to_string(),
                "-g",
                "--no-banner",
            ],
            180,
        )
        .ok_or_else(|| "rustscan : timeout (180s) ou binaire introuvable".to_string())?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let open_ports = Self::parse_output(&stdout);

        Ok(RustScanResult {
            host: target.to_string(),
            open_ports,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            success: output.status.success(),
        })
    }

    pub fn parse_output(stdout: &str) -> Vec<u16> {
        let mut ports = Vec::new();
        for line in stdout.lines() {
            // Format legacy : "Open 45.33.32.156:22"
            if let Some(idx) = line.find("Open ") {
                let after = &line[idx + 5..];
                if let Some(colon) = after.find(':') {
                    if let Ok(p) = after[colon + 1..].trim().parse::<u16>() {
                        if !ports.contains(&p) {
                            ports.push(p);
                        }
                    }
                }
            }
            // Format greppable -g (rustscan >= 2) : "1.2.3.4 -> [22,80,443]"
            if let Some(idx) = line.find("-> [") {
                let after = &line[idx + 4..];
                if let Some(end) = after.find(']') {
                    for tok in after[..end].split(',') {
                        if let Ok(p) = tok.trim().parse::<u16>() {
                            if !ports.contains(&p) {
                                ports.push(p);
                            }
                        }
                    }
                }
            }
        }
        ports.sort_unstable();
        ports
    }
}

fn which(tool: &str) -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("PATH") {
        for dir in std::env::split_paths(&p) {
            for ext in &["", ".exe"] {
                let candidate = dir.join(format!("{}{}", tool, ext));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}
