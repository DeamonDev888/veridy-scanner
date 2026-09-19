#![allow(dead_code)]
//! Port scan ultra-rapide via RustScan + intégration Nmap.
//!
//! Architecture RustScan :
//! 1. RustScan scan TOUS les ports en ~3 secondes (SYN scan via /dev/tcp)
//! 2. Passe les ports ouverts à Nmap pour détection version + scripts NSE
//!
//! Output RustScan : `45.33.32.156 -> [22,80]`
//! Output Nmap : XML avec services + versions
//!
//! Active via flag `--rustscan`. Fallback sur `ports.rs` (scan TCP Connect maison) si absent.

use std::process::Command;
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
    /// Vérifie la disponibilité de rustscan
    pub fn is_available() -> bool {
        which("rustscan").is_some()
    }

    /// Scan tous les ports d'une cible via rustscan (-a = address, --ulimit pour perf).
    /// Output attendu : "<ip> -> [22,80,443,...]"
    pub fn scan_ports(target: &str, timeout_secs: u64) -> Result<RustScanResult, String> {
        let start = Instant::now();
        let output = Command::new("rustscan")
            .args([
                "-a",
                target,
                "--ulimit",
                "5000",
                "-t",
                &timeout_secs.to_string(),
                "--no-banner",
            ])
            .output()
            .map_err(|e| format!("rustscan non lançable : {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "rustscan exit code {:?} : {}",
                output.status.code(),
                stderr
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let ports = Self::parse_ports(&stdout);

        Ok(RustScanResult {
            host: target.to_string(),
            open_ports: ports,
            scan_duration_ms: start.elapsed().as_millis() as u64,
            success: true,
        })
    }

    /// Parse la sortie rustscan (format : "<ip> -> [22,80,443]")
    fn parse_ports(output: &str) -> Vec<u16> {
        let mut ports = Vec::new();
        for line in output.lines() {
            let line = line.trim();

            // Format réel rustscan : "Open <ip>:<port>"
            if line.starts_with("Open ") {
                if let Some(colon) = line.rfind(':') {
                    let port_part: String = line[colon + 1..]
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();
                    if let Ok(port) = port_part.parse::<u16>() {
                        ports.push(port);
                    }
                }
            }

            // Format théorique : "x -> [22,80,443]" (defensif)
            if let Some(idx) = line.find("-> [") {
                let rest = &line[idx + 4..];
                if let Some(end) = rest.find(']') {
                    let inner = &rest[..end];
                    for p in inner.split(',') {
                        if let Ok(port) = p.trim().parse::<u16>() {
                            ports.push(port);
                        }
                    }
                }
            }
        }
        ports.sort();
        ports.dedup();
        ports
    }
}

fn which(tool: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_simple() {
        // Format théorique (defensif)
        let output = "45.33.32.156 -> [22,80]";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80]);
    }

    #[test]
    fn test_parse_ports_real_rustscan_format() {
        // Format réel rustscan : "Open <ip>:<port>"
        let output = "Open 45.33.32.156:22\nOpen 45.33.32.156:80\n[~] Starting Script(s)";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80]);
    }

    #[test]
    fn test_parse_ports_open_real_scan_output() {
        // Format réel complet d'un scan rustscan
        let output =
            "Open 45.33.32.156:22\nOpen 45.33.32.156:80\nOpen 45.33.32.156:443\n[~] Starting Nmap";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_mixed_format() {
        // Les deux formats combinés (futur-proof)
        let output = "Open 45.33.32.156:22\nOpen 45.33.32.156:80\nSummary x -> [443,8080]";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_complex() {
        let output = "Open 45.33.32.156:22\n45.33.32.156 -> [22,80,443,8080]\nDone!";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_empty() {
        assert!(RustScanWrapper::parse_ports("").is_empty());
        assert!(RustScanWrapper::parse_ports("No open ports").is_empty());
    }

    #[test]
    fn test_parse_ports_with_spaces() {
        let output = "45.33.32.156 -> [ 22 , 80 , 443 ]";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_dedup_and_sort() {
        let output = "x -> [443, 22, 80, 22, 443, 80]";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_invalid_lines() {
        let output = "garbage line 1\ngarbage line 2\n45.33.32.156 -> [22,80]\nnot a port here";
        let ports = RustScanWrapper::parse_ports(output);
        assert_eq!(ports, vec![22, 80]);
    }

    #[test]
    fn test_rustscan_availability() {
        // Test indirect : si rustscan n'est pas là, is_available retourne false
        // sinon true. On ne peut pas forcer un résultat sans PATH manipulation.
        let result = RustScanWrapper::is_available();
        // Au Kali sur lequel on tourne, rustscan est installé, donc doit être true
        // (ce test assume un environnement de dev)
        if which("rustscan").is_some() {
            assert!(result);
        } else {
            assert!(!result);
        }
    }
}
