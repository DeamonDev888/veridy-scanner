#![allow(dead_code)]
//! Détection de vulnérabilités SQL injection via SQLMap.
//! Version recréée après suppression accidentelle.




#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SqliFinding {
    pub url: String,
    pub parameter: String,
    pub method: String,
    pub injection_type: Vec<String>,
    pub payload: Option<String>,
    pub dbms: Option<String>,
}

pub struct SqliAuditor;

impl SqliAuditor {
    pub fn is_available() -> bool {
        which("sqlmap").is_some()
    }

    pub fn scan_url(url: &str, timeout_secs: u64) -> Result<Vec<SqliFinding>, String> {
        if !Self::is_available() {
            return Err("sqlmap non installé".into());
        }
        let output = crate::utils::run_tool(
            "sqlmap",
            &[
                "-u", url,
                "--batch",
                "--level=2",
                "--risk=2",
                "--threads=1",
                "--timeout", &timeout_secs.to_string(),
                "--retries=1",
                "--technique=BEUSTQ",
                "--flush-session",
                "--silent",
                "-v", "0",
            ],
            300,
        )
        .ok_or_else(|| "sqlmap : timeout (300s) ou binaire introuvable".to_string())?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_output(&stdout, url))
    }

    pub fn parse_output(stdout: &str, url: &str) -> Vec<SqliFinding> {
        // sqlmap est bavard même en --silent — on cherche les marqueurs explicites
        // de confirmation d'injection.
        let mut findings = Vec::new();
        let mut current: Option<SqliFinding> = None;

        for line in stdout.lines() {
            let l = line.trim();
            if l.starts_with("Parameter:") {
                if let Some(ref mut c) = current {
                    findings.push(c.clone());
                }
                let parts: Vec<&str> = l.split_whitespace().collect();
                let parameter = parts.get(1).unwrap_or(&"?").to_string();
                let method = parts.last().unwrap_or(&"?").trim_matches(|c| c == '(' || c == ')').to_string();
                current = Some(SqliFinding {
                    url: url.to_string(),
                    parameter,
                    method,
                    injection_type: Vec::new(),
                    payload: None,
                    dbms: None,
                });
            } else if let Some(ref mut c) = current {
                if l.starts_with("Type:") {
                    let inj = l.trim_start_matches("Type:").trim().to_string();
                    if !c.injection_type.contains(&inj) {
                        c.injection_type.push(inj);
                    }
                } else if l.starts_with("Payload:") {
                    c.payload = Some(l.trim_start_matches("Payload:").trim().to_string());
                } else if l.contains("back-end DBMS:") {
                    if let Some(idx) = l.find("back-end DBMS:") {
                        c.dbms = Some(l[idx + 14..].trim().to_string());
                    }
                }
            }
        }
        if let Some(c) = current {
            findings.push(c);
        }
        findings
    }
}

pub fn scan_urls_parallel(urls: Vec<String>, timeout_secs: u64) -> Vec<SqliFinding> {
    if !SqliAuditor::is_available() {
        return Vec::new();
    }
    let mut all = Vec::new();
    for url in urls {
        if let Ok(findings) = SqliAuditor::scan_url(&url, timeout_secs) {
            all.extend(findings);
        }
    }
    all
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
