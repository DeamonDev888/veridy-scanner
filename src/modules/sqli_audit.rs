#![allow(dead_code)]
//! Détection de vulnérabilités SQL injection via SQLMap.
//!
//! SQLMap est un outil mature de détection/exploitation SQLi.
//! On l'invoque en mode batch (--batch) sur les endpoints découverts qui
//! contiennent des paramètres (query strings).
//!
//! Active via `--sqli` flag.
//!
//! Output sqlmap : lignes du type :
//!   "Parameter: id (GET)"
//!   "    Type: boolean-based blind"
//!   "    Payload: id=1 AND 1=1"
//!   "    Title: AND boolean-based blind - WHERE or HAVING clause"

use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SqliFinding {
    pub url: String,
    pub parameter: String,
    pub method: String,              // "GET" | "POST"
    pub injection_type: Vec<String>, // ["boolean-based blind", "time-based blind", ...]
    pub payload: Option<String>,
    pub dbms: Option<String>,
}

pub struct SqliAuditor;

impl SqliAuditor {
    pub fn is_available() -> bool {
        which("sqlmap").is_some()
    }

    /// Lance sqlmap sur une URL.
    /// Retourne Ok avec les findings, ou Err si sqlmap échoue.
    pub fn scan_url(url: &str, timeout_secs: u64) -> Result<Vec<SqliFinding>, String> {
        let output = Command::new("sqlmap")
            .args([
                "-u",
                url,
                "--batch",        // mode non-interactif
                "--random-agent", // user-agent aléatoire
                "--level=2",      // 1-5 (5 = très agressif)
                "--risk=2",       // 1-3 (3 = très agressif)
                "--threads=1",    // 1 thread (sqlmap gère lui-même)
                "--timeout",
                &timeout_secs.to_string(),
                "--retries=1",
                "--no-cast",          // évite les conversions de type
                "--technique=BEUSTQ", // B=bool, E=error, U=union, S=stacked, T=time, Q=inlines
                "--flush-session",    // pas de cache entre URLs
                "--silent",           // réduit le bruit
                "-v",
                "0", // pas de verbose
            ])
            .output()
            .map_err(|e| format!("sqlmap non lançable : {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_output(&stdout, url))
    }

    /// Parse la sortie sqlmap et extrait les findings
    fn parse_output(output: &str, default_url: &str) -> Vec<SqliFinding> {
        let mut findings = Vec::new();
        let mut current: Option<SqliFinding> = None;

        for line in output.lines() {
            let trimmed = line.trim();

            // Détection d'un nouveau paramètre testé
            if let Some(rest) = trimmed.strip_prefix("Parameter: ") {
                // Flush le précédent
                if let Some(f) = current.take() {
                    if !f.injection_type.is_empty() {
                        findings.push(f);
                    }
                }
                // Format : "Parameter: id (GET)" ou "Parameter: id (POST)"
                let parts: Vec<&str> = rest.split_whitespace().collect();
                let parameter = parts.first().unwrap_or(&"").to_string();
                let method = rest
                    .rsplit('(')
                    .next()
                    .map(|s| s.trim_end_matches(')').to_string())
                    .unwrap_or_else(|| "GET".to_string());

                current = Some(SqliFinding {
                    url: default_url.to_string(),
                    parameter,
                    method,
                    injection_type: Vec::new(),
                    payload: None,
                    dbms: None,
                });
            } else if let Some(rest) = trimmed.strip_prefix("Type: ") {
                // Type d'injection détecté
                if let Some(c) = current.as_mut() {
                    let inj_type = rest.trim().to_string();
                    if !inj_type.is_empty() {
                        c.injection_type.push(inj_type);
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("Payload: ") {
                // Payload
                if let Some(c) = current.as_mut() {
                    c.payload = Some(rest.trim().to_string());
                }
            } else if let Some(rest) = trimmed.strip_prefix("back-end DBMS:") {
                // DBMS
                if let Some(c) = current.as_mut() {
                    c.dbms = Some(rest.trim().to_string());
                }
            }
        }

        // Flush le dernier
        if let Some(f) = current {
            if !f.injection_type.is_empty() {
                findings.push(f);
            }
        }

        findings
    }
}

/// Lance sqlmap en parallèle sur une liste d'URLs (1 thread par URL, sqlmap est lui-même single-thread).
pub fn scan_urls_parallel(urls: Vec<String>, timeout_secs: u64) -> Vec<SqliFinding> {
    if !SqliAuditor::is_available() {
        eprintln!("[WARN] sqlmap non installé");
        return Vec::new();
    }
    if urls.is_empty() {
        return Vec::new();
    }

    let (tx, rx) = mpsc::channel();
    let urls = Arc::new(urls);

    let mut handles = Vec::new();
    for url in urls.iter() {
        let tx_clone = tx.clone();
        let url = url.clone();
        let handle = thread::spawn(move || match SqliAuditor::scan_url(&url, timeout_secs) {
            Ok(findings) => {
                for f in findings {
                    let _ = tx_clone.send(Some(f));
                }
            }
            Err(e) => eprintln!("[WARN] sqlmap sur {} : {}", url, e),
        });
        handles.push(handle);
    }
    drop(tx);

    let mut all = Vec::new();
    for entry in rx.into_iter().flatten() {
        all.push(entry);
    }
    for h in handles {
        let _ = h.join();
    }
    all
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

    // Output réel typique de sqlmap --batch
    const SQLMAP_OUTPUT_VULN: &str = r#"
[*] starting @ 14:23:01 /2024
[14:23:02] [INFO] testing connection to the target URL
[14:23:03] [INFO] heuristics detected web page charset 'utf-8'
[14:23:04] [INFO] testing if the target URL is stable
[14:23:05] [INFO] target URL appears to be stable
[14:23:06] [INFO] testing if GET parameter 'id' is dynamic
[14:23:07] [INFO] GET parameter 'id' appears to be 'boolean-based blind' injectable
[14:23:08] [INFO] GET parameter 'id' is vulnerable
[14:23:09] [INFO] GET parameter 'id' is 'MySQL >= 5.0' injectable
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1
    Title: AND boolean-based blind - WHERE or HAVING clause
back-end DBMS: MySQL 5.7
Parameter: id (GET)
    Type: time-based blind
    Payload: id=1 AND SLEEP(5)
back-end DBMS: MySQL 5.7
[14:23:10] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output'
[*] ending @ 14:23:11 /2024
"#;

    const SQLMAP_OUTPUT_CLEAN: &str = r#"
[*] starting @ 14:25:01 /2024
[14:25:02] [INFO] testing connection to the target URL
[14:25:03] [INFO] GET parameter 'foo' does not appear to be 'injectable'
[*] ending @ 14:25:04 /2024
"#;

    #[test]
    fn test_sqlmap_availability() {
        // Si sqlmap est installé (ce qui est le cas sur Kali), doit être dispo
        if which("sqlmap").is_some() {
            assert!(SqliAuditor::is_available());
        }
    }

    #[test]
    fn test_parse_vulnerable_param() {
        let findings = SqliAuditor::parse_output(SQLMAP_OUTPUT_VULN, "http://test.com/page?id=1");
        assert_eq!(findings.len(), 2, "devrait avoir 2 findings");

        assert_eq!(findings[0].url, "http://test.com/page?id=1");
        assert_eq!(findings[0].parameter, "id");
        assert_eq!(findings[0].method, "GET");
        assert_eq!(findings[0].injection_type, vec!["boolean-based blind"]);
        assert_eq!(findings[0].payload.as_deref(), Some("id=1 AND 1=1"));
        assert_eq!(findings[0].dbms.as_deref(), Some("MySQL 5.7"));

        assert_eq!(findings[1].injection_type, vec!["time-based blind"]);
        assert_eq!(findings[1].payload.as_deref(), Some("id=1 AND SLEEP(5)"));
    }

    #[test]
    fn test_parse_clean_output() {
        let findings =
            SqliAuditor::parse_output(SQLMAP_OUTPUT_CLEAN, "http://test.com/page?foo=bar");
        assert!(findings.is_empty(), "Pas de finding sur clean output");
    }

    #[test]
    fn test_parse_empty_output() {
        let findings = SqliAuditor::parse_output("", "http://test.com/");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_post_method() {
        let output = r#"
Parameter: username (POST)
    Type: error-based
    Payload: username=admin' AND 1=1--
back-end DBMS: PostgreSQL 14
"#;
        let findings = SqliAuditor::parse_output(output, "http://test.com/login");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].method, "POST");
        assert_eq!(findings[0].injection_type, vec!["error-based"]);
        assert_eq!(findings[0].dbms.as_deref(), Some("PostgreSQL 14"));
    }

    #[test]
    fn test_parse_multiple_injection_types_one_param() {
        // Cas réel : sqlmap peut lister plusieurs types pour le même paramètre
        let output = r#"
Parameter: q (GET)
    Type: UNION query
    Payload: q=1' UNION SELECT NULL--
back-end DBMS: Microsoft SQL Server 2019
"#;
        let findings = SqliAuditor::parse_output(output, "http://test.com/search?q=test");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].injection_type, vec!["UNION query"]);
    }

    #[test]
    fn test_sqli_finding_default() {
        let f = SqliFinding::default();
        assert_eq!(f.url, "");
        assert_eq!(f.method, "");
        assert!(f.injection_type.is_empty());
    }
}
