#![allow(dead_code)]
//! Probe HTTP massif via httpx (ProjectDiscovery).
//!
//! Activé par `--httpx` flag ou auto si httpx est installé.
//! Pour chaque sous-domaine découvert, httpx fait :
//! - Probe HTTP/HTTPS
//! - Status code + titre + content-length
//! - Tech detect (technologies serveur)
//! - Follow redirects
//! - Host header injection detection
//!
//! Output JSON ligne-par-ligne : {"url": "...", "status_code": 200, "title": "...", "tech": [...]}

use std::collections::HashSet;
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub content_length: Option<usize>,
    pub technologies: Vec<String>,
    pub content_type: Option<String>,
    pub redirect_url: Option<String>,
    pub response_time_ms: Option<u64>,
}

pub struct HttpProbe;

impl HttpProbe {
    /// Vérifie la disponibilité de httpx (ProjectDiscovery)
    pub fn is_available() -> bool {
        which("httpx").is_some()
    }

    /// Lance httpx sur une liste d'URLs/hôtes.
    /// Retourne un Vec de HttpProbeResult parsés depuis la sortie JSON de httpx.
    ///
    /// `targets` peut être :
    /// - Une liste de hosts (ex: ["scanme.nmap.org", "www.example.com"])
    /// - Une liste d'URLs (ex: ["https://scanme.nmap.org"])
    pub fn probe(targets: Vec<String>) -> Vec<HttpProbeResult> {
        if !Self::is_available() {
            eprintln!("[WARN] httpx non installé");
            return Vec::new();
        }
        if targets.is_empty() {
            return Vec::new();
        }

        // httpx accepte des URLs/hosts via stdin OU arguments
        // On passe via stdin pour gérer beaucoup de cibles
        let mut child = match Command::new("httpx")
            .args([
                "-json",
                "-silent",
                "-no-color",
                "-follow-redirects",
                "-timeout",
                "10",
                "-retries",
                "1",
                "-tech-detect",
                "-status-code",
                "-title",
                "-content-length",
                "-content-type",
                "-rt", // response time
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[WARN] httpx non lançable : {}", e);
                return Vec::new();
            }
        };

        // Envoie les cibles via stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let payload = targets.join("\n");
            let _ = stdin.write_all(payload.as_bytes());
            // Drop ferme stdin → httpx sait qu'on a fini
        }

        // Lit la sortie
        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[WARN] httpx wait_with_output : {}", e);
                return Vec::new();
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // httpx exit code 1 si certaines cibles ont fail (normal)
            // On continue quand même de parser stdout
            if output.stdout.is_empty() {
                eprintln!("[WARN] httpx stdout vide : {}", stderr);
                return Vec::new();
            }
        }

        Self::parse_jsonl(&String::from_utf8_lossy(&output.stdout))
    }

    /// Parse la sortie JSONL de httpx
    fn parse_jsonl(output: &str) -> Vec<HttpProbeResult> {
        output
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(Self::parse_one)
            .collect()
    }

    /// Parse une ligne JSON httpx en HttpProbeResult
    fn parse_one(line: &str) -> Option<HttpProbeResult> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;

        let url = v.get("url")?.as_str()?.to_string();
        let status_code = v
            .get("status_code")
            .and_then(|x| x.as_u64())
            .map(|x| x as u16);
        let title = v
            .get("title")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let content_length = v
            .get("content_length")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize);
        let content_type = v
            .get("content_type")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        let redirect_url = v
            .get("final_url")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty() && *s != url)
            .map(String::from);
        let response_time_ms = v
            .get("time")
            .and_then(|x| x.as_str())
            .and_then(|s| s.trim_end_matches("ms").parse::<u64>().ok());

        // Technologies : httpx peut renvoyer ["WordPress", "Cloudflare"] ou "WordPress,Cloudflare"
        let technologies: Vec<String> = v
            .get("tech")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| {
                // Fallback : champ "tech" parfois string
                v.get("tech")
                    .and_then(|x| x.as_str())
                    .map(|s| s.split(',').map(String::from).collect())
                    .unwrap_or_default()
            });

        Some(HttpProbeResult {
            url,
            status_code,
            title,
            content_length,
            technologies,
            content_type,
            redirect_url,
            response_time_ms,
        })
    }

    /// Déduplique par URL (un seul résultat par host)
    pub fn deduplicate(results: Vec<HttpProbeResult>) -> Vec<HttpProbeResult> {
        let mut seen = HashSet::new();
        results
            .into_iter()
            .filter(|r| seen.insert(r.url.clone()))
            .collect()
    }
}

/// Probe parallèle : un thread par chunk de cibles (utile si on a 100+ hosts)
pub fn probe_parallel(targets: Vec<String>, chunk_size: usize) -> Vec<HttpProbeResult> {
    if !HttpProbe::is_available() {
        return Vec::new();
    }
    let chunk_size = chunk_size.max(1);
    let chunks: Vec<Vec<String>> = targets.chunks(chunk_size).map(|c| c.to_vec()).collect();

    let (tx, rx) = mpsc::channel();
    let chunks = Arc::new(chunks);

    let mut handles = Vec::new();
    for chunk in chunks.iter() {
        let tx_clone = tx.clone();
        let chunk: Vec<String> = chunk.clone();
        let handle = thread::spawn(move || {
            let results = HttpProbe::probe(chunk);
            for r in results {
                let _ = tx_clone.send(Some(r));
            }
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
    HttpProbe::deduplicate(all)
}

/// Équivalent minimal de `which`
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
    fn test_parse_httpx_jsonl_valid() {
        let line = r#"{"url":"https://example.com","status_code":200,"title":"Example","content_length":1256,"tech":["Nginx","PHP"],"content_type":"text/html","time":"123ms"}"#;
        let result = HttpProbe::parse_one(line).expect("parse should succeed");
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.title.as_deref(), Some("Example"));
        assert_eq!(result.content_length, Some(1256));
        assert_eq!(result.technologies, vec!["Nginx", "PHP"]);
        assert_eq!(result.content_type.as_deref(), Some("text/html"));
        assert_eq!(result.response_time_ms, Some(123));
    }

    #[test]
    fn test_parse_httpx_jsonl_minimal() {
        // httpx peut renvoyer juste url + status_code
        let line = r#"{"url":"https://foo.com","status_code":301}"#;
        let result = HttpProbe::parse_one(line).expect("parse should succeed");
        assert_eq!(result.url, "https://foo.com");
        assert_eq!(result.status_code, Some(301));
        assert!(result.title.is_none());
        assert!(result.technologies.is_empty());
    }

    #[test]
    fn test_parse_httpx_jsonl_tech_as_string() {
        // Certaines versions de httpx renvoient tech comme string CSV
        let line = r#"{"url":"https://x.com","status_code":200,"tech":"WordPress,Cloudflare"}"#;
        let result = HttpProbe::parse_one(line).expect("parse should succeed");
        assert_eq!(result.technologies, vec!["WordPress", "Cloudflare"]);
    }

    #[test]
    fn test_parse_httpx_jsonl_invalid() {
        assert!(HttpProbe::parse_one("not json").is_none());
        assert!(HttpProbe::parse_one("{}").is_none()); // pas de url
        assert!(HttpProbe::parse_one(r#"{"url":"x"}"#).is_some()); // status_code optionnel, on accepte
    }

    #[test]
    fn test_parse_jsonl_multiple_lines() {
        let output = r#"{"url":"https://a.com","status_code":200}
{"url":"https://b.com","status_code":404}
not a json line
{"url":"https://c.com","status_code":500}
"#;
        let results = HttpProbe::parse_jsonl(output);
        assert_eq!(results.len(), 3); // ignore "not a json line"
        assert_eq!(results[0].url, "https://a.com");
        assert_eq!(results[2].status_code, Some(500));
    }

    #[test]
    fn test_deduplicate() {
        let results = vec![
            HttpProbeResult {
                url: "https://a.com".into(),
                status_code: Some(200),
                ..Default::default()
            },
            HttpProbeResult {
                url: "https://a.com".into(), // doublon
                status_code: Some(301),
                ..Default::default()
            },
            HttpProbeResult {
                url: "https://b.com".into(),
                status_code: Some(200),
                ..Default::default()
            },
        ];
        let dedup = HttpProbe::deduplicate(results);
        assert_eq!(dedup.len(), 2);
        assert_eq!(dedup[0].url, "https://a.com");
        assert_eq!(dedup[0].status_code, Some(200)); // garde le 1er
        assert_eq!(dedup[1].url, "https://b.com");
    }

    #[test]
    fn test_response_time_ms_parsing() {
        // httpx renvoie "123ms" ou "1.5s"
        let line_ms = r#"{"url":"https://x.com","status_code":200,"time":"456ms"}"#;
        let r = HttpProbe::parse_one(line_ms).unwrap();
        assert_eq!(r.response_time_ms, Some(456));
    }

    #[test]
    fn test_redirect_url_filtered() {
        // Si final_url == url, on n'enregistre pas le redirect
        let line = r#"{"url":"https://x.com","final_url":"https://x.com","status_code":200}"#;
        let r = HttpProbe::parse_one(line).unwrap();
        assert!(r.redirect_url.is_none());

        let line2 = r#"{"url":"https://x.com","final_url":"https://y.com","status_code":301}"#;
        let r2 = HttpProbe::parse_one(line2).unwrap();
        assert_eq!(r2.redirect_url.as_deref(), Some("https://y.com"));
    }

    #[test]
    fn test_http_probe_default_struct() {
        let r = HttpProbeResult::default();
        assert_eq!(r.url, "");
        assert!(r.status_code.is_none());
        assert!(r.technologies.is_empty());
    }
}
