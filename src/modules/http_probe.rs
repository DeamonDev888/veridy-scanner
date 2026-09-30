#![allow(dead_code)]
//! Probe HTTP massif via httpx (ProjectDiscovery).
//! Version recréée après suppression accidentelle.

use std::process::Command;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HttpProbeResult {
    pub url: String,
    /// Hote tel que soumis au probe (avant redirection) - cle de fusion.
    pub input_host: Option<String>,
    /// Premiere IP resolue (champ "a" du JSON httpx).
    pub ip_address: Option<String>,
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
    pub fn is_available() -> bool {
        let candidates = ["pdhttpx", "httpx"];
        for bin in &candidates {
            if which(bin).is_some() {
                // Test : doit être ProjectDiscovery
                if let Ok(o) = Command::new(bin).arg("-version").output() {
                    // Le banner ProjectDiscovery ("[INF] Current Version: ...") sort sur
                    // STDERR, pas stdout : fusionner les deux avant detection.
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    s.push_str(&String::from_utf8_lossy(&o.stderr));
                    if s.contains("Current") {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn probe(targets: Vec<String>) -> Vec<HttpProbeResult> {
        if !Self::is_available() || targets.is_empty() {
            return Vec::new();
        }
        // Sélection du binaire ProjectDiscovery
        let binary = if which("pdhttpx").is_some() {
            "pdhttpx"
        } else {
            "httpx"
        };

        let payload = targets.join("\n");
        let mut child = match Command::new(binary)
            .args([
                "-json",
                "-silent",
                "-no-color",
                "-follow-redirects",
                "-tech-detect",
                "-status-code",
                "-title",
                "-content-length",
                "-content-type",
                "-rt",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = std::io::Write::write_all(&mut stdin, payload.as_bytes());
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(r) = Self::parse_one(line) {
                results.push(r);
            }
        }
        results
    }

    pub fn parse_one(line: &str) -> Option<HttpProbeResult> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        let url = v.get("url")?.as_str()?.to_string();
        let input_host = v
            .get("input")
            .and_then(|x| x.as_str())
            .map(host_of)
            .filter(|h| !h.is_empty());
        let ip_address = v
            .get("a")
            .and_then(|x| x.as_array())
            .and_then(|arr| arr.iter().find_map(|x| x.as_str().map(String::from)));
        let status_code = v
            .get("status_code")
            .and_then(|x| x.as_u64())
            .map(|x| x as u16);
        let title = v.get("title").and_then(|x| x.as_str()).map(String::from);
        let content_length = v
            .get("content_length")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize);
        let content_type = v
            .get("content_type")
            .and_then(|x| x.as_str())
            .map(String::from);
        let redirect_url = None;
        let response_time_ms = None;
        let technologies = v
            .get("tech")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Some(HttpProbeResult {
            url,
            input_host,
            ip_address,
            status_code,
            title,
            content_length,
            technologies,
            content_type,
            redirect_url,
            response_time_ms,
        })
    }

    pub fn deduplicate(results: Vec<HttpProbeResult>) -> Vec<HttpProbeResult> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        results
            .into_iter()
            .filter(|r| seen.insert(r.url.clone()))
            .collect()
    }
}

/// Extrait l'hote (sans scheme/chemin/port) d'une URL ou d'un bare host.
fn host_of(u: &str) -> String {
    let no_scheme = u.split_once("://").map(|x| x.1).unwrap_or(u);
    no_scheme
        .split('/')
        .next()
        .unwrap_or(no_scheme)
        .split(':')
        .next()
        .unwrap_or(no_scheme)
        .to_string()
}

/// Fusionne les resultats httpx dans les sous-domaines decouverts :
/// un hote avec status_code devient vivant (is_alive, http_status, IP).
/// Sans cette etape, tous les hotes restent affiches muets en DB/rapport
/// (bug scan #269 : 9/9 vivants declares morts).
/// Retourne le nombre d'hotes confirmes vivants.
pub fn merge_into_subdomains(
    subs: &mut [crate::modules::subdomains::SubdomainResult],
    probes: &[HttpProbeResult],
) -> usize {
    let mut updated = 0;
    for sub in subs.iter_mut() {
        let host = sub.subdomain.trim_end_matches('.').to_lowercase();
        let probe = probes.iter().find(|r| {
            r.input_host
                .as_deref()
                .map(|h| h.trim_end_matches('.').to_lowercase() == host)
                .unwrap_or(false)
        });
        if let Some(r) = probe {
            if let Some(st) = r.status_code {
                sub.is_alive = true;
                sub.http_status = Some(st);
                if sub.ip_address.is_none() {
                    sub.ip_address = r.ip_address.clone();
                }
                updated += 1;
            }
        }
    }
    updated
}

pub fn probe_parallel(targets: Vec<String>, chunk_size: usize) -> Vec<HttpProbeResult> {
    if !HttpProbe::is_available() || targets.is_empty() {
        return Vec::new();
    }
    let chunks: Vec<Vec<String>> = if chunk_size == 0 || chunk_size >= targets.len() {
        vec![targets]
    } else {
        targets.chunks(chunk_size).map(|c| c.to_vec()).collect()
    };
    let mut all = Vec::new();
    for chunk in chunks {
        all.extend(HttpProbe::probe(chunk));
    }
    HttpProbe::deduplicate(all)
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
